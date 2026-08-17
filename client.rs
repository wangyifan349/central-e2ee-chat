use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs as stdfs,
    io::{self as stdio, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    time,
};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

struct Identity {
    signing_key: SigningKey,
    encryption_secret: StaticSecret,
    public_identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendMessageRequest {
    identity: String,
    recipient: String,
    message_id: String,
    timestamp: i64,
    nonce: String,
    ciphertext: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncRequest {
    identity: String,
    friend: String,
    after_row_id: i64,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageRecord {
    row_id: i64,
    message_id: String,
    sender: String,
    recipient: String,
    nonce: String,
    ciphertext: String,
    created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageSyncResponse {
    messages: Vec<MessageRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileInitRequest {
    identity: String,
    recipient: String,
    file_id: String,
    timestamp: i64,
    encrypted_name: String,
    name_nonce: String,
    encrypted_key: String,
    key_nonce: String,
    nonce_prefix: String,
    plain_size: i64,
    chunk_size: i64,
    total_chunks: i64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileCompleteRequest {
    identity: String,
    file_id: String,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileListRequest {
    identity: String,
    friend: String,
    after_row_id: i64,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileInfoRequest {
    identity: String,
    file_id: String,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileRecord {
    row_id: i64,
    file_id: String,
    sender: String,
    recipient: String,
    encrypted_name: String,
    name_nonce: String,
    encrypted_key: String,
    key_nonce: String,
    nonce_prefix: String,
    plain_size: i64,
    chunk_size: i64,
    total_chunks: i64,
    completed: bool,
    created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileListResponse {
    files: Vec<FileRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ack {
    ok: bool,
    detail: String,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn read_input(prompt: &str) -> Result<String> {
    print!("{prompt}");
    stdio::stdout().flush()?;
    let mut input_buffer = String::new();
    stdio::stdin().read_line(&mut input_buffer)?;
    Ok(input_buffer.trim().to_string())
}

fn safe_received_file_name(file_name: &str) -> Result<String> {
    let base_name = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim();
    if base_name.is_empty() || base_name == "." || base_name == ".." {
        bail!("invalid received file name");
    }
    Ok(base_name.to_string())
}

fn safe_identity_name(identity_name_input: &str) -> Result<String> {
    let identity_name = identity_name_input.trim();
    if identity_name.is_empty() {
        bail!("identity name cannot be empty");
    }
    if !identity_name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("identity name may only contain letters, numbers, '-' and '_'");
    }
    Ok(identity_name.to_string())
}

fn list_identity_files() -> Result<Vec<PathBuf>> {
    let identity_directory = PathBuf::from("identities");
    stdfs::create_dir_all(&identity_directory)?;
    #[cfg(unix)]
    stdfs::set_permissions(&identity_directory, stdfs::Permissions::from_mode(0o700))
        .context("secure identity directory permissions failed")?;
    let mut identity_paths = stdfs::read_dir(identity_directory)?
        .filter_map(|directory_entry| directory_entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("key"))
        .collect::<Vec<_>>();
    identity_paths.sort();
    Ok(identity_paths)
}

fn select_identity() -> Result<Option<(String, Identity)>> {
    loop {
        let identity_paths = list_identity_files()?;
        println!("\n=== Identity ===");
        if identity_paths.is_empty() {
            println!("No local identities yet.");
        }
        for (index, identity_path) in identity_paths.iter().enumerate() {
            let identity_name = identity_path.file_stem().and_then(|file_stem| file_stem.to_str()).unwrap_or("unknown");
            println!("{}. {}", index + 1, identity_name);
        }
        println!("N. Create a new identity");
        println!("0. Exit");
        let menu_selection = read_input("Select: ")?;
        if menu_selection.eq_ignore_ascii_case("n") {
            let identity_name_input = read_input("New identity name: ")?;
            let identity_name = match safe_identity_name(&identity_name_input) {
                Ok(name) => name,
                Err(error) => {
                    println!("{error}");
                    continue;
                }
            };
            let identity_path = PathBuf::from("identities").join(format!("{identity_name}.key"));
            if identity_path.exists() {
                println!("Identity already exists.");
                continue;
            }
            let identity = load_or_create_identity(&identity_path)?;
            println!("Created identity: {identity_name}");
            return Ok(Some((identity_name, identity)));
        }
        if menu_selection == "0" {
            return Ok(None);
        }
        let Ok(selected_index) = menu_selection.parse::<usize>() else {
            println!("Invalid selection.");
            continue;
        };
        if !(1..=identity_paths.len()).contains(&selected_index) {
            println!("Invalid selection.");
            continue;
        }
        let identity_path = &identity_paths[selected_index - 1];
        let identity_name = identity_path.file_stem().and_then(|file_stem| file_stem.to_str()).unwrap_or("identity").to_string();
        return Ok(Some((identity_name, load_or_create_identity(identity_path)?)));
    }
}

fn select_server() -> Result<String> {
    loop {
        println!("\n=== Server ===");
        let server_ip_input = read_input("Server IP [127.0.0.1]: ")?;
        let server_port_input = read_input("Server port [8080]: ")?;
        let server_ip_text = if server_ip_input.is_empty() { "127.0.0.1" } else { server_ip_input.as_str() };
        let server_port_text = if server_port_input.is_empty() { "8080" } else { server_port_input.as_str() };
        let Ok(server_ip) = server_ip_text.parse::<IpAddr>() else {
            println!("Invalid server IP address.");
            continue;
        };
        let Ok(server_port) = server_port_text.parse::<u16>() else {
            println!("Server port must be 1-65535.");
            continue;
        };
        if server_port == 0 {
            println!("Server port must be 1-65535.");
            continue;
        }
        let server_host = match server_ip {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        return Ok(format!("http://{server_host}:{server_port}"));
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut random_buffer = [0u8; N];
    getrandom::fill(&mut random_buffer).map_err(|error| anyhow!("system random failed: {error}"))?;
    Ok(random_buffer)
}

fn load_or_create_identity(identity_path: &Path) -> Result<Identity> {
    let master_private_key = if identity_path.exists() {
        let private_key_text = stdfs::read_to_string(identity_path).context("read identity key failed")?;
        let decoded_private_key_bytes = hex::decode(private_key_text.trim()).context("identity key is not valid hex")?;
        if decoded_private_key_bytes.len() != 32 {
            bail!("identity key must contain exactly 32 bytes");
        }
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&decoded_private_key_bytes);
        private_key_bytes
    } else {
        let private_key_bytes = random_bytes::<32>()?;
        stdfs::write(identity_path, hex::encode(private_key_bytes)).context("write identity key failed")?;
        private_key_bytes
    };
    #[cfg(unix)]
    stdfs::set_permissions(identity_path, stdfs::Permissions::from_mode(0o600))
        .context("secure identity key permissions failed")?;
    let key_deriver = Hkdf::<Sha256>::new(Some(b"central-e2ee-master-v1"), &master_private_key);
    let mut signing_seed = [0u8; 32];
    let mut encryption_seed = [0u8; 32];
    key_deriver.expand(b"ed25519-signing-key", &mut signing_seed)
        .map_err(|_| anyhow!("HKDF signing key failed"))?;
    key_deriver.expand(b"x25519-encryption-key", &mut encryption_seed)
        .map_err(|_| anyhow!("HKDF encryption key failed"))?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let encryption_secret = StaticSecret::from(encryption_seed);
    let encryption_public_key = PublicKey::from(&encryption_secret);
    let mut public_identity_bytes = [0u8; 64];
    public_identity_bytes[..32].copy_from_slice(&signing_key.verifying_key().to_bytes());
    public_identity_bytes[32..].copy_from_slice(encryption_public_key.as_bytes());
    Ok(Identity {
        signing_key,
        encryption_secret,
        public_identity: URL_SAFE_NO_PAD.encode(public_identity_bytes),
    })
}

fn parse_peer_encryption_key(public_identity: &str) -> Result<[u8; 32]> {
    let decoded_identity_bytes = URL_SAFE_NO_PAD
        .decode(public_identity)
        .context("invalid public identity encoding")?;
    if decoded_identity_bytes.len() != 64 {
        bail!("public identity must decode to 64 bytes");
    }
    let mut encryption_public_key_bytes = [0u8; 32];
    encryption_public_key_bytes.copy_from_slice(&decoded_identity_bytes[32..]);
    Ok(encryption_public_key_bytes)
}

fn sign(identity: &Identity, canonical_request: &str) -> String {
    URL_SAFE_NO_PAD.encode(identity.signing_key.sign(canonical_request.as_bytes()).to_bytes())
}

fn derive_conversation_key(identity: &Identity, peer_public_identity: &str) -> Result<[u8; 32]> {
    let peer_encryption_key_bytes = parse_peer_encryption_key(peer_public_identity)?;
    let shared_secret = identity
        .encryption_secret
        .diffie_hellman(&PublicKey::from(peer_encryption_key_bytes));
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        bail!("peer X25519 public key produced an all-zero shared secret");
    }
    let (first_public_identity, second_public_identity) =
        if identity.public_identity.as_str() <= peer_public_identity {
            (identity.public_identity.as_str(), peer_public_identity)
        } else {
            (peer_public_identity, identity.public_identity.as_str())
        };
    let key_context = format!("central-e2ee-chat-v1|{first_public_identity}|{second_public_identity}");
    let key_deriver = Hkdf::<Sha256>::new(Some(b"central-e2ee-chat-salt-v1"), shared_secret.as_bytes());
    let mut conversation_key = [0u8; 32];
    key_deriver.expand(key_context.as_bytes(), &mut conversation_key)
        .map_err(|_| anyhow!("HKDF chat key failed"))?;
    Ok(conversation_key)
}

fn encrypt_message(
    encryption_key: &[u8; 32],
    message_id: &str,
    sender: &str,
    recipient: &str,
    plaintext: &str,
) -> Result<(String, String)> {
    let nonce_bytes = random_bytes::<24>()?;
    let associated_data = format!("message|{message_id}|{sender}|{recipient}");
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid message key"))?;
    let ciphertext_bytes = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext.as_bytes(), aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("message encryption failed"))?;
    Ok((URL_SAFE_NO_PAD.encode(nonce_bytes), URL_SAFE_NO_PAD.encode(ciphertext_bytes)))
}

fn decrypt_message(encryption_key: &[u8; 32], message: &MessageRecord) -> Result<String> {
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&message.nonce)?;
    if nonce_bytes.len() != 24 {
        bail!("invalid message nonce");
    }
    let ciphertext_bytes = URL_SAFE_NO_PAD.decode(&message.ciphertext)?;
    let associated_data = format!("message|{}|{}|{}", message.message_id, message.sender, message.recipient);
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid message key"))?;
    let plaintext_bytes = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: &ciphertext_bytes, aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("message authentication/decryption failed"))?;
    String::from_utf8(plaintext_bytes).context("message is not valid UTF-8")
}

fn encrypt_small(encryption_key: &[u8; 32], associated_data: &[u8], plaintext: &[u8]) -> Result<(String, String)> {
    let nonce_bytes = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid encryption key"))?;
    let ciphertext_bytes = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: plaintext, aad: associated_data })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok((URL_SAFE_NO_PAD.encode(nonce_bytes), URL_SAFE_NO_PAD.encode(ciphertext_bytes)))
}

fn decrypt_small(encryption_key: &[u8; 32], associated_data: &[u8], nonce: &str, ciphertext: &str) -> Result<Vec<u8>> {
    let nonce_bytes = URL_SAFE_NO_PAD.decode(nonce)?;
    if nonce_bytes.len() != 24 {
        bail!("invalid nonce");
    }
    let ciphertext_bytes = URL_SAFE_NO_PAD.decode(ciphertext)?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid encryption key"))?;
    cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: &ciphertext_bytes, aad: associated_data })
        .map_err(|_| anyhow!("authentication/decryption failed"))
}

fn chunk_nonce(nonce_prefix: &[u8; 16], chunk_index: u64) -> [u8; 24] {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(nonce_prefix);
    nonce_bytes[16..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce_bytes
}

fn encrypt_chunk(
    file_key: &[u8; 32],
    file_id: &str,
    nonce_prefix: &[u8; 16],
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = chunk_nonce(nonce_prefix, chunk_index);
    let associated_data = format!("file-chunk|{file_id}|{chunk_index}");
    let cipher = XChaCha20Poly1305::new_from_slice(file_key).map_err(|_| anyhow!("invalid file key"))?;
    cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("file chunk encryption failed"))
}

fn decrypt_chunk(
    file_key: &[u8; 32],
    file_id: &str,
    nonce_prefix: &[u8; 16],
    chunk_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = chunk_nonce(nonce_prefix, chunk_index);
    let associated_data = format!("file-chunk|{file_id}|{chunk_index}");
    let cipher = XChaCha20Poly1305::new_from_slice(file_key).map_err(|_| anyhow!("invalid file key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: ciphertext, aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("file chunk authentication/decryption failed"))
}

fn sha256_b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

fn file_key_associated_data(file_record: &FileRecord) -> String {
    format!(
        "file-key-v2|{}|{}|{}|{}|{}|{}|{}",
        file_record.file_id,
        file_record.sender,
        file_record.recipient,
        file_record.nonce_prefix,
        file_record.plain_size,
        file_record.chunk_size,
        file_record.total_chunks
    )
}

fn decrypt_file_key(conversation_key: &[u8; 32], file_record: &FileRecord) -> Result<[u8; 32]> {
    let authenticated_metadata = file_key_associated_data(file_record);
    let decrypted_file_key = decrypt_small(
        conversation_key,
        authenticated_metadata.as_bytes(),
        &file_record.key_nonce,
        &file_record.encrypted_key,
    )
    .or_else(|_| {
        let legacy_associated_data = format!("file-key|{}", file_record.file_id);
        decrypt_small(
            conversation_key,
            legacy_associated_data.as_bytes(),
            &file_record.key_nonce,
            &file_record.encrypted_key,
        )
    })?;
    decrypted_file_key
        .try_into()
        .map_err(|_| anyhow!("invalid encrypted file key"))
}

fn canonical_send(send_request: &SendMessageRequest) -> String {
    format!(
        "send_message|{}|{}|{}|{}|{}|{}",
        send_request.timestamp,
        send_request.identity,
        send_request.recipient,
        send_request.message_id,
        send_request.nonce,
        send_request.ciphertext
    )
}

fn canonical_sync(sync_request: &SyncRequest) -> String {
    format!(
        "sync|{}|{}|{}|{}",
        sync_request.timestamp, sync_request.identity, sync_request.friend, sync_request.after_row_id
    )
}

fn canonical_file_init(file_init_request: &FileInitRequest) -> String {
    format!(
        "file_init|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        file_init_request.timestamp,
        file_init_request.identity,
        file_init_request.recipient,
        file_init_request.file_id,
        file_init_request.encrypted_name,
        file_init_request.name_nonce,
        file_init_request.encrypted_key,
        file_init_request.key_nonce,
        file_init_request.nonce_prefix,
        file_init_request.plain_size,
        file_init_request.chunk_size,
        file_init_request.total_chunks
    )
}

fn canonical_file_complete(completion_request: &FileCompleteRequest) -> String {
    format!(
        "file_complete|{}|{}|{}",
        completion_request.timestamp, completion_request.identity, completion_request.file_id
    )
}

fn canonical_file_list(file_list_request: &FileListRequest) -> String {
    format!(
        "file_list|{}|{}|{}|{}",
        file_list_request.timestamp,
        file_list_request.identity,
        file_list_request.friend,
        file_list_request.after_row_id
    )
}

fn canonical_file_info(file_info_request: &FileInfoRequest) -> String {
    format!(
        "file_info|{}|{}|{}",
        file_info_request.timestamp, file_info_request.identity, file_info_request.file_id
    )
}

async fn post_json<T: Serialize, R: serde::de::DeserializeOwned>(
    client: &Client,
    server_url: &str,
    endpoint_path: &str,
    request_body: &T,
) -> Result<R> {
    let http_response = client
        .post(format!("{server_url}{endpoint_path}"))
        .json(request_body)
        .send()
        .await?;
    let response_status = http_response.status();
    if !response_status.is_success() {
        bail!(
            "server {response_status}: {}",
            http_response.text().await.unwrap_or_default()
        );
    }
    Ok(http_response.json::<R>().await?)
}

async fn send_message(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    peer_public_identity: &str,
    message_text: &str,
) -> Result<()> {
    let conversation_key = derive_conversation_key(identity, peer_public_identity)?;
    let message_id = Uuid::new_v4().to_string();
    let (nonce, ciphertext) =
        encrypt_message(&conversation_key, &message_id, &identity.public_identity, peer_public_identity, message_text)?;
    let mut send_request = SendMessageRequest {
        identity: identity.public_identity.clone(),
        recipient: peer_public_identity.to_string(),
        message_id,
        timestamp: now(),
        nonce,
        ciphertext,
        signature: String::new(),
    };
    send_request.signature = sign(identity, &canonical_send(&send_request));
    let _: Ack = post_json(client, server_url, "/messages/send", &send_request).await?;
    Ok(())
}

async fn sync_messages(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    peer_public_identity: &str,
    after_row_id: i64,
) -> Result<Vec<MessageRecord>> {
    let mut sync_request = SyncRequest {
        identity: identity.public_identity.clone(),
        friend: peer_public_identity.to_string(),
        after_row_id,
        timestamp: now(),
        signature: String::new(),
    };
    sync_request.signature = sign(identity, &canonical_sync(&sync_request));
    let sync_response: MessageSyncResponse =
        post_json(client, server_url, "/messages/sync", &sync_request).await?;
    Ok(sync_response.messages)
}

async fn send_file(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    peer_public_identity: &str,
    file_path: &Path,
) -> Result<()> {
    let file_metadata = tokio::fs::metadata(file_path).await?;
    if !file_metadata.is_file() {
        bail!("path is not a regular file");
    }
    let plaintext_size = file_metadata.len();
    let plaintext_size_i64 = i64::try_from(plaintext_size).context("file is too large")?;
    let total_chunk_count = plaintext_size.div_ceil(CHUNK_SIZE as u64).max(1);
    let total_chunk_count_i64 = i64::try_from(total_chunk_count).context("too many file chunks")?;
    let file_id = Uuid::new_v4().to_string();
    let file_key = random_bytes::<32>()?;
    let nonce_prefix = random_bytes::<16>()?;
    let conversation_key = derive_conversation_key(identity, peer_public_identity)?;
    let file_name = file_path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| anyhow!("file name is not valid UTF-8"))?;
    let encoded_nonce_prefix = URL_SAFE_NO_PAD.encode(nonce_prefix);
    let file_name_associated_data = format!("file-name|{file_id}");
    let file_key_associated_data = format!(
        "file-key-v2|{}|{}|{}|{}|{}|{}|{}",
        file_id,
        identity.public_identity,
        peer_public_identity,
        encoded_nonce_prefix,
        plaintext_size_i64,
        CHUNK_SIZE as i64,
        total_chunk_count_i64
    );
    let (name_nonce, encrypted_name) =
        encrypt_small(&file_key, file_name_associated_data.as_bytes(), file_name.as_bytes())?;
    let (key_nonce, encrypted_key) =
        encrypt_small(&conversation_key, file_key_associated_data.as_bytes(), &file_key)?;
    let mut file_init_request = FileInitRequest {
        identity: identity.public_identity.clone(),
        recipient: peer_public_identity.to_string(),
        file_id: file_id.clone(),
        timestamp: now(),
        encrypted_name,
        name_nonce,
        encrypted_key,
        key_nonce,
        nonce_prefix: encoded_nonce_prefix,
        plain_size: plaintext_size_i64,
        chunk_size: CHUNK_SIZE as i64,
        total_chunks: total_chunk_count_i64,
        signature: String::new(),
    };
    file_init_request.signature = sign(identity, &canonical_file_init(&file_init_request));
    let _: Ack = post_json(client, server_url, "/files/init", &file_init_request).await?;
    let mut source_file = File::open(file_path).await?;
    let mut plaintext_buffer = vec![0u8; CHUNK_SIZE];
    for chunk_index in 0..total_chunk_count {
        let mut bytes_read = 0usize;
        while bytes_read < CHUNK_SIZE {
            let current_read_count = source_file.read(&mut plaintext_buffer[bytes_read..]).await?;
            if current_read_count == 0 {
                break;
            }
            bytes_read += current_read_count;
        }
        let encrypted_chunk =
            encrypt_chunk(&file_key, &file_id, &nonce_prefix, chunk_index, &plaintext_buffer[..bytes_read])?;
        let request_timestamp = now();
        let encrypted_chunk_hash = sha256_b64(&encrypted_chunk);
        let canonical_request = format!(
            "file_chunk|{}|{}|{}|{}|{}",
            request_timestamp, identity.public_identity, file_id, chunk_index, encrypted_chunk_hash
        );
        let request_signature = sign(identity, &canonical_request);
        let http_response = client
            .post(format!(
                "{server_url}/files/{file_id}/chunks/{chunk_index}"
            ))
            .header("x-identity", &identity.public_identity)
            .header("x-timestamp", request_timestamp.to_string())
            .header("x-signature", request_signature)
            .body(encrypted_chunk)
            .send()
            .await?;
        if !http_response.status().is_success() {
            bail!(
                "upload chunk {chunk_index} failed: {}",
                http_response.text().await.unwrap_or_default()
            );
        }
        println!("uploaded chunk {}/{}", chunk_index + 1, total_chunk_count);
    }
    let mut completion_request = FileCompleteRequest {
        identity: identity.public_identity.clone(),
        file_id: file_id.clone(),
        timestamp: now(),
        signature: String::new(),
    };
    completion_request.signature = sign(identity, &canonical_file_complete(&completion_request));
    let _: Ack = post_json(client, server_url, "/files/complete", &completion_request).await?;
    println!("file sent");
    println!("file id: {file_id}");
    Ok(())
}

async fn list_files(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    peer_public_identity: &str,
) -> Result<Vec<FileRecord>> {
    let mut file_list_request = FileListRequest {
        identity: identity.public_identity.clone(),
        friend: peer_public_identity.to_string(),
        after_row_id: 0,
        timestamp: now(),
        signature: String::new(),
    };
    file_list_request.signature = sign(identity, &canonical_file_list(&file_list_request));
    let file_list_response: FileListResponse =
        post_json(client, server_url, "/files/list", &file_list_request).await?;
    let conversation_key = derive_conversation_key(identity, peer_public_identity)?;
    for file_record in &file_list_response.files {
        let file_key = decrypt_file_key(&conversation_key, file_record)?;
        let file_name_associated_data = format!("file-name|{}", file_record.file_id);
        let decrypted_file_name_bytes = decrypt_small(
            &file_key,
            file_name_associated_data.as_bytes(),
            &file_record.name_nonce,
            &file_record.encrypted_name,
        )?;
        let transfer_direction = if file_record.sender == identity.public_identity {
            "sent"
        } else {
            "received"
        };
        println!(
            "{} | {} bytes | {} | id={}",
            transfer_direction,
            file_record.plain_size,
            String::from_utf8_lossy(&decrypted_file_name_bytes),
            file_record.file_id
        );
    }
    Ok(file_list_response.files)
}

async fn receive_file(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    file_id: &str,
    output_path_override: Option<&Path>,
) -> Result<()> {
    let mut file_info_request = FileInfoRequest {
        identity: identity.public_identity.clone(),
        file_id: file_id.to_string(),
        timestamp: now(),
        signature: String::new(),
    };
    file_info_request.signature = sign(identity, &canonical_file_info(&file_info_request));
    let file_record: FileRecord = post_json(client, server_url, "/files/info", &file_info_request).await?;
    if !file_record.completed {
        bail!("file upload is incomplete");
    }
    let peer_public_identity = if file_record.sender == identity.public_identity {
        file_record.recipient.as_str()
    } else {
        file_record.sender.as_str()
    };
    let conversation_key = derive_conversation_key(identity, peer_public_identity)?;
    let file_key = decrypt_file_key(&conversation_key, &file_record)?;
    let file_name_associated_data = format!("file-name|{file_id}");
    let decrypted_file_name_bytes = decrypt_small(
        &file_key,
        file_name_associated_data.as_bytes(),
        &file_record.name_nonce,
        &file_record.encrypted_name,
    )?;
    let decrypted_file_name =
        String::from_utf8(decrypted_file_name_bytes).context("decrypted file name is not UTF-8")?;
    let received_file_name = safe_received_file_name(&decrypted_file_name)?;
    let nonce_prefix_bytes = URL_SAFE_NO_PAD.decode(&file_record.nonce_prefix)?;
    let nonce_prefix: [u8; 16] = nonce_prefix_bytes
        .try_into()
        .map_err(|_| anyhow!("invalid file nonce prefix"))?;
    let output_path = output_path_override
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(received_file_name));
    let mut temporary_path_os_string = output_path.as_os_str().to_os_string();
    temporary_path_os_string.push(".part");
    let temporary_path = PathBuf::from(temporary_path_os_string);
    let mut output_file = File::create(&temporary_path).await?;
    let mut written_plaintext_size = 0u64;
    for chunk_index in 0..file_record.total_chunks {
        let request_timestamp = now();
        let canonical_request = format!(
            "file_get_chunk|{}|{}|{}|{}",
            request_timestamp, identity.public_identity, file_id, chunk_index
        );
        let request_signature = sign(identity, &canonical_request);
        let http_response = client
            .get(format!(
                "{server_url}/files/{file_id}/chunks/{chunk_index}"
            ))
            .header("x-identity", &identity.public_identity)
            .header("x-timestamp", request_timestamp.to_string())
            .header("x-signature", request_signature)
            .send()
            .await?;
        if !http_response.status().is_success() {
            bail!(
                "download chunk {chunk_index} failed: {}",
                http_response.text().await.unwrap_or_default()
            );
        }
        let encrypted_chunk = http_response.bytes().await?;
        let plaintext_chunk = decrypt_chunk(
            &file_key,
            file_id,
            &nonce_prefix,
            chunk_index as u64,
            &encrypted_chunk,
        )?;
        output_file.write_all(&plaintext_chunk).await?;
        written_plaintext_size = written_plaintext_size
            .checked_add(plaintext_chunk.len() as u64)
            .ok_or_else(|| anyhow!("received file size overflow"))?;
        println!(
            "downloaded chunk {}/{}",
            chunk_index + 1,
            file_record.total_chunks
        );
    }
    output_file.flush().await?;
    output_file.sync_all().await?;
    drop(output_file);
    let expected_plaintext_size = u64::try_from(file_record.plain_size)
        .map_err(|_| anyhow!("invalid negative plaintext size"))?;
    if written_plaintext_size != expected_plaintext_size {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        bail!(
            "received plaintext size mismatch: expected {expected_plaintext_size}, got {written_plaintext_size}"
        );
    }
    if tokio::fs::try_exists(&output_path).await? {
        tokio::fs::remove_file(&output_path).await?;
    }
    tokio::fs::rename(&temporary_path, &output_path).await?;
    println!("saved: {}", output_path.display());
    Ok(())
}

fn display_messages(
    identity: &Identity,
    conversation_key: &[u8; 32],
    messages: Vec<MessageRecord>,
    last_message_row_id: &mut i64,
) {
    for message in messages {
        *last_message_row_id = (*last_message_row_id).max(message.row_id);
        match decrypt_message(conversation_key, &message) {
            Ok(message_text) => {
                let sender_label = if message.sender == identity.public_identity {
                    "me"
                } else {
                    "friend"
                };
                println!("[{sender_label}] {message_text}");
            }
            Err(error) => eprintln!("[decrypt error] {error}"),
        }
    }
}

fn is_file_command(input_text: &str) -> bool {
    matches!(input_text, "/send" | "/file")
}

async fn chat(client: &Client, server_url: &str, identity: &Identity, peer_public_identity: &str) -> Result<()> {
    parse_peer_encryption_key(peer_public_identity)?;
    println!("\n=== Chat ===");
    println!("Messages synchronize automatically every 2 seconds.");
    println!("Type /send or /file to send a file. Every other non-empty line is sent as an encrypted message.");
    println!("End input (EOF) to return to the main menu.\n");
    let conversation_key = derive_conversation_key(identity, peer_public_identity)?;
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut sync_timer = time::interval(Duration::from_secs(2));
    let mut last_message_row_id = 0i64;
    loop {
        tokio::select! {
            _ = sync_timer.tick() => match sync_messages(client, server_url, identity, peer_public_identity, last_message_row_id).await {
                Ok(messages) => display_messages(identity, &conversation_key, messages, &mut last_message_row_id),
                Err(error) => eprintln!("[sync error] {error}"),
            },
            input_result = stdin_lines.next_line() => {
                let Some(input_line) = input_result? else { break };
                let message_text = input_line.trim();
                if message_text.is_empty() {
                    continue;
                }
                if is_file_command(message_text) {
                    print!("File path: ");
                    stdio::stdout().flush()?;
                    let Some(file_path_input) = stdin_lines.next_line().await? else { break };
                    let file_path_text = file_path_input.trim();
                    if file_path_text.is_empty() {
                        eprintln!("[file error] file path cannot be empty");
                        continue;
                    }
                    if let Err(error) = send_file(client, server_url, identity, peer_public_identity, Path::new(file_path_text)).await {
                        eprintln!("[file error] {error}");
                    }
                    continue;
                }
                if let Err(error) = send_message(client, server_url, identity, peer_public_identity, message_text).await {
                    eprintln!("[send error] {error}");
                }
            }
        }
    }
    Ok(())
}

fn print_main_menu(identity_name: &str, server_url: &str, public_identity: &str) {
    println!("\n========================================");
    println!("Identity:  {identity_name}");
    println!("Server:    {server_url}");
    println!("Public ID: {public_identity}");
    println!("----------------------------------------");
    println!("1. Chat with a friend (use /send or /file for files)");
    println!("2. List files with a friend");
    println!("3. Receive a file");
    println!("4. Switch identity");
    println!("5. Change server");
    println!("0. Exit");
    println!("========================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(master_private_key: [u8; 32]) -> Identity {
        let key_deriver = Hkdf::<Sha256>::new(Some(b"central-e2ee-master-v1"), &master_private_key);
        let mut signing_seed = [0u8; 32];
        let mut encryption_seed = [0u8; 32];
        key_deriver.expand(b"ed25519-signing-key", &mut signing_seed).unwrap();
        key_deriver.expand(b"x25519-encryption-key", &mut encryption_seed).unwrap();
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let encryption_secret = StaticSecret::from(encryption_seed);
        let encryption_public_key = PublicKey::from(&encryption_secret);
        let mut public_identity_bytes = [0u8; 64];
        public_identity_bytes[..32].copy_from_slice(&signing_key.verifying_key().to_bytes());
        public_identity_bytes[32..].copy_from_slice(encryption_public_key.as_bytes());
        Identity {
            signing_key,
            encryption_secret,
            public_identity: URL_SAFE_NO_PAD.encode(public_identity_bytes),
        }
    }

    #[test]
    fn both_participants_derive_the_same_conversation_key() {
        let alice = test_identity([1u8; 32]);
        let bob = test_identity([2u8; 32]);
        let alice_key = derive_conversation_key(&alice, &bob.public_identity).unwrap();
        let bob_key = derive_conversation_key(&bob, &alice.public_identity).unwrap();
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn message_ciphertext_and_metadata_are_authenticated() {
        let alice = test_identity([3u8; 32]);
        let bob = test_identity([4u8; 32]);
        let conversation_key = derive_conversation_key(&alice, &bob.public_identity).unwrap();
        let message_id = Uuid::new_v4().to_string();
        let (nonce, ciphertext) = encrypt_message(
            &conversation_key,
            &message_id,
            &alice.public_identity,
            &bob.public_identity,
            "secret",
        )
        .unwrap();
        let message = MessageRecord {
            row_id: 1,
            message_id,
            sender: alice.public_identity.clone(),
            recipient: bob.public_identity.clone(),
            nonce,
            ciphertext,
            created_at: 0,
        };
        assert_eq!(decrypt_message(&conversation_key, &message).unwrap(), "secret");
        let mut tampered = message;
        tampered.recipient = alice.public_identity.clone();
        assert!(decrypt_message(&conversation_key, &tampered).is_err());
    }

    #[test]
    fn new_file_key_wrap_authenticates_transfer_metadata() {
        let conversation_key = [7u8; 32];
        let file_key = [8u8; 32];
        let file_id = Uuid::new_v4().to_string();
        let nonce_prefix = URL_SAFE_NO_PAD.encode([9u8; 16]);
        let associated_data = format!(
            "file-key-v2|{}|{}|{}|{}|{}|{}|{}",
            file_id, "sender", "recipient", nonce_prefix, 123, CHUNK_SIZE as i64, 1
        );
        let (key_nonce, encrypted_key) = encrypt_small(&conversation_key, associated_data.as_bytes(), &file_key).unwrap();
        let mut file_record = FileRecord {
            row_id: 1,
            file_id,
            sender: "sender".into(),
            recipient: "recipient".into(),
            encrypted_name: String::new(),
            name_nonce: String::new(),
            encrypted_key,
            key_nonce,
            nonce_prefix,
            plain_size: 123,
            chunk_size: CHUNK_SIZE as i64,
            total_chunks: 1,
            completed: true,
            created_at: 0,
        };
        assert_eq!(decrypt_file_key(&conversation_key, &file_record).unwrap(), file_key);
        file_record.total_chunks = 2;
        assert!(decrypt_file_key(&conversation_key, &file_record).is_err());
    }

    #[test]
    fn only_send_and_file_are_file_commands() {
        assert!(is_file_command("/send"));
        assert!(is_file_command("/file"));
        assert!(!is_file_command("/back"));
        assert!(!is_file_command("/send example.txt"));
        assert!(!is_file_command("hello"));
    }

    #[test]
    fn rejects_non_contributory_peer_x25519_key() {
        let alice = test_identity([10u8; 32]);
        let mut peer_identity_bytes = [0u8; 64];
        peer_identity_bytes[..32].copy_from_slice(&[1u8; 32]);
        let peer_public_identity = URL_SAFE_NO_PAD.encode(peer_identity_bytes);
        assert!(derive_conversation_key(&alice, &peer_public_identity).is_err());
    }

    #[test]
    fn file_chunk_index_is_authenticated() {
        let file_key = [11u8; 32];
        let nonce_prefix = [12u8; 16];
        let file_id = Uuid::new_v4().to_string();
        let encrypted_chunk = encrypt_chunk(&file_key, &file_id, &nonce_prefix, 0, b"chunk").unwrap();
        assert_eq!(decrypt_chunk(&file_key, &file_id, &nonce_prefix, 0, &encrypted_chunk).unwrap(), b"chunk");
        assert!(decrypt_chunk(&file_key, &file_id, &nonce_prefix, 1, &encrypted_chunk).is_err());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Central E2EE Chat");
    println!("No registration. Your local private key is your identity.");
    let client = Client::builder().build()?;
    let Some((mut identity_name, mut identity)) = select_identity()? else {
        return Ok(());
    };
    let mut server_url = select_server()?;
    loop {
        print_main_menu(&identity_name, &server_url, &identity.public_identity);
        match read_input("Select: ")?.as_str() {
            "1" => {
                let peer_public_identity = read_input("Friend public ID: ")?;
                if let Err(error) = chat(&client, &server_url, &identity, &peer_public_identity).await {
                    eprintln!("Chat error: {error}");
                }
            }
            "2" => {
                let peer_public_identity = read_input("Friend public ID: ")?;
                if let Err(error) = list_files(&client, &server_url, &identity, &peer_public_identity).await {
                    eprintln!("List files error: {error}");
                }
            }
            "3" => {
                let file_id = read_input("File ID: ")?;
                let save_path = read_input("Save path [original file name]: ")?;
                let output_path = if save_path.is_empty() {
                    None
                } else {
                    Some(Path::new(save_path.as_str()))
                };
                if let Err(error) = receive_file(&client, &server_url, &identity, &file_id, output_path).await {
                    eprintln!("Receive file error: {error}");
                }
            }
            "4" => {
                let Some((selected_identity_name, selected_identity)) = select_identity()? else {
                    continue;
                };
                identity_name = selected_identity_name;
                identity = selected_identity;
            }
            "5" => server_url = select_server()?,
            "0" => break,
            _ => println!("Invalid selection."),
        }
    }
    Ok(())
}
