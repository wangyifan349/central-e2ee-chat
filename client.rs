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
    let mut input = String::new();
    stdio::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn safe_identity_name(identity_name_input: &str) -> Result<String> {
    let identity_name = identity_name_input.trim();
    if identity_name.is_empty() {
        bail!("identity name cannot be empty");
    }
    if !identity_name.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')) {
        bail!("identity name may only contain letters, numbers, '-' and '_'");
    }
    Ok(identity_name.to_string())
}

fn list_identity_files() -> Result<Vec<PathBuf>> {
    let identity_directory = PathBuf::from("identities");
    stdfs::create_dir_all(&identity_directory)?;
    let mut identity_paths = stdfs::read_dir(identity_directory)?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("key"))
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
        } else {
            for (index, identity_path) in identity_paths.iter().enumerate() {
                let identity_name = identity_path.file_stem().and_then(|value| value.to_str()).unwrap_or("unknown");
                println!("{}. {}", index + 1, identity_name);
            }
        }
        println!("N. Create a new identity");
        println!("0. Exit");
        let selection = read_input("Select: ")?;
        if selection.eq_ignore_ascii_case("n") {
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
        if selection == "0" {
            return Ok(None);
        }
        let Ok(selected_index) = selection.parse::<usize>() else {
            println!("Invalid selection.");
            continue;
        };
        if !(1..=identity_paths.len()).contains(&selected_index) {
            println!("Invalid selection.");
            continue;
        }
        let identity_path = &identity_paths[selected_index - 1];
        let identity_name = identity_path.file_stem().and_then(|value| value.to_str()).unwrap_or("identity").to_string();
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
        let server_ip: IpAddr = match server_ip_text.parse() {
            Ok(address) => address,
            Err(_) => {
                println!("Invalid server IP address.");
                continue;
            }
        };
        let server_port: u16 = match server_port_text.parse() {
            Ok(port) if port > 0 => port,
            _ => {
                println!("Server port must be 1-65535.");
                continue;
            }
        };
        let server_host = match server_ip {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        return Ok(format!("http://{server_host}:{server_port}"));
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut random_data = [0u8; N];
    getrandom::fill(&mut random_data).map_err(|error| anyhow!("system random failed: {error}"))?;
    Ok(random_data)
}

fn load_or_create_identity(identity_path: &Path) -> Result<Identity> {
    let master_private_key = if identity_path.exists() {
        let private_key_text = stdfs::read_to_string(identity_path).context("read identity key failed")?;
        let decoded_private_key = hex::decode(private_key_text.trim()).context("identity key is not valid hex")?;
        if decoded_private_key.len() != 32 {
            bail!("identity key must contain exactly 32 bytes");
        }
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&decoded_private_key);
        private_key_bytes
    } else {
        let private_key_bytes = random_bytes::<32>()?;
        stdfs::write(identity_path, hex::encode(private_key_bytes)).context("write identity key failed")?;
        private_key_bytes
    };
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
    let decoded_identity = URL_SAFE_NO_PAD
        .decode(public_identity)
        .context("invalid public identity encoding")?;
    if decoded_identity.len() != 64 {
        bail!("public identity must decode to 64 bytes");
    }
    let mut encryption_public_key_bytes = [0u8; 32];
    encryption_public_key_bytes.copy_from_slice(&decoded_identity[32..]);
    Ok(encryption_public_key_bytes)
}

fn sign(identity: &Identity, canonical: &str) -> String {
    URL_SAFE_NO_PAD.encode(identity.signing_key.sign(canonical.as_bytes()).to_bytes())
}

fn derive_conversation_key(identity: &Identity, friend: &str) -> Result<[u8; 32]> {
    let peer_encryption_key_bytes = parse_peer_encryption_key(friend)?;
    let shared_secret = identity
        .encryption_secret
        .diffie_hellman(&PublicKey::from(peer_encryption_key_bytes));
    let (first_identity, second_identity) = if identity.public_identity.as_str() <= friend {
        (identity.public_identity.as_str(), friend)
    } else {
        (friend, identity.public_identity.as_str())
    };
    let key_context = format!("central-e2ee-chat-v1|{first_identity}|{second_identity}");
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
    let nonce = random_bytes::<24>()?;
    let associated_data = format!("message|{message_id}|{sender}|{recipient}");
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid message key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: plaintext.as_bytes(), aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("message encryption failed"))?;
    Ok((URL_SAFE_NO_PAD.encode(nonce), URL_SAFE_NO_PAD.encode(ciphertext)))
}

fn decrypt_message(encryption_key: &[u8; 32], message: &MessageRecord) -> Result<String> {
    let nonce = URL_SAFE_NO_PAD.decode(&message.nonce)?;
    if nonce.len() != 24 {
        bail!("invalid message nonce");
    }
    let ciphertext = URL_SAFE_NO_PAD.decode(&message.ciphertext)?;
    let associated_data = format!("message|{}|{}|{}", message.message_id, message.sender, message.recipient);
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid message key"))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: &ciphertext, aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("message authentication/decryption failed"))?;
    String::from_utf8(plaintext).context("message is not valid UTF-8")
}

fn encrypt_small(encryption_key: &[u8; 32], associated_data: &[u8], plaintext: &[u8]) -> Result<(String, String)> {
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid encryption key"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: associated_data })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok((URL_SAFE_NO_PAD.encode(nonce), URL_SAFE_NO_PAD.encode(ciphertext)))
}

fn decrypt_small(encryption_key: &[u8; 32], associated_data: &[u8], nonce: &str, ciphertext: &str) -> Result<Vec<u8>> {
    let nonce = URL_SAFE_NO_PAD.decode(nonce)?;
    if nonce.len() != 24 {
        bail!("invalid nonce");
    }
    let ciphertext = URL_SAFE_NO_PAD.decode(ciphertext)?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key).map_err(|_| anyhow!("invalid encryption key"))?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: associated_data })
        .map_err(|_| anyhow!("authentication/decryption failed"))
}

fn chunk_nonce(nonce_prefix: &[u8; 16], chunk_index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(nonce_prefix);
    nonce[16..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn encrypt_chunk(
    file_key: &[u8; 32],
    file_id: &str,
    nonce_prefix: &[u8; 16],
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = chunk_nonce(nonce_prefix, chunk_index);
    let associated_data = format!("file-chunk|{file_id}|{chunk_index}");
    let cipher = XChaCha20Poly1305::new_from_slice(file_key).map_err(|_| anyhow!("invalid file key"))?;
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
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
    let nonce = chunk_nonce(nonce_prefix, chunk_index);
    let associated_data = format!("file-chunk|{file_id}|{chunk_index}");
    let cipher = XChaCha20Poly1305::new_from_slice(file_key).map_err(|_| anyhow!("invalid file key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad: associated_data.as_bytes() },
        )
        .map_err(|_| anyhow!("file chunk authentication/decryption failed"))
}

fn sha256_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn canonical_send(request: &SendMessageRequest) -> String {
    format!(
        "send_message|{}|{}|{}|{}|{}|{}",
        request.timestamp, request.identity, request.recipient, request.message_id, request.nonce, request.ciphertext
    )
}

fn canonical_sync(request: &SyncRequest) -> String {
    format!(
        "sync|{}|{}|{}|{}",
        request.timestamp, request.identity, request.friend, request.after_row_id
    )
}

fn canonical_file_init(request: &FileInitRequest) -> String {
    format!(
        "file_init|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        request.timestamp,
        request.identity,
        request.recipient,
        request.file_id,
        request.encrypted_name,
        request.name_nonce,
        request.encrypted_key,
        request.key_nonce,
        request.nonce_prefix,
        request.plain_size,
        request.chunk_size,
        request.total_chunks
    )
}

fn canonical_file_complete(request: &FileCompleteRequest) -> String {
    format!("file_complete|{}|{}|{}", request.timestamp, request.identity, request.file_id)
}

fn canonical_file_list(request: &FileListRequest) -> String {
    format!(
        "file_list|{}|{}|{}|{}",
        request.timestamp, request.identity, request.friend, request.after_row_id
    )
}

fn canonical_file_info(request: &FileInfoRequest) -> String {
    format!("file_info|{}|{}|{}", request.timestamp, request.identity, request.file_id)
}

async fn post_json<T: Serialize, R: serde::de::DeserializeOwned>(
    client: &Client,
    server_url: &str,
    endpoint_path: &str,
    body: &T,
) -> Result<R> {
    let response = client
        .post(format!("{server_url}{endpoint_path}"))
        .json(body)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!(
            "server {status}: {}",
            response.text().await.unwrap_or_default()
        );
    }
    Ok(response.json::<R>().await?)
}

async fn send_message(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    friend: &str,
    text: &str,
) -> Result<()> {
    let conversation_key = derive_conversation_key(identity, friend)?;
    let message_id = Uuid::new_v4().to_string();
    let (nonce, ciphertext) =
        encrypt_message(&conversation_key, &message_id, &identity.public_identity, friend, text)?;
    let mut request = SendMessageRequest {
        identity: identity.public_identity.clone(),
        recipient: friend.to_string(),
        message_id,
        timestamp: now(),
        nonce,
        ciphertext,
        signature: String::new(),
    };
    request.signature = sign(identity, &canonical_send(&request));
    let _: Ack = post_json(client, server_url, "/messages/send", &request).await?;
    Ok(())
}

async fn sync_messages(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    friend: &str,
    after_row_id: i64,
) -> Result<Vec<MessageRecord>> {
    let mut request = SyncRequest {
        identity: identity.public_identity.clone(),
        friend: friend.to_string(),
        after_row_id: after_row_id,
        timestamp: now(),
        signature: String::new(),
    };
    request.signature = sign(identity, &canonical_sync(&request));
    let response: MessageSyncResponse =
        post_json(client, server_url, "/messages/sync", &request).await?;
    Ok(response.messages)
}

async fn send_file(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    friend: &str,
    file_path: &Path,
) -> Result<()> {
    let metadata = tokio::fs::metadata(file_path).await?;
    if !metadata.is_file() {
        bail!("path is not a regular file");
    }
    let plaintext_size = metadata.len();
    let total_chunks =
        ((plaintext_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64).max(1);
    let file_id = Uuid::new_v4().to_string();
    let file_key = random_bytes::<32>()?;
    let nonce_prefix = random_bytes::<16>()?;
    let conversation_key = derive_conversation_key(identity, friend)?;
    let file_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("file name is not valid UTF-8"))?;
    let file_name_associated_data = format!("file-name|{file_id}");
    let file_key_associated_data = format!("file-key|{file_id}");
    let (name_nonce, encrypted_name) =
        encrypt_small(&file_key, file_name_associated_data.as_bytes(), file_name.as_bytes())?;
    let (key_nonce, encrypted_key) =
        encrypt_small(&conversation_key, file_key_associated_data.as_bytes(), &file_key)?;
    let mut request = FileInitRequest {
        identity: identity.public_identity.clone(),
        recipient: friend.to_string(),
        file_id: file_id.clone(),
        timestamp: now(),
        encrypted_name,
        name_nonce,
        encrypted_key,
        key_nonce,
        nonce_prefix: URL_SAFE_NO_PAD.encode(nonce_prefix),
        plain_size: plaintext_size as i64,
        chunk_size: CHUNK_SIZE as i64,
        total_chunks: total_chunks as i64,
        signature: String::new(),
    };
    request.signature = sign(identity, &canonical_file_init(&request));
    let _: Ack = post_json(client, server_url, "/files/init", &request).await?;
    let mut input_file = File::open(file_path).await?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    for index in 0..total_chunks {
        let mut bytes_read = 0usize;
        while bytes_read < CHUNK_SIZE {
            let bytes_read_now = input_file.read(&mut buffer[bytes_read..]).await?;
            if bytes_read_now == 0 {
                break;
            }
            bytes_read += bytes_read_now;
        }
        let encrypted_chunk =
            encrypt_chunk(&file_key, &file_id, &nonce_prefix, index, &buffer[..bytes_read])?;
        let timestamp = now();
        let body_hash = sha256_b64(&encrypted_chunk);
        let canonical_request = format!(
            "file_chunk|{}|{}|{}|{}|{}",
            timestamp, identity.public_identity, file_id, index, body_hash
        );
        let signature = sign(identity, &canonical_request);
        let response = client
            .post(format!(
                "{server_url}/files/{file_id}/chunks/{index}"
            ))
            .header("x-identity", &identity.public_identity)
            .header("x-timestamp", timestamp.to_string())
            .header("x-signature", signature)
            .body(encrypted_chunk)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "upload chunk {index} failed: {}",
                response.text().await.unwrap_or_default()
            );
        }
        println!("uploaded chunk {}/{}", index + 1, total_chunks);
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
    friend: &str,
) -> Result<Vec<FileRecord>> {
    let mut request = FileListRequest {
        identity: identity.public_identity.clone(),
        friend: friend.to_string(),
        after_row_id: 0,
        timestamp: now(),
        signature: String::new(),
    };
    request.signature = sign(identity, &canonical_file_list(&request));
    let response: FileListResponse =
        post_json(client, server_url, "/files/list", &request).await?;
    let conversation_key = derive_conversation_key(identity, friend)?;
    for file_record in &response.files {
        let file_key_associated_data = format!("file-key|{}", file_record.file_id);
        let file_key = decrypt_small(
            &conversation_key,
            file_key_associated_data.as_bytes(),
            &file_record.key_nonce,
            &file_record.encrypted_key,
        )?;
        let file_key: [u8; 32] = file_key
            .try_into()
            .map_err(|_| anyhow!("invalid encrypted file key"))?;
        let file_name_associated_data = format!("file-name|{}", file_record.file_id);
        let file_name = decrypt_small(
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
            String::from_utf8_lossy(&file_name),
            file_record.file_id
        );
    }
    Ok(response.files)
}

async fn get_file_info(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    file_id: &str,
) -> Result<FileRecord> {
    let mut request = FileInfoRequest {
        identity: identity.public_identity.clone(),
        file_id: file_id.to_string(),
        timestamp: now(),
        signature: String::new(),
    };
    request.signature = sign(identity, &canonical_file_info(&request));
    post_json(client, server_url, "/files/info", &request).await
}

async fn receive_file(
    client: &Client,
    server_url: &str,
    identity: &Identity,
    file_id: &str,
    output_path_override: Option<&Path>,
) -> Result<()> {
    let file_info = get_file_info(client, server_url, identity, file_id).await?;
    if !file_info.completed {
        bail!("file upload is incomplete");
    }
    let peer_identity = if file_info.sender == identity.public_identity {
        file_info.recipient.as_str()
    } else {
        file_info.sender.as_str()
    };
    let conversation_key = derive_conversation_key(identity, peer_identity)?;
    let file_key_associated_data = format!("file-key|{file_id}");
    let file_key = decrypt_small(
        &conversation_key,
        file_key_associated_data.as_bytes(),
        &file_info.key_nonce,
        &file_info.encrypted_key,
    )?;
    let file_key: [u8; 32] = file_key
        .try_into()
        .map_err(|_| anyhow!("invalid encrypted file key"))?;
    let file_name_associated_data = format!("file-name|{file_id}");
    let file_name = decrypt_small(
        &file_key,
        file_name_associated_data.as_bytes(),
        &file_info.name_nonce,
        &file_info.encrypted_name,
    )?;
    let file_name =
        String::from_utf8(file_name).context("decrypted file name is not UTF-8")?;
    let nonce_prefix = URL_SAFE_NO_PAD.decode(&file_info.nonce_prefix)?;
    let nonce_prefix: [u8; 16] = nonce_prefix
        .try_into()
        .map_err(|_| anyhow!("invalid file nonce prefix"))?;
    let output_path = output_path_override
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(file_name));
    let mut output_file = File::create(&output_path).await?;
    for index in 0..file_info.total_chunks {
        let timestamp = now();
        let canonical_request = format!(
            "file_get_chunk|{}|{}|{}|{}",
            timestamp, identity.public_identity, file_id, index
        );
        let signature = sign(identity, &canonical_request);
        let response = client
            .get(format!(
                "{server_url}/files/{file_id}/chunks/{index}"
            ))
            .header("x-identity", &identity.public_identity)
            .header("x-timestamp", timestamp.to_string())
            .header("x-signature", signature)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "download chunk {index} failed: {}",
                response.text().await.unwrap_or_default()
            );
        }
        let encrypted_chunk = response.bytes().await?;
        let plaintext = decrypt_chunk(
            &file_key,
            file_id,
            &nonce_prefix,
            index as u64,
            &encrypted_chunk,
        )?;
        output_file.write_all(&plaintext).await?;
        println!(
            "downloaded chunk {}/{}",
            index + 1,
            file_info.total_chunks
        );
    }
    output_file.flush().await?;
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
            Ok(text) => {
                let sender_label = if message.sender == identity.public_identity {
                    "me"
                } else {
                    "friend"
                };
                println!("[{sender_label}] {text}");
            }
            Err(error) => eprintln!("[decrypt error] {error}"),
        }
    }
}

async fn chat(client: &Client, server_url: &str, identity: &Identity, friend: &str) -> Result<()> {
    parse_peer_encryption_key(friend)?;
    println!("\n=== Chat ===");
    println!("Messages synchronize automatically every 2 seconds.");
    println!("Type /back to return to the main menu.\n");
    let conversation_key = derive_conversation_key(identity, friend)?;
    let mut input_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut sync_timer = time::interval(Duration::from_secs(2));
    let mut last_message_row_id = 0i64;
    loop {
        tokio::select! {
            _ = sync_timer.tick() => match sync_messages(client, server_url, identity, friend, last_message_row_id).await {
                Ok(messages) => display_messages(identity, &conversation_key, messages, &mut last_message_row_id),
                Err(error) => eprintln!("[sync error] {error}"),
            },
            line = input_lines.next_line() => {
                let Some(line) = line? else { break };
                let text = line.trim();
                if text == "/back" { break; }
                if !text.is_empty() {
                    if let Err(error) = send_message(client, server_url, identity, friend, text).await {
                        eprintln!("[send error] {error}");
                    }
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
    println!("1. Chat with a friend");
    println!("2. Send a file");
    println!("3. List files with a friend");
    println!("4. Receive a file");
    println!("5. Switch identity");
    println!("6. Change server");
    println!("0. Exit");
    println!("========================================");
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
                let friend_public_identity = read_input("Friend public ID: ")?;
                if let Err(error) = chat(&client, &server_url, &identity, &friend_public_identity).await {
                    eprintln!("Chat error: {error}");
                }
            }
            "2" => {
                let friend_public_identity = read_input("Friend public ID: ")?;
                let file_path = read_input("File path: ")?;
                if let Err(error) = send_file(
                    &client,
                    &server_url,
                    &identity,
                    &friend_public_identity,
                    Path::new(&file_path),
                ).await {
                    eprintln!("Send file error: {error}");
                }
            }
            "3" => {
                let friend_public_identity = read_input("Friend public ID: ")?;
                if let Err(error) = list_files(&client, &server_url, &identity, &friend_public_identity).await {
                    eprintln!("List files error: {error}");
                }
            }
            "4" => {
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
            "5" => {
                if let Some((selected_name, selected_identity)) = select_identity()? {
                    identity_name = selected_name;
                    identity = selected_identity;
                }
            }
            "6" => server_url = select_server()?,
            "0" => break,
            _ => println!("Invalid selection."),
        }
    }
    Ok(())
}
