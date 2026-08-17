use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::fs;
use uuid::Uuid;

const AUTH_WINDOW_SECS: i64 = 300;
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    database_path: Arc<PathBuf>,
    storage_directory: Arc<PathBuf>,
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

type ApiError = (StatusCode, String);

fn api_error(status_code: StatusCode, error: impl ToString) -> ApiError {
    (status_code, error.to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn parse_signing_public_key(public_identity: &str) -> Result<[u8; 32]> {
    let decoded_identity_bytes = URL_SAFE_NO_PAD
        .decode(public_identity)
        .context("invalid public identity encoding")?;
    if decoded_identity_bytes.len() != 64 {
        bail!("public identity must decode to 64 bytes");
    }
    let mut signing_public_key_bytes = [0u8; 32];
    signing_public_key_bytes.copy_from_slice(&decoded_identity_bytes[..32]);
    Ok(signing_public_key_bytes)
}

fn verify(public_identity: &str, timestamp: i64, signature_text: &str, canonical_request: &str) -> Result<()> {
    if now().abs_diff(timestamp) > AUTH_WINDOW_SECS as u64 {
        bail!("request timestamp is outside the allowed window");
    }
    let signing_public_key_bytes = parse_signing_public_key(public_identity)?;
    let verifying_key = VerifyingKey::from_bytes(&signing_public_key_bytes).context("invalid Ed25519 public key")?;
    let decoded_signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_text)
        .context("invalid signature encoding")?;
    let signature_bytes: [u8; 64] = decoded_signature_bytes
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    verifying_key
        .verify_strict(canonical_request.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .context("signature verification failed")
}

fn sha256_b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
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

fn open_db(database_path: &PathBuf) -> Result<Connection, ApiError> {
    let connection = Connection::open(database_path).map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    connection.busy_timeout(Duration::from_secs(5))
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(connection)
}

fn file_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRecord> {
    Ok(FileRecord {
        row_id: row.get(0)?,
        file_id: row.get(1)?,
        sender: row.get(2)?,
        recipient: row.get(3)?,
        encrypted_name: row.get(4)?,
        name_nonce: row.get(5)?,
        encrypted_key: row.get(6)?,
        key_nonce: row.get(7)?,
        nonce_prefix: row.get(8)?,
        plain_size: row.get(9)?,
        chunk_size: row.get(10)?,
        total_chunks: row.get(11)?,
        completed: row.get::<_, i64>(12)? != 0,
        created_at: row.get(13)?,
    })
}

fn header(headers: &HeaderMap, header_name: &str) -> Result<String, ApiError> {
    headers
        .get(header_name)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, format!("missing header {header_name}")))?
        .to_str()
        .map(|header_value| header_value.to_string())
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))
}

async fn send_message(
    State(state): State<AppState>,
    Json(send_request): Json<SendMessageRequest>,
) -> Result<Json<Ack>, ApiError> {
    parse_signing_public_key(&send_request.recipient).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &send_request.identity,
        send_request.timestamp,
        &send_request.signature,
        &canonical_send(&send_request),
    )
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    Uuid::parse_str(&send_request.message_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let connection = open_db(&state.database_path)?;
    connection.execute(
        "INSERT OR IGNORE INTO messages
        (message_id, sender, recipient, nonce, ciphertext, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            send_request.message_id,
            send_request.identity,
            send_request.recipient,
            send_request.nonce,
            send_request.ciphertext,
            now()
        ],
    )
    .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(Ack {
        ok: true,
        detail: "message stored as ciphertext".into(),
    }))
}

async fn sync_messages(
    State(state): State<AppState>,
    Json(sync_request): Json<SyncRequest>,
) -> Result<Json<MessageSyncResponse>, ApiError> {
    parse_signing_public_key(&sync_request.friend).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &sync_request.identity,
        sync_request.timestamp,
        &sync_request.signature,
        &canonical_sync(&sync_request),
    )
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let mut statement = connection
        .prepare(
            "SELECT row_id, message_id, sender, recipient, nonce, ciphertext, created_at
             FROM messages
             WHERE row_id > ?1 AND
               ((sender = ?2 AND recipient = ?3) OR (sender = ?3 AND recipient = ?2))
             ORDER BY row_id ASC
             LIMIT 2000",
        )
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let message_rows = statement
        .query_map(params![sync_request.after_row_id, sync_request.identity, sync_request.friend], |row| {
            Ok(MessageRecord {
                row_id: row.get(0)?,
                message_id: row.get(1)?,
                sender: row.get(2)?,
                recipient: row.get(3)?,
                nonce: row.get(4)?,
                ciphertext: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let messages = message_rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(MessageSyncResponse { messages }))
}

fn expected_plain_chunk_size(plaintext_size: i64, chunk_size_bytes: i64, total_chunk_count: i64, chunk_index: i64) -> Result<usize> {
    if plaintext_size < 0
        || chunk_size_bytes <= 0
        || total_chunk_count <= 0
        || chunk_index < 0
        || chunk_index >= total_chunk_count
    {
        bail!("invalid file geometry");
    }
    let plaintext_size = u64::try_from(plaintext_size).context("invalid plaintext size")?;
    let chunk_size_bytes = u64::try_from(chunk_size_bytes).context("invalid chunk size")?;
    let total_chunk_count = u64::try_from(total_chunk_count).context("invalid total chunks")?;
    let chunk_index = u64::try_from(chunk_index).context("invalid chunk index")?;
    let expected_total_chunk_count = plaintext_size.div_ceil(chunk_size_bytes).max(1);
    if total_chunk_count != expected_total_chunk_count {
        bail!("inconsistent file geometry");
    }
    let chunk_offset = chunk_index
        .checked_mul(chunk_size_bytes)
        .ok_or_else(|| anyhow!("file offset overflow"))?;
    let remaining_plaintext_bytes = plaintext_size.saturating_sub(chunk_offset);
    usize::try_from(remaining_plaintext_bytes.min(chunk_size_bytes)).context("chunk size does not fit usize")
}

async fn init_file(
    State(state): State<AppState>,
    Json(file_init_request): Json<FileInitRequest>,
) -> Result<Json<Ack>, ApiError> {
    parse_signing_public_key(&file_init_request.recipient).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &file_init_request.identity,
        file_init_request.timestamp,
        &file_init_request.signature,
        &canonical_file_init(&file_init_request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    Uuid::parse_str(&file_init_request.file_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    if file_init_request.plain_size < 0
        || file_init_request.chunk_size <= 0
        || file_init_request.chunk_size > MAX_CHUNK_SIZE as i64
        || file_init_request.total_chunks <= 0
    {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid file sizes"));
    }
    expected_plain_chunk_size(
        file_init_request.plain_size,
        file_init_request.chunk_size,
        file_init_request.total_chunks,
        file_init_request.total_chunks - 1,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let file_directory = state.storage_directory.join(&file_init_request.file_id);
    fs::create_dir_all(&file_directory)
        .await
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let connection = open_db(&state.database_path)?;
    connection.execute(
        "INSERT OR IGNORE INTO files
        (file_id, sender, recipient, encrypted_name, name_nonce, encrypted_key, key_nonce,
         nonce_prefix, plain_size, chunk_size, total_chunks, completed, created_at, storage_path)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13)",
        params![
            file_init_request.file_id,
            file_init_request.identity,
            file_init_request.recipient,
            file_init_request.encrypted_name,
            file_init_request.name_nonce,
            file_init_request.encrypted_key,
            file_init_request.key_nonce,
            file_init_request.nonce_prefix,
            file_init_request.plain_size,
            file_init_request.chunk_size,
            file_init_request.total_chunks,
            now(),
            file_directory.to_string_lossy().to_string()
        ],
    )
    .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(Ack {
        ok: true,
        detail: "file metadata indexed".into(),
    }))
}

async fn upload_chunk(
    State(state): State<AppState>,
    Path((file_id, chunk_index)): Path<(String, i64)>,
    headers: HeaderMap,
    encrypted_chunk: Bytes,
) -> Result<Json<Ack>, ApiError> {
    Uuid::parse_str(&file_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let requester_identity = header(&headers, "x-identity")?;
    let request_timestamp: i64 = header(&headers, "x-timestamp")?
        .parse()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let request_signature = header(&headers, "x-signature")?;
    let encrypted_chunk_hash = sha256_b64(&encrypted_chunk);
    let canonical_request = format!(
        "file_chunk|{}|{}|{}|{}|{}",
        request_timestamp, requester_identity, file_id, chunk_index, encrypted_chunk_hash
    );
    verify(&requester_identity, request_timestamp, &request_signature, &canonical_request)
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, plaintext_size, chunk_size_bytes, total_chunk_count, completion_flag, file_storage_path):
        (String, i64, i64, i64, i64, String) = connection
        .query_row(
            "SELECT sender, plain_size, chunk_size, total_chunks, completed, storage_path
             FROM files WHERE file_id = ?1",
            params![file_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if sender_identity != requester_identity {
        return Err(api_error(StatusCode::FORBIDDEN, "only sender may upload"));
    }
    if completion_flag != 0 {
        return Err(api_error(StatusCode::CONFLICT, "file already completed"));
    }
    if chunk_index < 0 || chunk_index >= total_chunk_count {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid chunk index"));
    }
    let expected_plaintext_size = expected_plain_chunk_size(
        plaintext_size,
        chunk_size_bytes,
        total_chunk_count,
        chunk_index,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let expected_ciphertext_size = expected_plaintext_size
        .checked_add(16)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "chunk size overflow"))?;
    if encrypted_chunk.len() != expected_ciphertext_size {
        return Err(api_error(StatusCode::BAD_REQUEST, "wrong encrypted chunk size"));
    }
    fs::write(
        PathBuf::from(file_storage_path).join(format!("{chunk_index}.bin")),
        &encrypted_chunk,
    )
    .await
    .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(Ack {
        ok: true,
        detail: format!("chunk {chunk_index} stored"),
    }))
}

async fn complete_file(
    State(state): State<AppState>,
    Json(completion_request): Json<FileCompleteRequest>,
) -> Result<Json<Ack>, ApiError> {
    verify(
        &completion_request.identity,
        completion_request.timestamp,
        &completion_request.signature,
        &canonical_file_complete(&completion_request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, total_chunk_count, file_storage_path): (String, i64, String) = connection
        .query_row(
            "SELECT sender, total_chunks, storage_path FROM files WHERE file_id = ?1",
            params![completion_request.file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if sender_identity != completion_request.identity {
        return Err(api_error(StatusCode::FORBIDDEN, "only sender may complete"));
    }
    let file_directory = PathBuf::from(file_storage_path);
    for chunk_index in 0..total_chunk_count {
        let chunk_exists = fs::try_exists(file_directory.join(format!("{chunk_index}.bin")))
            .await
            .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
        if !chunk_exists {
            return Err(api_error(StatusCode::CONFLICT, format!("missing chunk {chunk_index}")));
        }
    }
    connection.execute(
        "UPDATE files SET completed = 1 WHERE file_id = ?1",
        params![completion_request.file_id],
    )
    .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(Ack {
        ok: true,
        detail: "file completed".into(),
    }))
}

async fn list_files(
    State(state): State<AppState>,
    Json(file_list_request): Json<FileListRequest>,
) -> Result<Json<FileListResponse>, ApiError> {
    parse_signing_public_key(&file_list_request.friend).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &file_list_request.identity,
        file_list_request.timestamp,
        &file_list_request.signature,
        &canonical_file_list(&file_list_request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let mut statement = connection
        .prepare(
            "SELECT row_id, file_id, sender, recipient, encrypted_name, name_nonce,
                    encrypted_key, key_nonce, nonce_prefix, plain_size, chunk_size,
                    total_chunks, completed, created_at
             FROM files
             WHERE row_id > ?1 AND completed = 1 AND
               ((sender = ?2 AND recipient = ?3) OR (sender = ?3 AND recipient = ?2))
             ORDER BY row_id ASC
             LIMIT 1000",
        )
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let file_rows = statement
        .query_map(
            params![file_list_request.after_row_id, file_list_request.identity, file_list_request.friend],
            file_record,
        )
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let files = file_rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(FileListResponse { files }))
}

async fn file_info(
    State(state): State<AppState>,
    Json(file_info_request): Json<FileInfoRequest>,
) -> Result<Json<FileRecord>, ApiError> {
    verify(
        &file_info_request.identity,
        file_info_request.timestamp,
        &file_info_request.signature,
        &canonical_file_info(&file_info_request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let file_record = connection
        .query_row(
            "SELECT row_id, file_id, sender, recipient, encrypted_name, name_nonce,
                    encrypted_key, key_nonce, nonce_prefix, plain_size, chunk_size,
                    total_chunks, completed, created_at
             FROM files WHERE file_id = ?1",
            params![file_info_request.file_id],
            file_record,
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if file_record.sender != file_info_request.identity && file_record.recipient != file_info_request.identity {
        return Err(api_error(StatusCode::FORBIDDEN, "not a participant"));
    }
    Ok(Json(file_record))
}

async fn download_chunk(
    State(state): State<AppState>,
    Path((file_id, chunk_index)): Path<(String, i64)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    Uuid::parse_str(&file_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let requester_identity = header(&headers, "x-identity")?;
    let request_timestamp: i64 = header(&headers, "x-timestamp")?
        .parse()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let request_signature = header(&headers, "x-signature")?;
    let canonical_request = format!(
        "file_get_chunk|{}|{}|{}|{}",
        request_timestamp, requester_identity, file_id, chunk_index
    );
    verify(&requester_identity, request_timestamp, &request_signature, &canonical_request)
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, recipient_identity, total_chunk_count, completion_flag, file_storage_path):
        (String, String, i64, i64, String) = connection
        .query_row(
            "SELECT sender, recipient, total_chunks, completed, storage_path
             FROM files WHERE file_id = ?1",
            params![file_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if requester_identity != sender_identity && requester_identity != recipient_identity {
        return Err(api_error(StatusCode::FORBIDDEN, "not a participant"));
    }
    if completion_flag == 0 {
        return Err(api_error(StatusCode::CONFLICT, "file incomplete"));
    }
    if chunk_index < 0 || chunk_index >= total_chunk_count {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid chunk index"));
    }
    let encrypted_chunk = fs::read(PathBuf::from(file_storage_path).join(format!("{chunk_index}.bin")))
        .await
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok((StatusCode::OK, encrypted_chunk).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_extreme_timestamp_without_overflow() {
        assert!(verify("invalid", i64::MIN, "invalid", "request").is_err());
        assert!(verify("invalid", i64::MAX, "invalid", "request").is_err());
    }

    #[test]
    fn validates_file_chunk_geometry() {
        assert_eq!(expected_plain_chunk_size(0, 4 * 1024 * 1024, 1, 0).unwrap(), 0);
        assert_eq!(
            expected_plain_chunk_size(4 * 1024 * 1024, 4 * 1024 * 1024, 1, 0).unwrap(),
            4 * 1024 * 1024
        );
        assert_eq!(
            expected_plain_chunk_size(4 * 1024 * 1024 + 1, 4 * 1024 * 1024, 2, 1).unwrap(),
            1
        );
        assert!(expected_plain_chunk_size(1, 4 * 1024 * 1024, 2, 0).is_err());
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_path = PathBuf::from(
        std::env::var("CHAT_DB").unwrap_or_else(|_| "chat.db".to_string()),
    );
    let storage_directory = PathBuf::from(
        std::env::var("CHAT_STORAGE").unwrap_or_else(|_| "storage".to_string()),
    );
    fs::create_dir_all(&storage_directory).await?;
    let database_connection = Connection::open(&database_path)?;
    database_connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS messages (
             row_id INTEGER PRIMARY KEY AUTOINCREMENT,
             message_id TEXT NOT NULL UNIQUE,
             sender TEXT NOT NULL,
             recipient TEXT NOT NULL,
             nonce TEXT NOT NULL,
             ciphertext TEXT NOT NULL,
             created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_messages_pair
             ON messages(sender, recipient, row_id);
         CREATE TABLE IF NOT EXISTS files (
             row_id INTEGER PRIMARY KEY AUTOINCREMENT,
             file_id TEXT NOT NULL UNIQUE,
             sender TEXT NOT NULL,
             recipient TEXT NOT NULL,
             encrypted_name TEXT NOT NULL,
             name_nonce TEXT NOT NULL,
             encrypted_key TEXT NOT NULL,
             key_nonce TEXT NOT NULL,
             nonce_prefix TEXT NOT NULL,
             plain_size INTEGER NOT NULL,
             chunk_size INTEGER NOT NULL,
             total_chunks INTEGER NOT NULL,
             completed INTEGER NOT NULL DEFAULT 0,
             created_at INTEGER NOT NULL,
             storage_path TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_files_pair
             ON files(sender, recipient, row_id);",
    )?;
    drop(database_connection);
    let state = AppState {
        database_path: Arc::new(database_path),
        storage_directory: Arc::new(storage_directory),
    };
    let app_router = Router::new()
        .route("/messages/send", post(send_message))
        .route("/messages/sync", post(sync_messages))
        .route("/files/init", post(init_file))
        .route(
            "/files/{file_id}/chunks/{chunk_index}",
            post(upload_chunk).get(download_chunk),
        )
        .route("/files/complete", post(complete_file))
        .route("/files/list", post(list_files))
        .route("/files/info", post(file_info))
        .layer(DefaultBodyLimit::max(MAX_CHUNK_SIZE + 16))
        .with_state(state);
    let bind_address = std::env::var("CHAT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let tcp_listener = tokio::net::TcpListener::bind(&bind_address).await?;
    println!("Central E2EE server: {bind_address}");
    println!("Database: {}", state.database_path.display());
    println!("Encrypted file storage: {}", state.storage_directory.display());
    axum::serve(tcp_listener, app_router).await?;
    Ok(())
}
