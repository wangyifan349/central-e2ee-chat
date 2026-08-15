use axum::{
    body::Bytes,
    extract::{Path, State},
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

fn api_error(status: StatusCode, error: impl ToString) -> ApiError {
    (status, error.to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn parse_signing_public_key(public_identity: &str) -> Result<[u8; 32]> {
    let decoded_identity = URL_SAFE_NO_PAD
        .decode(public_identity)
        .context("invalid public identity encoding")?;
    if decoded_identity.len() != 64 {
        bail!("public identity must decode to 64 bytes");
    }
    let mut signing_public_key_bytes = [0u8; 32];
    signing_public_key_bytes.copy_from_slice(&decoded_identity[..32]);
    Ok(signing_public_key_bytes)
}

fn verify(public_identity: &str, timestamp: i64, signature_text: &str, canonical_request: &str) -> Result<()> {
    if (now() - timestamp).abs() > AUTH_WINDOW_SECS {
        bail!("request timestamp is outside the allowed window");
    }
    let signing_public_key_bytes = parse_signing_public_key(public_identity)?;
    let verifying_key = VerifyingKey::from_bytes(&signing_public_key_bytes).context("invalid Ed25519 public key")?;
    let decoded_signature = URL_SAFE_NO_PAD
        .decode(signature_text)
        .context("invalid signature encoding")?;
    let signature_bytes: [u8; 64] = decoded_signature
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    verifying_key
        .verify_strict(canonical_request.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .context("signature verification failed")
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
    Json(request): Json<SendMessageRequest>,
) -> Result<Json<Ack>, ApiError> {
    parse_signing_public_key(&request.recipient).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(&request.identity, request.timestamp, &request.signature, &canonical_send(&request))
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    Uuid::parse_str(&request.message_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let connection = open_db(&state.database_path)?;
    connection.execute(
        "INSERT OR IGNORE INTO messages
        (message_id, sender, recipient, nonce, ciphertext, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.message_id,
            request.identity,
            request.recipient,
            request.nonce,
            request.ciphertext,
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
    Json(request): Json<SyncRequest>,
) -> Result<Json<MessageSyncResponse>, ApiError> {
    parse_signing_public_key(&request.friend).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(&request.identity, request.timestamp, &request.signature, &canonical_sync(&request))
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
    let query_rows = statement
        .query_map(params![request.after_row_id, request.identity, request.friend], |row| {
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
    let mut messages = Vec::new();
    for row in query_rows {
        messages.push(row.map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?);
    }
    Ok(Json(MessageSyncResponse { messages }))
}

async fn init_file(
    State(state): State<AppState>,
    Json(request): Json<FileInitRequest>,
) -> Result<Json<Ack>, ApiError> {
    parse_signing_public_key(&request.recipient).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &request.identity,
        request.timestamp,
        &request.signature,
        &canonical_file_init(&request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    Uuid::parse_str(&request.file_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    if request.plain_size < 0
        || request.chunk_size <= 0
        || request.chunk_size > 64 * 1024 * 1024
        || request.total_chunks <= 0
    {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid file sizes"));
    }
    let file_directory = state.storage_directory.join(&request.file_id);
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
            request.file_id,
            request.identity,
            request.recipient,
            request.encrypted_name,
            request.name_nonce,
            request.encrypted_key,
            request.key_nonce,
            request.nonce_prefix,
            request.plain_size,
            request.chunk_size,
            request.total_chunks,
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
    body: Bytes,
) -> Result<Json<Ack>, ApiError> {
    Uuid::parse_str(&file_id).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let requester_identity = header(&headers, "x-identity")?;
    let timestamp: i64 = header(&headers, "x-timestamp")?
        .parse()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let request_signature = header(&headers, "x-signature")?;
    let body_hash = sha256_b64(&body);
    let canonical_request = format!(
        "file_chunk|{}|{}|{}|{}|{}",
        timestamp, requester_identity, file_id, chunk_index, body_hash
    );
    verify(&requester_identity, timestamp, &request_signature, &canonical_request)
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, chunk_size, total_chunks, completed, storage_path):
        (String, i64, i64, i64, String) = connection
        .query_row(
            "SELECT sender, chunk_size, total_chunks, completed, storage_path
             FROM files WHERE file_id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if sender_identity != requester_identity {
        return Err(api_error(StatusCode::FORBIDDEN, "only sender may upload"));
    }
    if completed != 0 {
        return Err(api_error(StatusCode::CONFLICT, "file already completed"));
    }
    if chunk_index < 0 || chunk_index >= total_chunks {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid chunk index"));
    }
    if body.len() > chunk_size as usize + 16 {
        return Err(api_error(StatusCode::PAYLOAD_TOO_LARGE, "chunk too large"));
    }
    if chunk_index < total_chunks - 1 && body.len() != chunk_size as usize + 16 {
        return Err(api_error(StatusCode::BAD_REQUEST, "wrong chunk size"));
    }
    fs::write(
        PathBuf::from(storage_path).join(format!("{chunk_index}.bin")),
        &body,
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
    Json(request): Json<FileCompleteRequest>,
) -> Result<Json<Ack>, ApiError> {
    verify(
        &request.identity,
        request.timestamp,
        &request.signature,
        &canonical_file_complete(&request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, total_chunks, storage_path): (String, i64, String) = connection
        .query_row(
            "SELECT sender, total_chunks, storage_path FROM files WHERE file_id = ?1",
            params![request.file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if sender_identity != request.identity {
        return Err(api_error(StatusCode::FORBIDDEN, "only sender may complete"));
    }
    let file_directory = PathBuf::from(storage_path);
    for chunk_index in 0..total_chunks {
        if !fs::try_exists(file_directory.join(format!("{chunk_index}.bin")))
            .await
            .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?
        {
            return Err(api_error(StatusCode::CONFLICT, format!("missing chunk {chunk_index}")));
        }
    }
    connection.execute(
        "UPDATE files SET completed = 1 WHERE file_id = ?1",
        params![request.file_id],
    )
    .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(Ack {
        ok: true,
        detail: "file completed".into(),
    }))
}

async fn list_files(
    State(state): State<AppState>,
    Json(request): Json<FileListRequest>,
) -> Result<Json<FileListResponse>, ApiError> {
    parse_signing_public_key(&request.friend).map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    verify(
        &request.identity,
        request.timestamp,
        &request.signature,
        &canonical_file_list(&request),
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
    let query_rows = statement
        .query_map(params![request.after_row_id, request.identity, request.friend], file_record)
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let mut files = Vec::new();
    for row in query_rows {
        files.push(row.map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?);
    }
    Ok(Json(FileListResponse { files }))
}

async fn file_info(
    State(state): State<AppState>,
    Json(request): Json<FileInfoRequest>,
) -> Result<Json<FileRecord>, ApiError> {
    verify(
        &request.identity,
        request.timestamp,
        &request.signature,
        &canonical_file_info(&request),
    )
    .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let file_record = connection
        .query_row(
            "SELECT row_id, file_id, sender, recipient, encrypted_name, name_nonce,
                    encrypted_key, key_nonce, nonce_prefix, plain_size, chunk_size,
                    total_chunks, completed, created_at
             FROM files WHERE file_id = ?1",
            params![request.file_id],
            file_record,
        )
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "file not found"))?;
    if file_record.sender != request.identity && file_record.recipient != request.identity {
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
    let timestamp: i64 = header(&headers, "x-timestamp")?
        .parse()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, error))?;
    let request_signature = header(&headers, "x-signature")?;
    let canonical_request = format!(
        "file_get_chunk|{}|{}|{}|{}",
        timestamp, requester_identity, file_id, chunk_index
    );
    verify(&requester_identity, timestamp, &request_signature, &canonical_request)
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    let connection = open_db(&state.database_path)?;
    let (sender_identity, recipient_identity, total_chunks, completed, storage_path):
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
    if completed == 0 {
        return Err(api_error(StatusCode::CONFLICT, "file incomplete"));
    }
    if chunk_index < 0 || chunk_index >= total_chunks {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid chunk index"));
    }
    let encrypted_chunk = fs::read(PathBuf::from(storage_path).join(format!("{chunk_index}.bin")))
        .await
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok((StatusCode::OK, encrypted_chunk).into_response())
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
    let connection = Connection::open(&database_path)?;
    connection.execute_batch(
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
    drop(connection);
    let state = AppState {
        database_path: Arc::new(database_path),
        storage_directory: Arc::new(storage_directory),
    };
    let router = Router::new()
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
        .with_state(state);
    let bind_address = std::env::var("CHAT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    println!("Central E2EE server: {bind_address}");
    println!("Database: {}", state.database_path.display());
    println!("Encrypted file storage: {}", state.storage_directory.display());
    axum::serve(listener, router).await?;
    Ok(())
}
