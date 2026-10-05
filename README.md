# Central E2EE Chat

A lightweight centralized communication tool written in Rust with end-to-end encrypted messaging, message synchronization, and encrypted large-file transfer.

Central E2EE Chat is designed for users who want a simple self-hosted communication system without a traditional username and password registration model. Your local private key represents your identity. After selecting an identity and connecting to a server by IP address and port, you can communicate with a specific contact, synchronize previous encrypted messages, send new messages, and transfer files. Message contents, file contents, file names, and file encryption keys are encrypted on the client side before being sent to the server.

The server acts primarily as a centralized relay, synchronization service, encrypted storage service, and file index. Large files are not inserted directly into SQLite. Instead, the client encrypts them in chunks and uploads the encrypted chunks to the server's local storage. SQLite only stores searchable metadata and indexes such as file IDs, sender and recipient identities, file sizes, chunk counts, encrypted metadata, timestamps, and storage locations. This keeps the database small and makes the project more suitable for transferring very large files without loading the entire file into memory.

## ✨ Features

* 🔐 End-to-end encrypted messages
* 📁 End-to-end encrypted file transfer
* 🧩 Chunked large-file transmission
* 🔄 Message synchronization with a selected contact
* 🔑 Private-key-based identity
* 👤 Multiple local identities
* 🚫 No traditional account registration
* 🚫 No username/password system
* 🗄️ SQLite metadata and indexing
* 💾 Large files stored directly on server disk
* 📝 Encrypted file names
* 🔏 Signed client requests
* 🦀 Written in Rust
* 🖥️ Centralized and self-hostable architecture
* 📦 Minimal project structure

## 📁 Project Structure

The project intentionally keeps the source structure simple.

```text
central-e2ee-chat/
├── Cargo.toml
├── README.md
├── client.rs
└── server.rs
```

There are only two Rust source files:

```text
server.rs
client.rs
```

`server.rs` contains the server-side logic.

`client.rs` contains identity management, encryption, message synchronization, chat, file encryption, file upload, and file download logic.

## 🚀 Clone, Check, Test, and Build

```bash
git clone https://github.com/wangyifan349/central-e2ee-chat
cd central-e2ee-chat
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
cargo build --release
```

The final release binaries will normally be generated under:

```text
target/release/
```

On Windows:

```text
target\release\server.exe
target\release\client.exe
```

On Linux or macOS:

```text
target/release/server
target/release/client
```

## 🔑 Identity Model

This project does not use traditional account registration.

There is no central username/password account system.

Instead, the client creates and stores local identity keys.

Your private key is effectively your identity.

A local identity is used to derive cryptographic keys for:

```text
Ed25519
```

and:

```text
X25519
```

Ed25519 is used to sign requests so that the server can verify that the requester actually controls the corresponding identity.

X25519 is used to establish a shared secret between two identities.

The shared secret is then processed through HKDF-SHA256 to derive the conversation encryption key. The client rejects non-contributory X25519 peer public keys instead of accepting a degenerate shared secret.

Your public identity can be shared with other users.

Your private identity key must never be shared.

## 👥 Multiple Identities

The client supports multiple local identities.

A user may create several independent identities and select which identity to use before connecting to the server.

Each identity has its own private key material and public identity.

This allows one client installation to maintain multiple independent communication identities without requiring multiple server-side accounts.

## 🌐 Connecting to a Server

The intended startup flow is simple.

1. Start the client.
2. Select an existing identity or create a new one.
3. Enter the server IP address.
4. Enter the server port.
5. Connect.
6. Select or enter the public identity of a contact.
7. Start communicating. Inside chat, type `/send` or `/file` when you want to send a file.

The client does not require a complicated set of command-line arguments for normal use.

## 💬 Messaging

Messages are encrypted on the sender's client before being transmitted.

The server receives only encrypted message data.

A stored message contains information similar to:

```text
message_id
sender
recipient
nonce
ciphertext
created_at
```

The server does not need the plaintext message.

Inside the chat, only the exact commands `/send` and `/file` start file sending. The client then asks for a local file path. Every other non-empty input line is treated as a normal encrypted text message. File sending is therefore part of the conversation flow rather than a separate main-menu action.

When the recipient connects again and selects the same contact, the client requests the message history associated with those two identities.

The synchronized ciphertext is then decrypted locally.

## 🔄 Message Synchronization

Message synchronization is performed for a specific pair of identities.

For example:

```text
Identity A <-> Identity B
```

When Identity A selects Identity B, the client can request messages exchanged between A and B.

The server does not need to return every message belonging to every user.

Synchronization is scoped to the selected communication pair.

This makes reconnecting convenient while preserving the end-to-end encryption model.

## 🔐 Message Encryption

A conversation key is derived using:

```text
X25519
+
HKDF-SHA256
```

Messages are encrypted using:

```text
XChaCha20-Poly1305
```

Authenticated encryption provides both confidentiality and integrity.

The server stores ciphertext rather than plaintext.

## 📦 Large-File Transfer

Large files are intentionally not inserted into SQLite.

Instead, files are divided into fixed-size chunks.

The default design uses chunks similar to:

```text
4 MiB
```

The transfer process is approximately:

```text
Read one chunk
        ↓
Encrypt the chunk locally
        ↓
Upload the encrypted chunk
        ↓
Store the ciphertext on server disk
        ↓
Read the next chunk
```

This means a very large file does not need to be loaded completely into RAM.

For example, a multi-gigabyte file can be processed incrementally.

## 💾 Server File Storage

Encrypted file chunks are stored directly on the server filesystem.

A typical directory layout looks like:

```text
storage/
└── <file_id>/
    ├── 0.bin
    ├── 1.bin
    ├── 2.bin
    ├── 3.bin
    └── ...
```

These `.bin` files contain encrypted data.

The server should not require access to the plaintext file contents.

## 🗄️ SQLite File Index

SQLite is used for metadata and indexing instead of storing the complete file body.

Typical file metadata includes:

```text
file_id
sender
recipient
encrypted_name
name_nonce
encrypted_key
key_nonce
nonce_prefix
plain_size
chunk_size
total_chunks
completed
created_at
storage_path
```

This design avoids placing huge binary objects inside the database.

SQLite remains responsible for locating files and maintaining metadata, while the encrypted file data remains on disk.

## 🔒 File Encryption

Each file receives its own randomly generated file encryption key. The file key is wrapped with the conversation key, and the authenticated data binds the file ID, sender, recipient, nonce prefix, plaintext size, chunk size, and total chunk count. This prevents a server-side metadata change from being silently accepted for newly sent files. Legacy file-key metadata remains readable for backward compatibility.

The file itself is encrypted chunk by chunk using:

```text
XChaCha20-Poly1305
```

The file name is also encrypted.

The randomly generated file key is then encrypted using the conversation key shared between the sender and recipient.

The server therefore stores information such as:

```text
Encrypted file name
Encrypted file key
Encrypted file chunks
File metadata
```

The server does not need the plaintext file name or plaintext file contents.

## 📥 Receiving Files

When a recipient requests a file, the server returns the encrypted file metadata and encrypted chunks.

The client then:

```text
Downloads an encrypted chunk
        ↓
Authenticates and decrypts it locally
        ↓
Writes the plaintext chunk to disk
        ↓
Downloads the next encrypted chunk
```

Again, the complete file does not need to be loaded into memory.

## 🖥️ Server Responsibilities

The centralized server is responsible for:

```text
Message relay
Encrypted message storage
Message synchronization
Encrypted file storage
File metadata indexing
File chunk transfer
Request verification
```

The server is not intended to hold the user's private identity key.

## 🔐 Security Boundary

The security boundary of this project is important to understand.

The user's private identity material is stored locally on the client device.

Depending on the configured client storage layout, identity files are stored locally in an identity directory such as:

```text
identities/
```

These files contain the private cryptographic material required to represent the corresponding identity. On Unix-like systems, the client attempts to restrict the `identities/` directory to owner-only access and identity key files to mode `0600`. Other platforms rely on the operating system's normal account and filesystem permissions.

The server does not store the user's private identity key.

### ⚠️ Your Private Key Is Your Identity

If your private key is lost, you may permanently lose access to the corresponding identity.

You may also lose the ability to decrypt data that depends on that identity.

You should therefore create a secure offline backup of important identity files.

Do not send private identity files through ordinary chat applications, email, public cloud links, or other untrusted channels.

If another person copies your private identity key, they may be able to impersonate that identity.

Protecting the client computer, local filesystem, backups, operating system account, and private keys remains the user's responsibility.

## 🕵️ Metadata Is Not Fully Hidden

End-to-end encryption protects message and file contents.

It does not automatically hide all communication metadata.

Because this is a centralized server architecture, the server may still observe information such as:

```text
Which public identities communicate
Connection timestamps
Message timestamps
Ciphertext sizes
Approximate file sizes
Upload timestamps
Download timestamps
Client network addresses
```

This project is intended to protect communication content.

It is not designed to provide complete network anonymity.

## 🌐 Use HTTPS in Production

Even though message and file contents are encrypted end to end, production deployments should still use:

```text
HTTPS / TLS
```

TLS protects the transport connection between the client and server.

It also reduces exposure to active network attacks and protects additional protocol information while data travels across the network.

End-to-end encryption and TLS serve different purposes and should ideally be used together.

## ⚠️ Cryptographic Scope

This project provides a relatively compact end-to-end encrypted communication architecture.

It should not be considered equivalent to mature protocols such as Signal Protocol.

The current design does not claim to provide the full set of features associated with systems implementing:

```text
Double Ratchet
PreKeys
Automatic per-message key rotation
Advanced forward secrecy
Post-compromise security
Multi-device session management
Large-scale key transparency
Anonymous routing
```

It is better understood as a lightweight, self-hostable, understandable E2EE communication foundation.

Users with high-risk security requirements should carefully review the cryptographic implementation before deployment.

## 📉 Release Binary Size Optimization

The release profile is configured with binary size in mind.

Typical settings include:

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
debug = 0
strip = "symbols"
panic = "abort"
```

Unused dependency features should also be disabled whenever possible.

This helps reduce the size of the final server and client executables.

## 🧪 Recommended Development Checks

Before publishing changes, run:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
cargo build --release
```

These checks help detect formatting problems, compilation errors, Clippy warnings, test failures, and release-build issues.

## 📜 License

This project is licensed under the:

**GNU Affero General Public License v3.0**

**AGPL-3.0**

Please review and follow the terms of the AGPL-3.0 when using, modifying, distributing, or operating modified versions of this project.

## ⭐ Support the Project

If this project has helped you learn something new, saved you development time, helped you build your own communication system, or simply gave you a useful starting point, please consider giving the repository a ⭐ Star.

Any small sponsorship is also greatly appreciated. ❤️

This project is maintained independently, and continued development requires time, equipment, infrastructure, testing, and maintenance. The author is working with limited resources, so even a very small contribution can genuinely help keep the project alive and support future improvements. 😭🙏

If financial sponsorship is not convenient, starring the repository, sharing it with others, reporting bugs, submitting improvements, or contributing code is also extremely valuable. 🚀❤️

### ₿ Bitcoin

```text
bc1qwhzzk5tx07592vkf97rt8x8v0zdntad8lexnrgv3gdmecg8pfmhqzceedl
```

### ◆ Ethereum

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### Ł Litecoin

```text
ltc1qx60jqksl8pa38zmqjxau0vy04rqpjgfpn0xgw3
```

Thank you to everyone who uses, studies, stars, shares, improves, or supports this project. ❤️🦀🚀
