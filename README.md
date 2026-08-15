# Central E2EE Chat

这是一个精简的 Rust 中心化通信工具。服务器负责转发、同步、密文保存和文件索引，客户端负责身份私钥、端到端加密、消息解密和文件解密。项目只保留 `server.rs`、`client.rs`、`Cargo.toml` 和 `README.md`。

## 1. 获取、检查与编译

先克隆项目并进入目录：

```bash
git clone https://github.com/wangyifan349/central-e2ee-chat
cd central-e2ee-chat
```

确保 Rust 工具链、Rustfmt 和 Clippy 可用：

```bash
rustup update stable
rustup component add rustfmt clippy
```

依次执行格式检查、编译检查、Clippy、测试，最后生成最小化 Release 程序：

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
cargo build --release
```

其中 Clippy 是 Rust 官方静态检查工具。只有前面的检查全部通过后，再使用最后一条命令生成正式程序。

编译结果：

```text
target/release/server
target/release/client
```

Windows 对应：

```text
target\release\server.exe
target\release\client.exe
```

`Cargo.toml` 已关闭 Debug 信息，并对 Release 使用 `opt-level = "z"`、Fat LTO、单 codegen unit、`panic = "abort"` 和符号剥离，以尽量减小最终二进制体积；Tokio 也只启用当前代码实际需要的功能，不再使用 `full`。

依赖版本按当前稳定版本核对，但对于已经进入破坏性新版本的密码学依赖，保持与现有源码兼容的最新稳定分支，避免为了追版本而修改通信协议或业务代码。

## 2. 客户端启动流程

客户端编译完成后，Windows 下可以直接双击：

```text
target\release\client.exe
```

不需要再写：

```text
client chat ...
client send ...
client --server ...
```

客户端启动后按下面的顺序运行：

```text
启动 client.exe
    ↓
扫描 identities/ 目录
    ↓
选择已有身份 / 创建新身份
    ↓
输入服务器 IP
    ↓
输入服务器端口
    ↓
进入主菜单
```

服务器 IP 默认是：

```text
127.0.0.1
```

服务器端口默认是：

```text
8080
```

如果 IP 或端口输入错误，客户端不会直接退出，而是提示后重新输入。

## 3. 多身份

客户端支持创建多个身份。

第一次启动时如果没有身份，会看到类似：

```text
=== Identity ===
No local identities yet.
N. Create a new identity
0. Exit
```

输入 `N` 后可以创建身份，例如：

```text
work
personal
test
```

本地会自动生成：

```text
identities/
├── work.key
├── personal.key
└── test.key
```

每个 `.key` 文件保存一份独立的 32 字节主私钥。私钥就是身份，不存在用户名、密码和服务器注册流程。

身份名称只允许：

```text
A-Z
a-z
0-9
-
_
```

重新启动客户端后会自动扫描 `identities/`，显示编号供选择。

## 4. 身份和加密

客户端从主私钥派生两类密钥：

```text
Ed25519  -> 请求签名和身份验证
X25519   -> 与好友建立共享秘密
```

双方通过 X25519 得到共享秘密，再使用 HKDF-SHA256 派生会话密钥。

消息使用：

```text
XChaCha20-Poly1305
```

进行端到端加密。

服务器只保存：

```text
发送方公共身份
接收方公共身份
消息 ID
nonce
ciphertext
时间
```

服务器没有消息明文，也没有客户端私钥。

## 5. 主菜单

进入身份和服务器后，客户端显示：

```text
1. Chat with a friend
2. Send a file
3. List files with a friend
4. Receive a file
5. Switch identity
6. Change server
0. Exit
```

因此所有常用操作都从菜单进入，不需要重新启动程序并添加命令参数。

## 6. 聊天和消息同步

选择：

```text
1. Chat with a friend
```

然后粘贴好友的 Public ID。

客户端进入聊天后会立即同步：

```text
当前身份 <-> 指定好友
```

之间的历史消息，然后每 2 秒继续同步新消息。

聊天时直接输入文字即可发送，例如：

```text
hello
```

输入：

```text
/back
```

返回主菜单。

服务器同步查询只会返回当前身份与指定好友之间的数据，不会把其他人的消息一起同步回来。

## 7. 文件发送

主菜单选择：

```text
2. Send a file
```

然后输入：

```text
好友 Public ID
文件路径
```

例如 Windows 路径：

```text
D:\Video\large.iso
```

文件不会整体读入内存，也不会写进 SQLite。

默认分块大小：

```text
4 MiB
```

发送流程：

```text
读取一个文件块
    ↓
客户端加密
    ↓
上传密文块
    ↓
服务器写入硬盘
    ↓
继续下一块
```

因此适合很大的文件。

## 8. 文件在服务器上的存储

服务器文件目录类似：

```text
storage/
└── <file_id>/
    ├── 0.bin
    ├── 1.bin
    ├── 2.bin
    └── ...
```

这些 `.bin` 全部是加密后的文件块。

SQLite 只负责文件索引和统计信息，例如：

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

文件本体不会直接插入数据库。

## 9. 文件加密

每个文件会生成独立的随机 256-bit 文件密钥。

文件内容逐块使用 XChaCha20-Poly1305 加密，并为不同块使用不同 nonce。

文件名也会被加密。

文件密钥本身再使用双方的会话密钥进行加密，因此服务器保存的是：

```text
加密文件名
加密文件密钥
加密文件块
```

而不是明文文件。

## 10. 查看和接收文件

主菜单选择：

```text
3. List files with a friend
```

输入好友 Public ID 后，可以查看双方已经完成上传的文件。客户端会在本地解密文件名。

下载文件选择：

```text
4. Receive a file
```

输入文件 ID，然后可以直接使用原文件名，也可以指定保存路径。

下载过程也是逐块进行：

```text
服务器读取密文块
    ↓
客户端下载
    ↓
客户端验证并解密
    ↓
写入本地文件
```

## 11. 服务器启动

服务器默认不需要参数。

编译后 Windows 可以直接双击：

```text
target\release\server.exe
```

默认监听：

```text
0.0.0.0:8080
```

首次运行会自动创建：

```text
chat.db
storage/
```

服务器仍然保留 `CHAT_BIND`、`CHAT_DB` 和 `CHAT_STORAGE` 环境变量，方便高级部署，但普通使用不需要设置。

## 12. 项目结构

```text
central-e2ee-chat/
├── Cargo.toml
├── README.md
├── server.rs
└── client.rs
```

`server.rs` 包含：

```text
HTTP API
SQLite
消息密文存储
消息同步
文件索引
文件块磁盘存储
签名验证
```

`client.rs` 包含：

```text
多身份管理
启动菜单
服务器 IP/端口输入
身份私钥派生
Ed25519 请求签名
X25519 共享秘密
消息加解密
消息同步
大文件分块加解密
文件上传和下载
```

## 13. 本次代码整理

代码已经按照两轮方式处理。

第一轮只优化启动流程：去掉客户端启动参数，增加多身份选择、身份创建、服务器 IP/端口输入和主菜单。

第二轮再扫描全部 Rust 代码：变量改为更明确的英语命名，例如 `database_path`、`storage_directory`、`conversation_key`、`encryption_secret`、`public_identity`、`encrypted_chunk`、`canonical_request`、`bytes_read` 等；删除重复空行；统一四空格缩进；避免使用无意义的单字母业务变量；聊天同步的嵌套也进行了简化。

## 14. 安全边界

这是一个中心化服务器 + 端到端加密客户端的基础实现。

服务器看不到消息正文和文件正文，但仍然能够观察部分元数据，例如：

```text
哪些公共身份之间发生通信
通信时间
密文大小
文件大小
连接 IP
```

另外当前版本没有实现 Signal Protocol 的 Double Ratchet、PreKeys、多设备密钥管理和完整的前向保密机制。

正式部署到互联网时仍建议在服务器前使用 HTTPS/TLS。端到端加密保护消息和文件内容，TLS 则进一步保护客户端到服务器之间的传输层连接。

最重要的是：

```text
不要泄露 identities/*.key
```

丢失身份私钥就等于丢失该身份；泄露身份私钥则意味着别人可以冒充该身份。建议离线备份。