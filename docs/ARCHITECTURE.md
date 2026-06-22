# innerlink-core 架构说明

> 配合 [`docs/PRD.md`](./PRD.md) 阅读。本文档讲**怎么造出来**的：分层、接口、关键设计决策、当前实现的性能预算。

## 1. 分层依赖图

```
┌─────────────────────────────────────────────┐
│  cmd/innerlink                       │  ← CLI 集成 demo（M1+M2+M3 跑通）
│       （不是产品，是 core lib 的活体测试）       │
└─────────────────────────────────────────────┘
                  │  import
                  ▼
┌─────────────────────────────────────────────┐
│         internal/protocol                    │  ← 上层 API
│  Envelope / Channel / Send/Recv text/ping    │
│  + FileOffer/Chunk/Done/Abort 消息类型       │
└─────────────────────────────────────────────┘
        │                          │
        ▼                          ▼
┌──────────────────┐      ┌──────────────────┐
│ internal/handshake│      │ internal/transport│
│  SM2 ECDH 4 帧握手 │      │ TCP 帧 + 心跳     │
└──────────────────┘      └──────────────────┘
        │                          │
        └────────────┬─────────────┘
                     ▼
        ┌──────────────────┐
        │  internal/identity │
        │  SM2 密钥 + PeerID  │
        └──────────────────┘
                     │
                     ▼
        ┌──────────────────┐
        │  internal/crypto   │
        │  SM2/SM3/SM4/KDF   │
        └──────────────────┘
                     │
                     ▼
        ┌──────────────────┐
        │  github.com/       │
        │  tjfoc/gmsm v1.4.1 │
        └──────────────────┘

         ┌──────────────────┐
         │ internal/discovery │  ← 旁路：自动发现（UDP 广播）
         │  UDP peer announce │
         └──────────────────┘
                      │
                      ▼
         ┌──────────────────┐
         │  internal/identity │
         └──────────────────┘

         ┌──────────────────┐
         │  internal/storage  │  ← M3 旁路：加密本地落盘
         │  chat.enc 加密写   │    （KDF(SM2_D) → SM4-CBC 16 B IV）
         │  + history 加载   │
         └──────────────────┘

         ┌──────────────────┐
         │  internal/alias    │  ← M4 旁路：peer-id → 人类可读名字
         │  aliases.json      │    （atomic write; touch on activity）
         │  + ResolvePeerRef  │
         └──────────────────┘
                      │
                      ▼
         ┌──────────────────┐
         │  internal/crypto   │
         │  SM2/SM3/SM4/KDF   │
         └──────────────────┘
```

依赖是**单向**的：上层可以 import 下层，下层不能 import 上层。这由 Go 的 `internal/` 机制 + 包路径强制。

## 2. 关键设计决策

### 2.1 core 不 import 任何 GUI 框架

- 不引 Wails / Tauri / Electron / Qt
- `internal/` 包路径保证不会跨模块污染（Go 编译器强制）
- UI 是**另一个独立仓库**，`go mod require` 这个 core 即可
- **公开 API 入口**: `pkg/node/` 是唯一对外的包，导出 `*node.Node` 类型和它的方法（`New / Start / Close / SendText / SendFile / Scan / ListPeers / SubscribeMessages / SubscribePeers / History / SetAlias / ListAliases / RemoveAlias / DialAddr`）。`internal/*` 仅供 `pkg/node` 和 `cmd/innerlink` 内部使用。

### 2.2 不自实现国密算法

- **唯一** SM 实现：`github.com/tjfoc/gmsm v1.4.1`
- 自己写 SM2/SM3/SM4 几乎一定写错（侧信道、定时攻击、padding oracle）
- `internal/crypto` 是 thin wrapper，把 gmsm 的 API 包成 innerlink 自己的错误模型

### 2.3 Envelope 强制 `version` 字段

- 当前所有 Envelope `v=1`
- 协议升级时 `v=2`，老 client 收到可识别后拒绝
- 比"加个新字段"的兼容性更明确

### 2.4 零 CGO

- gmsm 是纯 Go（基于 GM 标准的恒定时间实现）
- `golang.org/x/sys` 拉了，但只在 Unix 上用 `SetReadDeadline` / `SetWriteDeadline` 的 syscall，Windows 用 net 包原生的
- Windows / macOS / Linux / ARM（amd64 + arm64）都不需要 C 编译器

### 2.5 单 reader per Channel

- `transport.Conn.Recv` 不是 thread-safe（Go net.Conn 本身的限制）
- `protocol.Channel` 加了 `recvMu`，但更干净的做法是**一个 Channel 一个 Recv goroutine**，分发到不同 handler
- cmd/innerlink 就是这么干的：单 dispatcher pump + chat/filetransfer/ping 路由
- 详见 `internal/filetransfer/receiver.go` 的 `Handle` API + AGENTS.md

### 2.6 测试策略

- 110+ 个测试（unit + dispatcher e2e + logx + storage 14 个）
- `go test ./...` 必须全过
- VMware 双机端到端测：CI 跑不了（无网段），由人类测试者在本地跑
- `go test -race` 在本机跑不了（无 CGO，Windows 上 race detector 依赖 C 编译器；CI Ubuntu runner 可跑）

### 2.7 M3 加密本地落盘的密钥派生

- `internal/storage` 的 SM4 密钥**不是独立存盘的**；每次启动从 SM2 私钥 D 用 KDF 派生
- `storageKey = KDF(D, "innerlink-storage-v1", 16)` — 16 字节 SM4-128 key
- D 来自 `identity.Identity.PrivateKeyD()`，永远不写盘
- 改 info 字符串 = 烧旧 history（domain separation，不是 bug）
- 丢 `device.key` = 丢 history（feature not bug）
- 任何持有 device.key 的进程都能读 chat.enc；任何不持有的都拿不到 plaintext（读路径直接返回 `ErrCorrupt`，不返回 garbage）

## 3. 接口约定

### 3.1 protocol.Channel（最常用）

```go
ch, _ := protocol.NewChannel(conn, sess)

// 发聊天
ch.SendText(ctx, "hello")

// 发 ping
ch.SendPing(ctx)

// 收一个 envelope（context 可以 cancel）
env, err := ch.Recv(ctx)

// 关
ch.Close()
```

### 3.2 filetransfer.Send / Receiver

```go
// 发
err := filetransfer.Send(ctx, ch, "/path/to/file", progress, rcv.WaitForReply)

// 收（两种模式）
// 模式 A：独占 channel，用 Loop
err := rcv.Loop(ctx)
// 模式 B：共享 channel（cmd/innerlink 模式），用 Handle + 自己的 dispatcher
go func() {
    for {
        env, _ := ch.Recv(ctx)
        rcv.Handle(ctx, env)
    }
}()
```

### 3.3 identity

```go
// 首次启动
id, created, _ := identity.LoadOrCreate("~/.innerlink/device.key")

// PeerID = SM3(公钥)[:16]，hex 32 字符
fmt.Println(id.PeerIDHex())

// 暴露给 M3 storage 用
deviceD := id.PrivateKeyD()  // 32 B SM2 私钥 D
```

### 3.4 storage（M3 落盘 + history）

```go
// 启动时打开
store, err := storage.Open(saveDir, id.PrivateKeyD())
defer store.Close()

// 启动时加载历史
records, err := store.ReadAll()  // 启动时一次性 in-memory 加载

// 收到 / 发出 chat 时 append
store.Append(&storage.Record{
    Timestamp: time.Now().UTC(),
    From:      peerHex,
    To:        id.PeerIDHex(),
    Direction: "in",  // 或 "out"
    Body:      string(env.Payload),
})

// REPL 的 history 命令走 in-memory slice
for i := max(0, len(records)-50); i < len(records); i++ {
    rec := records[i]
    fmt.Printf("%s %s %s %s\n", rec.Timestamp.Local().Format(...), rec.Direction, peerShort(rec.From), rec.Body)
}
```

**帧格式**（append-only self-describing）：

```
[4 B big-endian ciphertext length]
[16 B IV]
[N B SM4-CBC ciphertext of PKCS#7-padded JSON]
```

JSON 明文：

```json
{
  "v": 1,
  "ts": "2026-06-17T03:19:28.702Z",
  "from": "268fb7ee158d35160ef9ef76e0977f2a",
  "to":   "d50fdc68d3def9e0207fef011c678571",
  "dir":  "in",
  "body": "你好",
  "msgID": ""
}
```

> `msgID` 字段在 v0.1 留空 — 它是 v0.3 协议引入 AAD 时会填的。文件层已经准备好接，未来不破坏格式。

### 3.5 alias（M4 别名 + peer 列表）

```go
// 打开 ~/.innerlink/aliases.json（与 device.key 同目录）
store, _ := alias.Open(alias.DefaultPath(keyPath))
defer store.Close()

// 手动命名
store.Set(peerID, "老王工位机")
store.Save()  // atomic write: <path>.tmp + rename

// 解析 send 第一个参数（hex 或 alias）
peerID, ok := store.ResolvePeerRef("老王工位机")
```

**存储格式**（`~/.innerlink/aliases.json`）：

```json
{
  "v": 1,
  "aliases": {
    "<peer-id-hex>": {
      "name": "老王工位机",
      "first_seen": "2026-06-17T...",
      "last_seen":  "2026-06-17T..."
    }
  }
}
```

**两类写入**：

- `Set(peerID, name)` —— 来自 REPL `alias` 命令，**用户手动**
- `Touch(peerID)` —— 来自 cmd runtime：discovery `PeerAdded` + wrapChannel 入口**自动**。**未命名**的 peer 也会有 placeholder row（`name=""`），让 `peers` 命令能列出最近活跃但还没起名的设备

**一致性保证**：

- JSON 文件用 `<path>.tmp` + `os.Rename` 原子写，**crash 中断**不会留半截文件
- 解析失败 → 硬错（`ErrCorrupt`），**不**静默当成空表
- 写入并发由 `sync.Mutex` 序列化
- 输入校验：peer-id 必须是 32 字符小写 hex；name 1-64 字符

**REPL 集成**：

- `send`/`sendfile`/`ping`/`history` 第一个参数**同时**接受 32 字符 hex **或** alias name
- `alias <name> <peer-id-hex>` / `alias list` / `unalias <name-or-peer-id>` —— 增删查
- `peers` —— 列已知 peer，按 `last_seen` 倒序，named 显示 name，unnamed 显示 "(unnamed)"

**为什么 v0.4 不做协议 v2**：AAD、MsgID、重放窗口属于 v0.5 (M5)。M4 只解决"用户能识别对端"的人机交互层。

## 4. 性能预算（v0.4 实测）

| 指标 | 实测值 |
|---|---|
| 同 WiFi 端到端首次握手 | < 200ms |
| chat 消息端到端时延 | < 20ms |
| 2 GiB 文件跨 VMware 传输 | ~120s（受磁盘 IO 限制，不是协议） |
| `innerlink.exe` 大小 | 5.1 MB（upx 之前） |
| M3 chat.enc 写延迟（每条） | < 5ms（KDF 一次启动，crypto 在内存） |
| M3 chat.enc 启动加载 1000 条 | < 50ms（SM4 解密 + JSON 反序列化） |
| M4 alias 写（set + save） | < 1ms（10 个 alias 时） |
| M4 alias 启动加载 100 条 | < 5ms（JSON unmarshal） |
| M4 alias ResolvePeerRef | < 1μs（in-memory map 查找） |
| CI 全量测试 + race | ~1 min |

## 5. 失败模式

| 失败 | 用户感知 | 当前处理 |
|---|---|---|
| UDP 广播被防火墙挡 | 看不到同网段 peer | 文档说开 4747 UDP |
| TCP 4748 被防火墙挡 | 主动 dial 失败 | 文档说开 4748 TCP |
| 设备密钥泄露 | 隐私全无 | README 强调保管 device.key |
| 网络掉线 / 进程被杀 | channel 60s read deadline 后关 | dispatcher log + 上层 UI 重连 |
| 握手超时 | 5s 后报 handshake timeout | 上层 UI 显式提示 |
| 设备密钥丢失 / device.key 被删 | history 显示 corrupt | 退出时不 panic，REPL 显式提示 `ErrCorrupt` |
| chat.enc 文件被外部截断 / 篡改 | ReadAll 解析到一半停 | 启动时丢弃 corrupt tail（`ErrCorrupt` + 提示截断点） |

## 6. 仓库布局

```
D:\innerlink
├── cmd/innerlink/             CLI 集成 demo
│   ├── main.go                wire-up + REPL
│   └── helpers.go             hex/hostname 小工具
├── internal/
│   ├── crypto/                封装 4 个国密算法
│   ├── identity/              设备密钥 + PeerID
│   ├── discovery/             UDP 广播（build-tag 跨平台）
│   ├── transport/             TCP 帧 + heartbeat
│   ├── handshake/             SM2 ECDH 4 帧
│   ├── protocol/              Envelope + Channel
│   ├── filetransfer/          分片 + SHA-256 校验
│   ├── logx/                  日志级别 + 文件 sink
│   ├── storage/               M3 ✅ 加密落盘 + history
│   └── alias/                 M4 ✅ peer 别名 + 解析
├── docs/
│   ├── PRD.md                 产品需求
│   └── ARCHITECTURE.md        ← 你正在看
├── .github/workflows/ci.yml   CI（3 平台）
├── AGENTS.md                  协议约束 + 踩过的坑
├── LICENSE                    Apache 2.0
├── README.md                  项目入口
└── go.mod / go.sum            依赖（gmsm + x/sys）
```

## 7. 不在范围内

> 留一份给未来的自己 / 协作者，免得每次都重复解释

- **群组 / 多方** — 当前协议是 1:1，群组是另一个量级
- **NAT 穿透 / 中继** — 需要 STUN/TURN，core 不做
- **跨网段** — 当前假设同 WiFi / 同 NAT
- **移动端 (iOS / Android)** — gomobile bind 是个可能性，core 应该兼容但目前没在跑
- **WebAssembly** — 没测过
- **TLS fallback** — 当前是裸 SM4-GCM；上 TLS 1.3 可以加但不是 v0.x 的事
