# innerlink-core 架构说明

> 配合 [`docs/PRD.md`](./PRD.md) 阅读。本文档讲**怎么造出来**的：分层、接口、关键设计决策、当前实现的性能预算。

## 1. 分层依赖图

```
┌─────────────────────────────────────────────┐
│          cmd/innerlink                       │  ← CLI 集成 demo（M1+M2 跑通）
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
```

依赖是**单向**的：上层可以 import 下层，下层不能 import 上层。这由 Go 的 `internal/` 机制 + 包路径强制。

## 2. 关键设计决策

### 2.1 core 不 import 任何 GUI 框架

- 不引 Wails / Tauri / Electron / Qt
- `internal/` 包路径保证不会跨模块污染
- UI 是**另一个独立仓库**，`go mod require` 这个 core 即可

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

- 96 个测试（unit + dispatcher e2e + logx）
- `go test -race ./...` 必须全过
- VMware 双机端到端测：CI 跑不了（无网段），由人类测试者在本地跑

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
```

## 4. 性能预算（v0.2 实测）

| 指标 | 实测值 |
|---|---|
| 同 WiFi 端到端首次握手 | < 200ms |
| chat 消息端到端时延 | < 20ms |
| 2 GiB 文件跨 VMware 传输 | ~120s（受磁盘 IO 限制，不是协议） |
| `innerlink.exe` 大小 | 5.1 MB（upx 之前） |
| CI 全量测试 + race | ~5 min |

## 5. 失败模式

| 失败 | 用户感知 | 当前处理 |
|---|---|---|
| UDP 广播被防火墙挡 | 看不到同网段 peer | 文档说开 4747 UDP |
| TCP 4748 被防火墙挡 | 主动 dial 失败 | 文档说开 4748 TCP |
| 设备密钥泄露 | 隐私全无 | README 强调保管 device.key |
| 网络掉线 / 进程被杀 | channel 60s read deadline 后关 | dispatcher log + 上层 UI 重连 |
| 握手超时 | 5s 后报 handshake timeout | 上层 UI 显式提示 |

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
│   └── storage/               (M3) 加密落盘
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
