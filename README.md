# innerlink

> 像 V2Ray 那样做成经典开源软件 —— 纯 Go 国密局域网 IM 核心 + 多端 UI 壳。

## 这玩意能干啥（说人话版）

装上之后，**同 WiFi / 同局域网的两台电脑可以直接聊天 + 发文件，不用装服务器、不用注册账号、不用连公网**。聊天内容和文件全程**国密 SM2/SM3/SM4 端到端加密**。

致敬 IMO 内网通 / 飞秋 / 飞鸽传书 —— 用现代技术栈重新做一遍。

## 愿景

> 全球开发者愿意装、愿意贡献、愿意推荐给别人 —— **不是自用工具**。

长期对标 [V2Ray](https://github.com/v2fly/v2ray-core)：**核心是 Go 库**，永远不是 daemon-first。多端（Windows 桌面 / macOS / Linux / Android / iOS / Web）都直接 import 这个核心，零网络层、零 RPC、零妥协。

## 仓库结构

本仓库 `innerlink-core` 是 **核心层（纯 Go 库）**，按"可能被 1000 个人看"的标准打磨。

```
innerlink-core/
├── cmd/innerlink/             CLI 入口（集成 demo）
├── internal/
│   ├── crypto/                SM2 / SM3 / SM4 / KDF（封装 tjfoc/gmsm）
│   ├── identity/              SM2 身份 + PeerID
│   ├── discovery/             UDP 自动发现
│   ├── transport/             TCP 长连接 + 心跳
│   ├── handshake/             SM2 ECDH 互信
│   ├── protocol/              Envelope 消息协议
│   ├── filetransfer/          分片传输 + SHA-256 校验
│   └── storage/               加密本地存储
├── docs/                      PRD / ARCHITECTURE / TECH
├── .github/workflows/ci.yml   3 平台 CI（ubuntu / windows / macos）
├── go.mod
├── LICENSE                    Apache 2.0
└── README.md
```

## 架构原则（不可妥协的 7 条红线）

1. **核心层不 import GUI 框架** —— Wails / Tauri / Electron 都进不来 `internal/`
2. **`internal/` 跨 module 不可见** —— Go 硬规则 + 架构需要
3. **国密不自己实现** —— 只用 `github.com/tjfoc/gmsm`，绝不手写 SM2/SM3/SM4
4. **协议必须带 `version` 字段** —— 向前兼容
5. **核心层无 CGO** —— 多端移植 / 编译 / 交叉编译零障碍
6. **壳层无业务逻辑** —— 只调核心
7. **`pkg/api.go` 一旦暴露永远向下兼容**

## 安全设计

| 用途 | 算法 | 模式 |
|---|---|---|
| 消息内容 | SM4 | GCM（AEAD） |
| 文件加密 | SM4 | CTR |
| 完整性校验 | SM3 | - |
| 身份签名 / 密钥交换 | SM2 | ECDH |
| 密钥派生 | SM3 + 随机盐 | KDF |
| 本地存储 | SM4 | CBC + 设备密钥 |

**信任模型**：零信任公网、端到端加密、每次会话派生新密钥（PFS）、开源可审计、不留后门。

## 路线图（粗略）

```
核心层      →  国密基础 + P2P 一对一（局域网）   ← 当前在做
桌面 GUI    →  Wails Windows                   ← 核心跑通后
多端        →  macOS / Linux / Android / iOS / Web
协议升级    →  JSON → Protobuf（多端友好）
NAT 穿透    →  让跨网段也能连
```

## 开发

```powershell
# 编译
go build ./...

# 测试（含 race detector）
go test -race -v ./...

# 跑 CLI
go run ./cmd/innerlink
```

## CI

每次 push 自动跑 3 平台（Ubuntu / Windows / macOS）的 build + test + race detector。

## 协议

Apache 2.0 — 见 [LICENSE](./LICENSE)。

## 致谢

- [V2Ray](https://github.com/v2fly/v2ray-core) — 架构灵感（核心 = 库，多端 import）
- [tjfoc/gmsm](https://github.com/tjfoc/gmsm) — 国密标准 Go 实现
- IMO 内网通 / 飞秋 / 飞鸽传书 — 致敬那个"装上就能用"的局域网 IM 时代
