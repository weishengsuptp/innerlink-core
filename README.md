# innerlink

**同 WiFi / 同网段两台电脑直接发加密聊天 + 文件，无需注册账号、无需联网。**

底层是 **端到端加密的 P2P 协议核心库（纯 Go）**，M1（chat）+ M2（sendfile）+ M3（加密本地落盘）已完成。

## 用了啥

| | |
|---|---|
| 语言 | Go 1.22，**零 CGO**（Windows / macOS / Linux / ARM 都能直接编译） |
| 唯一外部依赖 | [`github.com/tjfoc/gmsm`](https://github.com/tjfoc/gmsm) v1.4.1 — 国密 SM2/SM3/SM4 标准 Go 实现 |
| 协议 | SM2 ECDH 握手 → 会话密钥 → SM4-GCM 加密每条消息 / 文件分片 → SM3 校验 |
| 端到端 | 无 CA / 无 PKI / 无服务器，每台设备有自己的 SM2 长期密钥对 |
| 许可证 | Apache 2.0 |

## 做了啥

v0.1 + v0.2 + v0.3 已经能跑通（VMware 双机端到端验证过）：

- **M1 加密 chat**：1:1 实时聊天，自动发现同网段 peer，每条消息端到端加密
- **M2 文件传输**：分片（256 KiB/chunk）+ 每片 SHA-256 + 全文件 SHA-256 校验，2 GiB 跨 VMware 实测 2 分钟
- **M3 加密本地落盘**：每条 chat envelope 加密写到 `chat.enc`（SM4-CBC，密钥 = KDF(设备私钥)），重启后 `history` 命令可查全部历史
- **3 平台 CI**：GitHub Actions 上 Ubuntu / Windows / macOS 自动 build + test
- **日志分级**：info 模式不刷屏，debug 模式记录每个 chunk 的 writeAt 时长
- **110+ 个测试**（unit + dispatcher e2e + logx e2e + storage 14 个），全部通过

## 仓库结构

```
innerlink-core/
├── cmd/innerlink/         CLI 入口（M1+M2 集成 demo，不是产品）
├── internal/
│   ├── crypto/            SM2 / SM3 / SM4 / KDF（封装 tjfoc/gmsm）
│   ├── identity/          SM2 密钥 + PeerID
│   ├── discovery/         UDP 自动发现
│   ├── transport/         TCP 帧格式 + 心跳
│   ├── handshake/         SM2 ECDH 4 帧握手
│   ├── protocol/          Envelope + Channel（上层 API）
│   ├── filetransfer/      分片发送 + 完整性校验
│   ├── logx/              log 级别 + 文件 sink
│   └── storage/           M3 加密落盘 chat log（SM4-CBC + 设备密钥）
├── docs/                  PRD + ARCHITECTURE
├── .github/workflows/     3 平台 CI
└── AGENTS.md              协议约束 + 踩过的坑
```

## 现阶段

- **已完成**：M1 加密 chat、M2 文件传输、M3 加密本地落盘（v0.3）
- **下阶段（M4）**：peer 别名、协议 v2 草案（AAD、重放窗口）、property-based tests
- **规划中**：多 peer 同步（channelRegistry 已按 peerID 索引，要测 N peer 同时活跃的稳定性）、M5 API 冻结 + 第三方密码学审计
- **不在 core 范围**：UI（计划另起一个仓库，用 Wails / Tauri 之类直接 import 本 core）

## 用法速览

`cmd/innerlink` 是 CLI demo，跟同网段另一台机器自动发现并握手，然后：

```
> send <peer-id-hex> 你好             # 发 chat
> sendfile <peer-id-hex> <file>      # 发文件
> history                            # 看最近 50 条 chat（重启后历史还在）
> history <peer-id-hex>              # 看跟某 peer 的 chat
> peers                              # 列出当前可见的 peer
> ping <peer-id-hex>                 # 心跳
> help                               # 列所有命令
```

## 构建 & 测试

```bash
# 构建
go build ./...

# 测试（CI 上 Ubuntu 跑 race detector；本机 Windows 因 CGO=0 跑不了 race）
go test ./...

# 跑 CLI
go run ./cmd/innerlink
```

## 关于作者

这个 core 库基本是 **Mavis**（minimax code 的 AI 智能体）从零开始写的 —— 协议设计、代码实现、VMware 复现的真凶追查、CI 调试，全是它干的。我是用户，本质就是个负责在 VMware 里双机端到端测试 + 提反馈的工具人。写出来的 PR / commit message 也基本都是 Mavis 的口气。

如果发现 bug，**欢迎开 issue** —— 但事先说明：Mavis 看到 issue 会自己来 debug，**我本人不一定能看懂**。直接贴日志 / 复现步骤，**别问我，问它**。

## 致谢

- [**tjfoc/gmsm**](https://github.com/tjfoc/gmsm) — 唯一非 Go stdlib 依赖，国密 SM2/SM3/SM4 的标准 Go 实现
- [**minimax code**](https://github.com/MiniMax-AI) — Mavis 智能体的老家，给了它在 sandbox 里随便 build / 跑测试 / 改我代码的能力
