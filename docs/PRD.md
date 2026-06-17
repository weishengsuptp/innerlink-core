# innerlink-core 产品需求（PRD）

> 版本：v0.2（2026-06-17）
> 状态：M1 / M2 已完成，M3 准备中
> 阅读对象：项目协作者、AI 智能体（Mavis）、测试者

---

## 1. 一句话

**`innerlink-core` 是一个纯 Go 实现的国密（SM2/SM3/SM4）端到端加密 P2P 通信核心库**。同 WiFi / 同 NAT 网段的两台电脑无需注册账号、无需联网，可以直接互发加密聊天和加密文件。

## 2. 设计目标

| 维度 | 目标 |
|---|---|
| 国密合规 | 端到端加密 + 完整性：SM2 ECDH 握手 / SM4-GCM 通信 / SM3 摘要 / SM4-CBC 落盘 |
| 跨平台 | Windows / macOS / Linux / ARM，零 CGO 编译 |
| 易嵌入 | 任何 Go 程序（CLI / 桌面 / 嵌入式 / 服务端）只要 import 这 7 个 internal 包就能用 |
| 零账号 | 无 CA / 无 PKI / 无中心服务器；每台设备一把 SM2 长期密钥对，PeerID = SM3(公钥)[:16] |
| 单二进制 | `innerlink.exe` 一个文件就包含全部协议逻辑，可直接运行也可被 import |

## 3. 范围

**在范围内（v0.x 都会做的）**：

- 端到端加密 1:1 通信（chat + sendfile）
- 加密本地落盘
- 跨平台 Go binary

**不在 core 范围（明确排除的）**：

- NAT 穿透 / 中继 / 跨网段 — 留给上层应用
- 用户账号 / 好友关系 — 无账号；上层应用可以基于 PeerID 自行扩展
- 群组通信 — v0.x 只 1:1
- UI — core 是库，UI 是另一个仓库
- 协议 v2 / AAD / 重放窗口 — v0.3+ 再考虑

## 4. 五个里程碑

### M1 — 加密 chat 协议 ✅（v0.1，2026-06-15）

7 个 internal 包全部跑通 + 3 平台 CI + VMware 双机端到端测试通过。

### M2 — 文件传输 ✅（v0.2，2026-06-17）

分片（256 KiB/chunk）+ 每片 SHA-256 + 全文件 SHA-256 校验 + cmd dispatcher 集成。VMware 双机 2 GiB 文件 2 分钟传输完成，期间双方仍可互发聊天。

### M3 — 加密本地存储（准备中）

`internal/storage/` 计划：SM4-CBC + 设备密钥加密 chat log 落盘，默认存 `~/Downloads/innerlink/`。设计原则：

- 每条消息一个 record，JSON 索引 + 加密 payload
- ping / pong 不落盘
- 默认保存 90 天，可调

### M4 — 关系与单元测试（规划中）

- PeerID 别名（"给这台 peer 起个名字"）
- 协议 v2 草案（AAD、重放窗口）
- 全链路 property-based tests

### M5 — API 稳定 + 外部审计（规划中）

- 协议冻结、API 冻结
- 邀请第三方做密码学审计

## 5. 协议规范（v0.1 / v0.2 已实现）

详见 [ARCHITECTURE.md](./ARCHITECTURE.md)。简短版：

| 层 | 算法 | 模式 |
|---|---|---|
| 消息加密 | SM4 | GCM（AEAD） |
| 文件分片 | SM4 | CTR（流模式，每片重新生成 nonce） |
| 完整性 | SM3 | - |
| 签名 / 密钥交换 | SM2 | ECDH |
| 密钥派生 | SM3 + 共享秘密 | KDF |
| 本地存储 | SM4 | CBC + 设备密钥（M3） |

**密钥模型**：每次握手产生新的临时密钥对，会话密钥 = KDF(ECDH 共享秘密, salt, 16 B)。无 PFS 妥协点。

## 6. 仓库约定

- **模块路径**：`github.com/weishengsuptp/innerlink-core`
- **许可证**：Apache 2.0
- **CI**：GitHub Actions，3 平台 (Ubuntu / Windows / macOS) build + test + race detector
- **依赖**：仅 `github.com/tjfoc/gmsm` + `golang.org/x/sys`（gmsm 的间接依赖），**无 CGO、无 GUI 框架、无 SQL 驱动**
- **AI 协作**：本仓库由 [Mavis](https://github.com/MiniMax-AI)（minimax code 智能体）配合人类测试者协作开发，commit message 都是 Mavis 写的口气。

## 7. 下一步

1. 实现 M3 storage（`internal/storage/`，SM4-CBC + 设备密钥）
2. 改进多 peer 同步：当前 channelRegistry 已经按 peerID 索引，但要测一下 N peer 同时活跃的稳定性
3. v0.3 协议：加 AAD（用 MsgID 做 AAD），加重放窗口（每 Channel 一个 ring buffer）
