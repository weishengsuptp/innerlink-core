# innerlink-core — 产品定义（PRD）

> 版本：v0.1（2026-06-16）
> 状态：核心协议层已完成，5 个里程碑中 1/5 达成
> 阅读对象：项目作者（潇男）、agent 协作上下文、未来二开者

---

## 1. 一句话

**innerlink-core** 是一套**纯 Go 国密（SM2/SM3/SM4）局域网 P2P 通信核心库**——自动发现、同端加密、断网零依赖，类似飞秋/Feige 的现代重写版，但用中国商用密码标准。

## 2. 目标

| 维度 | 目标 |
|---|---|
| 加密合规 | 全链路国密（SM2 身份 / SM2 ECDH 互信 / SM4-GCM 通道 / SM3 摘要） |
| 跨平台 | Windows / macOS / Linux / ARM（无 CGO 依赖） |
| 易集成 | 任何宿主（CLI / Wails GUI / 嵌入式 / 移动端 Go）只需 import 6 个 internal 包 |
| 局域网自动发现 | 接同 WiFi / 同 NAT 段，开机即用，零配置 |
| 端到端加密 | 不依赖任何 CA / PKI / 第三方服务 |
| 单文件可分发改 exe | 一个 Go binary，所有逻辑就位 |

## 3. 不做的事

- **不做公网穿透**——纯局域网。公网是后续 scope，不在 core 范围。
- **不做用户注册 / 账号体系**——设备即身份，PeerID 派生自 SM2 公钥。
- **不做群聊**——核心只做 1:1 加密通道；群聊是上层应用。
- **不做消息持久化**——上层做（未来 `internal/storage` 是给上层用的工具）。
- **不做 UI**——core 是库，UI 是别的项目的事。

## 4. 架构类比

| 角色 | 类比 | 我们 |
|---|---|---|
| 协议实现 | V2Ray 的 v2ray-core | innerlink-core |
| 协议规范 | VMess / VLESS | innerlink-protocol（私有） |
| 客户端壳 | V2RayN / Qv2ray | 未来某个 Wails 项目 |
| 测试壳 | v2ray 的 `cmd/v2ray` | `cmd/innerlink`（当前 CLI） |

> `cmd/innerlink` 现阶段不是产品，是**集成测试用 REPL**——用来"借壳"调 core 各层做端到端验证，等上层应用出来就退役。

## 5. 5 个里程碑

### M1 · 核心协议 ✅ v0.1 已达成

**6 个 internal 包**全部完成 + 单测 + CI 3 平台绿 + VMware 双机端到端实测通：

| 包 | 职责 |
|---|---|
| `internal/crypto` | SM2 / SM3 / SM4 / KDF（包 gmsm v1.4.1） |
| `internal/identity` | SM2 设备身份 + 16 字节 PeerID + 设备密钥落盘 |
| `internal/discovery` | UDP 广播自动发现（SO_BROADCAST，build-tag 跨平台） |
| `internal/transport` | TCP 长连接 + 4 字节长度帧 + heartbeat |
| `internal/handshake` | 4 帧 SM2 ECDH 互信 + KDF 派生会话密钥 |
| `internal/protocol` | JSON Envelope + SM4-GCM 加密 Channel |

**实测能力**：两台 Windows 10 虚拟机在同 WiFi，启动后 5 秒内互发现 → 互信 → 建通道 → 双向 send / ping 60s+ 不掉线。

### M2 · 文件传输 ⏳ 下一站

`internal/filetransfer`：

- **分片**：默认 256 KB / 片，全文件 SHA-256 + 每片 SM3
- **流控**：基于 protocol Channel 的 Envelope，加 `TypeFileOffer / TypeFileChunk / TypeFileAccept / TypeFileDone / TypeFileAbort` 5 种新类型
- **断点续传**：用 Envelope `MsgID` 作请求 ID；接收方按 `(fileID, offset)` 记录已收切片；中断后发送方从最近未确认 offset 续传
- **UI 钩子**：进度回调 `func(sent, total int64)` 给上层

**不依赖任何外部 storage**——纯协议层。

### M3 · 加密聊天记录 ⏳

`internal/storage`：

- **存储格式**：每行一个 JSON envelope，加 SM4-GCM 加密（GCM key 派生自 device.key 的 SM3 摘要）
- **索引**：`~/.innerlink/messages/<peerID>.log`，只追加不删除
- **查询接口**：`Open(peerID) → Reader`、`Append(peerID, env)`、`PruneBefore(time.Time)`
- **不做**全文搜索、不做去重、不做云同步——上层做

### M4 · 联系人/群元数据 ⏳

`internal/contacts`：

- 每个 peer 的"显示名 + 公钥指纹 + 首次见时间 + 最近活跃时间"——上层的"好友列表"数据源
- PeerID → 联系人记录的反向索引
- 名字可被上层覆写（比如"老王的笔记本"），不强制 SM2 公钥

### M5 · 多端 UI 宿主（独立项目） ⏳

不在 innerlink-core 范围。预计是 Wails（WebView + Go），跨平台。

- v0.1 不会出现 Wails 任何代码
- 任何想集成 core 的项目，import 即可，参考 `cmd/innerlink` 的 wire-up 模式

## 6. 关键合规 / 选型约束（不可妥协）

| 约束 | 原因 | 落地点 |
|---|---|---|
| 国密 SM2/SM3/SM4 必须 | 国内合规 | `internal/crypto` 只包 gmsm |
| 不得引入 CGO | 跨端 / ARM / 移动 | `go.mod` 强约束 |
| core 不得 import UI 框架 | 防止污染 | 架构 linter（手动） |
| `pkg/api.go` 暴露后保持后向兼容 | 集成方依赖 | 锁版本 v0.x → v1.0 |
| Envelope 必须含 `Version` 字段 | 协议演进 | `protocol.Envelope.Version` |
| 不自己造密码学原语 | 现成库比自己写靠谱 | 全部走 gmsm |
| 不引入需要 GCM 联网的依赖 | 国内环境不稳定 | `GOPROXY=https://goproxy.cn,direct` |

## 7. 协议规范概要（v0.1 现状）

完整字段表见 [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md)，此处只列关键。

### 7.1 设备身份
- 64 字节 SM2 公钥（X‖Y）
- **PeerID = SM3(公钥)[:16]** —— 16 字节，hex 显示 32 字符
- 私钥 32 字节（`D`）
- 落盘 40 字节：`[32 bytes D][64 bytes pubX‖pubY]` → `~/.innerlink/device.key`

### 7.2 发现（UDP）
- 端口 **4747**
- 5 秒一次广播
- 报文：`{"v":1, "pid":<16B>, "pub":<64B>, "seq":<u32>, "name":<str>}`
- 收到时跳过自己、按 PeerID 去重、地址变更 / seq 前进时 emit `PeerUpdated`

### 7.3 传输（TCP）
- 端口 **4748**
- 帧格式：`[4 字节大端长度][body ≤ 16 MiB]`
- 15 秒一次心跳（1 字节 0x00 body，协议层透明丢弃）
- 60 秒空闲 read deadline（被 heartbeat 续命）
- 注册表：按 `RemoteAddr().String()` 去重

### 7.4 握手（4 帧）
```
A → B: helloA     (我的公钥, 我的临时公钥, nonceA)
B → A: helloB     (我的公钥, 我的临时公钥, nonceB)
A → B: confirmA   (sig(我的临时私钥, "innerlink-hs-A"|nonceA|nonceB|B 的临时公钥))
B → A: confirmB   (sig(我的临时私钥, "innerlink-hs-B"|nonceA|nonceB|A 的临时公钥))
```
- 会话密钥 = `KDF(SM2-ECDH(A私, A临时私, B公, B临时公) ‖ SM2-ECDH(B私, B临时私, A公, A临时公), "innerlink-handshake-v1"‖nonceA‖nonceB, 16 字节)`
- A 侧用 `gmsm.KeyExchangeA`、B 侧用 `KeyExchangeB`，**角色不可换**

### 7.5 协议层
- 帧结构：`[4B len][12B GCM nonce][ciphertext ‖ 16B GCM tag]`
- 载荷：`{"v":1, "type":"text"|"ping"|"pong", "id":<8B>, "payload":<base64>}`（v0.1 无 AAD，未来用 MsgID 作 AAD）

## 8. 未来路线（v0.2 → v1.0）

| 版本 | 重点 |
|---|---|
| v0.2 | M2 文件传输 + M3 加密落盘 |
| v0.3 | M4 联系人元数据 + 协议 v2（AAD 防重放） |
| v0.4 | 性能 / 内存 profile、大文件压测 |
| v0.5 | API 冻结、文档定稿 |
| v1.0 | tag 切稳定，外部可依赖 |

## 9. 仓库契约

- **模块路径**：`github.com/weishengsuptp/innerlink-core`
- **许可证**：Apache 2.0
- **CI**：GitHub Actions，3 平台 × 编译 + 单测
- **不接受**：CGO 依赖、非国密密码库、UI 框架、SQL 驱动
