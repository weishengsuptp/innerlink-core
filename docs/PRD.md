# innerlink-core 产品需求（PRD）

> 版本：v0.5（2026-06-18）
> 状态：M1 / M2 / M3 / M4 已完成，M5 规划中
> 阅读对象：项目协作者、AI 智能体（Mavis）、测试者

---

## 1. 一句话

**`innerlink-core` 是一个纯 Go 实现的国密（SM2/SM3/SM4）端到端加密 P2P 通信核心库**。同 WiFi / 同 NAT 网段的两台电脑无需注册账号、无需联网，可以直接互发加密聊天和加密文件。

## 2. 设计目标

| 维度 | 目标 |
|---|---|
| 国密合规 | 端到端加密 + 完整性：SM2 ECDH 握手 / SM4-GCM 通信 / SM3 摘要 / SM4-CBC 落盘 |
| 跨平台 | Windows / macOS / Linux / ARM，零 CGO 编译 |
| 易嵌入 | 任何 Go 程序（CLI / 桌面 / 嵌入式 / 服务端）通过 `import "github.com/weishengsuptp/innerlink-core/pkg/node"` 即可构造一个长生命周期 `*node.Node`，调用 `New / Start / SendText / SendFile / ListPeers / SubscribeMessages / History / SetAlias` 等公开 API；底层 12 个 `internal/*` 包仍保持私有，不对外暴露 |
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

### M3 — 加密本地存储 ✅（v0.3，2026-06-17）

`internal/storage/` 完成：SM4-CBC + 设备密钥派生，加密落盘 `chat.enc`（v0.5+ 默认 `<cwd>/.innerlink/chat.enc`）。cmd REPL 新增 `history` 命令（无参显示最近 50 条；带 peer-id-hex 参数则过滤该 peer）。

**设计原则（落地版）**：

- 每条 chat envelope 一个加密 record（in 跟 out 都落盘）
- 帧格式自描述：`[4B BE ctLen][16B IV][N B SM4-CBC ct]`；明文 = JSON `{v, ts, from, to, dir, body, msgID}` + PKCS#7 padding
- 密钥派生：`KDF(SM2_D, "innerlink-storage-v1", 16)` — 改 info 字符串 = 烧旧 history（domain separation）
- fsync 节奏：每 10 条 record 强制 sync 一次（power-loss 最多丢 9 条）；Close 强制 final sync
- ping / pong **不落盘**（v0.1 范围）
- 设备密钥丢失 = history 不可读（feature not bug — 密钥永不下盘）

**实测**（VMware 双机，2026-06-17）：

- 聊 10 条 chat → 退出 → 重启 → `chat log: 10 records loaded` 提示
- `history` 跟 `history <peer-id-hex>` 都正确
- `chat.enc` 文件存在，notepad 打开是密文（符合预期）
- 跟 M2 的 `.incoming/` 目录共存，互不干扰

**测试**：`internal/storage/storage_test.go` 14 个测试全过（wrong-key、并发、Unicode、64 KiB 大 body、version 校验等）。

## 5.1 v0.5 — 统一 cwd 落盘布局 ✅（2026-06-18）

用户反馈 v0.1-v0.4 把状态文件散落在 `~/.innerlink/`、`~/Downloads/innerlink/`、exe 同目录等多个位置，测试和清理都不方便。v0.5 引入 `internal/paths` 包做单一配置源，所有路径都从 `cwd` 派生：

```
<启动时的当前目录>/
├── .innerlink/         ← 内部状态（隐藏目录）
│   ├── device.key      ← SM2 私钥（40 字节二进制）
│   ├── aliases.json    ← M4 别名表
│   └── chat.enc        ← M3 加密聊天记录
├── received/           ← 收到的文件（M2）
└── innerlink.log       ← 运行日志
```

**好处**：
- 整个 innerlink 状态可以装在一个文件夹里：复制 = 备份，`rm -rf <test-dir>` = 完全卸载
- 不污染 `~/Downloads`、`~/.config` 等用户全局目录
- 多开测试零串扰：每个测试 `t.TempDir()` 跑一份独立 instance

**灵活 override**（v0.5+ CLI flag）：
- `-data-dir <path>` 改 `.innerlink/` 位置
- `-save-dir <path>` 改 `received/` 位置
- `-device-key <path>` 单独指定密钥文件
- `-log-file <path>` 单独指定日志文件

**未来扩展点**（不破坏 API）：
- 读 YAML/JSON config 文件：在 `paths.Overrides` 加 `LoadFile(path) error` 即可
- 走 XDG / AppData：在 `paths.NewLayout` 里加平台检测分支，单点改

**v0.1 明确不做的**（PRD 出 v0.3 后才提的、避免 scope creep）：

- 90 天自动 rotate
- chat 全文搜索 / 导出
- ping / pong 落盘
- 文件附件落盘
- mlock'd key material
- per-peer 独立文件

### M4 — 关系与别名 ✅（v0.4，2026-06-17）

`internal/alias` 完成：peer-id → 人类可读名字的映射，存 `~/.innerlink/aliases.json`（与 device.key 同目录）。cmd REPL 新增：

- `alias <name> <peer-id-hex>` — 给 peer 起名字
- `alias list` — 列所有别名
- `unalias <name-or-peer-id>` — 删别名
- `peers` — 列当前所有已知 peer（含未命名），按最后活跃时间倒序

`send` / `sendfile` / `ping` / `history` 第一个参数**同时支持 32 字符 hex 跟别名**。未知的引用会清晰报错（不会静默发送失败）。

**v0.1 明确不做的**（留 M5 之前）：

- 协议 v2（AAD / 重放窗口）
- group alias
- 通知 / 声音
- 别名 import/export

### M5 — 协议 v2 + API 冻结（规划中）

- 协议 v2：MsgID 做 AAD，每个 Channel 一个 ring buffer 防重放
- 第三方密码学审计
- 邀请第三方做密码学审计

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
- **CI**：GitHub Actions，3 平台 (Ubuntu / Windows / macOS) build + test
- **依赖**：仅 `github.com/tjfoc/gmsm` + `golang.org/x/sys`（gmsm 的间接依赖），**无 CGO、无 GUI 框架、无 SQL 驱动**
- **测试规模**（v0.3 末）：9 个 internal 包，110+ 个测试，全过
- **AI 协作**：本仓库由 [Mavis](https://github.com/MiniMax-AI)（minimax code 智能体）配合人类测试者协作开发，commit message 都是 Mavis 写的口气。

## 7. 下一步

1. 改进多 peer 同步：当前 channelRegistry 已经按 peerID 索引，但要测一下 N peer 同时活跃的稳定性
2. M4 关系层：peer 别名 + 协议 v2 草案
3. M5 API 冻结 + 第三方密码学审计
