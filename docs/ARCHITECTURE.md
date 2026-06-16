# innerlink-core — 架构与设计

> 配套 [`docs/PRD.md`](./PRD.md)。本文讲**怎么搭起来的**——分层、接口、关键设计决策、未来扩展点。

---

## 1. 分层依赖图

```
┌──────────────────────────────────────────────────────┐
│                cmd/innerlink                         │  ← 集成测试用 REPL
│         (CLI demo — 不是产品)                          │
└──────────────────────────────────────────────────────┘
                       ↓ 调
┌──────────────────────────────────────────────────────┐
│              internal/protocol                       │  ← 上层 API
│   Envelope / Channel / Send/Recv text/ping/pong     │
└──────────────────────────────────────────────────────┘
         ↓                                  ↓
┌──────────────────────┐         ┌──────────────────────┐
│  internal/handshake  │         │  internal/transport  │
│  SM2 ECDH + KDF     │ ←────  │  TCP frame + HB      │
└──────────────────────┘         └──────────────────────┘
         ↓                                  ↓
         └──────────┐         ┌────────────┘
                    ↓         ↓
            ┌──────────────────────┐
            │  internal/identity   │
            │  SM2 + PeerID 落盘   │
            └──────────────────────┘
                       ↓
            ┌──────────────────────┐
            │  internal/crypto     │
            │  SM2/SM3/SM4/KDF     │
            └──────────────────────┘
                       ↓
            ┌──────────────────────┐
            │  github.com/tjfoc/   │
            │  gmsm  v1.4.1        │
            └──────────────────────┘

   ┌──────────────────────┐
   │  internal/discovery  │  ← 独立侧枝（不进加密栈）
   │  UDP 广播自动发现     │
   └──────────────────────┘
                       ↓ 调
            ┌──────────────────────┐
            │  internal/identity   │
            └──────────────────────┘
```

**不可逾越的边**：
- `internal/X` 不得 import `internal/Y` 当 `Y` 在 `X` 上方（环）
- `internal/*` 不得 import `cmd/*`
- `internal/*` 不得 import 任何 GUI / ORM / SQL 驱动
- gmsm 是唯一允许的密码学原语源

## 2. 各包接口契约

### 2.1 `internal/crypto` — 国密原语

零依赖 gmsm 的薄包装。**不发明**——`gmsm` 啥用，我们就提供啥用。

| 函数 | 用途 | 返回 |
|---|---|---|
| `SM2Generate()` | 生成新 SM2 密钥对 | `(priv, pub, err)` |
| `SM2Sign(priv, msg)` | 签名 | `(sig, err)` |
| `SM2Verify(pub, msg, sig)` | 验签 | `bool, err` |
| `SM3Sum(data)` | SM3 摘要 | `[32]byte` |
| `SM3Hash()` | 流式 Hash 接口 | `hash.Hash` |
| `SM4EncryptGCM/DecryptGCM` | AEAD（推荐） | `(out, err)` |
| `SM4EncryptCTR/DecryptCTR` | 流加密 | `(out, err)` |
| `SM4EncryptCBC/DecryptCBC` | 块模式（含自实现 PKCS#7 padding） | `(out, err)` |
| `KDF(secret, info, outLen)` | SM3-based counter-mode KDF | `[]byte` |
| `NewNonce(n)` / `NewNonceFill(b)` | CSPRNG 随机 | `(n, err)` |

**所有 `[]byte` 入参必须非 nil 时长合法**，包内不重做防御（边界在调用方）。

### 2.2 `internal/identity` — 设备身份

**核心类型**：

```go
type Identity struct {
    Private *sm2.PrivateKey
    PubKey  []byte  // 64 字节 X‖Y
}

func (id *Identity) PeerID() []byte     // SM3(pubkey)[:16]
func (id *Identity) PeerIDHex() string  // 32 字符小写 hex
```

**落盘格式**（`~/.innerlink/device.key`，40 字节）：
```
[4 bytes magic "ILK1"][32 bytes priv.D][64 bytes pub.X‖pub.Y]
```
- magic 防误读别的二进制
- **不加密**——私钥保护由 OS 文件权限承担（0600）
- 未来可加 SM4 加密 wrap（设备密码派生 KDF），不在 v0.1 scope

**API**：
- `Generate()` — 新建
- `Load(path)` — 加载
- `LoadOrCreate(path) (id, created, err)` — 集成用
- `Save(path) error` — Identity 自带
- `PrivateKeyFromAny(*Identity or *sm2.PrivateKey) → *sm2.PrivateKey` — 类型适配
- `PublicKeyFromBytes(b) (*sm2.PublicKey, err)` — 反序列化 + 验在曲线上
- `EqualPeerIDs(a, b) bool` — 恒定时间比较

### 2.3 `internal/discovery` — UDP 广播

**核心类型**：
```go
type Peer struct {
    PeerID    []byte
    PublicKey []byte
    Name      string
    Addr      *net.UDPAddr
    LastSeen  time.Time
    Seq       uint32
}

type Announcer struct{ ... }

type PeerEvent struct {
    Type   PeerEventType  // PeerAdded / PeerUpdated / PeerRemoved
    PeerID []byte
    Peer   *Peer
}
```

**协议**：
- UDP 端口 4747
- 5 秒一次广播
- 报文 JSON：`{"v":1, "pid":<hex16>, "pub":<hex64>, "seq":<u32>, "name":<str>}`
- **跳过自己**（PeerID == self）
- **peer table GC**：15 秒未刷新的 peer 触发 `PeerRemoved`

**平台分支**：
- `bind_unix.go` — `golang.org/x/sys/unix` 设 `SO_BROADCAST`
- `bind_windows.go` + `sockopt_windows.go` — `syscall.SetsockoptInt(SO_BROADCAST = 0x0020)`
- `subnet.go` — 跨子网定向广播地址计算

**Device 接口**（解耦 ID 类型）：
```go
type Device interface {
    PeerID() []byte
    PublicKeyRaw() []byte
}
```
`*identity.Identity` 已实现。

### 2.4 `internal/transport` — TCP 长连接

**核心类型**：
```go
type Frame struct{ Body []byte }

type Conn struct { ... }  // 不可导出，构造靠 Transport
func (c *Conn) Send(body []byte) error
func (c *Conn) Recv() (Frame, error)  // 透明吞心跳
func (c *Conn) Close() error
func (c *Conn) RemoteAddr() net.Addr

type Transport struct { ... }
func NewTransport() *Transport
func (t *Transport) Listen() error
func (t *Transport) Run(ctx) error
func (t *Transport) Dial(ctx, addr) (*Conn, error)  // 注册进 heartbeat
func (t *Transport) Inbounds() <-chan *Conn
func (t *Transport) ActiveConns() []*Conn
func (t *Transport) Close()

func DialStandalone(ctx, addr) (*Conn, error)  // 不注册，仅供测试
```

**帧格式**：`[4 字节大端 len BE][body]`
- MaxFrameSize = 16 MiB
- 心跳 = 1 字节 0x00 body（**Conn.Recv 自动跳过**）
- read deadline 60s，**每次成功 Recv 重设**

**registry**：按 `RemoteAddr().String()` 去重，重复 `Dial` 同一远端返回已注册 conn。

### 2.5 `internal/handshake` — SM2 ECDH 互信

**核心类型**：
```go
type Session struct {
    SessionKey   []byte  // 16 字节
    RemotePeerID []byte  // 16 字节
    RemotePubKey []byte  // 64 字节 X‖Y
}

type Identity interface {
    Private() *sm2.PrivateKey
    Public()  []byte  // 64 字节
    PeerID()  []byte  // 16 字节
}

func RunAsInitiator(ctx, id, conn) (*Session, error)
func RunAsResponder(ctx, id, conn) (*Session, error)
```

**4 帧协议**：
```
1. A→B: helloA  { myPub, myEphPub, nonceA }
2. B→A: helloB  { myPub, myEphPub, nonceB }
3. A→B: confA   { sig(ephPrivA, "innerlink-hs-A"|nonceA|nonceB|ephPubB) }
4. B→A: confB   { sig(ephPrivB, "innerlink-hs-B"|nonceA|nonceB|ephPubA) }
```

**会话密钥派生**：
```
shared = ECDH(privA, ephPrivA, pubB, ephPubB) ‖ ECDH(privB, ephPrivB, pubA, ephPubA)
       // 两侧顺序不同但结果相同（gmsm KeyExchangeA/B 内保证）
key = KDF(shared, "innerlink-handshake-v1"||nonceA||nonceB, 16)
```

**关键易错点**（已踩）：
- A 侧用 `KeyExchangeA`，B 侧用 `KeyExchangeB`——**不能两边都用 A**
- 两侧 `nonceA`/`nonceB` 必须**用对方发的**，不能自造
- 临时密钥对每握手重新生成
- 5 秒握手超时（应用层 context）

### 2.6 `internal/protocol` — 加密 Channel

**核心类型**：
```go
type MsgType string
const (
    TypeText MsgType = "text"
    TypePing MsgType = "ping"
    TypePong MsgType = "pong"
    // 未来：TypeFileOffer / TypeFileChunk / TypeFileAccept / ...
)

type Envelope struct {
    Version int     // 当前 1
    Type    MsgType
    ID      string  // 8 字节 hex
    Payload []byte  // base64 自动 marshal
}

type Channel struct { ... }
func NewChannel(conn *transport.Conn, session *handshake.Session) (*Channel, error)
func (c *Channel) Send(ctx, env Envelope) error
func (c *Channel) Recv(ctx) (Envelope, error)
func (c *Channel) SendText(ctx, s string) error
func (c *Channel) SendPing(ctx) error
func (c *Channel) Close() error
```

**帧结构**：
```
[4B len BE][12B GCM nonce][SM4-GCM(plaintext)]   // ciphertext 含 16B tag
```

**v0.1 限制**：
- 无 AAD（v0.2 计划用 Envelope.ID 作 AAD，MsgID 先于密文发送）
- 无重放窗口
- 无重连——应用层做

**不做的**（v0.1）：
- 不做 NACK / 可靠传输——TCP 已可靠
- 不做流量控制——`internal/transport` MaxFrameSize = 16 MiB
- 不做多路复用——一对 peer 一个 channel

## 3. 关键设计决策

### 3.1 PeerID = SM3(公钥)[:16]，不用 IP

- **IP 不行**：DHCP 重连、WiFi 漫游、VPN 切换都会变
- **公钥太长**：64 字节做主键太重
- **SM3 截断是安全 trade-off**：碰撞概率 2⁻⁶⁴，10 亿设备规模下生日攻击大约 2⁻¹⁵——可接受
- **16 字节 hex = 32 字符**，命令行 / 日志 / 短链都好读

### 3.2 gmsm v1.4.1，不自己写

- 国密 4 个原语（SM2/SM3/SM4/KDF）有 gmsm 这种**有国密局测试向量背书**的实现
- 自己写 = 必须重做 KAT 测 = 永远赶不上审计 = 长期维护炸弹
- gmsm v1.4.1 已知 bug 我们用 workaround 绕开了：
  - `Sm4Cbc` 维护全局 IV（issue #199 / #220）→ 改用 `sm4.NewCipher` + stdlib `cipher.NewCBCEncrypter`
  - PKCS#7 padding 不在 stdlib → 自己实现（**PKCS#7 不是密码学原语**，是字节填充规范，stdlib 故意不提供）
  - `sm3.Sum` 的 `Write` 后行为反直觉（issue #69）→ 只用 `Sum(nil)` + 重新建 Hash

### 3.3 Envelope JSON 不用 protobuf

- **JSON 够用**：v0.1 协议体小（< 1 KiB），可读性 > 性能
- **proto 的 5 倍优势**（< 200 字节消息省 80 字节）在 IM 场景下无意义
- v0.2 测出瓶颈再换不迟

### 3.4 心跳帧 = 1 字节 0x00，协议层透明吞

- 0 字节 frame 撞到 `protocol.Channel` 的"短帧判定"会误关 channel（**已踩**）
- 不能走 TCP `SetKeepAlive`——那只是 OS 层探活，应用层看不见，不能 Refresh 自己的 read deadline
- 1 字节 magic + Recv() 循环跳过 = 协议层完全无感

### 3.5 Dial 必须走 `Transport.Dial`，不是 `DialStandalone`

- 走 Standalone = conn **不在 `t.conns` 里** = heartbeat loop 看不见 = 60s 后 read deadline 触发 = i/o timeout（**已踩**）
- `DialStandalone` 保留仅给测试 / 未来的"外部到进程"桥
- CLI 集成必须 `tr.Dial(ctx, addr)`

### 3.6 handshake 5 秒超时

- 局域网 < 100ms，5s 顶天了——再长就是死锁
- context 在 Transport 链路 / handshake 阶段都尊重

### 3.7 文件传输**不**进 core 协议层 v0.1

- 文件 = 流式分片 + 进度 + 续传 = 跟 chat 完全不同的事件语义
- 套到现有 Channel = 把 protocol.Channel 撑成"全能管家"，API 复杂度爆炸
- v0.2 起开 `internal/filetransfer`，它**依赖** protocol 但不污染 protocol
- 新 Envelope Type（`TypeFileOffer` 等）由 protocol 留接口，filetransfer 实现

### 3.8 cmd/innerlink 是测试壳，**不是产品**

- 它能用 = core 各层通了
- 它被换 = 上层应用出现（CLI / Wails / 嵌入式）
- 不要把业务逻辑（消息持久化、联系人列表、UI 状态）写进 `cmd/innerlink`
- 一旦发现 cmd 在堆业务，立刻拆包

## 4. 测试策略

| 层 | 测试类型 | 数量 |
|---|---|---|
| crypto | 单元 + 已知答案测试（KAT, SM3 GBT 32905-2016 vectors）| 24 |
| identity | 单元 + round-trip + 错误注入 | 18 |
| discovery | 单元 + 双 announcer loopback 集成 | 15 |
| transport | 单元 + 并发 + 帧边界 | 16 |
| handshake | 单元 + KAT 模式 | 3 |
| protocol | 单元 + 双向 + 篡改检测 + 帧长度边界 | 10 |
| **合计** | | **86** |

- **每层独立能 mock 上一层**（interface）
- **无时间相关 flaky test**：所有 timeout 用 `time.After` + buffered channel，可控
- **集成测试靠真 VMware**：CI 不跑（依赖网络），开发者手测

## 5. 性能预算（v0.1 实测）

- 握手延迟（局域网，2 跳）：**< 100ms**
- 通道建立到 first message：**< 1s**（含 5s 一次 announce 周期，最坏 5s 抖动）
- 单消息延迟：**< 10ms**
- 心跳开销：每 15s 5 字节/conn（一个局域网 5 个设备 = 5×4=20 字节/15s，可忽略）
- 二进制大小：`innerlink.exe` 4.7 MB（无 UPX，无 strip -s -w）
- 启动时间：**< 50ms**（无依赖解包，无插件加载）

## 6. 失败模式

| 失败 | 用户感知 | 我们做 |
|---|---|---|
| UDP 广播被防火墙挡 | 看不到对端 | 文档：放行 4747 UDP |
| TCP 4748 被防火墙挡 | 看到对端但 dial 失败 | 文档：放行 4748 TCP |
| 跨子网 / 跨 VLAN | UDP 广播不可达 | 文档：要求同网段；预留"手动 IP 配对"接口（v0.2） |
| 设备密钥被偷 | 冒名顶替 | 物理安全兜底；不存公网 |
| 握手超时 | channel 没建起来 | 5s 超时；上层 UI 显示"连接中" |
| 心跳失败 / 网络抖动 | channel 60s 后掉 | `internal/transport` 检测 + 触发重连（v0.2） |

## 7. 仓库布局（截至 v0.1）

```
D:\innerlink
├── cmd/innerlink/             CLI 集成测试 REPL
│   ├── main.go                wire-up + REPL
│   └── helpers.go             hex/hostname 等小工具
├── internal/
│   ├── crypto/                国密 4 件套
│   ├── identity/              设备身份
│   ├── discovery/             UDP 广播（build-tag 跨平台）
│   ├── transport/             TCP 帧 + heartbeat
│   ├── handshake/             SM2 ECDH 互信
│   └── protocol/              Envelope + Channel
├── docs/
│   ├── PRD.md                 ← 产品定义（5 里程碑）
│   └── ARCHITECTURE.md        ← 本文件
├── .github/workflows/ci.yml   CI（3 平台）
├── AGENTS.md                  协作约束（已踩的坑）
├── LICENSE                    Apache 2.0
├── README.md                  入口
└── go.mod / go.sum            依赖（gmsm + x/sys）
```

## 8. 未来扩展点

| 想加的 | 加在哪 | 难易 |
|---|---|---|
| 多端消息同步 | `internal/storage` + 上层 | 中 |
| 大文件 P2P 传输 | `internal/filetransfer` | 中 |
| 群聊 | `internal/multiplex`（v0.3+） | 高 |
| 公网穿透 | `internal/relay`（v0.4+） | 高 |
| 移动端 (iOS/Android) | gomobile bind core | 中 |
| WebAssembly | core 必须先小、纯 Go 已有基础 | 中 |
| 协议 v2（AAD / 重放窗口） | `protocol.Envelope.Version=2` | 低 |
| TLS 1.3 fallback | 暂不（国密优先） | — |
