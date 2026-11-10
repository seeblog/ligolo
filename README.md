# relaykit

一个轻量的反向 TLS 隧道中继（Go 实现，无 CGO 依赖，单二进制）。

> 本项目 fork 自 Ligolo（原版 SOCKS 隧道模型），经过大幅重构与加固，着重解决
> 原版实现中一系列可被流量分析与静态检测识别的特征问题。

## 架构

```
[使用方] --SOCKS5--> [ligolos 中继服务] <--TLS/yamux-- [ligoloc 客户端] --TCP--> [目标网络]
                     反向连接：客户端主动外连，无需暴露入站端口
```

- **ligolos**（服务端）：监听 TLS 端口（默认 0.0.0.0:443），本地提供 SOCKS5 入口（默认 127.0.0.1:1080）；
- **ligoloc**（客户端）：在目标主机上运行，反向连出到服务端，将隧道流量落地为 SOCKS5 或固定端口转发；无特权要求。

## 快速使用

```shell
# 1. 服务端：自动生成证书并打印指纹
./ligolos -l 0.0.0.0:443 -p 127.0.0.1:1080
# Generated self-signed certificate (CN=...). SHA-256 fingerprint: <fp>
# Pass this fingerprint to the client with -fingerprint <fp>

# 2. 客户端：反向连接（TOFU 指纹校验）
./ligoloc -s server.example.com:443 -fingerprint <fp>

# 3. 使用方经 SOCKS5 访问目标网络
curl --proxy socks5h://127.0.0.1:1080 http://10.0.0.5:8080
```

### 服务端参数（ligolos）

| 参数 | 默认 | 说明 |
|---|---|---|
| `-l` | `0.0.0.0:443` | TLS 监听地址（客户端回连地址） |
| `-p` | `127.0.0.1:1080` | 本地 SOCKS5 入口 |
| `-cert` / `-key` | 空 | 自定义证书（不传则每次启动自动生成，指纹随之变化） |
| `-cert-domain` | 随机 | 自动生成证书的 CN |

### 客户端参数（ligoloc）

| 参数 | 默认 | 说明 |
|---|---|---|
| `-s` | 必填 | 服务端 ip:port |
| `-fingerprint` | 空 | 服务端证书 SHA-256 指纹（TOFU 校验，强烈建议提供） |
| `-t` | 空 | 固定目标转发（不填则为 SOCKS5 模式） |
| `-proxy` | 空 | 出网上游代理（http:// 或 socks5://，支持认证） |
| `-profile` | `chrome` | 伪装身份：`chrome` / `firefox` / `safari` |

## 构建与开发

依赖 Go ≥ 1.24。标准流程（字符串混淆 → 编译 → 元数据剥离）：

```shell
make build        # 当前平台
make build-linux  # linux/amd64 交叉编译
```

### 源码结构

```
lib.go                证书生成/指纹、随机工具、退避算法、客户端身份(profile)
noise.go              噪声流协议、心跳抑制、活性看门狗、yamux 配置
recordShaper.go       TLS 记录随机切分
obfuscated_strings.go 【生成物】字符串密文表（由 _strgen 生成，勿手编）
strings.manifest      明文字符串清单（改文案在这里改）
_strgen/              字符串混淆生成器（go run ./_strgen 换密钥）
_strip/               buildinfo/模块路径剥离器
cmd/ligoloc/          客户端
cmd/ligolos/          服务端
```

修改输出文案：编辑 `strings.manifest` → `go run ./_strgen` → 重新 `make build`。

## 加固设计（相对原版 Ligolo）

### 流量行为层

| 原版特征 | 本项目处理 |
|---|---|
| yamux 固定 30s 心跳（周期性双向配对包） | 关闭内置 keepalive，改为应用层噪声流：随机 60–180s 间隔、空闲 >90s 才发、载荷 64–4096B 随机长度；有业务流量时完全静默 |
| 握手后服务端立即 Ping（固定"下行先行"模板） | 已移除；建连后随机延迟 200ms–2s 再首帧 |
| 心跳密文恒定 29 字节 | 噪声帧长度连续分布 + TLS 记录随机切分（recordShaper） |
| 固定 10s 重连节奏 | 指数退避（1s→300s 封顶，±40% 抖动） |
| Go 标准 TLS ClientHello（JA3/JA4 指纹） | uTLS 模拟真实浏览器指纹（chrome/firefox/safari 三档，进程内恒定） |
| 直连 IP 时无 SNI | 按 profile 填充常见伪装域名 |
| 全局共享硬编码证书（固定 IOC） | 每次部署独立生成证书（ECDSA P-256，随机 CN），或加载自定义证书 |
| `InsecureSkipVerify` 裸奔 | TOFU 指纹固定校验（`-fingerprint`），错误指纹直接拒绝握手 |
| keepalive 关闭后无死亡检测 | 10 分钟无活动看门狗强制回收会话 |

### 二进制静态层

| 特征 | 处理 |
|---|---|
| 模块路径/依赖清单/VCS 溯源（buildinfo） | `-buildvcs=false` + `_strip` 构建后剥离，`go version -m` 不可读；路径中性化（等长替换，不破坏 pclntab） |
| 自有字符串明文（UA/SNI/日志/帮助文案） | 编译期 XOR 密文化（`strings.manifest` + `_strgen`），运行时原样输出；重跑 `_strgen` 即换密钥 |
| UA 与 TLS 指纹不一致风险 | profile 体系将 HelloID/UA/SNI 三要素绑定，单点选择 |

### 已知残留（有意保留或暂不处理）

- 依赖库（yamux/go-socks5/utls）内部字符串与包名仍在二进制中——这些库被大量良性软件使用，单独不构成定性规则；
- SOCKS 业务流量形态（被代理协议的包长/时序统计）属原理性特征；
- 运行期明文存在于进程内存与 stderr 输出（"原样输出"的设计取舍）。

## 免责声明

本项目仅供安全研究与授权测试使用。使用者需自行确保遵守当地法律法规。
