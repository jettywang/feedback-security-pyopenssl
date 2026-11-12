# pyOpenSSL 会话缓存的跨后端身份边界评审

环境：pyOpenSSL 26.4.0，链接 OpenSSL 4.0.3（stdlib `ssl` 报 OpenSSL 3.5.3，
cryptography 绑定实际加载 4.0.3），Python 3.12，全程内存 `MemoryBIO`，无网络、无端口。

所有结论由 `resume_experiment.py` 实测产出，恢复判定不依赖“握手没抛异常”，而是同时要求：

- `SSL_session_reused(ssl) == 1`（OpenSSL 权威标志，经 cryptography 底层绑定调用）；
- TLS 1.2 额外要求两次连接 master key 一致（pyOpenSSL 测试套件同款代理判据）。
  TLS 1.3 不通过 `SSL_SESSION_get_master_key` 暴露 master key，故只以 reuse 标志为准。

`reused=0` 一律记为完整握手，绝不计作恢复成功。

## 1. 库现有边界是什么

- `Connection.set_session` 仅校验 `Session._context is self._context`（对象身份），
  不同 `Context` 直接抛 `ValueError`（场景 S6）。这是必要但远不充分的边界。
- 同一个 `Context` 被多个主机名 / 协议 / 证书共用时，OpenSSL **不会**替应用把会话
  绑定到这些逻辑身份上。

## 2. 实测结果（同一 Context 内）

| 场景 | TLS 1.2 | TLS 1.3 | 含义 |
|---|---|---|---|
| S1 同 SNI/ALPN/证书基线 | 真实恢复 | 真实恢复 | 对照组，证明实验能稳定触发恢复 |
| S2 仅 SNI 不同（a→b） | 恢复 | 恢复 | 会话不绑定 SNI |
| S2b SNI 回调切换不同叶子证书 | 恢复，且客户端仍持有旧证书 A | 同左 | 恢复时根本不发 Certificate，B 的证书不可见 |
| S3 ALPN 变化（h2→http/1.1） | 恢复，协商结果随之改变 | 恢复 | 会话不绑定应用层协议 |
| S4 后端轮换叶子证书（SAN 不变） | 恢复，客户端仍读到旧 CN；完整握手才能看到新 CN | 同左 | 恢复路径完全跳过证书，认证结论被沿用 |
| S7 SNI 与 SAN 不匹配 | 链验证仍为 0 | 同左 | pyOpenSSL 只验链，不做主机名匹配 |

S4 的报文级证据：恢复握手服务端首程 1329 字节，完整握手 2389 字节——恢复时
Certificate/CertificateVerify 整条被省略。客户端 `get_peer_certificate()` 返回的是
随会话缓存的旧证书。

### 验证结果不能只看异常（S5）

- 默认 `VERIFY_PEER`（无回调或回调透传 `ok`）：链验证失败时握手抛
  `certificate verify failed`，且 `SSL_get_verify_result == 20`
  （unable to get issuer cert locally）。
- 恒 `True` 的验证回调会让握手“成功”，但 `get_verify_result` 仍是非 0，信任并未建立。
- 因此“没有抛异常”既不能证明恢复，也不能证明对端可信。

## 3. 本构建中不稳定 / 需显式处理的恢复点

- **TLS 1.3 NewSessionTicket 是后置记录**：握手完成后 NST 才到达。若只做
  `do_handshake` 泵，客户端永远不存 ticket，后续连接静默退化为完整握手（`reused=0`）。
  必须在握手结束后继续泵并对客户端 `recv()` 以消费后置记录（见 `drain_tickets`）。
  用标准库 `ssl` 的 `MemoryBIO` 复现了同一现象，确认是 OpenSSL 内存 BIO 语义，
  不是 pyOpenSSL 接线问题。
- **会话生命周期与连接绑定**：本构建中，一旦产生 `Session` 的 `Connection` 被
  GC，该 `Session` 在 TLS 1.2 与 1.3 下都无法再触发恢复（即使 `get_session()` 用
  `SSL_get1_session` 拿了独立引用、即使开了 `SESS_CACHE_BOTH`）。保持原始连接存活、
  每次从存活连接重新 `get_session()` 才能稳定反复恢复。缓存设计必须据此持有连接引用。
- pyOpenSSL 未封装 `SSL_session_reused`、`SSL_get_verify_result`、主机名校验，
  需经 `cryptography.hazmat.bindings.openssl.binding` 调用或自行实现 SAN 比对。

## 4. 推荐的应用级会话缓存键

只在 `Context` 对象身份相同的前提下，再用完整逻辑身份做键（`BackendIdentity`）：

- `hostname`：你认证的主机名（SNI / 目标名），而不是网络地址；
- `alpn`：协商出的应用协议；协议不同即不同信任域；
- `leaf_fingerprint`：叶子证书 DER 的 SHA-256 指纹，用于识别证书轮换；
- `proto_version`：`TLSv1.2` / `TLSv1.3`，避免票据跨版本误用；
- `session_id_context`：`Context.set_session_id` 的值，纵深防御。
- 如系统还有租户 ID、客户端证书策略等会改变信任域的维度，应一并入键。

任一字段不同都视为缓存未命中，走完整握手，绝不返回“近似匹配”。

## 5. 失效条件（至少）

- 叶子证书轮换 / 续发：按 `leaf_fingerprint` 或 `hostname` 失效；
- 后端下线、SNI/ALPN 路由配置变化；
- 信任锚（CA）变更、CRL/OCSP 指示吊销；
- 会话 TTL 到期、缓存容量淘汰；
- 任何疑似事件（密钥泄露、异常票据）→ 主动 `invalidate`。

## 6. 每次握手后必须独立确认的两件事

1. 是否真恢复：`SSL_session_reused == 1`（TLS 1.2 再加 master key 比对）。
2. 对端是否可信：`SSL_get_verify_result == X509_V_OK` **且** 自行做主机名/SAN 匹配
   **且**（恢复时）当前叶子指纹与缓存身份一致。

恢复握手不发证书，所以恢复路径要把“当前指纹 == 缓存身份指纹”作为硬性条件；不一致就
拒绝该连接并使条目失效，强制下一次完整握手。这样 A 服务的认证结论不可能被带到 B。

## 7. 交付物与运行方式

- `resume_experiment.py`：S1–S7 内存 BIO 实验，打印每连接的版本/SNI/ALPN/reused/
  verify/peer CN，并明确标注 `REAL_RESUME`。
  `python resume_experiment.py`
- `safe_session_cache.py`：`BoundSessionCache` + `BackendIdentity` + `establish`，
  含同服务恢复、跨主机名隔离、跨 ALPN 隔离、失效、证书轮换守卫五个可运行断言。
  `python safe_session_cache.py`

两个脚本均为纯内存 BIO、自签证书即时生成，可重复运行、不产生网络副作用。
