# Veydeck Simulation Rules

`veydeck-sim-rules` 是 Veydeck 协议仿真规则库，负责维护可导入协议仿真套件的规则资产，并生成独立发布的 `.vprp` 规则包。

Veydeck（可扩展的分布式 Linux 主机运维平台）通过套件按需扩展平台能力，本仓库提供协议仿真套件所需的规则资产。

规则库只负责规则资产、YAML 审计、Protobuf 载荷生成、签名和发布产物。主控负责规则导入、实例生命周期、端口调度和审计日志。

## 当前库存

当前规则包包含 51 条规则，覆盖 HTTP、Redis、SMTP、POP3、IMAP、SSH、FTP、RDP、Telnet、MySQL、PostgreSQL、SMB、LDAP、DNS、MongoDB、Memcached、SNMP、MQTT 和 VNC：

| 分类 | 数量 | 说明 |
| --- | --- | --- |
| `cve_sim` | 27 | 真实 CVE 仿真规则。 |
| `vuln_sim` | 4 | Redis 泛漏洞仿真规则。 |
| `honeypot` | 19 | HTTP、缓存、邮件、远程访问、数据库、企业、网络与消息协议诱捕规则。 |
| `test_env` | 1 | HTTP 测试环境规则。 |

## 目录结构

```text
rules/
├── http/
│   ├── cve/
│   ├── honeypot/
│   └── test-env/
├── database/
│   ├── redis/
│   ├── mysql/
│   ├── postgresql/
│   ├── mongodb/
│   └── memcached/
├── enterprise/
│   ├── ldap/
│   └── smb/
├── remote-access/
│   ├── telnet/
│   └── vnc/
├── network/
│   ├── dns/
│   └── snmp/
├── messaging/
│   └── mqtt/
└── mail/
    ├── smtp/
    ├── pop3/
    └── imap/
```

规则目录必须和 `category` 对齐。规则 ID 使用 6 位数字，`[1, 999_999]` 由官方规则库使用，`1_000_000+` 预留给用户自定义规则。

## 规则字段

每条规则使用 YAML 描述，必填字段包括：

- `id`
- `defaultPort`
- `name`
- `nameEn`
- `category`
- `vendor`
- `product`
- `severity`
- `references`
- `tags`
- `ruleVersion`
- `descriptionZh`
- `descriptionEn`
- `protocol`
- `configYaml`

`severity` 只允许 `critical`、`high`、`medium`、`low`、`info`。`references` 至少包含一个 HTTPS 来源链接。

## 构建与审计

```bash
cargo fmt
cargo test
cargo build --release
```

规则审计会检查：

1. YAML 字段完整性。
2. 规则 ID 分区。
3. 协议目录和分类一致性。
4. 协议配置 schema。
5. 规则总数和核心分类数量。

## 规则包

主控通过导入以下格式的规则包消费规则库：

```text
veydeck-sim-rules-<version>.vprp
```

`.vprp` 文件内部仍是 gzip 压缩的 tar 归档。规则包的 v1 契约包含 `schema_version: 1`、具名端点清单、Protobuf 载荷、Ed25519/minisign 签名和版本声明。manifest 通过 `suite_id = "veydeck.protocol-simulation"` 和 `package_type = "protocol-simulation-rules"` 声明归属，并纳入签名载荷。导入端必须实际验签并检查归属，不能只检查后缀或签名文件存在。

## 契约

规则库和主控必须保持 Protobuf 字段、规则包格式、版本声明和 ID 分区一致。契约文档位于：

```text
docs/design/Veydeck主控与规则库兼容性契约.md
```
