//! # Veydeck 仿真规则库一键打包与签名工具 (CI/CD Rules Packager)
//!
//! 此工具读取本地的 YAML 规则，进行静态安全与合规审计，
//! 随后将其转换为 Protobuf 二进制文件 `rules.bin`，并使用私钥生成 Ed25519 分离签名 `rules.bin.sig`，
//! 最后将两者直接在内存中压缩打包成外层交付文件 `veydeck-sim-rules-{version}.vprp`。

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine;
use clap::Parser;
use flate2::Compression;
use flate2::write::GzEncoder;
use ring::signature;
use veydeck_sim_rules::{
    RuleEndpointProto, RulePackageManifestProto, SimRulePackageProto, SimRuleProto, YamlRule,
};

/// 该规则库要求的最低主控版本号，当规则库开始依赖主控新版本才引入的解析能力时更新
const MIN_VEYDECK_VERSION: &str = "0.1.0-alpha.1";
/// 规则集的载荷格式版本，标识Protobuf schema 和  config_json 内部结构的兼容代次，仅当 Protobuf字段发生不兼容变更、或config_json  内部 JSON schema发生不兼容变更时递增
const RULESET_FORMAT_VERSION: i32 = 1;
const PACKAGE_SCHEMA_VERSION: i32 = 1;

/// Veydeck 仿真规则库一键打包与签名工具
#[derive(Parser, Debug)]
#[command(
    name = "veydeck-rules-pack",
    version = env!("CARGO_PKG_VERSION"),
    about = "Veydeck 仿真规则库打包与签名工具",
    long_about = None
)]
struct Args {
    /// 规则库的版本号 (例如: 0.1.0-alpha.1)。未指定时默认使用 Cargo.toml 中的版本号
    #[arg(value_name = "VERSION")]
    package_version: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 使用 clap 解析命令行参数
    let args = Args::parse();
    let version = args
        .package_version
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    // 2. 加载私钥与密码环境变量
    let private_key_source = env::var("VEYDECK_SIGNING_PRIVATE_KEY").map_err(|_| {
        "Environment variable VEYDECK_SIGNING_PRIVATE_KEY is missing! Cannot sign the rules package."
    })?;
    let password = env::var("VEYDECK_SIGNING_PRIVATE_KEY_PASSWORD").ok();

    println!(
        "Starting simulation rules package generation for version: v{}",
        version
    );

    // 3. 递归查找并加载 YAML 规则
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let signing_key = resolve_signing_key(&private_key_source, manifest_dir)?;
    let rules_dir = manifest_dir.join("rules");
    if !rules_dir.is_dir() {
        return Err(format!("Rules directory not found: {:?}", rules_dir).into());
    }

    let mut yaml_rules = Vec::new();
    visit_rules_dir(&rules_dir, &mut yaml_rules, &rules_dir)?;
    println!("Loaded {} rule files.", yaml_rules.len());

    // 4. 执行静态审计
    audit_rules(&yaml_rules)?;
    println!("Static rules audit passed successfully.");

    // 5. 组装 Protobuf 模型
    let mut proto_rules = Vec::new();
    for entry in &yaml_rules {
        let y = &entry.rule;
        // 将嵌套的行为序列化为紧凑 JSON 串
        let config_json = serde_json::to_string(&y.config_yaml)?;
        proto_rules.push(SimRuleProto {
            id: y.id,
            name: y.name.clone(),
            name_en: y.name_en.clone(),
            cve: y.cve.clone(),
            category: y.category.clone(),
            description_zh: y.description_zh.clone(),
            description_en: y.description_en.clone(),
            protocol: y.protocol.clone(),
            default_port: y.default_port,
            config_json,
            endpoints: protocol_endpoints(&y.protocol, y.default_port)?,
        });
    }

    let now_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;

    let manifest = RulePackageManifestProto {
        package_id: "veydeck-sim-rules".to_string(),
        suite_id: "veydeck.protocol-simulation".to_string(),
        package_type: "protocol-simulation-rules".to_string(),
        version: version.clone(),
        ruleset_format_version: RULESET_FORMAT_VERSION,
        min_veydeck_version: MIN_VEYDECK_VERSION.to_string(),
        generated_at: now_epoch,
        rule_count: proto_rules.len() as i32,
        schema_version: PACKAGE_SCHEMA_VERSION,
    };

    let package = SimRulePackageProto {
        manifest: Some(manifest),
        rules: proto_rules,
    };

    // 6. 序列化 Protobuf
    let mut bin_bytes = Vec::new();
    prost::Message::encode(&package, &mut bin_bytes)?;
    println!(
        "Protobuf serialization completed ({} bytes).",
        bin_bytes.len()
    );

    // 7. Ed25519 签名 (支持加密 Minisign 私钥调用 CLI，或未加密私钥内存签名)
    let sig_content = if signing_key.is_minisign_encrypted {
        let pwd = password.ok_or(
            "The private key file is encrypted, but VEYDECK_SIGNING_PRIVATE_KEY_PASSWORD is empty.",
        )?;
        println!("The private key is encrypted. Fallback to system 'minisign' tool...");

        // 将 rules.bin 暂存入文件（使用 CARGO_MANIFEST_DIR 确保 CI 下路径稳定）
        let tmp_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".tmp");
        fs::create_dir_all(&tmp_dir)?;
        let tmp_bin = tmp_dir.join("rules.bin");
        let tmp_sig = tmp_dir.join("rules.bin.sig");
        fs::write(&tmp_bin, &bin_bytes)?;

        // 执行 minisign 命令
        let mut child = std::process::Command::new("minisign")
            .arg("-S")
            .arg("-s")
            .arg(&signing_key.path)
            .arg("-c")
            .arg("signature by minisign") // untrusted comment
            .arg("-m")
            .arg(tmp_bin.to_str().unwrap())
            .arg("-x")
            .arg(tmp_sig.to_str().unwrap())
            .arg("-q")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| format!("Failed to spawn 'minisign' CLI: {:?}. Please ensure it is installed and in PATH.", err))?;

        // 将密码作为 stdin 输入给 minisign
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(format!("{}\n", pwd).as_bytes())?;
        }

        let status = child.wait()?;
        if !status.success() {
            return Err("minisign CLI execution failed. Check if password is correct.".into());
        }

        // 读取生成的 rules.bin.sig
        let sig = fs::read_to_string(&tmp_sig)?;

        // 清理临时文件
        let _ = fs::remove_file(&tmp_bin);
        let _ = fs::remove_file(&tmp_sig);
        let _ = fs::remove_dir(&tmp_dir);
        sig
    } else {
        // 未加密私钥，我们直接通过纯 Rust 提取 seed 并在内存中通过 ring 快速签名！
        println!(
            "The private key is unencrypted. Performing high-performance signature in memory using ring..."
        );
        let key_pair = load_key_pair_from_bytes(&signing_key.bytes)?;
        let signature = key_pair.sign(&bin_bytes);
        let sig_base64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
        format!("{}\n", sig_base64)
    };
    signing_key.cleanup();

    // 8. 内存压缩为 .vprp 交付文件，内部仍是 gzip tar。
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("dist");
    fs::create_dir_all(&output_dir)?;
    let output_path = output_dir.join(format!("veydeck-sim-rules-{}.vprp", version));
    let file = fs::File::create(&output_path)?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);

    // 添加 rules.bin 到归档
    let mut bin_header = tar::Header::new_gnu();
    bin_header.set_path("rules.bin")?;
    bin_header.set_size(bin_bytes.len() as u64);
    bin_header.set_mode(0o644);
    bin_header.set_cksum();
    tar_builder.append(&bin_header, &bin_bytes[..])?;

    // 添加 rules.bin.sig 到归档
    let sig_bytes = sig_content.as_bytes();
    let mut sig_header = tar::Header::new_gnu();
    sig_header.set_path("rules.bin.sig")?;
    sig_header.set_size(sig_bytes.len() as u64);
    sig_header.set_mode(0o644);
    sig_header.set_cksum();
    tar_builder.append(&sig_header, sig_bytes)?;

    tar_builder.finish()?;
    println!(
        "Package successfully generated and signed: {}",
        output_path.display()
    );

    Ok(())
}

fn protocol_port(protocol: &str) -> Result<u16, Box<dyn std::error::Error>> {
    match protocol {
        "http" => Ok(80),
        "redis" => Ok(6379),
        "smtp" => Ok(25),
        "pop3" => Ok(110),
        "imap" => Ok(143),
        "ssh" => Ok(22),
        "ftp" => Ok(21),
        "rdp" => Ok(3389),
        "telnet" => Ok(23),
        "mysql" => Ok(3306),
        "postgresql" => Ok(5432),
        "smb" => Ok(445),
        "ldap" => Ok(389),
        "dns" => Ok(53),
        "mongodb" => Ok(27017),
        "memcached" => Ok(11211),
        "snmp" => Ok(161),
        "mqtt" => Ok(1883),
        "vnc" => Ok(5900),
        _ => Err(format!("unsupported protocol: {protocol}").into()),
    }
}

fn protocol_endpoints(
    protocol: &str,
    default_port: Option<i64>,
) -> Result<Vec<RuleEndpointProto>, Box<dyn std::error::Error>> {
    let container_port = protocol_port(protocol)?;
    let default_host_port = default_port
        .and_then(|port| u16::try_from(port).ok())
        .unwrap_or(container_port);
    if protocol == "dns" {
        return Ok([("dns-tcp", "tcp"), ("dns-udp", "udp")]
            .into_iter()
            .map(|(id, transport)| RuleEndpointProto {
                id: id.to_string(),
                transport: transport.to_string(),
                container_port: i32::from(container_port),
                default_host_port: i32::from(default_host_port),
                required: true,
            })
            .collect());
    }
    let transport = if protocol == "snmp" { "udp" } else { "tcp" };
    Ok(vec![RuleEndpointProto {
        id: "main".to_string(),
        transport: transport.to_string(),
        container_port: i32::from(container_port),
        default_host_port: i32::from(default_host_port),
        required: true,
    }])
}

struct LoadedRule {
    file_path: String,
    rule: YamlRule,
}

/// 递归加载目录下的 YAML 规则文件
fn visit_rules_dir(
    dir: &Path,
    rules: &mut Vec<LoadedRule>,
    base_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit_rules_dir(&path, rules, base_dir)?;
            } else {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    let content = fs::read(&path)?;
                    let rule: YamlRule = serde_yaml::from_slice(&content)?;
                    let relative_path = path.strip_prefix(base_dir)?.to_string_lossy().to_string();
                    rules.push(LoadedRule {
                        file_path: relative_path,
                        rule,
                    });
                }
            }
        }
    }
    Ok(())
}

struct SigningKey {
    path: PathBuf,
    bytes: Vec<u8>,
    is_minisign_encrypted: bool,
    temp_path: Option<PathBuf>,
}

impl SigningKey {
    fn cleanup(&self) {
        if let Some(path) = &self.temp_path {
            let _ = fs::remove_file(path);
        }
    }
}

/// 解析签名私钥，支持环境变量传入文件路径或完整私钥文件内容。
fn resolve_signing_key(
    source: &str,
    manifest_dir: &Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let source_path = Path::new(source);
    if source_path.is_file() {
        let bytes = fs::read(source_path)?;
        return Ok(SigningKey {
            is_minisign_encrypted: is_minisign_encrypted(&bytes),
            path: source_path.to_path_buf(),
            bytes,
            temp_path: None,
        });
    }

    let bytes = source.as_bytes().to_vec();
    let tmp_dir = manifest_dir.join(".tmp");
    fs::create_dir_all(&tmp_dir)?;
    let temp_path = tmp_dir.join(format!("signing-key-{}.key", std::process::id()));
    fs::write(&temp_path, &bytes)?;

    Ok(SigningKey {
        is_minisign_encrypted: is_minisign_encrypted(&bytes),
        path: temp_path.clone(),
        bytes,
        temp_path: Some(temp_path),
    })
}

/// 判断 minisign 私钥内容是否被加密。
fn is_minisign_encrypted(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|content| content.lines().next())
        .map(|line| line.contains("minisign encrypted secret key"))
        .unwrap_or(false)
}

/// 从字节切片中解析并加载 Ed25519 密钥对，支持 Minisign 私钥、PEM、Hex 以及 Base64 格式
fn load_key_pair_from_bytes(
    key_bytes: &[u8],
) -> Result<signature::Ed25519KeyPair, Box<dyn std::error::Error>> {
    // 尝试转成 UTF-8 字符串进行解析
    if let Ok(raw_str) = std::str::from_utf8(key_bytes) {
        let raw_str = raw_str.trim();
        // 1. 判断是否是 minisign 格式
        if raw_str.starts_with("untrusted comment:") {
            let mut lines = raw_str.lines();
            let _comment = lines.next().ok_or("Invalid private key file format")?;
            let b64_data = lines
                .next()
                .ok_or("Missing base64 data in private key file")?
                .trim();
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64_data)?;

            let seed = if decoded.len() == 108 {
                &decoded[44..76]
            } else if decoded.len() == 104 {
                &decoded[40..72]
            } else {
                return Err(
                    format!("Unsupported minisign secret key length: {}", decoded.len()).into(),
                );
            };
            return seed_to_key_pair(seed);
        }

        // 2. 判断是否是 PEM 格式
        if raw_str.starts_with("-----BEGIN") {
            let lines: Vec<&str> = raw_str
                .lines()
                .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
                .collect();
            let b64_concat = lines.concat();
            let der_bytes = base64::engine::general_purpose::STANDARD.decode(b64_concat)?;
            return der_to_key_pair(&der_bytes);
        }

        // 3. 尝试 Hex 或原始 Base64
        if let Ok(decoded) = hex::decode(raw_str) {
            return der_to_key_pair(&decoded);
        }
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw_str) {
            return der_to_key_pair(&decoded);
        }
    }

    // 4. 如果是二进制数据，直接作为 DER 字节解析
    der_to_key_pair(key_bytes)
}

fn seed_to_key_pair(seed: &[u8]) -> Result<signature::Ed25519KeyPair, Box<dyn std::error::Error>> {
    if seed.len() != 32 {
        return Err(format!("Invalid seed length: {} (expected 32)", seed.len()).into());
    }
    let mut pkcs8 = vec![
        0x30, 0x2e, // Sequence (46 bytes)
        0x02, 0x01, 0x00, // Version 0
        0x30, 0x05, // Algorithm Identifier (5 bytes)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (curve Ed25519)
        0x04, 0x22, // Octet String (34 bytes)
        0x04, 0x20, // Octet String (32 bytes seed)
    ];
    pkcs8.extend_from_slice(seed);
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|err| format!("Invalid private key PKCS#8: {:?}", err))?;
    Ok(key_pair)
}

fn der_to_key_pair(
    der_bytes: &[u8],
) -> Result<signature::Ed25519KeyPair, Box<dyn std::error::Error>> {
    if der_bytes.len() == 32 {
        seed_to_key_pair(der_bytes)
    } else {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(der_bytes)
            .map_err(|err| format!("Invalid private key PKCS#8: {:?}", err))?;
        Ok(key_pair)
    }
}

/// 执行与主测试同级别的静态安全审计
fn audit_rules(rules: &[LoadedRule]) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen_ids = HashSet::new();
    let allowed_protocols: HashSet<&str> = [
        "http",
        "redis",
        "smtp",
        "pop3",
        "imap",
        "ssh",
        "ftp",
        "rdp",
        "telnet",
        "mysql",
        "postgresql",
        "smb",
        "ldap",
        "dns",
        "mongodb",
        "memcached",
        "snmp",
        "mqtt",
        "vnc",
    ]
    .into_iter()
    .collect();
    let allowed_categories: HashSet<&str> = ["cve_sim", "vuln_sim", "honeypot", "test_env"]
        .into_iter()
        .collect();

    for entry in rules {
        let r = &entry.rule;
        let context = format!(
            "File: '{}' (ID: {}, Name: '{}')",
            entry.file_path, r.id, r.name
        );

        // 1. ID 冲突防御
        if !seen_ids.insert(r.id) {
            return Err(format!("Conflict Error: Duplicate rule ID found! {}", context).into());
        }

        // 2. 必填字段非空校验
        if r.name.trim().is_empty()
            || r.name_en.trim().is_empty()
            || r.category.trim().is_empty()
            || r.protocol.trim().is_empty()
            || r.description_zh.trim().is_empty()
            || r.description_en.trim().is_empty()
        {
            return Err(
                format!("Validation Error: Required fields are empty in {}", context).into(),
            );
        }

        // 3. 协议合法性
        if !allowed_protocols.contains(r.protocol.as_str()) {
            return Err(format!(
                "Value Error: Unsupported protocol '{}' in {}",
                r.protocol, context
            )
            .into());
        }

        // 4. 类别合法性
        if !allowed_categories.contains(r.category.as_str()) {
            return Err(format!(
                "Value Error: Unsupported category '{}' in {}",
                r.category, context
            )
            .into());
        }

        // 5. 默认端口范围
        if r.default_port
            .is_some_and(|port| !(1..=65535).contains(&port))
        {
            return Err(format!("Value Error: defaultPort out of bounds in {}", context).into());
        }

        // 6. ID 分区范围合法性
        match r.protocol.as_str() {
            "http" if !(100000..=199999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: HTTP rule ID out of bounds. {}", context).into(),
                );
            }
            "redis" if !(300000..=309999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: Redis rule ID out of bounds. {}", context).into(),
                );
            }
            "smtp" if !(400000..=409999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: SMTP rule ID out of bounds. {}", context).into(),
                );
            }
            "pop3" if !(410000..=419999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: POP3 rule ID out of bounds. {}", context).into(),
                );
            }
            "imap" if !(420000..=429999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: IMAP rule ID out of bounds. {}", context).into(),
                );
            }
            "ssh" if !(200000..=299999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: SSH rule ID out of bounds. {}", context).into(),
                );
            }
            "ftp" if !(600000..=699999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: FTP rule ID out of bounds. {}", context).into(),
                );
            }
            "rdp" if !(620000..=629999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: RDP rule ID out of bounds. {}", context).into(),
                );
            }
            "telnet" if !(630000..=639999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: Telnet rule ID out of bounds. {}", context).into(),
                );
            }
            "mysql" if !(310000..=319999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: MySQL rule ID out of bounds. {}", context).into(),
                );
            }
            "postgresql" if !(320000..=329999).contains(&r.id) => {
                return Err(format!(
                    "Boundary Error: PostgreSQL rule ID out of bounds. {}",
                    context
                )
                .into());
            }
            "smb" if !(700000..=709999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: SMB rule ID out of bounds. {}", context).into(),
                );
            }
            "ldap" if !(710000..=719999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: LDAP rule ID out of bounds. {}", context).into(),
                );
            }
            "dns" if !(500000..=509999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: DNS rule ID out of bounds. {}", context).into(),
                );
            }
            "mongodb" if !(330000..=339999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: MongoDB rule ID out of bounds. {}", context).into(),
                );
            }
            "memcached" if !(340000..=349999).contains(&r.id) => {
                return Err(format!(
                    "Boundary Error: Memcached rule ID out of bounds. {}",
                    context
                )
                .into());
            }
            "snmp" if !(510000..=519999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: SNMP rule ID out of bounds. {}", context).into(),
                );
            }
            "mqtt" if !(520000..=529999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: MQTT rule ID out of bounds. {}", context).into(),
                );
            }
            "vnc" if !(640000..=649999).contains(&r.id) => {
                return Err(
                    format!("Boundary Error: VNC rule ID out of bounds. {}", context).into(),
                );
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::protocol_endpoints;

    #[test]
    fn dns_rules_are_packed_with_tcp_and_udp_endpoints() {
        let endpoints = protocol_endpoints("dns", Some(1053)).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].id, "dns-tcp");
        assert_eq!(endpoints[0].transport, "tcp");
        assert_eq!(endpoints[1].id, "dns-udp");
        assert_eq!(endpoints[1].transport, "udp");
        assert!(endpoints.iter().all(|endpoint| {
            endpoint.container_port == 53 && endpoint.default_host_port == 1053
        }));
    }

    #[test]
    fn snmp_rules_are_packed_with_one_udp_endpoint() {
        let endpoints = protocol_endpoints("snmp", Some(161)).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id, "main");
        assert_eq!(endpoints[0].transport, "udp");
        assert_eq!(endpoints[0].container_port, 161);
        assert_eq!(endpoints[0].default_host_port, 161);
    }
}
