//! # Veydeck 协议仿真内置策略库
//!
//! 此 crate 负责加载和解析以 YAML 形式存储的诱捕、仿真指纹策略模板。
//! 实现了平台“主控功能”与安全“指纹规则”在生命周期、开发体验及发版控制上的完全解耦。

use prost::Message;
use serde::{Deserialize, Serialize};

/// 仿真策略模板的定义结构体，使用 Protobuf 二进制序列化
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SimRuleProto {
    #[prost(int64, tag = "1")]
    pub id: i64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub name_en: String,
    #[prost(string, optional, tag = "4")]
    pub cve: Option<String>,
    #[prost(string, tag = "5")]
    pub category: String,
    #[prost(string, tag = "6")]
    pub description_zh: String,
    #[prost(string, tag = "7")]
    pub description_en: String,
    #[prost(string, tag = "8")]
    pub protocol: String,
    #[prost(int64, optional, tag = "9")]
    pub default_port: Option<i64>,
    #[prost(string, tag = "10")]
    pub config_json: String, // 内层行为序列化后的高内聚 JSON 串
    #[prost(message, repeated, tag = "11")]
    pub endpoints: Vec<RuleEndpointProto>,
}

/// v1 规则声明的具名运行端点。
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct RuleEndpointProto {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub transport: String,
    #[prost(int32, tag = "3")]
    pub container_port: i32,
    #[prost(int32, tag = "4")]
    pub default_host_port: i32,
    #[prost(bool, tag = "5")]
    pub required: bool,
}

/// 规则包元数据
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct RulePackageManifestProto {
    #[prost(string, tag = "1")]
    pub package_id: String,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(int32, tag = "3")]
    pub ruleset_format_version: i32,
    #[prost(string, tag = "4")]
    pub min_veydeck_version: String,
    #[prost(int64, tag = "5")]
    pub generated_at: i64,
    #[prost(int32, tag = "6")]
    pub rule_count: i32,
    #[prost(int32, tag = "7")]
    pub schema_version: i32,
    /// 消费规则包的套件标识。
    #[prost(string, tag = "8")]
    pub suite_id: String,
    /// 套件业务资产类型。
    #[prost(string, tag = "9")]
    pub package_type: String,
}

/// 统一的 Protobuf 二进制规则包载荷
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SimRulePackageProto {
    #[prost(message, optional, tag = "1")]
    pub manifest: Option<RulePackageManifestProto>,
    #[prost(message, repeated, tag = "2")]
    pub rules: Vec<SimRuleProto>,
}

/// 专用于解析本地 YAML 文件结构体的辅助映射模型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YamlRule {
    pub id: i64,
    pub name: String,
    pub name_en: String,
    pub cve: Option<String>,
    pub category: String,
    pub vendor: String,
    pub product: String,
    pub severity: String,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub rule_version: String,
    pub description_zh: String,
    pub description_en: String,
    pub protocol: String,
    pub default_port: Option<i64>,
    pub config_yaml: serde_json::Value, // 直接将嵌套的诱捕细节解析为 JSON 对象
}

// --- 指纹规则合规性自动化审查测试套件 (CI/CD Rules Auditor) ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::{HashMap, HashSet};

    #[derive(Debug, Deserialize)]
    struct HttpRuleConfig {
        server_header: Option<String>,
        headers: Option<HashMap<String, String>>,
        html: Option<String>,
        exploit_paths: Option<Vec<HttpExploitPath>>,
    }

    #[derive(Debug, Deserialize)]
    struct HttpExploitPath {
        path: String,
        trigger_method: Option<String>,
        response_status: u16,
        response_body: String,
        response_headers: Option<HashMap<String, String>>,
    }

    #[derive(Debug, Deserialize)]
    struct RedisRuleConfig {
        banner: Option<String>,
        require_auth: Option<bool>,
        password: Option<String>,
        server_info: Option<HashMap<String, String>>,
        keys: Option<HashMap<String, String>>,
        command_responses: Option<Vec<RedisCommandResponse>>,
    }

    #[derive(Debug, Deserialize)]
    struct RedisCommandResponse {
        command: String,
        args_contains: Option<Vec<String>>,
        response: String,
        event_type: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct MailCredential {
        username: String,
        password: String,
        display_name: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct MailMessage {
        uid: Option<String>,
        from: String,
        to: Vec<String>,
        subject: String,
        date: Option<String>,
        body: String,
        flags: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    struct MailCustomResponse {
        command: String,
        args_contains: Option<Vec<String>>,
        response: String,
        event_type: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct SmtpRuleConfig {
        banner: Option<String>,
        hostname: Option<String>,
        require_auth: Option<bool>,
        credentials: Option<Vec<MailCredential>>,
        capabilities: Option<Vec<String>>,
        accepted_recipients: Option<Vec<String>>,
        custom_responses: Option<Vec<MailCustomResponse>>,
    }

    #[derive(Debug, Deserialize)]
    struct Pop3RuleConfig {
        banner: Option<String>,
        require_auth: Option<bool>,
        credentials: Option<Vec<MailCredential>>,
        capabilities: Option<Vec<String>>,
        messages: Option<Vec<MailMessage>>,
        custom_responses: Option<Vec<MailCustomResponse>>,
    }

    #[derive(Debug, Deserialize)]
    struct ImapRuleConfig {
        banner: Option<String>,
        require_auth: Option<bool>,
        credentials: Option<Vec<MailCredential>>,
        capabilities: Option<Vec<String>>,
        mailboxes: Option<HashMap<String, Vec<MailMessage>>>,
        messages: Option<Vec<MailMessage>>,
        custom_responses: Option<Vec<MailCustomResponse>>,
    }

    #[derive(Debug, Deserialize)]
    struct SshCredential {
        username: String,
        password: String,
    }

    #[derive(Debug, Deserialize)]
    struct SshRuleConfig {
        banner: Option<String>,
        credentials: Option<Vec<SshCredential>>,
    }

    #[derive(Debug, Deserialize)]
    struct FtpCredential {
        username: String,
        password: String,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct FtpRuleConfig {
        banner: Option<String>,
        credentials: Option<Vec<FtpCredential>>,
        server_name: Option<String>,
        allow_anonymous: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    struct RdpCredential {
        username: String,
        password: String,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct RdpRuleConfig {
        flags: Option<u32>,
        credentials: Option<Vec<RdpCredential>>,
    }

    struct AuditedYamlRule {
        file_path: String,
        rule: YamlRule,
    }

    const ALLOWED_CATEGORIES: &[&str] = &["cve_sim", "vuln_sim", "honeypot", "test_env"];
    const ALLOWED_PROTOCOLS: &[&str] = &[
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
    ];
    const ALLOWED_SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
    const ALLOWED_HTTP_METHODS: &[&str] =
        &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    fn is_valid_cve(value: &str) -> bool {
        let Some(rest) = value.strip_prefix("CVE-") else {
            return false;
        };
        let parts = rest.split('-').collect::<Vec<_>>();
        if parts.len() != 2 {
            return false;
        }

        let year = parts[0];
        let sequence = parts[1];
        year.len() == 4
            && year.chars().all(|ch| ch.is_ascii_digit())
            && sequence.len() >= 4
            && sequence.chars().all(|ch| ch.is_ascii_digit())
    }

    fn collect_json_strings<'a>(value: &'a serde_json::Value, output: &mut Vec<&'a str>) {
        match value {
            serde_json::Value::String(text) => output.push(text),
            serde_json::Value::Array(values) => {
                for item in values {
                    collect_json_strings(item, output);
                }
            }
            serde_json::Value::Object(map) => {
                for item in map.values() {
                    collect_json_strings(item, output);
                }
            }
            _ => {}
        }
    }

    fn assert_safe_simulation_content(rule: &YamlRule, rule_context: &str) {
        let mut strings = Vec::new();
        collect_json_strings(&rule.config_yaml, &mut strings);

        for text in strings {
            let lowered = text.to_ascii_lowercase();
            let blocked = [
                "-----begin rsa private key-----",
                "-----begin openssh private key-----",
                "-----begin ec private key-----",
                "nc -e ",
                "ncat -e ",
                "bash -i",
                "/dev/tcp/",
                "rm -rf /",
                "curl | sh",
                "curl -s | sh",
                "wget | sh",
                "wget -q | sh",
            ];

            assert!(
                !blocked.iter().any(|pattern| lowered.contains(pattern)),
                "Safety Error: configYaml contains blocked executable or secret-like content in {}",
                rule_context
            );
        }
    }

    fn category_path_prefix(protocol: &str, category: &str) -> &'static str {
        match (protocol, category) {
            ("http", "cve_sim") => "http/cve/",
            ("http", "vuln_sim") => "http/vuln/",
            ("http", "honeypot") => "http/honeypot/",
            ("http", "test_env") => "http/test-env/",
            ("redis", "cve_sim") => "database/redis/cve/",
            ("redis", "vuln_sim") => "database/redis/vuln/",
            ("redis", "honeypot") => "database/redis/honeypot/",
            ("redis", "test_env") => "database/redis/test-env/",
            ("smtp", "cve_sim") => "mail/smtp/cve/",
            ("smtp", "vuln_sim") => "mail/smtp/vuln/",
            ("smtp", "honeypot") => "mail/smtp/honeypot/",
            ("smtp", "test_env") => "mail/smtp/test-env/",
            ("pop3", "cve_sim") => "mail/pop3/cve/",
            ("pop3", "vuln_sim") => "mail/pop3/vuln/",
            ("pop3", "honeypot") => "mail/pop3/honeypot/",
            ("pop3", "test_env") => "mail/pop3/test-env/",
            ("imap", "cve_sim") => "mail/imap/cve/",
            ("imap", "vuln_sim") => "mail/imap/vuln/",
            ("imap", "honeypot") => "mail/imap/honeypot/",
            ("imap", "test_env") => "mail/imap/test-env/",
            ("ssh", "cve_sim") => "ssh/cve/",
            ("ssh", "vuln_sim") => "ssh/vuln/",
            ("ssh", "honeypot") => "ssh/honeypot/",
            ("ssh", "test_env") => "ssh/test-env/",
            ("ftp", "cve_sim") => "ftp/cve/",
            ("ftp", "vuln_sim") => "ftp/vuln/",
            ("ftp", "honeypot") => "ftp/honeypot/",
            ("ftp", "test_env") => "ftp/test-env/",
            ("rdp", "cve_sim") => "rdp/cve/",
            ("rdp", "vuln_sim") => "rdp/vuln/",
            ("rdp", "honeypot") => "rdp/honeypot/",
            ("rdp", "test_env") => "rdp/test-env/",
            ("telnet", "honeypot") => "remote-access/telnet/honeypot/",
            ("mysql", "honeypot") => "database/mysql/honeypot/",
            ("postgresql", "honeypot") => "database/postgresql/honeypot/",
            ("smb", "honeypot") => "enterprise/smb/honeypot/",
            ("ldap", "honeypot") => "enterprise/ldap/honeypot/",
            ("dns", "honeypot") => "network/dns/honeypot/",
            ("mongodb", "honeypot") => "database/mongodb/honeypot/",
            ("memcached", "honeypot") => "database/memcached/honeypot/",
            ("snmp", "honeypot") => "network/snmp/honeypot/",
            ("mqtt", "honeypot") => "messaging/mqtt/honeypot/",
            ("vnc", "honeypot") => "remote-access/vnc/honeypot/",
            _ => "unknown/",
        }
    }

    fn assert_http_id_partition(rule: &YamlRule, rule_context: &str) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (100000..=149999).contains(&rule.id),
            "vuln_sim" => (150000..=169999).contains(&rule.id),
            "honeypot" => (170000..=189999).contains(&rule.id),
            "test_env" => (190000..=199999).contains(&rule.id),
            _ => false,
        };

        assert!(
            valid_partition,
            "Boundary Error: HTTP rule ID is outside the category partition in {}",
            rule_context
        );
    }

    fn assert_redis_id_partition(rule: &YamlRule, rule_context: &str) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (300000..=301999).contains(&rule.id),
            "vuln_sim" => (302000..=306999).contains(&rule.id),
            "honeypot" => (307000..=308999).contains(&rule.id),
            "test_env" => (309000..=309999).contains(&rule.id),
            _ => false,
        };

        assert!(
            valid_partition,
            "Boundary Error: Redis rule ID is outside the category partition in {}",
            rule_context
        );
    }

    fn assert_mail_id_partition(
        rule: &YamlRule,
        rule_context: &str,
        protocol_name: &str,
        base: i64,
    ) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (base..=base + 1_999).contains(&rule.id),
            "vuln_sim" => (base + 2_000..=base + 6_999).contains(&rule.id),
            "honeypot" => (base + 7_000..=base + 8_999).contains(&rule.id),
            "test_env" => (base + 9_000..=base + 9_999).contains(&rule.id),
            _ => false,
        };

        assert!(
            valid_partition,
            "Boundary Error: {} rule ID is outside the category partition in {}",
            protocol_name, rule_context
        );
    }

    fn assert_ssh_id_partition(rule: &YamlRule, rule_context: &str) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (200000..=201999).contains(&rule.id),
            "vuln_sim" => (202000..=206999).contains(&rule.id),
            "honeypot" => (207000..=208999).contains(&rule.id),
            "test_env" => (209000..=209999).contains(&rule.id),
            _ => false,
        };
        assert!(
            valid_partition,
            "Boundary Error: SSH rule ID is outside the category partition in {}",
            rule_context
        );
    }

    fn assert_ftp_id_partition(rule: &YamlRule, rule_context: &str) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (600000..=601999).contains(&rule.id),
            "vuln_sim" => (602000..=606999).contains(&rule.id),
            "honeypot" => (607000..=608999).contains(&rule.id),
            "test_env" => (609000..=609999).contains(&rule.id),
            _ => false,
        };
        assert!(
            valid_partition,
            "Boundary Error: FTP rule ID is outside the category partition in {}",
            rule_context
        );
    }

    fn assert_rdp_id_partition(rule: &YamlRule, rule_context: &str) {
        let valid_partition = match rule.category.as_str() {
            "cve_sim" => (620000..=621999).contains(&rule.id),
            "vuln_sim" => (622000..=626999).contains(&rule.id),
            "honeypot" => (627000..=628999).contains(&rule.id),
            "test_env" => (629000..=629999).contains(&rule.id),
            _ => false,
        };
        assert!(
            valid_partition,
            "Boundary Error: RDP rule ID is outside the category partition in {}",
            rule_context
        );
    }

    fn assert_ssh_config(source_rule: &YamlRule, rule_context: &str) {
        let ssh_config = serde_json::from_value::<SshRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match SSH rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(banner) = &ssh_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: SSH banner cannot be empty! {}",
                rule_context
            );
        }
        if let Some(credentials) = &ssh_config.credentials {
            for credential in credentials {
                assert!(
                    !credential.username.trim().is_empty()
                        && !credential.password.trim().is_empty(),
                    "Validation Error: SSH credential username/password cannot be empty! {}",
                    rule_context
                );
            }
        }
    }

    fn assert_ftp_config(source_rule: &YamlRule, rule_context: &str) {
        let ftp_config = serde_json::from_value::<FtpRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match FTP rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(banner) = &ftp_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: FTP banner cannot be empty! {}",
                rule_context
            );
        }
        if let Some(server_name) = &ftp_config.server_name {
            assert!(
                !server_name.trim().is_empty(),
                "Validation Error: FTP server_name cannot be empty! {}",
                rule_context
            );
        }
        if let Some(credentials) = &ftp_config.credentials {
            for credential in credentials {
                assert!(
                    !credential.username.trim().is_empty()
                        && !credential.password.trim().is_empty(),
                    "Validation Error: FTP credential username/password cannot be empty! {}",
                    rule_context
                );
            }
        }
    }

    fn assert_rdp_config(source_rule: &YamlRule, rule_context: &str) {
        let rdp_config = serde_json::from_value::<RdpRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match RDP rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(credentials) = &rdp_config.credentials {
            for credential in credentials {
                assert!(
                    !credential.username.trim().is_empty()
                        && !credential.password.trim().is_empty(),
                    "Validation Error: RDP credential username/password cannot be empty! {}",
                    rule_context
                );
            }
        }
    }

    fn assert_http_config(source_rule: &YamlRule, rule_context: &str) {
        let http_config = serde_json::from_value::<HttpRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match HTTP rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        let server_header = http_config.server_header.as_deref().unwrap_or_else(|| {
            panic!(
                "Validation Error: server_header is required! {}",
                rule_context
            )
        });
        assert!(
            !server_header.trim().is_empty(),
            "Validation Error: server_header cannot be empty! {}",
            rule_context
        );
        let html = http_config
            .html
            .as_deref()
            .unwrap_or_else(|| panic!("Validation Error: html is required! {}", rule_context));
        assert!(
            !html.trim().is_empty(),
            "Validation Error: html cannot be empty! {}",
            rule_context
        );
        if let Some(headers) = &http_config.headers {
            assert!(
                headers
                    .iter()
                    .all(|(name, value)| !name.trim().is_empty() && !value.trim().is_empty()),
                "Validation Error: headers cannot contain empty names or values! {}",
                rule_context
            );
        }

        let exploit_paths = http_config.exploit_paths.as_deref().unwrap_or_else(|| {
            panic!(
                "Validation Error: exploit_paths is required! {}",
                rule_context
            )
        });
        assert!(
            !exploit_paths.is_empty(),
            "Validation Error: exploit_paths cannot be empty! {}",
            rule_context
        );

        for exploit_path in exploit_paths {
            assert!(
                exploit_path.path.starts_with('/'),
                "Validation Error: exploit path must start with '/'. Got '{}' in {}",
                exploit_path.path,
                rule_context
            );
            if let Some(method) = &exploit_path.trigger_method {
                assert!(
                    ALLOWED_HTTP_METHODS.contains(&method.as_str()),
                    "Validation Error: trigger_method must be one of {:?}! Got '{}' in {}",
                    ALLOWED_HTTP_METHODS,
                    method,
                    rule_context
                );
            }
            assert!(
                (100..=599).contains(&exploit_path.response_status),
                "Validation Error: response_status must be within 100-599! Got '{}' in {}",
                exploit_path.response_status,
                rule_context
            );
            assert!(
                !exploit_path.response_body.trim().is_empty(),
                "Validation Error: response_body cannot be empty! {}",
                rule_context
            );
            if let Some(headers) = &exploit_path.response_headers {
                assert!(
                    headers
                        .iter()
                        .all(|(name, value)| !name.trim().is_empty() && !value.trim().is_empty()),
                    "Validation Error: response_headers cannot contain empty names or values! {}",
                    rule_context
                );
            }
        }
    }

    fn assert_redis_config(source_rule: &YamlRule, rule_context: &str) {
        let redis_config =
            serde_json::from_value::<RedisRuleConfig>(source_rule.config_yaml.clone())
                .unwrap_or_else(|err| {
                    panic!(
                        "Validation Error: configYaml must match Redis rule schema in {}: {:?}",
                        rule_context, err
                    )
                });

        if let Some(banner) = &redis_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: Redis banner cannot be empty! {}",
                rule_context
            );
        }
        if redis_config.require_auth.unwrap_or(false) {
            let password = redis_config.password.as_deref().unwrap_or_else(|| {
                panic!(
                    "Validation Error: Redis password is required when require_auth is true! {}",
                    rule_context
                )
            });
            assert!(
                !password.trim().is_empty(),
                "Validation Error: Redis password cannot be empty! {}",
                rule_context
            );
        }
        if let Some(server_info) = &redis_config.server_info {
            assert!(
                server_info
                    .iter()
                    .all(|(name, value)| !name.trim().is_empty() && !value.trim().is_empty()),
                "Validation Error: Redis server_info cannot contain empty names or values! {}",
                rule_context
            );
        }
        if let Some(keys) = &redis_config.keys {
            assert!(
                keys.iter()
                    .all(|(name, value)| !name.trim().is_empty() && !value.trim().is_empty()),
                "Validation Error: Redis keys cannot contain empty names or values! {}",
                rule_context
            );
        }

        let responses = redis_config
            .command_responses
            .as_deref()
            .unwrap_or_else(|| {
                panic!(
                    "Validation Error: Redis command_responses is required! {}",
                    rule_context
                )
            });
        assert!(
            !responses.is_empty(),
            "Validation Error: Redis command_responses cannot be empty! {}",
            rule_context
        );
        for response in responses {
            assert!(
                !response.command.trim().is_empty(),
                "Validation Error: Redis command response command cannot be empty! {}",
                rule_context
            );
            assert!(
                !response.response.trim().is_empty(),
                "Validation Error: Redis command response body cannot be empty! {}",
                rule_context
            );
            if let Some(args_contains) = &response.args_contains {
                assert!(
                    args_contains.iter().all(|item| !item.trim().is_empty()),
                    "Validation Error: Redis args_contains cannot contain empty values! {}",
                    rule_context
                );
            }
            if let Some(event_type) = &response.event_type {
                assert!(
                    matches!(event_type.as_str(), "redis_command" | "exploit_attempt"),
                    "Validation Error: Redis event_type must be redis_command or exploit_attempt! {}",
                    rule_context
                );
            }
        }
    }

    fn assert_mail_credentials(
        credentials: Option<&[MailCredential]>,
        require_auth: bool,
        rule_context: &str,
    ) {
        if require_auth {
            let credentials = credentials.unwrap_or_else(|| {
                panic!(
                    "Validation Error: mail credentials are required when require_auth is true! {}",
                    rule_context
                )
            });
            assert!(
                !credentials.is_empty(),
                "Validation Error: mail credentials cannot be empty! {}",
                rule_context
            );
        }

        if let Some(credentials) = credentials {
            for credential in credentials {
                assert!(
                    !credential.username.trim().is_empty()
                        && !credential.password.trim().is_empty(),
                    "Validation Error: mail credential username/password cannot be empty! {}",
                    rule_context
                );
                if let Some(display_name) = &credential.display_name {
                    assert!(
                        !display_name.trim().is_empty(),
                        "Validation Error: mail credential display_name cannot be empty! {}",
                        rule_context
                    );
                }
            }
        }
    }

    fn assert_mail_message(message: &MailMessage, rule_context: &str) {
        assert!(
            !message.from.trim().is_empty(),
            "Validation Error: mail message from cannot be empty! {}",
            rule_context
        );
        assert!(
            !message.to.is_empty() && message.to.iter().all(|item| !item.trim().is_empty()),
            "Validation Error: mail message to cannot be empty! {}",
            rule_context
        );
        assert!(
            !message.subject.trim().is_empty(),
            "Validation Error: mail message subject cannot be empty! {}",
            rule_context
        );
        assert!(
            !message.body.trim().is_empty(),
            "Validation Error: mail message body cannot be empty! {}",
            rule_context
        );
        if let Some(uid) = &message.uid {
            assert!(
                !uid.trim().is_empty(),
                "Validation Error: mail message uid cannot be empty! {}",
                rule_context
            );
        }
        if let Some(date) = &message.date {
            assert!(
                !date.trim().is_empty(),
                "Validation Error: mail message date cannot be empty! {}",
                rule_context
            );
        }
        if let Some(flags) = &message.flags {
            assert!(
                flags.iter().all(|flag| !flag.trim().is_empty()),
                "Validation Error: mail message flags cannot contain empty values! {}",
                rule_context
            );
        }
    }

    fn assert_mail_custom_responses(
        responses: Option<&[MailCustomResponse]>,
        command_event_type: &str,
        rule_context: &str,
    ) {
        if let Some(responses) = responses {
            for response in responses {
                assert!(
                    !response.command.trim().is_empty() && !response.response.trim().is_empty(),
                    "Validation Error: mail custom response command/response cannot be empty! {}",
                    rule_context
                );
                if let Some(args_contains) = &response.args_contains {
                    assert!(
                        args_contains.iter().all(|item| !item.trim().is_empty()),
                        "Validation Error: mail custom response args_contains cannot contain empty values! {}",
                        rule_context
                    );
                }
                if let Some(event_type) = &response.event_type {
                    assert!(
                        matches!(event_type.as_str(), "auth_attempt" | "exploit_attempt")
                            || event_type == command_event_type,
                        "Validation Error: mail custom response event_type is invalid! {}",
                        rule_context
                    );
                }
            }
        }
    }

    fn assert_smtp_config(source_rule: &YamlRule, rule_context: &str) {
        let smtp_config = serde_json::from_value::<SmtpRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match SMTP rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(banner) = &smtp_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: SMTP banner cannot be empty! {}",
                rule_context
            );
        }
        if let Some(hostname) = &smtp_config.hostname {
            assert!(
                !hostname.trim().is_empty(),
                "Validation Error: SMTP hostname cannot be empty! {}",
                rule_context
            );
        }
        assert_mail_credentials(
            smtp_config.credentials.as_deref(),
            smtp_config.require_auth.unwrap_or(false),
            rule_context,
        );
        if let Some(capabilities) = &smtp_config.capabilities {
            assert!(
                capabilities.iter().all(|item| !item.trim().is_empty()),
                "Validation Error: SMTP capabilities cannot contain empty values! {}",
                rule_context
            );
        }
        let recipients = smtp_config
            .accepted_recipients
            .as_deref()
            .unwrap_or_else(|| {
                panic!(
                    "Validation Error: SMTP accepted_recipients is required! {}",
                    rule_context
                )
            });
        assert!(
            !recipients.is_empty() && recipients.iter().all(|item| !item.trim().is_empty()),
            "Validation Error: SMTP accepted_recipients cannot be empty! {}",
            rule_context
        );
        assert_mail_custom_responses(
            smtp_config.custom_responses.as_deref(),
            "smtp_command",
            rule_context,
        );
    }

    fn assert_pop3_config(source_rule: &YamlRule, rule_context: &str) {
        let pop3_config = serde_json::from_value::<Pop3RuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match POP3 rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(banner) = &pop3_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: POP3 banner cannot be empty! {}",
                rule_context
            );
        }
        assert_mail_credentials(
            pop3_config.credentials.as_deref(),
            pop3_config.require_auth.unwrap_or(false),
            rule_context,
        );
        if let Some(capabilities) = &pop3_config.capabilities {
            assert!(
                capabilities.iter().all(|item| !item.trim().is_empty()),
                "Validation Error: POP3 capabilities cannot contain empty values! {}",
                rule_context
            );
        }
        let messages = pop3_config.messages.as_deref().unwrap_or_else(|| {
            panic!(
                "Validation Error: POP3 messages are required! {}",
                rule_context
            )
        });
        assert!(
            !messages.is_empty(),
            "Validation Error: POP3 messages cannot be empty! {}",
            rule_context
        );
        for message in messages {
            assert_mail_message(message, rule_context);
        }
        assert_mail_custom_responses(
            pop3_config.custom_responses.as_deref(),
            "pop3_command",
            rule_context,
        );
    }

    fn assert_imap_config(source_rule: &YamlRule, rule_context: &str) {
        let imap_config = serde_json::from_value::<ImapRuleConfig>(source_rule.config_yaml.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Validation Error: configYaml must match IMAP rule schema in {}: {:?}",
                    rule_context, err
                )
            });
        if let Some(banner) = &imap_config.banner {
            assert!(
                !banner.trim().is_empty(),
                "Validation Error: IMAP banner cannot be empty! {}",
                rule_context
            );
        }
        assert_mail_credentials(
            imap_config.credentials.as_deref(),
            imap_config.require_auth.unwrap_or(false),
            rule_context,
        );
        if let Some(capabilities) = &imap_config.capabilities {
            assert!(
                capabilities.iter().all(|item| !item.trim().is_empty()),
                "Validation Error: IMAP capabilities cannot contain empty values! {}",
                rule_context
            );
        }
        let has_messages = imap_config
            .messages
            .as_ref()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
            || imap_config
                .mailboxes
                .as_ref()
                .map(|items| !items.is_empty())
                .unwrap_or(false);
        assert!(
            has_messages,
            "Validation Error: IMAP messages or mailboxes are required! {}",
            rule_context
        );
        if let Some(messages) = &imap_config.messages {
            for message in messages {
                assert_mail_message(message, rule_context);
            }
        }
        if let Some(mailboxes) = &imap_config.mailboxes {
            for (name, messages) in mailboxes {
                assert!(
                    !name.trim().is_empty() && !messages.is_empty(),
                    "Validation Error: IMAP mailbox name/messages cannot be empty! {}",
                    rule_context
                );
                for message in messages {
                    assert_mail_message(message, rule_context);
                }
            }
        }
        assert_mail_custom_responses(
            imap_config.custom_responses.as_deref(),
            "imap_command",
            rule_context,
        );
    }

    fn assert_discovery_protocol_config(source_rule: &YamlRule, rule_context: &str) {
        let config = source_rule.config_yaml.as_object().unwrap_or_else(|| {
            panic!(
                "Validation Error: {} config must be an object. {}",
                source_rule.protocol, rule_context
            )
        });
        let non_empty_string = |field: &str| {
            config
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        };
        match source_rule.protocol.as_str() {
            "mongodb" => {
                assert!(
                    non_empty_string("server_version") && non_empty_string("hostname"),
                    "Validation Error: MongoDB server_version and hostname are required. {}",
                    rule_context
                );
                assert!(
                    config
                        .get("max_wire_version")
                        .and_then(serde_json::Value::as_i64)
                        .is_some_and(|value| (0..=100).contains(&value)),
                    "Validation Error: MongoDB max_wire_version must be within 0-100. {}",
                    rule_context
                );
            }
            "memcached" => assert!(
                non_empty_string("server_version"),
                "Validation Error: Memcached server_version is required. {}",
                rule_context
            ),
            "snmp" => {
                assert!(
                    non_empty_string("community")
                        && non_empty_string("system_description")
                        && non_empty_string("system_name")
                        && non_empty_string("system_location"),
                    "Validation Error: SNMP identity fields are required. {}",
                    rule_context
                );
                if let Some(oids) = config.get("oids").and_then(serde_json::Value::as_object) {
                    assert!(
                        oids.iter().all(|(oid, value)| {
                            oid.trim_start_matches('.')
                                .split('.')
                                .all(|part| part.parse::<u32>().is_ok())
                                && value.as_str().is_some()
                        }),
                        "Validation Error: SNMP oids must map numeric OIDs to strings. {}",
                        rule_context
                    );
                }
            }
            "mqtt" => assert!(
                config
                    .get("allow_anonymous")
                    .and_then(serde_json::Value::as_bool)
                    .is_some(),
                "Validation Error: MQTT allow_anonymous is required. {}",
                rule_context
            ),
            "vnc" => {
                assert!(
                    config
                        .get("protocol_version")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| matches!(value, "3.3" | "3.7" | "3.8")),
                    "Validation Error: VNC protocol_version must be 3.3, 3.7, or 3.8. {}",
                    rule_context
                );
                assert!(
                    config
                        .get("security_types")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|values| {
                            !values.is_empty()
                                && values.iter().all(|value| {
                                    value
                                        .as_str()
                                        .is_some_and(|name| matches!(name, "none" | "vnc_auth"))
                                })
                        }),
                    "Validation Error: VNC security_types contains an unsupported value. {}",
                    rule_context
                );
            }
            _ => unreachable!("discovery protocol validator received another protocol"),
        }
    }

    fn load_yaml_rules_for_audit() -> Vec<AuditedYamlRule> {
        let mut rules = Vec::new();
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rules_dir = manifest_dir.join("rules");

        fn visit_dir(
            dir: &std::path::Path,
            rules: &mut Vec<AuditedYamlRule>,
            base_dir: &std::path::Path,
        ) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dir(&path, rules, base_dir);
                    } else {
                        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                        if ext == "yaml" || ext == "yml" {
                            let content = std::fs::read(&path).unwrap_or_else(|err| {
                                panic!("Failed to read rule file '{:?}': {:?}", path, err)
                            });
                            let rule = serde_yaml::from_slice::<YamlRule>(&content).unwrap_or_else(
                                |err| panic!("Failed to parse rule file '{:?}': {:?}", path, err),
                            );
                            let relative_path = path
                                .strip_prefix(base_dir)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .to_string();
                            rules.push(AuditedYamlRule {
                                file_path: relative_path,
                                rule,
                            });
                        }
                    }
                }
            }
        }

        visit_dir(&rules_dir, &mut rules, &rules_dir);
        rules.sort_by_key(|entry| entry.rule.id);
        rules
    }

    #[test]
    fn test_rules_auditor_suite() {
        let yaml_rules = load_yaml_rules_for_audit();
        assert!(
            !yaml_rules.is_empty(),
            "Error: No simulation rules were loaded. Check rules/ directory."
        );

        let mut seen_ids = HashSet::new();

        for entry in &yaml_rules {
            let p = &entry.rule;
            let rule_context = format!("Rule ID: {} (Name: '{}')", p.id, p.name);

            // 1. 唯一性校验 (数字 ID 冲突防御)
            assert!(
                seen_ids.insert(p.id),
                "Conflict Error: Duplicate numeric ID found! {}",
                rule_context
            );

            // 2. 必填非空字段校验
            assert!(
                !p.name.trim().is_empty(),
                "Validation Error: name cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.name_en.trim().is_empty(),
                "Validation Error: name_en cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.category.trim().is_empty(),
                "Validation Error: category cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.protocol.trim().is_empty(),
                "Validation Error: protocol cannot be empty! {}",
                rule_context
            );
            assert!(
                ALLOWED_PROTOCOLS.contains(&p.protocol.as_str()),
                "Value Error: protocol must be one of {:?}! Got '{}' in {}",
                ALLOWED_PROTOCOLS,
                p.protocol,
                rule_context
            );
            assert!(
                !p.description_zh.trim().is_empty(),
                "Validation Error: description_zh cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.description_en.trim().is_empty(),
                "Validation Error: description_en cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.vendor.trim().is_empty(),
                "Validation Error: vendor cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.product.trim().is_empty(),
                "Validation Error: product cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.rule_version.trim().is_empty(),
                "Validation Error: ruleVersion cannot be empty! {}",
                rule_context
            );
            assert!(
                !p.references.is_empty()
                    && p.references
                        .iter()
                        .all(|reference| reference.starts_with("https://")),
                "Validation Error: references must contain HTTPS source URLs! {}",
                rule_context
            );
            assert!(
                !p.tags.is_empty() && p.tags.iter().all(|tag| !tag.trim().is_empty()),
                "Validation Error: tags cannot be empty! {}",
                rule_context
            );
            assert!(
                ALLOWED_SEVERITIES.contains(&p.severity.as_str()),
                "Value Error: severity must be one of {:?}! Got '{}' in {}",
                ALLOWED_SEVERITIES,
                p.severity,
                rule_context
            );

            // 3. 漏洞类别枚举属性合法性校验
            assert!(
                ALLOWED_CATEGORIES.contains(&p.category.as_str()),
                "Value Error: category must be one of {:?}! Got '{}' in {}",
                ALLOWED_CATEGORIES,
                p.category,
                rule_context
            );
            let expected_path_prefix = category_path_prefix(&p.protocol, &p.category);
            assert!(
                entry
                    .file_path
                    .replace('\\', "/")
                    .starts_with(expected_path_prefix),
                "Layout Error: rule file '{}' must be under '{}' for category '{}' in {}",
                entry.file_path,
                expected_path_prefix,
                p.category,
                rule_context
            );
            match p.category.as_str() {
                "cve_sim" => {
                    let cve = p.cve.as_deref().unwrap_or_else(|| {
                        panic!("Validation Error: cve_sim requires cve! {}", rule_context)
                    });
                    assert!(
                        is_valid_cve(cve),
                        "Validation Error: cve must match CVE-YYYY-NNNN format! Got '{}' in {}",
                        cve,
                        rule_context
                    );
                }
                _ => {
                    if let Some(cve) = &p.cve {
                        assert!(
                            is_valid_cve(cve),
                            "Validation Error: optional cve must match CVE-YYYY-NNNN format! Got '{}' in {}",
                            cve,
                            rule_context
                        );
                    }
                }
            }

            // 5. 默认端口合法性校验（必须非空且处于合理的 TCP 端口区间 [1, 65535]）
            if let Some(port) = p.default_port {
                assert!(
                    (1..=65535).contains(&port),
                    "Value Error: defaultPort must be within 1-65535! Got '{}' in {}",
                    port,
                    rule_context
                );
            }

            match p.protocol.as_str() {
                "http" => {
                    assert!(
                        (100000..=199999).contains(&p.id),
                        "Boundary Error: HTTP rule ID must be within 100000-199999. {}",
                        rule_context
                    );
                    assert_http_id_partition(p, &rule_context);
                    assert_http_config(p, &rule_context);
                }
                "redis" => {
                    assert!(
                        (300000..=309999).contains(&p.id),
                        "Boundary Error: Redis rule ID must be within 300000-309999. {}",
                        rule_context
                    );
                    assert_redis_id_partition(p, &rule_context);
                    assert_redis_config(p, &rule_context);
                }
                "smtp" => {
                    assert!(
                        (400000..=409999).contains(&p.id),
                        "Boundary Error: SMTP rule ID must be within 400000-409999. {}",
                        rule_context
                    );
                    assert_mail_id_partition(p, &rule_context, "SMTP", 400000);
                    assert_smtp_config(p, &rule_context);
                }
                "pop3" => {
                    assert!(
                        (410000..=419999).contains(&p.id),
                        "Boundary Error: POP3 rule ID must be within 410000-419999. {}",
                        rule_context
                    );
                    assert_mail_id_partition(p, &rule_context, "POP3", 410000);
                    assert_pop3_config(p, &rule_context);
                }
                "imap" => {
                    assert!(
                        (420000..=429999).contains(&p.id),
                        "Boundary Error: IMAP rule ID must be within 420000-429999. {}",
                        rule_context
                    );
                    assert_mail_id_partition(p, &rule_context, "IMAP", 420000);
                    assert_imap_config(p, &rule_context);
                }
                "ssh" => {
                    assert!(
                        (200000..=299999).contains(&p.id),
                        "Boundary Error: SSH rule ID must be within 200000-299999. {}",
                        rule_context
                    );
                    assert_ssh_id_partition(p, &rule_context);
                    assert_ssh_config(p, &rule_context);
                }
                "ftp" => {
                    assert!(
                        (600000..=699999).contains(&p.id),
                        "Boundary Error: FTP rule ID must be within 600000-699999. {}",
                        rule_context
                    );
                    assert_ftp_id_partition(p, &rule_context);
                    assert_ftp_config(p, &rule_context);
                }
                "rdp" => {
                    assert!(
                        (620000..=629999).contains(&p.id),
                        "Boundary Error: RDP rule ID must be within 620000-629999. {}",
                        rule_context
                    );
                    assert_rdp_id_partition(p, &rule_context);
                    assert_rdp_config(p, &rule_context);
                }
                "telnet" => {
                    assert!(
                        (630000..=639999).contains(&p.id),
                        "Boundary Error: Telnet rule ID out of bounds. {}",
                        rule_context
                    );
                    assert!(
                        p.config_yaml.is_object(),
                        "Validation Error: Telnet config must be an object. {}",
                        rule_context
                    );
                }
                "mysql" => {
                    assert!(
                        (310000..=319999).contains(&p.id),
                        "Boundary Error: MySQL rule ID out of bounds. {}",
                        rule_context
                    );
                    assert!(
                        p.config_yaml.is_object(),
                        "Validation Error: MySQL config must be an object. {}",
                        rule_context
                    );
                }
                "postgresql" => {
                    assert!(
                        (320000..=329999).contains(&p.id),
                        "Boundary Error: PostgreSQL rule ID out of bounds. {}",
                        rule_context
                    );
                    assert!(
                        p.config_yaml.is_object(),
                        "Validation Error: PostgreSQL config must be an object. {}",
                        rule_context
                    );
                }
                "smb" => {
                    assert!(
                        (700000..=709999).contains(&p.id),
                        "Boundary Error: SMB rule ID out of bounds. {}",
                        rule_context
                    );
                    assert!(
                        p.config_yaml.is_object(),
                        "Validation Error: SMB config must be an object. {}",
                        rule_context
                    );
                }
                "ldap" => {
                    assert!(
                        (710000..=719999).contains(&p.id),
                        "Boundary Error: LDAP rule ID out of bounds. {}",
                        rule_context
                    );
                    assert!(
                        p.config_yaml
                            .get("base_dn")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| !value.trim().is_empty()),
                        "Validation Error: LDAP base_dn is required. {}",
                        rule_context
                    );
                }
                "dns" => {
                    assert!(
                        (500000..=509999).contains(&p.id),
                        "Boundary Error: DNS rule ID out of bounds. {}",
                        rule_context
                    );
                    let records = p
                        .config_yaml
                        .get("records")
                        .and_then(serde_json::Value::as_object);
                    assert!(
                        records.is_some_and(|records| !records.is_empty()),
                        "Validation Error: DNS records must be a non-empty object. {}",
                        rule_context
                    );
                }
                "mongodb" => {
                    assert!(
                        (330000..=339999).contains(&p.id),
                        "Boundary Error: MongoDB rule ID out of bounds. {}",
                        rule_context
                    );
                    assert_discovery_protocol_config(p, &rule_context);
                }
                "memcached" => {
                    assert!(
                        (340000..=349999).contains(&p.id),
                        "Boundary Error: Memcached rule ID out of bounds. {}",
                        rule_context
                    );
                    assert_discovery_protocol_config(p, &rule_context);
                }
                "snmp" => {
                    assert!(
                        (510000..=519999).contains(&p.id),
                        "Boundary Error: SNMP rule ID out of bounds. {}",
                        rule_context
                    );
                    assert_discovery_protocol_config(p, &rule_context);
                }
                "mqtt" => {
                    assert!(
                        (520000..=529999).contains(&p.id),
                        "Boundary Error: MQTT rule ID out of bounds. {}",
                        rule_context
                    );
                    assert_discovery_protocol_config(p, &rule_context);
                }
                "vnc" => {
                    assert!(
                        (640000..=649999).contains(&p.id),
                        "Boundary Error: VNC rule ID out of bounds. {}",
                        rule_context
                    );
                    assert_discovery_protocol_config(p, &rule_context);
                }
                _ => unreachable!("protocol was validated before protocol schema audit"),
            }

            assert_safe_simulation_content(p, &rule_context);
        }
    }
}
