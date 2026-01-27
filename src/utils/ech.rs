use super::toml::EchArgs;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use reqwest::Client;
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const TYPE_HTTPS: u16 = 65;
const TIMEOUT_DOH_QUERY: Duration = Duration::from_secs(5); // DoH查询超时时间
const CACHE_TTL: Duration = Duration::from_secs(300); // 联网获取的，ECH 缓存有效期，单位秒，默认5分钟

struct EchConfigCache;

impl EchConfigCache {
    fn generate_cache_path(domain: &str, dns_server: &str) -> PathBuf {
        let cache_key = format!("{}:{}", domain, dns_server);
        let mut hasher = DefaultHasher::new();
        cache_key.hash(&mut hasher);
        let hash = hasher.finish();

        let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        let project_root = current_exe.parent().unwrap_or_else(|| Path::new("."));
        let cache_dir = project_root.join("ech_cache");
        fs::create_dir_all(&cache_dir).ok();

        cache_dir.join(format!("{}.cache", hash))
    }

    fn is_cache_valid(file_path: &PathBuf) -> bool {
        if let Ok(metadata) = fs::metadata(file_path) {
            if let Ok(modified) = metadata.modified() {
                let elapsed = SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                return elapsed < CACHE_TTL;
            }
        }
        false
    }

    fn load_cached_data(file_path: &PathBuf) -> Option<String> {
        if file_path.exists() && Self::is_cache_valid(file_path) {
            fs::read_to_string(file_path).ok()
        } else {
            None
        }
    }

    fn store_cached_data(file_path: &PathBuf, data: &str) {
        if !data.is_empty() {
            fs::write(file_path, data).ok();
        }
    }
}

struct EchConfigFetcher;

impl EchConfigFetcher {
    async fn fetch_ech_data(domain: &str, dns_server: &str) -> Result<Bytes> {
        let ech_base64 = Self::query_https_record(domain, dns_server).await?;

        if ech_base64.is_empty() {
            return Err(anyhow!("未找到 ECH 参数"));
        }

        let raw = general_purpose::STANDARD
            .decode(ech_base64)
            .map_err(|e| anyhow!("ECH 解码失败: {}", e))?;

        Ok(Bytes::from(raw))
    }

    async fn query_https_record(domain: &str, dns_server: &str) -> Result<String> {
        let doh_url = if dns_server.starts_with("http") {
            dns_server.to_string()
        } else {
            format!("https://{}", dns_server)
        };

        Self::query_doh_server(domain, &doh_url).await
    }

    async fn query_doh_server(domain: &str, doh_url: &str) -> Result<String> {
        let client = Client::builder().timeout(TIMEOUT_DOH_QUERY).build()?;

        let dns_query = DnsQueryBuilder::build(domain, TYPE_HTTPS);
        let dns_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&dns_query);
        let url = format!("{}?dns={}", doh_url, dns_base64);

        let response = client
            .get(&url)
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message")
            .header("User-Agent", "ech-workers-rust/1.0")
            .send()
            .await?;

        if response.status().is_success() {
            let body = response.bytes().await?;
            DnsResponseParser::parse(&body).await
        } else {
            Err(anyhow!("DoH 服务器返回错误: {}", response.status()))
        }
    }
}

struct DnsQueryBuilder;

impl DnsQueryBuilder {
    fn build(domain: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::with_capacity(512);

        // DNS header
        query.extend_from_slice(&[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        // QNAME
        for label in domain.split('.') {
            if !label.is_empty() {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
        }
        query.push(0); // End of QNAME

        // QTYPE and QCLASS
        query.extend_from_slice(&[(qtype >> 8) as u8, (qtype & 0xFF) as u8, 0x00, 0x01]);

        query
    }
}

struct DnsResponseParser;

impl DnsResponseParser {
    async fn parse(response: &[u8]) -> Result<String> {
        if response.len() < 12 {
            return Err(anyhow!("响应过短"));
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Err(anyhow!("无应答记录"));
        }

        let mut offset = Self::skip_question_section(response);

        for _ in 0..ancount {
            if let Some(ech) = Self::parse_answer_record(response, &mut offset) {
                return Ok(ech);
            }
        }

        Err(anyhow!("未找到 HTTPS 记录"))
    }

    fn skip_question_section(response: &[u8]) -> usize {
        let mut offset = 12;

        // Skip QNAME
        while offset < response.len() && response[offset] != 0 {
            offset += response[offset] as usize + 1;
        }
        offset + 5 // Skip QTYPE, QCLASS, and null terminator
    }

    fn parse_answer_record(response: &[u8], offset: &mut usize) -> Option<String> {
        if *offset >= response.len() {
            return None;
        }

        // Skip name
        Self::skip_name(response, offset);

        if *offset + 10 > response.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
        *offset += 8;
        let data_len = u16::from_be_bytes([response[*offset], response[*offset + 1]]) as usize;
        *offset += 2;

        if *offset + data_len > response.len() {
            return None;
        }

        let data = &response[*offset..*offset + data_len];
        *offset += data_len;

        if rr_type == TYPE_HTTPS {
            HttpsRecordParser::parse(data)
        } else {
            None
        }
    }

    fn skip_name(response: &[u8], offset: &mut usize) {
        if response[*offset] & 0xC0 == 0xC0 {
            *offset += 2;
        } else {
            while *offset < response.len() && response[*offset] != 0 {
                *offset += response[*offset] as usize + 1;
            }
            *offset += 1;
        }
    }
}

struct HttpsRecordParser;

impl HttpsRecordParser {
    fn parse(data: &[u8]) -> Option<String> {
        if data.len() < 2 {
            return None;
        }

        let mut offset = 2;

        // Skip priority and target name
        offset = Self::skip_priority_and_target(data, offset);

        // Parse SvcParams looking for ECH key (key = 5)
        while offset + 4 <= data.len() {
            let key = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + length > data.len() {
                break;
            }

            if key == 5 {
                // ECH key found
                return Some(general_purpose::STANDARD.encode(&data[offset..offset + length]));
            }

            offset += length;
        }

        None
    }

    fn skip_priority_and_target(data: &[u8], mut offset: usize) -> usize {
        // Skip priority
        if offset < data.len() && data[offset] == 0 {
            offset += 1;
        } else {
            while offset < data.len() && data[offset] != 0 {
                offset += data[offset] as usize + 1;
            }
            offset += 1;
        }
        offset
    }
}

/// 获取 ECH 配置，带缓存机制
async fn fetch_ech_config(domain: Option<&str>, dns_server: Option<&str>) -> String {
    let domain = domain.unwrap_or("cloudflare-ech.com");
    let dns_server = dns_server.unwrap_or("dns.alidns.com/dns-query");
    let cache_file = EchConfigCache::generate_cache_path(domain, dns_server);

    // 检查缓存
    if let Some(cached_data) = EchConfigCache::load_cached_data(&cache_file) {
        return cached_data;
    }

    // 缓存未命中，重新获取
    let result = match EchConfigFetcher::fetch_ech_data(domain, dns_server).await {
        Ok(ech_data) => {
            let encoded = general_purpose::STANDARD.encode(&ech_data);
            EchConfigCache::store_cached_data(&cache_file, &encoded);
            encoded
        }
        Err(_) => String::new(),
    };

    result
}

pub async fn process_ech(toml_ech_args: EchArgs, uri_fetch_ech: &bool) -> String {
    let enble_ech = toml_ech_args.enble_ech == Some(true);
    let dns_server = toml_ech_args
        .doh
        .clone()
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let ech_domain = toml_ech_args
        .ech_domain
        .clone()
        .unwrap_or_else(|| "cloudflare-ech.com".to_string());
    let mut ech_config_list = toml_ech_args.ech_config_list.clone().unwrap_or_default();
    if *uri_fetch_ech && enble_ech {
        ech_config_list = fetch_ech_config(Some(&ech_domain), Some(&dns_server)).await;
    } else if !enble_ech && !ech_config_list.is_empty() {
        ech_config_list = "".to_string();
    }
    ech_config_list
}
