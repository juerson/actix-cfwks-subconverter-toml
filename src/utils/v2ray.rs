use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_qs as qs;
use std::collections::BTreeMap;
use toml::Value;

pub fn batch_process_v2ray_links(
    ip_with_port_vec: &Vec<String>,
    ip_with_none_port_vec: &Vec<String>,
    toml_value: &Value,
    userid: usize,
    proxy_type: &str,
    set_port: u16,
) -> Vec<String> {
    let mut links = Vec::new();

    match ip_with_port_vec.is_empty() {
        true => {
            ip_with_none_port_vec.iter().for_each(|server| {
                let link = build_v2ray_link(
                    toml_value.clone(),
                    userid,
                    proxy_type,
                    server.clone(),
                    set_port,
                );
                links.push(link);
            });
        }
        false => {
            ip_with_port_vec.iter().for_each(|item| {
                let parts: Vec<&str> = item.split(',').collect();
                match parts.len() == 2 {
                    true => {
                        let ip = parts[0].to_string();
                        let port = parts[1].parse::<u16>().unwrap_or(set_port);
                        let link =
                            build_v2ray_link(toml_value.clone(), userid, proxy_type, ip, port);
                        links.push(link);
                    }
                    false => println!("无效数据: {}", item),
                }
            });
        }
    }
    links
}

fn build_v2ray_link(
    toml_value: Value,
    userid: usize,
    proxy_type: &str,
    set_server: String,
    set_port: u16,
) -> String {
    let proxy: toml::Value = crate::utils::toml::get_toml_proxy(toml_value, userid, proxy_type);

    // 候补端口列表，后续随机选择一个端口
    let alternate_ports: Vec<u16> = vec![443, 2053, 2083, 2087, 2096, 8443];
    if proxy.is_table() {
        match proxy.get("uuid") {
            Some(_) => {
                let vless_link = build_vless_link(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return vless_link.clone();
            }
            None => "".to_string(),
        };
        match proxy.get("password") {
            Some(_) => {
                let trojan_link = build_trojan_linnk(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return trojan_link.clone();
            }
            None => "".to_string(),
        };
    }
    "".to_string()
}

fn build_trojan_linnk(
    toml_value: &Value,
    ports: Vec<u16>,
    server: String,
    set_port: u16,
) -> String {
    let (remarks_prefix, host, server_name, path, random_ports, password) =
        crate::utils::toml::get_toml_parameters(toml_value, ports, "password".to_string());

    let mut port = match set_port == 0 {
        true => random_ports
            .choose(&mut thread_rng())
            .copied()
            .unwrap_or(443),
        false => set_port,
    };

    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    // 主要处理workers.dev没有开启tls情况的端口问题（代理软件中也没有开启分片的情况）
    match [443, 2053, 2083, 2087, 2096, 8443].contains(&port) && security == "none" {
        true => {
            port = [80, 8080, 8880, 2052, 2082, 2086, 2095]
                .choose(&mut thread_rng())
                .copied()
                .unwrap()
        }
        false => port = port,
    }

    let remarks = format!("{}|{}:{}", remarks_prefix, server, port);
    let encoding_remarks = urlencoding::encode(&remarks);

    let fingerprint = crate::utils::common::random_fingerprint();

    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &server_name);
    params.insert("fp", &fingerprint);
    params.insert("type", "ws");
    params.insert("host", &host);
    params.insert("path", &path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);
    let trojan_link =
        format!("trojan://{password}@{server}:{port}/?{all_params_str}#{encoding_remarks}");

    trojan_link
}

fn build_vless_link(toml_value: &Value, ports: Vec<u16>, server: String, set_port: u16) -> String {
    let (remarks_prefix, host, server_name, path, random_ports, uuid) =
        crate::utils::toml::get_toml_parameters(toml_value, ports, "uuid".to_string());

    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    let mut port = match set_port == 0 {
        true => random_ports
            .choose(&mut thread_rng())
            .copied()
            .unwrap_or(443),
        false => set_port,
    };

    // 主要处理workers.dev没有开启tls情况的端口问题（代理软件中也没有开启分片的情况）
    match [443, 2053, 2083, 2087, 2096, 8443].contains(&port) && security == "none" {
        true => {
            port = [80, 8080, 8880, 2052, 2082, 2086, 2095]
                .choose(&mut thread_rng())
                .copied()
                .unwrap()
        }
        false => port = port,
    }

    let remarks = format!("{}|{}:{}", remarks_prefix, server, port);
    let encoding_remarks = urlencoding::encode(&remarks);

    let fingerprint = crate::utils::common::random_fingerprint();

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", "ws");
    params.insert("host", &host);
    params.insert("path", &path);
    params.insert("sni", &server_name);
    params.insert("fp", &fingerprint);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);
    let vless_link = format!("vless://{uuid}@{server}:{port}/?{all_params_str}#{encoding_remarks}");

    vless_link
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();

    all_params_str
}
