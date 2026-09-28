use super::toml::{selecting_config_of_node, Proxy};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use rand::seq::SliceRandom;
use serde_json::json;
use serde_qs as qs;
use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

pub async fn build_v2ray_link(
    toml_proxies: &Proxy,
    csv_tag: String,
    csv_addr: String,
    csv_port: u16,
    uri_port: u16,
    uri_userid: u8,
    uri_proxy_type: String,
    fingerprint: String,
    http_ports: &[u16; 7],   // 非TLS 模式下，http的端口
    https_ports: &[u16; 6],  // TLS 模式下，https的端口
    ech_config_list: String, // ECH 配置内容
) -> String {
    for _ in 0..100 {
        match selecting_config_of_node(toml_proxies, uri_proxy_type.clone(), uri_userid) {
            Ok(prxy) => {
                let node_type = prxy.node_type.as_str();
                let toml_tag: String = prxy.node.remarks_prefix;
                let host: String = prxy.node.host;
                let server_name: String = prxy.node.server_name.unwrap_or_default();
                let toml_ss_tls = prxy.node.tls.unwrap_or(true);
                let toml_network = prxy.node.network.unwrap_or("ws".to_string()).to_lowercase();
                let toml_mode = prxy.node.mode.unwrap_or_default().to_lowercase();
                let path: String = prxy.node.path;
                let uuid: String = prxy
                    .node
                    .uuid
                    .unwrap_or("00000000-0000-0000-0000-000000000000".to_string());
                let method: String = prxy.node.method.unwrap_or("none".to_string()); // shadowSocks的加密方式，默认是none
                let password: String = prxy.node.password.unwrap_or("unset".to_string());

                // 不知道ss的xhttp的分享链接格式
                if node_type == "ss" && toml_network != "ws" && toml_mode != "" {
                    continue;
                }

                let condition = if ["vless", "trojan", "vmess"].contains(&node_type) {
                    host.ends_with("workers.dev")
                } else {
                    !toml_ss_tls // ss协议的
                };

                let (security, mut ports, reverse_ports) = match condition
                    && (ech_config_list.is_empty()
                        || (!ech_config_list.is_empty()
                            && !["vless", "trojan"].contains(&node_type)))
                {
                    true => ("none", http_ports.to_vec(), https_ports.to_vec()),
                    false => ("tls", https_ports.to_vec(), http_ports.to_vec()),
                };
                // 注意：不会检查配置文件的端口是否合法
                ports = prxy.node.random_ports.unwrap_or(ports);

                let (port, is_continue) = match (uri_port == 0, csv_port == 0) {
                    (true, true) => (*ports.choose(&mut rand::thread_rng()).unwrap(), false), // uri端口与csv端口都没有，就随机选一个端口
                    (true, false) => (csv_port, reverse_ports.contains(&csv_port)), // csv端口有，就使用csv端口
                    (false, true) => (uri_port, reverse_ports.contains(&uri_port)), // uri端口有，就使用uri端口
                    (false, false) => (uri_port, false), // uri端口与csv端口都有，不管端口是否能使用，都使用uri端口
                };

                // 端口不匹配，开启tls和没有开启tls的端口不同，需要换另一个配置
                if is_continue {
                    continue;
                }

                // 处理IPv6地址，需要加上中括号
                let formatted_addr = format_ip(&csv_addr);
                // 节点的别名
                let remarks = match (csv_tag.trim().is_empty(), toml_tag.is_empty()) {
                    (true, true) => format!("{}:{}", formatted_addr, port), // cvs_tag与toml_tag都没有
                    (false, true) => format!("{}|{}:{}", csv_tag, formatted_addr, port), // 仅有csv_tag
                    (true, false) => format!("{}|{}:{}", toml_tag, formatted_addr, port), // 仅有toml_tag
                    (false, false) => {
                        format!("{}{}|{}:{}", toml_tag, csv_tag, formatted_addr, port)
                    } // 既有csv_tag，也有toml_tag
                };

                match node_type {
                    "vless" => {
                        let link = build_vless_link(
                            &remarks,
                            csv_addr.clone(),
                            port,
                            uuid,
                            security,
                            host,
                            toml_network,
                            toml_mode,
                            server_name,
                            path,
                            fingerprint,
                            ech_config_list,
                        );
                        return link;
                    }
                    "vmess" => {
                        let link = build_vmess_link(
                            &remarks,
                            csv_addr.clone(),
                            port,
                            uuid,
                            security,
                            host,
                            toml_network,
                            toml_mode,
                            server_name,
                            path,
                        );
                        return link;
                    }
                    "trojan" => {
                        let link = build_trojan_linnk(
                            &remarks,
                            csv_addr.clone(),
                            port,
                            password,
                            security,
                            host,
                            toml_network,
                            toml_mode,
                            server_name,
                            path,
                            fingerprint,
                            ech_config_list,
                        );
                        return link;
                    }
                    "ss" => {
                        let link = build_ss_link(
                            &remarks,
                            csv_addr.clone(),
                            port,
                            method,
                            password,
                            toml_ss_tls,
                            host,
                            path,
                        );
                        return link;
                    }
                    _ => {}
                }
            }
            Err(err) => eprintln!("警告：{}", err),
        }
    }
    "".to_string()
}

fn build_ss_link(
    remarks: &str,
    server: String,
    port: u16,
    method: String,
    password: String,
    toml_tls: bool,
    host: String,
    path: String,
) -> String {
    let base64_encoded = URL_SAFE.encode(format!("{}:{}", method, password).as_bytes());

    let plugin = match toml_tls {
        true => format!(
            "v2ray-plugin;tls;mux=0;mode=websocket;path={};host={}",
            path, host
        )
        .replace("=", "%3D"),
        false => format!(
            "v2ray-plugin;mux=0;mode=websocket;path={};host={}",
            path, host
        )
        .replace("=", "%3D"),
    };

    let ss_link = format!(
        "ss://{}@{}:{}?plugin={}#{}",
        base64_encoded,
        format_ip(&server),
        port,
        plugin,
        remarks
    );
    ss_link
}

fn build_trojan_linnk(
    remarks: &str,
    server: String,
    port: u16,
    password: String,
    security: &str,
    host: String,
    toml_network: String,
    toml_mode: String,
    sni: String,
    path: String,
    fingerprint: String,
    ech_config_list: String,
) -> String {
    let encoding_remarks = urlencoding::encode(&remarks);

    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &sni);
    params.insert("fp", &fingerprint);
    params.insert("type", &toml_network);
    params.insert("mode", &toml_mode);
    params.insert("host", &host);
    params.insert("path", &path);
    params.insert("alpn", choose_alpn(&toml_network));
    params.insert("ech", &ech_config_list);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str: String = serialize_to_query_string(params);
    let trojan_link = format!(
        "trojan://{password}@{}:{port}/?{all_params_str}#{encoding_remarks}",
        format_ip(&server)
    );

    trojan_link
}

fn build_vless_link(
    remarks: &str,
    server: String,
    port: u16,
    uuid: String,
    security: &str,
    host: String,
    toml_network: String,
    toml_mode: String,
    sni: String,
    path: String,
    fingerprint: String,
    ech_config_list: String,
) -> String {
    let encoding_remarks = urlencoding::encode(remarks);

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", &toml_network);
    params.insert("mode", &toml_mode);
    params.insert("host", &host);
    params.insert("path", &path);
    params.insert("sni", &sni);
    params.insert("fp", &fingerprint);
    params.insert("alpn", choose_alpn(&toml_network));
    params.insert("ech", &ech_config_list);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);
    let vless_link = format!(
        "vless://{uuid}@{}:{port}/?{all_params_str}#{encoding_remarks}",
        format_ip(&server)
    );

    vless_link
}

fn build_vmess_link(
    remarks: &str,
    server: String,
    port: u16,
    uuid: String,
    security: &str,
    host: String,
    toml_network: String, // type => net字段
    toml_mode: String,    // mode => type字段
    sni: String,
    path: String,
) -> String {
    let tls = match security == "tls" {
        true => "tls",
        false => "",
    };
    let vmess_type = match toml_network.as_str() == "ws" {
        true => "none",
        false => toml_mode.as_str(),
    };
    let vmess = json!({
      "v": "2",
      "ps": remarks,
      "add": server,
      "port": port,
      "id": uuid,
      "aid": "0",
      "scy": "zero",
      "net": toml_network,
      "type": vmess_type,
      "host": host,
      "path": path,
      "tls": tls,
      "sni": sni,
      "alpn": "",
      "fp": "",
      "insecure": "0",
      "pcs": ""
    });

    format!("vmess://{}", URL_SAFE.encode(vmess.to_string()))
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();

    all_params_str
}

fn format_ip(ip: &str) -> String {
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V6(_)) => format!("[{}]", ip),
        Ok(IpAddr::V4(_)) => ip.to_string(),
        Err(_) => ip.to_string(),
    }
}

fn choose_alpn(protocol: &str) -> &'static str {
    match protocol {
        "ws" => "http/1.1",
        "xhttp" => "h2",
        _ => "",
    }
}
