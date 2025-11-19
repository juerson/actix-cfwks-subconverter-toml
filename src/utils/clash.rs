use crate::utils::toml::{selecting_config_of_node, Proxy};
use rand::seq::SliceRandom;
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;

pub fn build_clash_json(
    toml_proxies: &Proxy,
    csv_tag: String,
    csv_addr: String,
    csv_port: u16,
    uri_port: u16,
    uri_userid: u8,
    uri_proxy_type: String,
    fingerprint: String,
    http_ports: &[u16; 7],  // 非TLS 模式下，http的端口
    https_ports: &[u16; 6], // TLS 模式下，https的端口
) -> (String, JsonValue) {
    for _ in 0..100 {
        match selecting_config_of_node(toml_proxies, uri_proxy_type.clone(), uri_userid) {
            Ok(prxy) => {
                let node_type = prxy.node_type.as_str();
                let toml_tag: String = prxy.node.remarks_prefix;
                let host: String = prxy.node.host;
                let server_name: String = prxy.node.server_name.unwrap_or_default();
                let toml_ss_tls = prxy.node.tls.unwrap_or(true);
                let toml_type = prxy.node.network.unwrap_or("ws".to_string()).to_lowercase();
                let toml_mode = prxy.node.mode.unwrap_or_default().to_lowercase();
                let path: String = prxy.node.path;

                // class.meta、mihomo不支持xhttp协议的，其他的协议，诸如：tcp、kcp、httpupgrade、h2、quic、grpc的暂不考虑支持
                if toml_mode != "" && toml_type != "ws" {
                    continue;
                }

                let condition = if ["vless", "trojan", "vmess"].contains(&node_type) {
                    host.ends_with("workers.dev")
                } else {
                    !toml_ss_tls // ss协议的
                };

                let (mut ports, reverse_ports) = match condition {
                    true => (http_ports.to_vec(), https_ports.to_vec()),
                    false => (https_ports.to_vec(), http_ports.to_vec()),
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
                // 节点的别名
                let remarks = match (csv_tag.trim().is_empty(), toml_tag.is_empty()) {
                    (true, true) => format!("{}:{}", csv_addr, port), // cvs_tag与toml_tag都没有
                    (false, true) => format!("{}|{}:{}", csv_tag, csv_addr, port), // 仅有csv_tag
                    (true, false) => format!("{}|{}:{}", toml_tag, csv_addr, port), // 仅有toml_tag
                    (false, false) => format!("{}{}|{}:{}", toml_tag, csv_tag, csv_addr, port), // 既有csv_tag，也有toml_tag
                };

                match node_type {
                    "vless" => {
                        let (remarks, jsonvalue) = build_vless_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.uuid.unwrap_or_default(),
                            host,
                            server_name,
                            path,
                            fingerprint,
                        );
                        return (remarks, jsonvalue);
                    }
                    "vmess" => {
                        let (remarks, jsonvalue) = build_vmess_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.uuid.unwrap_or_default(),
                            host,
                            server_name,
                            path,
                        );
                        return (remarks, jsonvalue);
                    }
                    "trojan" => {
                        let (remarks, jsonvalue) = build_trojan_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.password.unwrap_or_default(),
                            host,
                            server_name,
                            path,
                            fingerprint,
                        );
                        return (remarks, jsonvalue);
                    }
                    "ss" => {
                        let (remarks, jsonvalue) = build_ss_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.password.unwrap_or("none".to_string()),
                            toml_ss_tls,
                            host,
                            path,
                        );
                        return (remarks, jsonvalue);
                    }
                    _ => {
                        return ("".to_string(), JsonValue::Null);
                    }
                }
            }
            Err(err) => eprintln!("警告：{}", err),
        }
    }
    return ("".to_string(), JsonValue::Null);
}

fn build_ss_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_tls: bool,
    toml_host: String,
    toml_path: String,
) -> (String, serde_json::Value) {
    let ss_with_jsonvalue = json!({
        "name": remarks,
        "type": "ss",
        "server": csv_addr,
        "port": port,
        "cipher": "none",
        "password": toml_password,
        "udp": false,
        "plugin": "v2ray-plugin",
        "plugin-opts": {
            "mode": "websocket",
            "path": toml_path,
            "host": toml_host,
            "tls": toml_tls,
            "mux": false
        }
    });

    (remarks, ss_with_jsonvalue)
}

fn build_trojan_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, serde_json::Value) {
    let trojan_with_jsonvalue = json!({
        "type": "trojan",
        "name": remarks,
        "server": csv_addr,
        "port": port,
        "password": toml_password,
        "network": "ws",
        "udp": false,
        "sni": toml_server_name,
        "client-fingerprint": fingerprint,
        "skip-cert-verify": true,
        "ws-opts": {
            "path": toml_path,
            "headers": {"Host": toml_host}
        }
    });

    (remarks, trojan_with_jsonvalue)
}

fn build_vless_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_uuid: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, serde_json::Value) {
    let tls = match !toml_host.ends_with("workers.dev") {
        true => true,
        false => false,
    };
    let vless_with_jsonvalue = json!({
        "type": "vless",
        "name": remarks,
        "server": csv_addr,
        "port": port,
        "uuid": toml_uuid,
        "network": "ws",
        "tls": tls,
        "udp": false,
        "servername": toml_server_name,
        "client-fingerprint": fingerprint,
        "skip-cert-verify": true,
        "ws-opts": {
            "path": toml_path,
            "headers": {"Host": toml_host}
        }
    });

    (remarks, vless_with_jsonvalue)
}

fn build_vmess_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_uuid: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
) -> (String, serde_json::Value) {
    let tls = match !toml_host.ends_with("workers.dev") {
        true => true,
        false => false,
    };
    let vmess_with_jsonvalue = json!({
    "name": remarks,
    "port": port,
    "server": csv_addr,
    "type": "vmess",
    "uuid": toml_uuid,
    "alterId": 0,
    "cipher": "zero",
    "udp": false,
    "tls": tls,
    "skip-cert-verify": true,
    "servername": toml_server_name,
    "network": "ws",
    "ws-opts": {
        "path": toml_path,
        "headers": {
        "Host": toml_host
        }
    }});

    (remarks, vmess_with_jsonvalue)
}

pub fn add_clash_template(clash_template: &mut YamlValue, clash_data: Vec<(String, String)>) {
    // 处理节点信息
    if let Some(outside_proxies) = clash_template.get_mut("proxies") {
        if let serde_yaml::Value::Sequence(array) = outside_proxies {
            array.clear(); // 清空数组

            let proxies_vec: Vec<serde_yaml::Value> = clash_data
                .iter()
                .filter_map(|(_k, v)| {
                    // 将 JSON 字符串解析为 serde_json::Value
                    let json_value: JsonValue = serde_json::from_str(v).unwrap();
                    // 将 serde_json::Value 转换为 serde_yaml::Value
                    let yaml_value: YamlValue =
                        serde_yaml::from_str(&serde_json::to_string(&json_value).unwrap()).unwrap();
                    Some(yaml_value)
                })
                .collect::<Vec<_>>()
                .to_vec();
            array.extend(proxies_vec);
        }
    }
    // 处理代理组名称
    if let Some(proxy_groups) = clash_template.get_mut("proxy-groups") {
        if let YamlValue::Sequence(array) = proxy_groups {
            array.iter_mut().for_each(|groups| {
                groups.get_mut("proxies").and_then(|proxies_seq| {
                    if let YamlValue::Sequence(ref mut seq) = proxies_seq {
                        let mut contains_s01 = false;
                        let mut filtered_s01_with_proxies: Vec<YamlValue> = Vec::new();
                        // 遍历并处理 proxies 数组（里面的proxies字段值）
                        seq.drain(..).for_each(|item| {
                            if let YamlValue::String(ref s) = item {
                                match s == "s01" {
                                    true => {
                                        contains_s01 = true;
                                    }
                                    false => filtered_s01_with_proxies.push(item),
                                }
                            }
                        });
                        match contains_s01 {
                            true => {
                                filtered_s01_with_proxies.extend(
                                    clash_data
                                        .iter()
                                        .map(|(k, _v)| k.to_string())
                                        .collect::<Vec<_>>()
                                        .to_vec()
                                        .into_iter()
                                        .map(|name| YamlValue::String(name.to_string())),
                                );
                            }
                            false => {}
                        }
                        *seq = filtered_s01_with_proxies;
                    }
                    return proxies_seq.as_sequence_mut();
                });
            });
        }
    }
}
