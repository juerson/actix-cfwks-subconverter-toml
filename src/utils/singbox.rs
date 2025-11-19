use crate::utils::toml::{selecting_config_of_node, Proxy};
use rand::seq::SliceRandom;
use serde_json::{json, Value as JsonValue};

pub fn build_singbox_json(
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

                // singbox不支持xhttp协议的，其他的协议，诸如：tcp、kcp、httpupgrade、h2、quic、grpc的暂不考虑支持
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
                        let (remarks, jsonvalue) = build_vless_singbox(
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
                        let (remarks, jsonvalue) = build_vmess_singbox(
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
                    "trojan" => {
                        let (remarks, jsonvalue) = build_trojan_singbox(
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
                        let (remarks, jsonvalue) = build_ss_singbox(
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

fn build_ss_singbox(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_tls: bool,
    toml_host: String,
    toml_path: String,
) -> (String, JsonValue) {
    let plugin_value = match toml_tls {
        true => format!(
            "tls;mux=0;mode=websocket;path={};host={}",
            toml_path, toml_host
        ),
        false => format!("mux=0;mode=websocket;path={};host={}", toml_path, toml_host),
    };

    let ss_with_jsonvalue = json!({
        "type": "shadowsocks",
        "tag": remarks,
        "server": csv_addr,
        "server_port": port,
        "method": "none",
        "password": toml_password,
        "plugin": "v2ray-plugin",
        "plugin_opts": plugin_value
    });

    return (remarks, ss_with_jsonvalue);
}

fn build_trojan_singbox(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, JsonValue) {
    let tls = match !toml_host.ends_with("workers.dev") {
        true => true,
        false => false,
    };
    let trojan_with_jsonvalue = json!({
        "type": "trojan",
        "tag": remarks,
        "server": csv_addr,
        "server_port": port,
        "password": toml_password,
        "network": "tcp",
        "tls": {
            "enabled": tls,
            "server_name": toml_server_name,
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": fingerprint
            }
        },
        "transport": {
            "type": "ws",
            "path": toml_path,
            "headers": {"Host": toml_host}
        }
    });

    (remarks, trojan_with_jsonvalue)
}

fn build_vless_singbox(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_uuid: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, JsonValue) {
    let tls = match !toml_host.ends_with("workers.dev") {
        true => true,
        false => false,
    };
    let vless_with_jsonvalue = json!({
        "type": "vless",
        "tag": remarks,
        "server": csv_addr,
        "server_port": port,
        "uuid": toml_uuid,
        "network": "tcp",
        "tls": {
            "enabled": tls,
            "server_name": toml_server_name,
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": fingerprint
            }
        },
        "transport": {
            "type": "ws",
            "path": toml_path,
            "headers": {"Host": toml_host}
        }
    });

    (remarks, vless_with_jsonvalue)
}

fn build_vmess_singbox(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_uuid: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, JsonValue) {
    let tls = match !toml_host.ends_with("workers.dev") {
        true => true,
        false => false,
    };
    let vmess_with_jsonvalue = json!({
        "type": "vmess",
        "tag": remarks,
        "server": csv_addr,
        "server_port": port,
        "uuid": toml_uuid,
        "security": "zero",
        "alter_id": 0,
        "tls": {
            "enabled": tls,
            "server_name": toml_server_name,
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": fingerprint
            }
        },
        "transport": {
            "type": "ws",
            "path": toml_path,
            "headers": {"Host": toml_host}
        }
    });

    (remarks, vmess_with_jsonvalue)
}

pub fn add_singbox_template(template: JsonValue, outbounds_vec: Vec<(String, String)>) -> String {
    let mut singbox_template = template.clone();
    let inside_outbounds_data: Vec<(String, JsonValue)> = outbounds_vec
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::from_str(v).unwrap_or(JsonValue::Null),
            )
        })
        .collect();
    if let Some(outside_outbounds) = singbox_template["outbounds"].as_array_mut() {
        inside_outbounds_data
            .iter()
            .enumerate()
            .for_each(|(i, value)| {
                // 过滤掉空值，并将代理的json数据插入对应的位置，这里从第2+i个位置开始
                if !value.0.is_empty() {
                    outside_outbounds.insert(2 + i, value.1.clone());
                }
            });

        // 更新singbox模板中含有{all}的向量值
        outside_outbounds.iter_mut().for_each(|item| {
            // 处理字段为对象的情况
            if let Some(obj) = item.as_object_mut() {
                if let Some(inside_outbounds) = obj
                    .get_mut("outbounds")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    // 查找并删除目标值 "{all}"、并将新值合并进来
                    if let Some(pos) = inside_outbounds
                        .iter()
                        .position(|x| x.as_str() == Some("{all}"))
                    {
                        inside_outbounds.remove(pos);

                        // [将代理tag别名插入] 获取要插入的新值，其中page是指定的内部vec数组的索引
                        let insert_values: Vec<JsonValue> = inside_outbounds_data
                            .iter()
                            .filter_map(|(k, _v)| {
                                if !k.is_empty() {
                                    Some(JsonValue::String(k.to_string()))
                                } else {
                                    None
                                }
                            })
                            .collect();

                        // 将新数据合并到目标数组
                        inside_outbounds.extend(insert_values);
                    }
                }
            }
        });
    }

    serde_json::to_string_pretty(&singbox_template).unwrap_or_default()
}
