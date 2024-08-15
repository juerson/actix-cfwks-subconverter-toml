use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_json::{json, Value as JsonValue};
use toml::Value;

pub fn batch_process_singbox_outbounds(
    ip_with_port_vec: Vec<String>,
    ip_with_none_port_vec: Vec<String>,
    toml_value: Value,
    userid: usize,
    proxy_type: &str,
    set_port: u16,
    max_element_count: usize,
) -> Vec<Vec<(String, serde_json::Value)>> {
    // 初始化分页容器
    let mut singbox_outbounds_vecs: Vec<Vec<(String, serde_json::Value)>> = Vec::new();
    // 初始化第一页
    let mut sub_singbox_outbounds_vec: Vec<(String, serde_json::Value)> = Vec::new();

    match ip_with_port_vec.is_empty() {
        true => {
            ip_with_none_port_vec.iter().for_each(|server| {
                let (remarks, outbounds_value) = build_singbox_config(
                    toml_value.clone(),
                    userid,
                    proxy_type,
                    server.clone(),
                    set_port,
                );
                // 检查当前分页容器是否已满（max_element_count 个元素）
                if sub_singbox_outbounds_vec.len() == max_element_count {
                    // 将已满的分页容器添加到分页数组中
                    singbox_outbounds_vecs.push(sub_singbox_outbounds_vec.clone());
                    // 创建一个新的分页容器
                    sub_singbox_outbounds_vec = Vec::new();
                }
                // 添加修改后的 JSON 对象到当前分页容器
                sub_singbox_outbounds_vec.push((remarks, outbounds_value));
            });
        }
        false => {
            ip_with_port_vec.iter().for_each(|item| {
                let parts: Vec<&str> = item.split(',').collect();
                match parts.len() == 2 {
                    true => {
                        let set_server = parts[0].to_string();
                        let set_port = parts[1].parse::<u16>().unwrap_or(set_port);

                        let (remarks, outbounds_value) = build_singbox_config(
                            toml_value.clone(),
                            userid,
                            proxy_type,
                            set_server,
                            set_port,
                        );
                        // 检查当前分页容器是否已满（max_element_count 个元素）
                        if sub_singbox_outbounds_vec.len() == max_element_count {
                            // 将已满的分页容器添加到分页数组中
                            singbox_outbounds_vecs.push(sub_singbox_outbounds_vec.clone());
                            // 创建一个新的分页容器
                            sub_singbox_outbounds_vec = Vec::new();
                        }
                        // 添加修改后的 JSON 对象到当前分页容器
                        sub_singbox_outbounds_vec.push((remarks, outbounds_value));
                    }
                    false => println!("无效数据: {}", item),
                }
            });
        }
    }
    // 最后一页可能未满 max_element_count 个元素，将其添加到分页数组中
    if !sub_singbox_outbounds_vec.is_empty() {
        singbox_outbounds_vecs.push(sub_singbox_outbounds_vec);
    }
    singbox_outbounds_vecs
}

pub fn match_template_output_singbox_config(
    enable_template: bool,
    template: serde_json::Value,
    outbounds_datas: Vec<Vec<(String, serde_json::Value)>>,
    page: usize,
) -> String {
    match enable_template {
        true => {
            let mut singbox_template = template.clone();
            if let Some(outside_outbounds) = singbox_template["outbounds"].as_array_mut() {
                outbounds_datas[page]
                    .iter()
                    .enumerate()
                    .for_each(|(i, value)| {
                        // 过滤掉空值，并将代理的json数据插入对应的位置，这里从第2+i个位置开始
                        if !value.0.is_empty() {
                            outside_outbounds.insert(2 + i, value.1.clone());
                        }
                    });
                // 更新singbox模板中含有{all}的向量值
                update_singbox_template_value(outside_outbounds, &outbounds_datas, page);
            }
            let formatted_json =
                serde_json::to_string_pretty(&singbox_template).unwrap_or_else(|_| "".to_string());
            return formatted_json;
        }
        false => {
            let outbounds_json = serde_json::json!({
                "outbounds": outbounds_datas[page].iter().map(|(_, v)| v).collect::<Vec<_>>()
            });

            let formatted_json =
                serde_json::to_string_pretty(&outbounds_json).unwrap_or_else(|_| "".to_string());
            return formatted_json;
        }
    }
}

fn update_singbox_template_value(
    outside_outbounds: &mut Vec<serde_json::Value>,
    outbounds_datas: &Vec<Vec<(String, serde_json::Value)>>,
    page: usize,
) {
    // 遍历数组中的每个元素
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
                    let insert_values: Vec<serde_json::Value> = (*outbounds_datas[page]
                        .iter()
                        .filter_map(|(k, _v)| {
                            if !k.is_empty() {
                                Some(serde_json::Value::String(k.to_string()))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>())
                    .to_vec();

                    // 将新数据合并到目标数组
                    inside_outbounds.extend(insert_values);
                }
            }
        }
    });
}

fn build_singbox_config(
    toml_value: Value,
    userid: usize,
    proxy_type: &str,
    set_server: String,
    set_port: u16,
) -> (String, serde_json::Value) {
    let proxy: toml::Value = crate::utils::toml::get_toml_proxy(toml_value, userid, proxy_type);

    // 候补端口列表，后续随机选择一个端口
    let alternate_ports: Vec<u16> = vec![443, 2053, 2083, 2087, 2096, 8443];
    if proxy.is_table() {
        match proxy.get("uuid") {
            Some(_) => {
                let (remarks, vless_with_singbox) = build_vless_singbox(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return (remarks, vless_with_singbox);
            }
            None => serde_json::Value::Null,
        };
        match proxy.get("password") {
            Some(_) => {
                let (remarks, trojan_with_singbox) = build_trojan_singbox(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return (remarks, trojan_with_singbox);
            }
            None => serde_json::Value::Null,
        };
    }
    ("".to_string(), serde_json::Value::Null)
}

fn build_trojan_singbox(
    toml_value: &Value,
    alternate_ports: Vec<u16>, // 候补端口列表
    set_server: String,
    set_port: u16,
) -> (String, serde_json::Value) {
    let (remarks_prefix, host, server_name, path, random_ports, password) =
        crate::utils::toml::get_toml_parameters(
            toml_value,
            alternate_ports,
            "password".to_string(),
        );

    // 使用外面设置的端口，还是随机端口
    let port = match set_port == 0 {
        true => random_ports
            .choose(&mut thread_rng())
            .copied()
            .unwrap_or(443),
        false => set_port,
    };
    let remarks = format!("{}|{}:{}", remarks_prefix, set_server, port);

    let singbox_trojan_json_str = r#"{
        "type": "trojan",
        "tag": "tag_name",
        "server": "",
        "server_port": 443,
        "password": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;

    let mut jsonvalue: JsonValue =
        serde_json::from_str(singbox_trojan_json_str).unwrap_or(JsonValue::Null);

    let password_field = vec!["password", &password];

    modify_singbox_json_value(
        &mut jsonvalue,
        remarks.clone(),
        password_field,
        set_server,
        port,
        path,
        host,
        server_name,
    );

    (remarks, jsonvalue)
}

fn build_vless_singbox(
    toml_value: &Value,
    ports: Vec<u16>,
    set_server: String,
    set_port: u16,
) -> (String, serde_json::Value) {
    let (remarks_prefix, host, server_name, path, random_ports, uuid) =
        crate::utils::toml::get_toml_parameters(toml_value, ports, "uuid".to_string());

    // 使用外面设置的端口，还是随机端口
    let port = match set_port == 0 {
        true => random_ports
            .choose(&mut thread_rng())
            .copied()
            .unwrap_or(443),
        false => set_port,
    };
    let remarks = format!("{}|{}:{}", remarks_prefix, set_server, port);

    let vless_with_singbox = r#"{
        "type": "vless",
        "tag": "vless_tag",
        "server": "",
        "server_port": 443,
        "uuid": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;
    let mut jsonvalue: JsonValue =
        serde_json::from_str(vless_with_singbox).unwrap_or(JsonValue::Null);

    let uuid_field = vec!["uuid", &uuid];

    modify_singbox_json_value(
        &mut jsonvalue,
        remarks.clone(),
        uuid_field,
        set_server,
        port,
        path,
        host,
        server_name,
    );

    (remarks, jsonvalue)
}

fn modify_singbox_json_value(
    jsonvalue: &mut JsonValue,
    remarks: String,
    uuid_password_field: Vec<&str>, // 修改uuid或password字段，vless的uuid，trojan的password
    set_server: String,
    port: u16,
    path: &str,
    host: &str,
    sni: &str,
) {
    // 生成随机指纹
    let fingerprint = crate::utils::common::random_fingerprint();

    // 修改顶层字段值
    if let Some(obj) = jsonvalue.as_object_mut() {
        // vless的uuid的字段，trojan的password的字段
        obj.insert(
            uuid_password_field[0].to_string(),
            JsonValue::String(uuid_password_field[1].to_string()),
        );
        obj.insert("tag".to_string(), JsonValue::String(remarks));
        obj.insert("server".to_string(), JsonValue::String(set_server.clone()));
        obj.insert("server_port".to_string(), JsonValue::Number(port.into()));
    }

    // 修改内层tls字段值
    if let Some(tls) = jsonvalue.get_mut("tls") {
        if let Some(tls_obj) = tls.as_object_mut() {
            tls_obj.insert(
                "server_name".to_string(),
                JsonValue::String(sni.to_string()),
            );

            // 手动关闭tls
            if host.ends_with("workers.dev") {
                if let Some(tls_enabled) = tls_obj.get_mut("enabled") {
                    *tls_enabled = json!(false);
                }
            }

            if let Some(utls) = tls_obj.get_mut("utls") {
                if let Some(utls_obj) = utls.as_object_mut() {
                    utls_obj.insert(
                        "fingerprint".to_string(),
                        JsonValue::String(fingerprint.to_string()),
                    );
                }
            }
        }
    }

    // 修改内层transport字段值
    if let Some(transport) = jsonvalue.get_mut("transport") {
        if let Some(transport_obj) = transport.as_object_mut() {
            transport_obj.insert("path".to_string(), JsonValue::String(path.to_string()));

            if let Some(details) = transport_obj.get_mut("headers") {
                if let Some(details_obj) = details.as_object_mut() {
                    details_obj.insert("Host".to_string(), JsonValue::String(host.to_string()));
                }
            }
        }
    }
}
