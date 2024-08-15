use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use toml::Value;

#[allow(dead_code)]
pub fn batch_process_clash_outbounds(
    ip_with_port_vec: Vec<String>,
    ip_with_none_port_vec: Vec<String>,
    toml_value: Value,
    userid: usize,
    proxy_type: &str,
    set_port: u16,
    max_element_count: usize,
) -> Vec<Vec<(String, serde_json::Value)>> {
    // 初始化分页容器
    let mut clash_outbounds_vecs: Vec<Vec<(String, serde_json::Value)>> = Vec::new();
    // 初始化第一页
    let mut sub_clash_outbounds_vec: Vec<(String, serde_json::Value)> = Vec::new();

    match ip_with_port_vec.is_empty() {
        true => {
            ip_with_none_port_vec.iter().for_each(|server| {
                let (remarks, outbounds_value) = build_clash_config(
                    toml_value.clone(),
                    userid,
                    proxy_type,
                    server.clone(),
                    set_port,
                );
                // 检查当前分页容器是否已满（max_element_count 个元素）
                if sub_clash_outbounds_vec.len() == max_element_count {
                    // 将已满的分页容器添加到分页数组中
                    clash_outbounds_vecs.push(sub_clash_outbounds_vec.clone());
                    // 创建一个新的分页容器
                    sub_clash_outbounds_vec = Vec::new();
                }
                // 添加修改后的 JSON 对象到当前分页容器
                sub_clash_outbounds_vec.push((remarks, outbounds_value));
            });
        }
        false => {
            ip_with_port_vec.iter().for_each(|item| {
                let parts: Vec<&str> = item.split(',').collect();
                match parts.len() == 2 {
                    true => {
                        let set_server = parts[0].to_string();
                        let set_port = parts[1].parse::<u16>().unwrap_or(set_port);

                        let (remarks, outbounds_value) = build_clash_config(
                            toml_value.clone(),
                            userid,
                            proxy_type,
                            set_server,
                            set_port,
                        );
                        // 检查当前分页容器是否已满（max_element_count 个元素）
                        if sub_clash_outbounds_vec.len() == max_element_count {
                            // 将已满的分页容器添加到分页数组中
                            clash_outbounds_vecs.push(sub_clash_outbounds_vec.clone());
                            // 创建一个新的分页容器
                            sub_clash_outbounds_vec = Vec::new();
                        }
                        // 添加修改后的 JSON 对象到当前分页容器
                        sub_clash_outbounds_vec.push((remarks, outbounds_value));
                    }
                    false => println!("无效数据: {}", item),
                }
            });
        }
    }
    // 最后一页可能未满 max_element_count 个元素，将其添加到分页数组中
    if !sub_clash_outbounds_vec.is_empty() {
        clash_outbounds_vecs.push(sub_clash_outbounds_vec);
    }
    clash_outbounds_vecs
}

pub fn match_template_output_clash_config(
    enable_template: bool,
    template: serde_yaml::Value,
    outbounds_datas: Vec<Vec<(String, serde_json::Value)>>,
    page: usize,
) -> String {
    let proxy_name = outbounds_datas[page]
        .iter()
        .filter_map(|(k, _v)| k.to_string().parse::<String>().ok())
        .collect::<Vec<_>>();
    match enable_template {
        true => {
            let mut clash_template: serde_yaml::Value = template.clone();
            // 添加节点信息到proxies数组（外层）
            add_node_to_proxies(&mut clash_template, &outbounds_datas, page);
            // 添加节点名称到proxies数组（里面）
            add_node_name_to_proxies(&mut clash_template, proxy_name);
            let yaml_string = serde_yaml::to_string(&clash_template).unwrap_or("".to_string());
            return yaml_string;
        }
        false => {
            let outbounds_json = serde_json::json!({
                "proxies": outbounds_datas[page].iter().map(|(_, v)| v).collect::<Vec<_>>()
            });

            // 将 serde_json::Value 序列化为 serde_yaml::Value
            let yaml_value: YamlValue = match serde_yaml::to_value(outbounds_json) {
                Ok(value) => value,
                Err(_) => return String::new(), // 发生错误时返回空字符串
            };

            // 将 serde_yaml::Value 序列化为 YAML 字符串
            match serde_yaml::to_string(&yaml_value) {
                Ok(yaml_string) => yaml_string.to_string(),
                Err(_) => String::new(), // 发生错误时返回空字符串
            }
        }
    }
}

fn add_node_to_proxies(
    clash_template: &mut YamlValue,
    outbounds_datas: &Vec<Vec<(String, JsonValue)>>,
    page: usize,
) {
    if let Some(outside_proxies) = clash_template.get_mut("proxies") {
        if let serde_yaml::Value::Sequence(array) = outside_proxies {
            array.clear(); // 清空数组

            let proxies_vec: Vec<serde_yaml::Value> = (*outbounds_datas[page]
                .iter()
                .filter_map(|(_k, v)| serde_yaml::to_value(v).ok())
                .collect::<Vec<_>>())
            .to_vec();
            array.extend(proxies_vec);
        }
    }
}

fn add_node_name_to_proxies(clash_template: &mut YamlValue, proxy_name: Vec<String>) {
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
                                    true => contains_s01 = true,
                                    false => filtered_s01_with_proxies.push(item),
                                }
                            }
                        });
                        match contains_s01 {
                            true => {
                                filtered_s01_with_proxies.extend(
                                    proxy_name
                                        .clone()
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

fn build_clash_config(
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
                let (remarks, vless_with_clash) = build_vless_clash(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return (remarks, vless_with_clash);
            }
            None => serde_json::Value::Null,
        };
        match proxy.get("password") {
            Some(_) => {
                let (remarks, trojan_with_clash) = build_trojan_clash(
                    &proxy,
                    alternate_ports.clone(),
                    set_server.clone(),
                    set_port,
                );
                return (remarks, trojan_with_clash);
            }
            None => serde_json::Value::Null,
        };
    }
    ("".to_string(), serde_json::Value::Null)
}

fn build_trojan_clash(
    toml_value: &Value,
    alternate_ports: Vec<u16>, // 候补端口列表
    server: String,
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
    let remarks = format!("{}|{}:{}", remarks_prefix, server, port);

    let clash_trojan_json_str = r#"{
        "type": "trojan",
        "name": "",
        "server": "",
        "port": 443,
        "password": "",
        "network": "ws",
        "tls": true,
        "udp": false,
        "sni": "",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
            "path": "/",
            "headers": {"Host": ""}
        }
    }"#;

    let mut jsonvalue: JsonValue =
        serde_json::from_str(clash_trojan_json_str).unwrap_or(JsonValue::Null);

    let password_field = vec!["password", &password];
    let sni_field = vec!["sni", &server_name];

    modify_clash_json_value(
        &mut jsonvalue,
        remarks.clone(),
        password_field,
        sni_field,
        server,
        port,
        path,
        host,
    );

    (remarks, jsonvalue)
}

fn build_vless_clash(
    toml_value: &Value,
    ports: Vec<u16>,
    server: String,
    set_port: u16,
) -> (String, serde_json::Value) {
    let (remarks_prefix, host, server_name, path, random_ports, uuid) =
        crate::utils::toml::get_toml_parameters(toml_value, ports, "uuid".to_string());

    // 使用外面设置的端口，还是随机端口
    let mut port = match set_port == 0 {
        true => random_ports
            .choose(&mut thread_rng())
            .copied()
            .unwrap_or(443),
        false => set_port,
    };

    let vless_with_clash = r#"{
        "type": "vless",
        "name": "tag_name",
        "server": "",
        "port": 443,
        "uuid": "",
        "network": "ws",
        "tls": true,
        "udp": false,
        "servername": "",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
            "path": "/",
            "headers": {"Host": ""}
        }
    }"#;
    let mut jsonvalue: JsonValue =
        serde_json::from_str(vless_with_clash).unwrap_or(JsonValue::Null);

    // 遇到host是workers.dev的，手动修改tls为false
    if host.ends_with("workers.dev") {
        jsonvalue.as_object_mut().map(|obj| {
            obj.insert("tls".to_string(), JsonValue::Bool(false));
        });
        match [443, 2053, 2083, 2087, 2096, 8443].contains(&port) {
            true => {
                port = [80, 8080, 8880, 2052, 2082, 2086, 2095]
                    .choose(&mut thread_rng())
                    .copied()
                    .unwrap()
            }
            false => port = port,
        }
    }

    let remarks = format!("{}|{}:{}", remarks_prefix, server, port);

    let uuid_field = vec!["uuid", &uuid];
    let servername_filed = vec!["servername", &server_name];

    modify_clash_json_value(
        &mut jsonvalue,
        remarks.clone(),
        uuid_field,
        servername_filed,
        server,
        port,
        path,
        host,
    );

    (remarks, jsonvalue)
}

fn modify_clash_json_value(
    jsonvalue: &mut JsonValue,
    remarks: String,
    uuid_password_field: Vec<&str>, // 修改uuid或password字段，vless的uuid，trojan的password
    servername_sni_field: Vec<&str>, // 修改servername或sni字段，vless的uuid，trojan的password
    server: String,
    port: u16,
    path: &str,
    host: &str,
) {
    // 生成随机指纹
    let fingerprint = crate::utils::common::random_fingerprint();

    // 修改顶层字段值
    if let Some(obj) = jsonvalue.as_object_mut() {
        // vless的uuid，trojan的password
        obj.insert(
            uuid_password_field[0].to_string(),
            JsonValue::String(uuid_password_field[1].to_string()),
        );
        // vless的servername，trojan的sni
        obj.insert(
            servername_sni_field[0].to_string(),
            JsonValue::String(servername_sni_field[1].to_string()),
        );
        obj.insert(
            "client-fingerprint".to_string(),
            JsonValue::String(fingerprint.to_string()),
        );
        obj.insert("name".to_string(), JsonValue::String(remarks));
        obj.insert("server".to_string(), JsonValue::String(server));
        obj.insert("port".to_string(), JsonValue::Number(port.into()));
    }

    // 修改ws-opts字段里面其它字段值
    if let Some(ws_opts) = jsonvalue.get_mut("ws-opts") {
        if let Some(ws_opts_obj) = ws_opts.as_object_mut() {
            ws_opts_obj.insert("path".to_string(), JsonValue::String(path.to_string()));
            if let Some(headers) = ws_opts_obj.get_mut("headers") {
                if let Some(headers_obj) = headers.as_object_mut() {
                    headers_obj.insert("Host".to_string(), JsonValue::String(host.to_string()));
                }
            }
        }
    }
}
