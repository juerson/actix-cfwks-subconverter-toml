use rand::{seq::SliceRandom, thread_rng};
use std::collections::HashMap;
use toml::Value;

pub fn get_toml_proxy(toml_value: Value, userid: usize, proxy_type: &str) -> toml::Value {
    let proxies = toml_value.get("proxies").unwrap();
    let all_proxy = get_toml_all_proxy(proxies);

    let mut map = HashMap::new();
    map.insert("vless", "uuid");
    map.insert("trojan", "password");
    let proxy: toml::Value = match (1..all_proxy.len() + 1).contains(&userid) {
        true => match map.get(&proxy_type) {
            Some(map_vlaue) => match all_proxy[userid - 1].get(map_vlaue) {
                Some(_v) => all_proxy[userid - 1].clone(),
                None => toml::Value::String("".to_string()),
            },
            None => match !["vless", "trojan"].contains(&proxy_type) {
                true => all_proxy[userid - 1].clone(),
                false => toml::Value::String("".to_string()),
            },
        },
        false => get_toml_proxy_param(proxies.clone(), proxy_type, all_proxy),
    };
    proxy
}

pub fn get_toml_parameters(
    toml_value: &Value,
    alternate_ports: Vec<u16>, // 候补端口列表
    uuid_or_password: String,
) -> (&str, &str, &str, &str, Vec<u16>, String) {
    let remarks_prefix = toml_value
        .get("remarks_prefix")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let host = toml_value
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let server_name = toml_value
        .get("server_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let path = toml_value
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let random_ports: Vec<u16> = toml_value
        .get("random_ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_integer().and_then(|i| u16::try_from(i).ok()))
                .collect()
        })
        .unwrap_or_else(|| alternate_ports.to_vec());

    let uuid_or_password_value = match toml_value.get(uuid_or_password) {
        Some(v) => v.as_str().unwrap_or("").to_string(),
        None => "".to_string(),
    };
    (
        remarks_prefix,
        host,
        server_name,
        path,
        random_ports,
        uuid_or_password_value,
    )
}

fn get_toml_all_proxy(proxies: &Value) -> Vec<&Value> {
    let mut all_proxy: Vec<&Value> = Vec::new();
    if let Value::Table(table) = proxies {
        for (_, value) in table {
            if let Value::Array(array) = value {
                all_proxy.extend(array);
            }
        }
    }
    all_proxy
}

fn get_toml_proxy_param(
    proxies_value: toml::Value,
    proxy_type: &str,
    all_poxy: Vec<&Value>,
) -> toml::Value {
    let default_value: Vec<toml::Value> = Vec::new();
    match proxy_type {
        "vless" => {
            let vless_vec: &Vec<toml::Value> = proxies_value
                .get("vless")
                .and_then(|v| v.as_array())
                .unwrap_or(&default_value);
            vless_vec.choose(&mut thread_rng()).unwrap().clone()
        }
        "trojan" => {
            let trojan_vec: &Vec<toml::Value> = proxies_value
                .get("trojan")
                .and_then(|v| v.as_array())
                .unwrap_or(&default_value);
            trojan_vec.choose(&mut thread_rng()).unwrap().clone()
        }
        _ => match all_poxy.choose(&mut thread_rng()).cloned() {
            Some(value) => value.clone(),
            None => Value::String("".to_string()),
        },
    }
}
