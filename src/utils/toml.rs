use rand::seq::SliceRandom;
use serde::Deserialize;
use std::usize;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Config {
    pub proxies: Proxy,
    pub ech: Option<EchArgs>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Proxy {
    vless: Option<Vec<Node>>,
    trojan: Option<Vec<Node>>,
    ss: Option<Vec<Node>>,
    vmess: Option<Vec<Node>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct EchArgs {
    /*
    例如："AEX+DQBBCgAgACDisSCHN77Ah26T78buZIBUJ7ZUM8ZAqpom+EAnZiyzTQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" (有时间限制，会过期)
         "cloudflare-ech.com+https://dns.alidns.com/dns-query" (永久有效，除非域名被墙)
     */
    pub ech_config_list: Option<String>, // 自定义v2rayN上的EchConfigList字段内容
    pub doh: Option<String>,             // DoH服务器地址，用于查询ECH参数
    pub ech_domain: Option<String>,      // ECH域名，用于查询ECH域名
    pub enble_ech: Option<bool>,        // 是否启用ECH功能
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Node {
    pub remarks_prefix: String,
    pub uuid: Option<String>,     // vless/vmess拥有
    pub password: Option<String>, // trojan/ss拥有
    pub tls: Option<bool>,        // ss拥有
    pub host: String,
    pub server_name: Option<String>,
    pub path: String,
    pub random_ports: Option<Vec<u16>>,
    pub network: Option<String>, // ws、xhttp、tcp、kcp等这类内容
    pub mode: Option<String>, // stream-one、stream-up、packet-up、auto，有的代理协议用不到这个字段值
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SelectedNode {
    pub node_type: String, // 选中节点的类型，不是传入的proxy_type
    pub node: Node,
}

// 筛选数据
#[allow(dead_code)]
enum FilterCondition {
    Text(String), // 节点类型
    Number(u8),   // 节点id，从1开始，超出范围就随机
}

// 选中某个节点的配置
#[allow(dead_code)]
pub fn selecting_config_of_node(
    proxies: &Proxy,
    poxy_type: String,
    node_id: u8,
) -> Result<SelectedNode, String> {
    let mut rng = rand::thread_rng();

    let vless_length: u8 = match proxies.vless.clone() {
        Some(vless) => vless.clone().len().try_into().unwrap(),
        None => 0,
    };
    let trojan_length: u8 = match proxies.trojan.clone() {
        Some(trojan) => trojan.clone().len().try_into().unwrap(),
        None => 0,
    };
    let ss_length: u8 = match proxies.ss.clone() {
        Some(ss) => ss.clone().len().try_into().unwrap(),
        None => 0,
    };
    let vmess_length: u8 = match proxies.vmess.clone() {
        Some(vmess) => vmess.clone().len().try_into().unwrap(),
        None => 0,
    };
    let all_length = vless_length + trojan_length + ss_length + vmess_length;

    match (
        FilterCondition::Text(poxy_type.clone()),
        FilterCondition::Number(node_id),
    ) {
        // vless+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n))
            if s == "vless" && (1..=vless_length).contains(&n) =>
        {
            match proxies.vless.clone() {
                Some(vless) => Ok(SelectedNode {
                    node_type: "vless".to_string(),
                    node: vless[(n as usize) - 1].clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // vless+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "vless" => {
            match proxies.vless.clone() {
                Some(vless) => Ok(SelectedNode {
                    node_type: "vless".to_string(),
                    node: vless.choose(&mut rng).unwrap().clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // ——————————————————————————————————————————————————————————————————————————————————————

        // trojan+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n))
            if s == "trojan" && (1..=trojan_length).contains(&n) =>
        {
            match proxies.trojan.clone() {
                Some(trojan) => Ok(SelectedNode {
                    node_type: "trojan".to_string(),
                    node: trojan[(n as usize) - 1].clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // trojan+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "trojan" => {
            match proxies.trojan.clone() {
                Some(trojan) => Ok(SelectedNode {
                    node_type: "trojan".to_string(),
                    node: trojan.choose(&mut rng).unwrap().clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // ——————————————————————————————————————————————————————————————————————————————————————

        // ss+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n))
            if s == "ss" && (1..=ss_length).contains(&n) =>
        {
            match proxies.ss.clone() {
                Some(ss) => Ok(SelectedNode {
                    node_type: "ss".to_string(),
                    node: ss[(n as usize) - 1].clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // ss+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "ss" => {
            match proxies.ss.clone() {
                Some(ss) => Ok(SelectedNode {
                    node_type: "ss".to_string(),
                    node: ss.choose(&mut rng).unwrap().clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // ——————————————————————————————————————————————————————————————————————————————————————

        // vmess+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n))
            if s == "vmess" && (1..=vmess_length).contains(&n) =>
        {
            match proxies.vmess.clone() {
                Some(vmess) => Ok(SelectedNode {
                    node_type: "vmess".to_string(),
                    node: vmess[(n as usize) - 1].clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // vmess+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "vmess" => {
            match proxies.vmess.clone() {
                Some(vmess) => Ok(SelectedNode {
                    node_type: "vmess".to_string(),
                    node: vmess.choose(&mut rng).unwrap().clone(),
                }),
                None => Err("发生未知错误！".to_string()),
            }
        }

        // ——————————————————————————————————————————————————————————————————————————————————————

        // 指定id，不论vless还是trojan、ss、vmess
        (_, FilterCondition::Number(n)) if (1..=all_length).contains(&n) => {
            let all_nodes = extend_all_nodes(proxies);
            match all_nodes.is_empty() {
                true => Err("发生未知错误！".to_string()),
                false => Ok(all_nodes[(n as usize) - 1].clone()),
            }
        }

        // 随机节点，不论vless还是trojan、ss
        (_, _) => {
            let all_nodes = extend_all_nodes(proxies);
            all_nodes
                .choose(&mut rng)
                .cloned()
                .ok_or("发生未知错误！".to_string())
        }
    }
}

// 合并toml中所有trojan和vless、ss节点的配置（先trojan后vless、ss）
fn extend_all_nodes(proxies: &Proxy) -> Vec<SelectedNode> {
    let trojan_vec: Vec<SelectedNode> = match proxies.trojan.clone() {
        Some(trojan) => trojan
            .iter()
            .map(|p| SelectedNode {
                node_type: "trojan".to_string(),
                node: p.clone(),
            })
            .collect(),
        None => Vec::new(),
    };
    let vless_vec: Vec<SelectedNode> = match proxies.vless.clone() {
        Some(vless) => vless
            .iter()
            .map(|p| SelectedNode {
                node_type: "vless".to_string(),
                node: p.clone(),
            })
            .collect(),
        None => Vec::new(),
    };
    let ss_vec: Vec<SelectedNode> = match proxies.ss.clone() {
        Some(ss) => ss
            .iter()
            .map(|p| SelectedNode {
                node_type: "ss".to_string(),
                node: p.clone(),
            })
            .collect(),
        None => Vec::new(),
    };
    let vmess_vec: Vec<SelectedNode> = match proxies.vmess.clone() {
        Some(vmess) => vmess
            .iter()
            .map(|p| SelectedNode {
                node_type: "vmess".to_string(),
                node: p.clone(),
            })
            .collect(),
        None => Vec::new(),
    };
    let all_nodes: Vec<SelectedNode> = trojan_vec
        .into_iter()
        .chain(vless_vec)
        .chain(ss_vec)
        .chain(vmess_vec)
        .collect();
    all_nodes
}
