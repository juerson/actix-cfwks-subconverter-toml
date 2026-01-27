mod utils;

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use clap::{error::ErrorKind, CommandFactory, Parser};
use lazy_static::lazy_static;
use local_ip_address::local_ip;
use rand::Rng;
use serde_json::{json, Value as JsonValue};
use serde_urlencoded::from_str;
use serde_yaml::Value as YamlValue;
use utils::{
    clash::{add_clash_template, build_clash_json},
    ech::process_ech,
    file_data::MyData,
    indent::adjust_yaml_indentation,
    singbox::{add_singbox_template, build_singbox_json},
    toml::Config,
    v2ray::build_v2ray_link,
};

const SPECIFICATION: &str = include_str!("../使用说明.txt");
const CONFIG_FILE_PATH: &str = "config.toml";
const SINGBOX_TEMPLATE_PATH: &str = "template/sing-box.json";
const CLASH_TEMPLATE_PATH: &str = "template/clash.yaml";

lazy_static! {
    static ref HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    static ref HTTPS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];
    static ref FINGERPRINT: [&'static str; 9] = [
        "chrome",
        "firefox",
        "safari",
        "edge",
        "random",
        "ios",
        "android",
        "random",
        "randomized",
    ];
}

#[derive(Default, Clone)]
pub struct Params {
    pub target: String,
    pub max_node_count: usize,
    pub default_port: u16,
    pub userid: u8,
    pub column_name: String,
    pub enable_template: bool,
    pub proxy_type: String,
    pub tls_mode: bool,
    pub data_source: String,
    pub page: usize,
    pub fetch_ech: bool,
}

/// 基于HTTP传输协议的vless、trojan、ss-v2ray代理转换v2ray、sing-box、clash订阅工具
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// HTTP服务器的端口
    #[arg(short, long, default_value = "10222")]
    port: u16,

    /// 默认转换为v2ray，可选singbox、clash
    #[arg(long, default_value = "v2ray")]
    target: String,
}

struct AppState {
    args: Args,
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();

    let html_doc = SPECIFICATION.replace("127.0.0.1:10222", &host_address);

    // 获取当前局域网IP地址
    let ip_address = local_ip().unwrap().to_string();

    // 获取当前URL
    let url = format!(
        "{}://{}{}",
        req.connection_info().scheme(),
        req.connection_info()
            .host()
            .replace("127.0.0.1", &ip_address),
        req.uri()
    );

    // 生成二维码并将html_body嵌入网页中
    let html_content = utils::qrcode::generate_html_with_qrcode(&html_doc, &url);

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_content)
}

fn string_to_bool(value: &str, current_bool_value: bool) -> bool {
    match value {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => current_bool_value,
    }
}

#[get("/sub")]
async fn subconverter(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let query_str = req.query_string();
    let params: Vec<(String, String)> = from_str(&query_str).expect("Failed to parse query string");

    // ———————————————————————————————— URI参数控制 —————————————————————————————————

    let mut uri_params = Params {
        target: data.args.target.to_string(), // 转换的目标，只支持v2ray、singbox、clash
        tls_mode: true,                       // 用于筛选csv数据中的TLS/非TLS端口
        enable_template: true,                // 是否启用sing-box、clash配置模板
        default_port: 0,                      // 0表示：由内部代码确定端口
        max_node_count: 300,
        page: 1,                    // 默认使用第一页的数据，构建节点订阅
        userid: 0,                  // 使用toml配置中，具体哪个代理信息，有效值从1开始
        proxy_type: "".to_string(), // 使用toml配置中，哪些代理信息，可选：[vless,trojan]
        data_source: "./data".to_string(),
        column_name: "colo".to_string(), // csv文件中，以哪个列的字段名作为前缀？可选：[colo,loc,region,city]
        fetch_ech: false,                // 是否在线获取ECH Base64值
    };

    // ———————————————————————————————— 解析URI参数 —————————————————————————————————

    for (key, value) in params {
        if key.to_lowercase() == "target" {
            uri_params.target = value.to_string();
        } else if key.to_lowercase() == "template" {
            uri_params.enable_template = string_to_bool(&value, uri_params.enable_template);
        } else if vec!["tls", "mode", "tls_mode"].contains(&key.to_lowercase().as_str()) {
            uri_params.tls_mode = string_to_bool(&value, uri_params.tls_mode);
        } else if vec!["type", "proxy", "proxytype"].contains(&key.to_lowercase().as_str()) {
            uri_params.proxy_type = value.to_string();
        } else if vec!["source", "datasource"].contains(&key.to_lowercase().as_str()) {
            uri_params.data_source = value.to_string();
        } else if vec!["column", "columnname"].contains(&key.to_lowercase().as_str()) {
            uri_params.column_name = value.to_string();
        } else if vec!["n", "nodesize", "nodecount"].contains(&key.to_lowercase().as_str()) {
            uri_params.max_node_count = value.parse().unwrap_or(uri_params.max_node_count);
        } else if key.to_lowercase() == "page" {
            uri_params.page = value.parse().unwrap_or(uri_params.page).max(1);
        } else if vec!["id", "userid"].contains(&key.to_lowercase().as_str()) {
            uri_params.userid = value.parse().unwrap_or(uri_params.userid);
        } else if vec!["dport", "defaultport"].contains(&key.to_lowercase().as_str()) {
            let port = value.parse().unwrap_or(uri_params.default_port);
            uri_params.default_port = (80..=65535)
                .contains(&port)
                .then_some(port)
                .unwrap_or(uri_params.default_port);
        } else if vec!["fetchech", "fetch_ech"].contains(&key.to_lowercase().as_str()) {
            uri_params.fetch_ech = string_to_bool(&value, uri_params.fetch_ech);
        }
    }

    // ———————————————————————————————— 读取toml配置 ————————————————————————————————

    let toml_content = std::fs::read_to_string(CONFIG_FILE_PATH).unwrap();
    let toml_value: Config = toml::from_str(&toml_content).expect("Failed to parse TOML");

    // ——————————————————— 读取IP/Domain数据(填到节点的服务器地址) ————————————————————

    // 针对win11中"复制文件地址"出现双引号的情况
    let trimmed_quotes_path = uri_params.data_source.trim_matches('"');

    // 从文件中读取数据，最大读取数，数据没有过滤
    let max_line: usize = 10000;

    // 获取数据(网络数据/本地数据)
    let my_datas: Vec<MyData> = if trimmed_quotes_path.to_lowercase().starts_with("https://") {
        // 传入的一个https://链接，就从网络获取数据
        utils::net_data::process_network_data(
            &uri_params.column_name,
            uri_params.default_port,
            max_line,
            trimmed_quotes_path,
        )
    } else {
        // 传入的是本地文件路径，就从本地获取数据
        utils::file_data::process_files_data(
            &uri_params.column_name, // 获取指定字段的数据作为节点别名的前缀
            uri_params.default_port, // 没有找到端口的情况，就使用它
            max_line,                // 获取指定数量的数据就返回
            trimmed_quotes_path,     // 指定数据源所在文件夹路径或文件路径
        )
    };

    // ———————————————————————————————— 过滤不要的数据 ——————————————————————————————

    // 根据TLS模式是否开启，反向剔除不要端口的数据
    let filter_ports = match uri_params.tls_mode {
        true => HTTP_PORTS.to_vec(),   // 过滤掉非TLS模式的端口
        false => HTTPS_PORTS.to_vec(), // 过滤掉TLS模式的端口
    };
    let filtered_data: Vec<MyData> = my_datas
        .iter()
        .filter(|item| {
            // 端口不在filter_ports中，则保留
            if let Some(port) = item.port {
                !filter_ports.contains(&port)
            } else {
                true // 如果port为None，保留该元素
            }
        })
        .cloned()
        .collect();

    // —————————————————————————————————— 数据分页 ——————————————————————————————————

    // 定义每页的最大长度（元素个数），主要限制singbox、clash配置文件最多节点数
    let page_size = match uri_params.target.as_str() {
        "singbox" | "clash" => match (1..151).contains(&uri_params.max_node_count) {
            true => uri_params.max_node_count,
            false => 50,
        },
        _ => uri_params.max_node_count,
    };

    // 将 Vec<MyData> 转换为 Vec<Vec<MyData>>
    let paginated_data: Vec<Vec<MyData>> = filtered_data
        .chunks(page_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // ————————————————————— VLESS And Trojan to v2rayN ECH 配置 ———————————————————

    // toml判断是否添加ech，再根据fetch_ech值判断是在线获取,还是读取toml中的ech_config_list
    let toml_ech = toml_value.ech.unwrap_or_default();
    let ech_config_list = process_ech(toml_ech, &uri_params.fetch_ech).await;

    // —————————————————————————————————— 构建节点 ——————————————————————————————————

    let uri_port = uri_params.default_port;
    // 收集构建的所有节点别名和v2ray/singbox/clash的节点信息
    let mut vec: Vec<(String, String)> = Vec::new();
    // 根据页码获取某一页的数据，默认为1，且页码要从1开始
    match paginated_data.get(uri_params.page - 1) {
        Some(page_data) => {
            // 检查是否读取到数据，如果为空就返回空白页面
            if page_data.is_empty() {
                return HttpResponse::Ok()
                    .content_type("text/plain; charset=utf-8")
                    .body("".to_string());
            }
            for item in page_data {
                let csv_tag: String = item.alias.clone().unwrap_or("".to_string()); // 数据中心,地区,城市,国家代码
                let csv_addr: String = item.addr.clone();
                let csv_port: u16 = item.port.unwrap_or(0);
                let fingerprint = FINGERPRINT[rand::thread_rng().gen_range(0..FINGERPRINT.len())]; // 指纹
                match uri_params.target.as_str() {
                    "v2ray" => {
                        let link = build_v2ray_link(
                            &toml_value.proxies,
                            csv_tag,
                            csv_addr,
                            csv_port,
                            uri_port,
                            uri_params.userid,
                            uri_params.proxy_type.clone(),
                            fingerprint.to_string(),
                            &HTTP_PORTS,
                            &HTTPS_PORTS,
                            ech_config_list.clone(),
                        )
                        .await;
                        if !link.is_empty() {
                            vec.push(("".to_string(), link));
                        }
                    }
                    "singbox" => {
                        let (remark, singbox_json) = build_singbox_json(
                            &toml_value.proxies,
                            csv_tag,
                            csv_addr,
                            csv_port,
                            uri_port,
                            uri_params.userid,
                            uri_params.proxy_type.clone(),
                            fingerprint.to_string(),
                            &HTTP_PORTS,
                            &HTTPS_PORTS,
                        );
                        if !remark.is_empty() {
                            let formatted_json = serde_json::to_string_pretty(&singbox_json)
                                .unwrap_or_else(|_| "".to_string());
                            vec.push((remark, formatted_json));
                        }
                    }
                    "clash" => {
                        let (remark, clash_json) = build_clash_json(
                            &toml_value.proxies,
                            csv_tag,
                            csv_addr,
                            csv_port,
                            uri_port,
                            uri_params.userid,
                            uri_params.proxy_type.clone(),
                            fingerprint.to_string(),
                            &HTTP_PORTS,
                            &HTTPS_PORTS,
                        );
                        if !remark.is_empty() {
                            let formatted_json = serde_json::to_string_pretty(&clash_json)
                                .unwrap_or_else(|_| "".to_string());
                            vec.push((remark, formatted_json));
                        }
                    }
                    _ => {}
                }
            }
        }
        None => {
            println!("无效的页码：{}", uri_params.page);
            return HttpResponse::Ok()
                .content_type("text/plain; charset=utf-8")
                .body("".to_string());
        }
    }

    // --------------------------- 读取singbox、clash模板 ---------------------------

    // sing-box配置模板
    let template_content = std::fs::read_to_string(SINGBOX_TEMPLATE_PATH).unwrap();
    let singbox_template: JsonValue = serde_json::from_str(&template_content).unwrap();

    // clash配置模板
    let template_content = std::fs::read_to_string(CLASH_TEMPLATE_PATH).unwrap();
    let mut clash_template: YamlValue = serde_yaml::from_str(&template_content).unwrap();

    // ------------------------- 处理输出的内容(是否添加模板) -------------------------

    let html_body: String = match uri_params.target.as_str() {
        "v2ray" => vec
            .iter()
            .map(|(_, value)| value)
            .cloned()
            .collect::<Vec<String>>()
            .join("\n"),
        "singbox" => {
            match uri_params.enable_template {
                true => add_singbox_template(singbox_template, vec),
                false => {
                    let outbounds_json: JsonValue = json!({
                        "outbounds": vec.iter().map(|(_, v)| serde_json::from_str(v).unwrap_or(JsonValue::Null)).collect::<Vec<_>>()
                    });
                    // 将serde_json::value数据转换为JSON字符串
                    serde_json::to_string_pretty(&outbounds_json).unwrap_or_default()
                }
            }
        }
        "clash" => {
            match uri_params.enable_template {
                true => {
                    add_clash_template(&mut clash_template, vec);
                    // 将serde_json::value数据转换为YAML字符串，并美化字符串的缩进形式
                    adjust_yaml_indentation(
                        &serde_json::to_string_pretty(&clash_template).unwrap_or_default(),
                    )
                }
                false => {
                    let clash_json_data: JsonValue = json!({
                        "proxies": vec.iter().map(|(_, v)| serde_json::from_str(v).unwrap_or(JsonValue::Null)).collect::<Vec<_>>()
                    });
                    // 将serde_json::value数据转换为YAML字符串，并美化字符串的缩进形式
                    adjust_yaml_indentation(
                        &serde_json::to_string_pretty(&clash_json_data).unwrap_or_default(),
                    )
                }
            }
        }
        _ => "".to_string(),
    };
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(html_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 获取命令行参数
    let result = Args::try_parse();
    match result {
        Ok(args) => {
            let shared_state = web::Data::new(AppState { args: args.clone() });
            // 获取本机的私有IP地址
            let local_ip = match local_ip() {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("Failed to get local IP address: {}", e);
                    return Ok(());
                }
            };
            // 绑定的端口
            let port = args.port;
            println!(
                "Server is running on http://{}:{} or http://127.0.0.1:{}",
                local_ip.to_string(),
                port,
                port
            );
            // 创建并运行HTTP服务器
            return HttpServer::new(move || {
                App::new()
                    .app_data(shared_state.clone())
                    .service(index)
                    .service(subconverter)
            })
            .bind(format!("0.0.0.0:{}", port))?
            .run()
            .await;
        }
        Err(e) => {
            if e.kind() == ErrorKind::MissingRequiredArgument || e.kind() == ErrorKind::InvalidValue
            {
                // 如果是因为缺少必需参数或无效值导致的错误，则显示帮助信息
                Args::command().print_help().unwrap();
            } else {
                // 其他类型的错误则正常打印错误信息
                e.print().unwrap();
            }
        }
    }
    return Ok(());
}
