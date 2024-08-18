mod utils;

use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use local_ip_address::local_ip;
use std::fs;
use toml::Value;

const SPECIFICATION: &str = include_str!("../使用说明.txt");

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();

    let repalced_html = SPECIFICATION.replace("127.0.0.1:10222", &host_address);

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
    let html_content = utils::qrcode::generate_html_with_qrcode(&repalced_html, &url);

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_content)
}

#[get("/sub")]
async fn subconverter(req: HttpRequest) -> impl Responder {
    let query_string = req.query_string();
    let params: Vec<(String, String)> =
        serde_urlencoded::from_str(&query_string).expect("Failed to parse query string");

    // ------------------------------ 配置文件、文件夹 -------------------------------

    let folder_path = "data";
    let config_file = "config.toml";

    // -------------------------------- URL参数控制 ---------------------------------

    // 用于筛选csv数据中的tls端口
    let mut tls_mode = "tls".to_string();
    let mut set_port = 0;

    // 每页最大元素个数、当前页码、是否启用sing-box、clash配置模板
    let mut max_node_count = 300;
    let mut page = 0;
    let mut enable_template = true;

    // 使用toml配置中的哪些代理信息或具体哪个代理信息
    let mut proxy_type = "".to_string();
    let mut userid: usize = 0;

    // 转换的目标，只支持v2ray、singbox、clash
    let mut target: String = "v2ray".to_string();

    // -------------------------------- 解析URL参数 ---------------------------------

    for (key, value) in params {
        if key.to_lowercase() == "target" {
            target = value.to_string();
        } else if key.to_lowercase() == "userid" {
            userid = value.parse().expect("Failed to parse userid");
        } else if key.to_lowercase() == "proxytype" || key.to_lowercase() == "proxy" {
            proxy_type = value.to_string();
        } else if key.to_lowercase() == "template" {
            enable_template = value.parse().expect("Failed to parse enabletemplate");
        } else if key.to_lowercase() == "dport" || key.to_lowercase() == "defaultport" {
            let port = value.parse().expect("Failed to parse setport");
            match port >= 80 && port < 65535 {
                true => set_port = port,
                false => set_port = set_port,
            }
        } else if key.to_lowercase() == "nodesize" {
            max_node_count = value.parse().expect("Failed to parse maxelementcount");
        } else if key.to_lowercase() == "page" {
            let page_number = value.parse().expect("Failed to parse page");
            match 0 < page_number {
                true => page = page_number,
                false => page = page,
            }
        } else if key.to_lowercase() == "tls" || key.to_lowercase() == "tlsmode" {
            tls_mode = value.to_string();
        }
    }

    // -------------------------------- 读取toml配置 --------------------------------

    let toml_content = fs::read_to_string(config_file).unwrap();
    let toml_value: Value = toml::from_str(&toml_content).unwrap();

    // -------------------------- 读取data文件夹里面的数据 ---------------------------

    let (ip_with_none_port_vec, ip_with_port_vec) =
        match utils::data::read_ip_domain_from_files(folder_path, &tls_mode) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Error reading files: {}", err);
                return HttpResponse::InternalServerError().finish();
            }
        };

    // --------------------------- 读取singbox、clash模板 ---------------------------

    // sing-box配置模板
    let template_content = fs::read_to_string("template/sing-box.json").unwrap();
    let singbox_template: serde_json::Value = serde_json::from_str(&template_content).unwrap();

    // clash配置模板
    let template_content = fs::read_to_string("template/clash.yaml").unwrap();
    let clash_template: serde_yaml::Value = serde_yaml::from_str(&template_content).unwrap();

    // ------------------------------ 输出html正文内容 ------------------------------

    let html_body: String = match target.as_str() {
        "v2ray" => {
            let links = utils::v2ray::batch_process_v2ray_links(
                &ip_with_port_vec,
                &ip_with_none_port_vec,
                &toml_value,
                userid,
                proxy_type.as_str(),
                set_port,
            );

            let pages: Vec<Vec<String>> = links
                .chunks(max_node_count)
                .map(|chunk| chunk.to_vec())
                .collect();

            pages[page].join("\n").to_string()
        }
        "singbox" => {
            // 限制最大的节点数
            if max_node_count > 150 {
                max_node_count = 50;
            }
            let singbox_outbounds_vecs = utils::singbox::batch_process_singbox_outbounds(
                ip_with_port_vec.clone(),
                ip_with_none_port_vec.clone(),
                toml_value.clone(),
                userid,
                proxy_type.as_str(),
                set_port,
                max_node_count,
            );

            let format_json = utils::singbox::match_template_output_singbox_config(
                enable_template,
                singbox_template,
                singbox_outbounds_vecs,
                page,
            );

            format_json.to_string()
        }
        "clash" => {
            // 限制最大的节点数
            if max_node_count > 150 {
                max_node_count = 100;
            }
            let clash_outbounds_vecs: Vec<Vec<(String, serde_json::Value)>> =
                utils::clash::batch_process_clash_outbounds(
                    ip_with_port_vec.clone(),
                    ip_with_none_port_vec.clone(),
                    toml_value.clone(),
                    userid,
                    proxy_type.as_str(),
                    set_port,
                    max_node_count,
                );

            let format_json: String = utils::clash::match_template_output_clash_config(
                enable_template,
                clash_template,
                clash_outbounds_vecs,
                page,
            );
            // 调整yaml的缩进（数组）
            let yaml_string: String = utils::indent::adjust_yaml_indentation(&format_json);

            yaml_string
        }
        _ => "".to_string(),
    };

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(html_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 获取本机的私有IP地址
    let local_ip = match local_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Failed to get local IP address: {}", e);
            return Ok(());
        }
    };
    // 绑定的端口
    let port = 10222;
    println!(
        "Server is running on http://{}:{} or http://127.0.0.1:{}",
        local_ip.to_string(),
        port,
        port
    );
    // 创建并运行HTTP服务器
    HttpServer::new(|| App::new().service(index).service(subconverter))
        .bind(format!("0.0.0.0:{}", port))?
        .run()
        .await
}
