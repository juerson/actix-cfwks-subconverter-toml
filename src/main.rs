mod utils;

use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use local_ip_address::local_ip;
use std::fs;
use toml::Value;

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();

    let html_doc = r#"【TOML版】本工具的功能：批量将优选的IP(不是WARP的优选IP)或域名，写入到 Cloudflare 搭建的 vless/trojan 协议的配置节点中，并转换为 v2ray、sing-box、clash.mate/mihomo 订阅!

—————————————————————————————————————————————————————————————————————————————————————————————————

web服务地址：http://{host_address}

订阅地址格式：http://{host_address}/sub?target=[v2ray,singbox,clash]&page=[0,?)&template=[true,false]&nodesize=[1..?]&proxytype=[vless,trojan]&userid=[1..?)&tls=[true,false]&dport=[80..65535)

—————————————————————————————————————————————————————————————————————————————————————————————————
订阅示例：

http://{host_address}/sub
——————————————————————————————
http://{host_address}/sub?target=singbox&template=false

http://{host_address}/sub?target=singbox&template=false&userid=1
http://{host_address}/sub?target=singbox&template=false&proxy=vless

http://{host_address}/sub?target=clash&template=false
——————————————————————————————
http://{host_address}/sub?target=v2ray
http://{host_address}/sub?target=singbox
http://{host_address}/sub?target=clash
——————————————————————————————
http://{host_address}/sub?target=v2ray&page=2
http://{host_address}/sub?target=singbox&page=2
http://{host_address}/sub?target=clash&page=2
——————————————————————————————
http://{host_address}/sub?target=v2ray&userid=1
http://{host_address}/sub?target=singbox&userid=1
http://{host_address}/sub?target=clash&userid=1
——————————————————————————————
http://{host_address}/sub?target=v2ray&proxy=vless
http://{host_address}/sub?target=v2ray&proxy=trojan

http://{host_address}/sub?target=singbox&proxy=vless
http://{host_address}/sub?target=singbox&proxy=trojan

http://{host_address}/sub?target=clash&proxy=vless
http://{host_address}/sub?target=clash&proxy=trojan
——————————————————————————————
http://{host_address}/sub?target=v2ray&tls=true
http://{host_address}/sub?target=v2ray&tls=false

http://{host_address}/sub?target=singbox&tls=true
http://{host_address}/sub?target=singbox&tls=false

http://{host_address}/sub?target=clash&tls=true
http://{host_address}/sub?target=clash&tls=false
——————————————————————————————
http://{host_address}/sub?target=v2ray&nodesize=800
http://{host_address}/sub?target=singbox&nodesize=300
http://{host_address}/sub?target=clash&nodesize=300

注意：
    1、以上的参数均可随意组合，具体效果自己研究。
    2、转换问题：
        a.如果转换为v2ray的，支持vless+ws、vless+ws+tls、trojan+ws、vless+ws+tls。
        b.如果转换为singbox的，支持vless+ws、vless+ws+tls、trojan+ws+tls。
        c.如果转换为clash的，支持vless+ws、vless+ws+tls、trojan+ws+tls。
       注意：原则上，以上的4种代理形式都能生成对应目标客户端的配置，只是无法联网使用。
—————————————————————————————————————————————————————————————————————————————————————————————————
订阅链接的参数介绍：

    1、target：转换的目标客户端，默认是v2ray，可选v2ray、singbox、clash。

    2、page：订阅的页码。
    注意：分页是根据读取data目录下面的数据分页，不是根据生成的全部订阅分页；如果设置随机代理信息，代理信息随时变动，ip和反代域名固定不变。
    
    3、nodesize：您需要的节点数量，是从data目录下，读取txt、csv文件的所有数据中，截取前n个数据来构建节点信息。
    注意： 
        (1)如果符合要求的txt、csv文件比较多，读取到数据比较多，文件之间的数据拼接顺序跟文件名有一点关系；
        (2)不是随机从data目录中读取到的全部数据中选择n个数据，而是按照读取到的数据先后顺序，截取前n个数据来构建节点的信息。
        (3)v2ray默认是300个节点；sing-box默认是50个节点，最大150个节点；clash默认100个节点，最大150个节点。

    4、template：是否启用sing-box、clash配置模板，默认是启用的，可选true、false值。
    
    5、proxytype（proxy）：选择什么协议的节点？只能选择vless、trojan，这里指您在配置文件中，存放的节点类型，符合要求的，才使用它。

    6、userid：指定使用哪个toml配置信息，生成v2ray链接或sing-box、clash配置文件？它是虚构的，是根据toml文件的配置，数组下标+1来计算的。
    例如：
        userid=1就是使用第一个节点的配置信息，2就是使用第二个节点的配置信息，以此类推。
        userid值的范围是[0,?)，为0是随机配置信息，超过代理配置的总个数，也是随机配置信息。
    注意：
        (1)proxy 和 userid 两个都设置，只使用userid的值，proxy的值无效。
        (2)所有的vless在前面，trojan在后面，不是按照toml的书写顺序排序的，如果userid的顺序跟toml中书写的顺序有出入，建议调整一下toml文件中的代理信息顺序，方便下次使用

    7、tls（tlsmode）：默认是tls端口的数据。这个只针对csv文件有端口的，用于控制读取data目录下哪些端口对应的数据，也就是除了[80, 8080, 8880, 2052, 2082, 2086, 2095]的其它端口对应的数据。

    8、dport（defaultport）：默认0端口，随机tls的端口。data目录下，读取到txt、csv文件的数据中，没有端口的情况，才使用这里设置的默认端口，workers.dev的host，由内部随机生成。

—————————————————————————————————————————————————————————————————————————————————————————————————
温馨提示：

    使用 Cloudflare workers 搭建的 trojan 节点，转换为 clash.mate/mihomo 订阅使用，PROXYIP 地址可能会丢失，跟没有设置 PROXYIP 效果一样，也就是不能使用它访问一些地区封锁的网站，比如：ChatGPT、Netflix 等。"#;

    let repalced_html = html_doc.replace("{host_address}", &host_address);

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
