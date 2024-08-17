use yaml_rust::{YamlEmitter, YamlLoader};

/// 调整 YAML 缩进
pub fn adjust_yaml_indentation(yaml_str: &str) -> String {
    // 尝试加载和处理 YAML 数据
    match YamlLoader::load_from_str(yaml_str) {
        Ok(data) => {
            // 获取第一个文档
            if let Some(doc) = data.get(0) {
                let mut output = String::new();
                let mut emitter = YamlEmitter::new(&mut output);

                if emitter.dump(doc).is_ok() {
                    // 去掉开头的 `---\n`（如果存在的话）
                    if output.starts_with("---\n") {
                        return output[4..].to_string();
                    }
                    return output;
                } else {
                    return "Error: Failed to emit YAML".to_string();
                }
            } else {
                return "Error: No document found in YAML input".to_string();
            }
        }
        Err(_) => "Error: Failed to parse YAML input".to_string(),
    }
}
