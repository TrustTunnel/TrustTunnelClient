use toml_edit::{DocumentMut, value, Array};
use crate::ssh_deploy::portable_data_dir;

fn exclusions_json_path() -> std::path::PathBuf {
    portable_data_dir().join("exclusions.json")
}

#[tauri::command]
pub fn load_exclusion_json() -> Result<Vec<String>, String> {
    let path = exclusions_json_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let domains: Vec<String> = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse exclusions.json: {e}"))?;
            Ok(domains)
        }
        Err(_) => Ok(Vec::new()),
    }
}

#[tauri::command]
pub fn save_exclusion_json(domains: Vec<String>) -> Result<(), String> {
    let path = exclusions_json_path();
    let json = serde_json::to_string_pretty(&domains)
        .map_err(|e| format!("Failed to serialize: {e}"))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write exclusions.json: {e}"))?;
    eprintln!("[exclusions] {} domains backed up to {}", domains.len(), path.display());
    Ok(())
}

#[tauri::command]
pub fn load_exclusion_list(config_path: String) -> Result<Vec<String>, String> {
    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    let doc: DocumentMut = content
        .parse()
        .map_err(|e: toml_edit::TomlError| format!("Failed to parse config: {e}"))?;
    let domains = doc
        .get("exclusions")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(domains)
}

#[tauri::command]
pub fn save_exclusion_list(config_path: String, domains: Vec<String>) -> Result<(), String> {
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {e}"))?;
    let mut doc: DocumentMut = content
        .parse()
        .map_err(|e: toml_edit::TomlError| format!("Failed to parse config: {e}"))?;

    let mut arr = Array::new();
    for d in &domains {
        arr.push(d.as_str());
    }
    doc["exclusions"] = value(arr);

    std::fs::write(&config_path, doc.to_string())
        .map_err(|e| format!("Failed to write config: {e}"))?;
    eprintln!("[exclusions] {} domains saved to {}", domains.len(), config_path);

    // Also backup to JSON for persistence across config deletions
    let json_path = exclusions_json_path();
    if let Ok(json) = serde_json::to_string_pretty(&domains) {
        std::fs::write(&json_path, json).ok();
    }

    Ok(())
}
