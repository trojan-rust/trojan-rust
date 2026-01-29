//! Configuration file loading and error types.

use std::{fs, path::Path};

use crate::Config;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported config format")]
    UnsupportedFormat,
    #[error("validation: {0}")]
    Validation(String),
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let data = fs::read_to_string(path)?;
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "json" | "jsonc" => {
            let stripped = json_comments::StripComments::new(data.as_bytes());
            Ok(serde_json::from_reader(stripped)?)
        }
        "yaml" | "yml" => Ok(serde_yaml::from_str(&data)?),
        "toml" => Ok(toml::from_str(&data)?),
        _ => Err(ConfigError::UnsupportedFormat),
    }
}
