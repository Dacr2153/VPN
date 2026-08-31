// vpnd/src/config/mod.rs

mod schema;
pub use schema::*;

use anyhow::{Context, Result};
use std::path::Path;

/// Load configuration from a TOML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<VpndConfig> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let config: VpndConfig =
        toml::from_str(&content).with_context(|| "Failed to parse TOML config")?;
    config.validate()?;
    Ok(config)
}

/// Save configuration to a TOML file
pub fn save_config<P: AsRef<Path>>(config: &VpndConfig, path: P) -> Result<()> {
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}
