use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Signature error: {0}")]
    Signature(String),

    #[error("Quarantine error: {0}")]
    Quarantine(String),

    #[error("Monitor error: {0}")]
    Monitor(String),

    #[error("CLI error: {0}")]
    Cli(String),

    #[error("Engine error: {0}")]
    Engine(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}