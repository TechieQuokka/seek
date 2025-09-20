use clap::Parser;
use seek::{cli, config, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 설정 로드
    let config = config::load_config()?;

    // CLI 파싱 및 실행
    let args = cli::Args::parse();
    cli::run(args, config).await
}