use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "seek")]
#[command(about = "🛡️ Rust로 개발된 고성능 백신 CLI 도구")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// 설정 파일 경로
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 상세 출력 모드
    #[arg(short, long)]
    pub verbose: bool,

    /// 조용한 모드
    #[arg(short, long)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 파일 및 디렉토리 스캔
    Scan(ScanArgs),
    /// 실시간 모니터링 관리
    Monitor(MonitorArgs),
    /// 격리된 파일 관리
    Quarantine(QuarantineArgs),
    /// 시그니처 데이터베이스 업데이트
    Update(UpdateArgs),
    /// 스캔 스케줄 관리
    Schedule(ScheduleArgs),
    /// 설정 관리
    Config(ConfigArgs),
    /// 스캔 리포트 조회
    Report(ReportArgs),
    /// 시스템 상태 확인
    Status(StatusArgs),
}

#[derive(Parser)]
pub struct ScanArgs {
    /// 스캔할 경로
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// 하위 디렉토리 포함 스캔
    #[arg(short, long)]
    pub recursive: bool,

    /// 특정 파일 스캔
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// 스캔 깊이 제한
    #[arg(short, long, value_name = "DEPTH")]
    pub depth: Option<usize>,

    /// 위협 발견 시 자동 격리
    #[arg(short, long)]
    pub quarantine: bool,

    /// 스캔 스레드 수
    #[arg(short, long, value_name = "NUMBER")]
    pub threads: Option<usize>,

    /// 제외할 파일/경로 패턴
    #[arg(long, value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// 포함할 파일/경로 패턴
    #[arg(long, value_name = "PATTERN")]
    pub include: Vec<String>,

    /// 상세 스캔 모드
    #[arg(long)]
    pub detailed: bool,

    /// 빠른 스캔 모드
    #[arg(long)]
    pub quick: bool,

    /// 출력 형식
    #[arg(long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// 결과를 파일로 저장
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// 위협 발견 시에도 성공 종료 코드(0) 반환
    #[arg(long)]
    pub success_exit: bool,
}

#[derive(Parser, Debug)]
pub struct MonitorArgs {
    #[command(subcommand)]
    pub command: MonitorCommands,
}

#[derive(Subcommand, Debug)]
pub enum MonitorCommands {
    /// 실시간 모니터링 시작
    Start(MonitorStartArgs),
    /// 실시간 모니터링 중지
    Stop,
    /// 모니터링 상태 확인
    Status,
    /// 모니터링 로그 조회
    Logs(MonitorLogsArgs),
}

#[derive(Parser, Debug)]
pub struct MonitorStartArgs {
    /// 모니터링할 경로
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// 백그라운드에서 실행
    #[arg(long)]
    pub daemon: bool,

    /// 알림 방법
    #[arg(long, value_enum)]
    pub alert: Option<AlertMethod>,

    /// 제외할 파일/경로 패턴
    #[arg(long, value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// 탐지 민감도
    #[arg(long, value_enum, default_value = "medium")]
    pub sensitivity: SensitivityLevel,
}

#[derive(Parser, Debug)]
pub struct MonitorLogsArgs {
    /// 표시할 로그 라인 수
    #[arg(short, long, default_value = "50")]
    pub lines: usize,

    /// 실시간 로그 추적
    #[arg(short, long)]
    pub follow: bool,
}

#[derive(Parser, Debug)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    pub command: QuarantineCommands,
}

#[derive(Subcommand, Debug)]
pub enum QuarantineCommands {
    /// 격리된 파일 목록
    List,
    /// 격리된 파일 복구
    Restore { file_id: String },
    /// 격리된 파일 삭제
    Delete { file_id: String },
    /// 격리 파일 상세 정보
    Info { file_id: String },
}

#[derive(Parser, Debug)]
pub struct UpdateArgs {
    /// 업데이트 확인만 수행
    #[arg(long)]
    pub check: bool,

    /// 시그니처 다운로드
    #[arg(long)]
    pub download: bool,

    /// 강제 업데이트
    #[arg(long)]
    pub force: bool,

    /// 사용자 정의 업데이트 소스
    #[arg(long, value_name = "URL")]
    pub source: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ScheduleArgs {
    #[command(subcommand)]
    pub command: ScheduleCommands,
}

#[derive(Subcommand, Debug)]
pub enum ScheduleCommands {
    /// 새 스케줄 추가
    Add(ScheduleAddArgs),
    /// 스케줄 목록
    List,
    /// 스케줄 제거
    Remove { schedule_id: String },
    /// 스케줄 활성화
    Enable { schedule_id: String },
    /// 스케줄 비활성화
    Disable { schedule_id: String },
}

#[derive(Parser, Debug)]
pub struct ScheduleAddArgs {
    /// 스케줄 이름
    #[arg(long)]
    pub name: String,

    /// 스캔 경로
    #[arg(long)]
    pub path: PathBuf,

    /// 매일 실행
    #[arg(long)]
    pub daily: bool,

    /// 매주 실행
    #[arg(long)]
    pub weekly: bool,

    /// 매월 실행
    #[arg(long)]
    pub monthly: bool,

    /// 실행 시간 (HH:MM 형식)
    #[arg(long)]
    pub time: Option<String>,

    /// 크론 표현식
    #[arg(long)]
    pub cron: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// 현재 설정 표시
    Show,
    /// 설정 값 변경
    Set { key: String, value: String },
    /// 설정 초기화
    Reset,
    /// 설정 내보내기
    Export { file: PathBuf },
    /// 설정 가져오기
    Import { file: PathBuf },
}

#[derive(Parser, Debug)]
pub struct ReportArgs {
    /// 리포트 타입
    #[arg(long, value_enum)]
    pub report_type: Option<ReportType>,

    /// 출력 형식
    #[arg(long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// 기간
    #[arg(long, value_enum)]
    pub period: Option<Period>,

    /// 출력 파일
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// 필터 조건
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// 실시간 상태 모니터링
    #[arg(long)]
    pub watch: bool,

    /// JSON 형식 출력
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
    Html,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum AlertMethod {
    Email,
    Desktop,
    Log,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum SensitivityLevel {
    Low,
    Medium,
    High,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ReportType {
    Scan,
    Threat,
    System,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Period {
    Day,
    Week,
    Month,
    Year,
}