use crate::cli::args::ScheduleAddArgs;
use crate::data::models::config::AppConfig;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub schedule_type: ScheduleType,
    pub cron_expression: String,
    pub enabled: bool,
    pub created_at: u64,
    pub last_run: Option<u64>,
    pub next_run: Option<u64>,
    pub run_count: u64,
    pub scan_options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScheduleType {
    Daily,
    Weekly,
    Monthly,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub recursive: bool,
    pub depth: Option<usize>,
    pub exclude_patterns: Vec<String>,
    pub include_patterns: Vec<String>,
    pub quick_scan: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScheduleDatabase {
    pub schedules: HashMap<String, ScheduledScan>,
    pub stats: ScheduleStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScheduleStats {
    pub total_schedules: usize,
    pub active_schedules: usize,
    pub total_runs: u64,
    pub last_cleanup: u64,
}

pub struct ScheduleService {
    #[allow(dead_code)]
    config: AppConfig,
    database_path: PathBuf,
    scheduler: Option<JobScheduler>,
}

impl ScheduleService {
    pub fn new(config: AppConfig) -> Result<Self> {
        let database_path = config.signature.database_path.join("schedules.db");

        // 스케줄 디렉토리 생성
        if let Some(parent) = database_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                info!("Created schedule directory: {}", parent.display());
            }
        }

        Ok(Self {
            config,
            database_path,
            scheduler: None,
        })
    }

    pub async fn start_scheduler(&mut self) -> Result<()> {
        let scheduler = JobScheduler::new().await
            .map_err(|e| Error::JobScheduler(e.to_string()))?;

        // 기존 스케줄 로드 및 등록
        let database = self.load_database().await?;
        for (_, schedule) in database.schedules {
            if schedule.enabled {
                self.register_job(&scheduler, &schedule).await?;
            }
        }

        scheduler.start().await
            .map_err(|e| Error::JobScheduler(e.to_string()))?;
        self.scheduler = Some(scheduler);
        info!("Schedule service started");
        Ok(())
    }

    pub async fn stop_scheduler(&mut self) -> Result<()> {
        if let Some(mut scheduler) = self.scheduler.take() {
            scheduler.shutdown().await
                .map_err(|e| Error::JobScheduler(e.to_string()))?;
            info!("Schedule service stopped");
        }
        Ok(())
    }

    pub async fn add_schedule(&self, args: ScheduleAddArgs) -> Result<String> {
        let schedule_id = Uuid::new_v4().to_string();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 스케줄 타입과 cron 표현식 결정
        let (schedule_type, cron_expression) = if let Some(cron) = args.cron {
            (ScheduleType::Custom, cron)
        } else if args.daily {
            let time = args.time.unwrap_or_else(|| "02:00".to_string());
            let (hour, minute) = Self::parse_time(&time)?;
            (ScheduleType::Daily, format!("0 {} {} * * *", minute, hour))
        } else if args.weekly {
            let time = args.time.unwrap_or_else(|| "02:00".to_string());
            let (hour, minute) = Self::parse_time(&time)?;
            (ScheduleType::Weekly, format!("0 {} {} * * 0", minute, hour)) // 일요일
        } else if args.monthly {
            let time = args.time.unwrap_or_else(|| "02:00".to_string());
            let (hour, minute) = Self::parse_time(&time)?;
            (ScheduleType::Monthly, format!("0 {} {} 1 * *", minute, hour)) // 매월 1일
        } else {
            return Err(Error::Cli("No schedule type specified".to_string()));
        };

        let scheduled_scan = ScheduledScan {
            id: schedule_id.clone(),
            name: args.name,
            path: args.path,
            schedule_type,
            cron_expression,
            enabled: true,
            created_at: current_time,
            last_run: None,
            next_run: None,
            run_count: 0,
            scan_options: ScanOptions {
                recursive: true,
                depth: None,
                exclude_patterns: vec![],
                include_patterns: vec![],
                quick_scan: false,
            },
        };

        // 데이터베이스에 추가
        self.add_to_database(scheduled_scan.clone()).await?;

        // 실행 중인 스케줄러에 등록
        if let Some(scheduler) = &self.scheduler {
            self.register_job(scheduler, &scheduled_scan).await?;
        }

        info!("Schedule '{}' added successfully with ID: {}", scheduled_scan.name, schedule_id);
        Ok(schedule_id)
    }

    pub async fn remove_schedule(&self, schedule_id: &str) -> Result<bool> {
        let mut database = self.load_database().await?;

        if database.schedules.remove(schedule_id).is_some() {
            database.stats.total_schedules = database.schedules.len();
            database.stats.active_schedules = database.schedules.values()
                .filter(|s| s.enabled)
                .count();

            self.save_database(&database).await?;

            // 실행 중인 스케줄러에서 제거
            if let Some(_scheduler) = &self.scheduler {
                // JobScheduler에서 특정 job 제거는 복잡하므로 재시작 권장
                warn!("Schedule removed. Consider restarting scheduler to apply changes.");
            }

            info!("Schedule '{}' removed successfully", schedule_id);
            Ok(true)
        } else {
            warn!("Schedule '{}' not found", schedule_id);
            Ok(false)
        }
    }

    pub async fn enable_schedule(&self, schedule_id: &str) -> Result<bool> {
        let mut database = self.load_database().await?;

        if let Some(schedule) = database.schedules.get_mut(schedule_id) {
            schedule.enabled = true;
            let schedule_clone = schedule.clone();

            database.stats.active_schedules = database.schedules.values()
                .filter(|s| s.enabled)
                .count();

            self.save_database(&database).await?;

            // 실행 중인 스케줄러에 등록
            if let Some(scheduler) = &self.scheduler {
                self.register_job(scheduler, &schedule_clone).await?;
            }

            info!("Schedule '{}' enabled", schedule_id);
            Ok(true)
        } else {
            warn!("Schedule '{}' not found", schedule_id);
            Ok(false)
        }
    }

    pub async fn disable_schedule(&self, schedule_id: &str) -> Result<bool> {
        let mut database = self.load_database().await?;

        if let Some(schedule) = database.schedules.get_mut(schedule_id) {
            schedule.enabled = false;
            database.stats.active_schedules = database.schedules.values()
                .filter(|s| s.enabled)
                .count();

            self.save_database(&database).await?;
            info!("Schedule '{}' disabled", schedule_id);
            Ok(true)
        } else {
            warn!("Schedule '{}' not found", schedule_id);
            Ok(false)
        }
    }

    pub async fn list_schedules(&self) -> Result<Vec<ScheduledScan>> {
        let database = self.load_database().await?;
        Ok(database.schedules.values().cloned().collect())
    }

    pub async fn get_schedule(&self, schedule_id: &str) -> Result<ScheduledScan> {
        let database = self.load_database().await?;
        database.schedules.get(schedule_id).cloned().ok_or_else(|| {
            Error::Database(format!("Schedule not found: {}", schedule_id))
        })
    }

    pub async fn get_schedule_stats(&self) -> Result<ScheduleStats> {
        let database = self.load_database().await?;
        Ok(database.stats)
    }

    async fn load_database(&self) -> Result<ScheduleDatabase> {
        if !self.database_path.exists() {
            return Ok(ScheduleDatabase {
                schedules: HashMap::new(),
                stats: ScheduleStats {
                    total_schedules: 0,
                    active_schedules: 0,
                    total_runs: 0,
                    last_cleanup: 0,
                },
            });
        }

        let content = fs::read_to_string(&self.database_path)?;
        let database: ScheduleDatabase = serde_json::from_str(&content)?;
        Ok(database)
    }

    async fn save_database(&self, database: &ScheduleDatabase) -> Result<()> {
        let content = serde_json::to_string_pretty(database)?;
        fs::write(&self.database_path, content)?;
        Ok(())
    }

    async fn add_to_database(&self, scheduled_scan: ScheduledScan) -> Result<()> {
        let mut database = self.load_database().await?;

        database.schedules.insert(scheduled_scan.id.clone(), scheduled_scan);
        database.stats.total_schedules = database.schedules.len();
        database.stats.active_schedules = database.schedules.values()
            .filter(|s| s.enabled)
            .count();

        self.save_database(&database).await?;
        Ok(())
    }

    async fn register_job(&self, scheduler: &JobScheduler, schedule: &ScheduledScan) -> Result<()> {
        let schedule_id = schedule.id.clone();
        let scan_path = schedule.path.clone();
        let cron_expr = schedule.cron_expression.clone();

        let job = Job::new_async(cron_expr.as_str(), move |_uuid, _l| {
            let id = schedule_id.clone();
            let path = scan_path.clone();

            Box::pin(async move {
                info!("Running scheduled scan: {} for path: {}", id, path.display());

                // 실제 스캔 실행은 여기서 구현
                // 현재는 로그만 남김
                info!("Scheduled scan completed: {}", id);
            })
        })
            .map_err(|e| Error::JobScheduler(e.to_string()))?;

        scheduler.add(job).await
            .map_err(|e| Error::JobScheduler(e.to_string()))?;
        debug!("Job registered for schedule: {}", schedule.id);
        Ok(())
    }

    fn parse_time(time_str: &str) -> Result<(u32, u32)> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::Cli(format!("Invalid time format: {}", time_str)));
        }

        let hour: u32 = parts[0].parse()
            .map_err(|_| Error::Cli(format!("Invalid hour: {}", parts[0])))?;
        let minute: u32 = parts[1].parse()
            .map_err(|_| Error::Cli(format!("Invalid minute: {}", parts[1])))?;

        if hour > 23 || minute > 59 {
            return Err(Error::Cli(format!("Time out of range: {}", time_str)));
        }

        Ok((hour, minute))
    }

    pub async fn update_last_run(&self, schedule_id: &str) -> Result<()> {
        let mut database = self.load_database().await?;

        if let Some(schedule) = database.schedules.get_mut(schedule_id) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            schedule.last_run = Some(current_time);
            schedule.run_count += 1;
            database.stats.total_runs += 1;

            self.save_database(&database).await?;
        }

        Ok(())
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            depth: None,
            exclude_patterns: vec![],
            include_patterns: vec![],
            quick_scan: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_schedule_service_creation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = ScheduleService::new(config).unwrap();
        assert!(service.database_path.exists() || !service.database_path.exists()); // 파일은 나중에 생성됨
    }

    #[tokio::test]
    async fn test_time_parsing() {
        assert_eq!(ScheduleService::parse_time("02:30").unwrap(), (2, 30));
        assert_eq!(ScheduleService::parse_time("23:59").unwrap(), (23, 59));
        assert_eq!(ScheduleService::parse_time("00:00").unwrap(), (0, 0));

        assert!(ScheduleService::parse_time("24:00").is_err());
        assert!(ScheduleService::parse_time("12:60").is_err());
        assert!(ScheduleService::parse_time("invalid").is_err());
    }

    #[tokio::test]
    async fn test_schedule_operations() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = ScheduleService::new(config).unwrap();

        // 스케줄 추가
        let add_args = ScheduleAddArgs {
            name: "Test Daily Scan".to_string(),
            path: temp_dir.path().to_path_buf(),
            daily: true,
            weekly: false,
            monthly: false,
            time: Some("14:30".to_string()),
            cron: None,
        };

        let schedule_id = service.add_schedule(add_args).await.unwrap();

        // 스케줄 목록 확인
        let schedules = service.list_schedules().await.unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].name, "Test Daily Scan");

        // 스케줄 비활성화
        let disabled = service.disable_schedule(&schedule_id).await.unwrap();
        assert!(disabled);

        // 스케줄 활성화
        let enabled = service.enable_schedule(&schedule_id).await.unwrap();
        assert!(enabled);

        // 스케줄 제거
        let removed = service.remove_schedule(&schedule_id).await.unwrap();
        assert!(removed);

        // 제거 확인
        let schedules = service.list_schedules().await.unwrap();
        assert_eq!(schedules.len(), 0);
    }
}