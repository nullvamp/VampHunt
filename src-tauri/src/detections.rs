use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tauri::Manager;
use walkdir::WalkDir;

mod artifact_detections;

const CORRELATION_PACK: &str = include_str!("../../rules/vamphunt/correlations.json");

#[derive(Serialize)]
pub struct DetectionStatus {
    sigma_rules: usize,
    sigma_compatible: usize,
    hayabusa_rules: usize,
    chainsaw_rules: usize,
    correlation_rules: usize,
    yara_rules: usize,
    sigma_release: String,
    yara_release: String,
    hayabusa_release: String,
    chainsaw_release: String,
    yara_x_version: String,
    hayabusa_version: String,
    chainsaw_version: String,
    file_ready: bool,
    event_ready: bool,
    artifact_ready: bool,
    ready: bool,
}

#[derive(Serialize)]
pub struct DetectionLead {
    id: i64,
    engine: String,
    rule_id: String,
    title: String,
    severity: String,
    target: String,
    source: String,
    created_utc: String,
    raw: String,
    supporting_events: i64,
}

#[derive(Serialize)]
pub struct DetectionRunSummary {
    yara_new_leads: usize,
    hayabusa_new_leads: usize,
    chainsaw_new_leads: usize,
    correlation_new_leads: usize,
    total_new_leads: usize,
    files_considered: usize,
    evtx_files: usize,
    layers_run: Vec<String>,
}

#[derive(Deserialize)]
struct CorrelationPack {
    version: String,
    rules: Vec<CorrelationRule>,
}

#[derive(Clone, Deserialize)]
struct CorrelationRule {
    id: String,
    title: String,
    severity: String,
    kind: String,
    description: String,
    #[serde(default)]
    artifacts: Vec<String>,
    #[serde(default)]
    execution_artifacts: Vec<String>,
    #[serde(default)]
    deletion_artifacts: Vec<String>,
    #[serde(default)]
    file_names: Vec<String>,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    decoy_extensions: Vec<String>,
    #[serde(default)]
    path_markers: Vec<String>,
    #[serde(default)]
    allowed_path_markers: Vec<String>,
    #[serde(default)]
    window_days: i64,
    #[serde(default)]
    minimum_artifact_types: usize,
    #[serde(default)]
    markers: Vec<String>,
    #[serde(default)]
    event_ids: Vec<i64>,
    #[serde(default)]
    group_markers: Vec<String>,
    #[serde(default)]
    minimum_count: usize,
    #[serde(default)]
    window_minutes: i64,
}

#[derive(Clone)]
struct EventEvidence {
    id: i64,
    timestamp: Option<String>,
    artifact: String,
    path: String,
    process: String,
    summary: String,
    source_database: String,
    source_table: String,
    source_row_id: String,
}

struct CasePaths {
    root: PathBuf,
    evidence: PathBuf,
    output: PathBuf,
    audit: PathBuf,
}

fn rules_root(app: Option<&tauri::AppHandle>) -> PathBuf {
    if let Ok(value) = std::env::var("VAMPHUNT_RULES") {
        return PathBuf::from(value);
    }
    if let Some(app) = app {
        if let Ok(resource) = app.path().resource_dir() {
            let bundled = resource.join("rules");
            if bundled.join("manifest.json").is_file() {
                return bundled;
            }
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("rules")
}

fn release(manifest: &Value, name: &str) -> String {
    manifest["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|item| item["name"] == name))
        .and_then(|item| item["release"].as_str())
        .unwrap_or("Not installed")
        .to_owned()
}

fn locate_tree(root: &Path, required: &str) -> Option<PathBuf> {
    if root.join(required).is_dir() {
        return Some(root.to_owned());
    }
    WalkDir::new(root)
        .min_depth(1)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_dir() && entry.path().join(required).is_dir())
        .map(|entry| entry.path().to_owned())
}

fn locate_file(root: &Path, name: &str) -> Option<PathBuf> {
    WalkDir::new(root)
        .max_depth(4)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| {
            entry.file_type().is_file()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(name)
        })
        .map(|entry| entry.path().to_owned())
}

fn executable_version(path: &Path) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if stdout.is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_owned()
            } else {
                stdout
            }
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Not installed".into())
}

fn yaml_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(&format!("{key}:"))
            .map(|value| value.trim().trim_matches(['\'', '"']).to_ascii_lowercase())
    })
}

fn rule_level_is_enabled(text: &str) -> bool {
    let level = yaml_value(text, "level").unwrap_or_default();
    let status = yaml_value(text, "status").unwrap_or_else(|| "stable".into());
    matches!(level.as_str(), "medium" | "med" | "high" | "critical")
        && !matches!(status.as_str(), "deprecated" | "unsupported")
}

fn count_enabled_yaml(root: &Path) -> usize {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && matches!(
                    entry.path().extension().and_then(|value| value.to_str()),
                    Some("yml" | "yaml")
                )
        })
        .filter(|entry| {
            fs::read_to_string(entry.path())
                .map(|text| rule_level_is_enabled(&text))
                .unwrap_or(false)
        })
        .count()
}

fn load_correlation_pack(root: &Path) -> Result<CorrelationPack, String> {
    let path = root.join("vamphunt").join("correlations.json");
    let text = fs::read_to_string(path).unwrap_or_else(|_| CORRELATION_PACK.to_owned());
    serde_json::from_str(&text).map_err(|error| format!("Correlation rules are invalid: {error}"))
}

#[tauri::command]
pub fn detection_status(app: tauri::AppHandle) -> Result<DetectionStatus, String> {
    let root = rules_root(Some(&app));
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|_| "Rules are not installed. Run scripts\\sync-rules.ps1.".to_string())?;
    let manifest_text = String::from_utf8_lossy(&manifest_bytes);
    let manifest: Value = serde_json::from_str(manifest_text.trim_start_matches('\u{feff}'))
        .map_err(|error| format!("Rule manifest is invalid: {error}"))?;

    let yara_file = root.join("active/yara-core/packages/core/yara-rules-core.yar");
    let yara_rules = fs::read_to_string(&yara_file)
        .map(|text| {
            text.lines()
                .filter(|line| line.trim_start().starts_with("rule "))
                .count()
        })
        .unwrap_or(0);
    let yara_engine = root.join("active/yara-x/yr.exe");
    let hayabusa_engine = root.join("active/hayabusa-engine/hayabusa-4.0.0-win-x64.exe");
    let hayabusa_tree = locate_tree(&root.join("active/hayabusa-rules"), "sigma");
    let (sigma_rules, hayabusa_rules) = hayabusa_tree
        .as_ref()
        .map(|tree| {
            (
                count_enabled_yaml(&tree.join("sigma")),
                count_enabled_yaml(&tree.join("hayabusa")),
            )
        })
        .unwrap_or_default();
    let chainsaw_engine = locate_file(&root.join("active/chainsaw-engine"), "chainsaw.exe");
    let chainsaw_tree = locate_tree(&root.join("active/chainsaw-rules"), "rules");
    let chainsaw_rules = chainsaw_tree
        .as_ref()
        .map(|tree| count_enabled_yaml(&tree.join("rules")))
        .unwrap_or(0);
    let correlation_rules = load_correlation_pack(&root)?.rules.len();
    let file_ready = yara_engine.is_file() && yara_file.is_file();
    let event_ready = hayabusa_engine.is_file() && hayabusa_tree.is_some();
    let artifact_ready = chainsaw_engine.is_some() && chainsaw_tree.is_some();
    Ok(DetectionStatus {
        sigma_rules,
        sigma_compatible: sigma_rules,
        hayabusa_rules,
        chainsaw_rules,
        correlation_rules,
        yara_rules,
        sigma_release: release(&manifest, "sigma-core"),
        yara_release: release(&manifest, "yara-core"),
        hayabusa_release: release(&manifest, "hayabusa-rules"),
        chainsaw_release: release(&manifest, "chainsaw-rules"),
        yara_x_version: executable_version(&yara_engine),
        hayabusa_version: executable_version(&hayabusa_engine),
        chainsaw_version: chainsaw_engine
            .as_deref()
            .map(executable_version)
            .unwrap_or_else(|| "Not installed".into()),
        file_ready,
        event_ready,
        artifact_ready,
        ready: file_ready && event_ready && artifact_ready,
    })
}

fn case_paths(case_path: &str) -> Result<CasePaths, String> {
    let root = Path::new(case_path)
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    if !root.join("case.json").is_file() {
        return Err("Open a valid VampHunt case first.".into());
    }
    let evidence = root
        .join("EVIDENCE")
        .canonicalize()
        .map_err(|_| "The case evidence directory is unavailable.".to_string())?;
    for name in ["OUTPUT", "AUDIT", "DATABASE"] {
        fs::create_dir_all(root.join(name)).map_err(|error| error.to_string())?;
    }
    let output = root
        .join("OUTPUT")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let audit = root
        .join("AUDIT")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !evidence.starts_with(&root) || !output.starts_with(&root) || !audit.starts_with(&root) {
        return Err("A case directory points outside this case.".into());
    }
    Ok(CasePaths {
        root,
        evidence,
        output,
        audit,
    })
}

fn validate_target(paths: &CasePaths, evidence_path: &str) -> Result<PathBuf, String> {
    let target = Path::new(evidence_path.trim())
        .canonicalize()
        .map_err(|_| "Select an existing case evidence file or directory.".to_string())?;
    if !target.starts_with(&paths.evidence) {
        return Err("Import the source into this case before scanning it.".into());
    }
    if !target.is_file() && !target.is_dir() {
        return Err("The selected evidence target is unavailable.".into());
    }
    Ok(target)
}

fn ensure_detection_schema(db: &Connection) -> Result<(), String> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS detection_leads(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           engine TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL,
           severity TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL,
           created_utc TEXT NOT NULL, raw TEXT NOT NULL,
           UNIQUE(engine,rule_id,target));
         CREATE TABLE IF NOT EXISTS detection_lead_events(
           lead_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
           PRIMARY KEY(lead_id,event_id),
           FOREIGN KEY(lead_id) REFERENCES detection_leads(id),
           FOREIGN KEY(event_id) REFERENCES events(id));
         CREATE INDEX IF NOT EXISTS idx_detection_leads_rule ON detection_leads(rule_id);
         CREATE INDEX IF NOT EXISTS idx_detection_lead_events_event ON detection_lead_events(event_id);
         CREATE TABLE IF NOT EXISTS detection_state(
           name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_utc TEXT NOT NULL);",
    )
    .map_err(|error| error.to_string())?;
    let has_events = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if has_events {
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source_record
             ON events(source_database,source_table,source_sql_rowid)",
            [],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn case_db(case_path: &str) -> Result<Connection, String> {
    let paths = case_paths(case_path)?;
    let db = Connection::open(crate::paths::case_database(&paths.root)?)
        .map_err(|error| error.to_string())?;
    ensure_detection_schema(&db)?;
    Ok(db)
}

#[allow(clippy::too_many_arguments)]
fn insert_lead(
    db: &Connection,
    engine: &str,
    rule_id: &str,
    title: &str,
    level: &str,
    target: &str,
    source: &str,
    raw: &str,
    event_ids: &[i64],
) -> Result<usize, String> {
    let inserted = db.execute(
        "INSERT OR IGNORE INTO detection_leads(engine,rule_id,title,severity,target,source,created_utc,raw)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![engine, rule_id, title, level, target, source, Utc::now().to_rfc3339(), raw],
    ).map_err(|error| error.to_string())?;
    let lead_id = db
        .query_row(
            "SELECT id FROM detection_leads WHERE engine=?1 AND rule_id=?2 AND target=?3",
            params![engine, rule_id, target],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?;
    for event_id in event_ids {
        db.execute(
            "INSERT OR IGNORE INTO detection_lead_events(lead_id,event_id) VALUES(?1,?2)",
            params![lead_id, event_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(inserted)
}

fn metadata(rule: &Value, key: &str) -> Option<String> {
    rule["meta"].as_array()?.iter().find_map(|pair| {
        let values = pair.as_array()?;
        if values.first()?.as_str()? != key {
            return None;
        }
        values.get(1).map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        })
    })
}

fn severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "crit" | "critical" => "Critical".into(),
        "high" => "High".into(),
        "med" | "medium" => "Medium".into(),
        "info" | "informational" | "low" => "Low".into(),
        _ => "Unknown".into(),
    }
}

fn severity_rank(value: &str) -> u8 {
    match severity(value).as_str() {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn count_files(target: &Path) -> usize {
    if target.is_file() {
        return 1;
    }
    WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .count()
}

fn count_extension(target: &Path, wanted: &str) -> usize {
    WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|v| v.to_str())
                    .map(|value| value.eq_ignore_ascii_case(wanted))
                    .unwrap_or(false)
        })
        .count()
}

fn audit_path(paths: &CasePaths, prefix: &str) -> PathBuf {
    paths.audit.join(format!(
        "{}-{}.json",
        prefix,
        Utc::now().format("%Y%m%d-%H%M%S-%3f")
    ))
}

fn write_audit(paths: &CasePaths, prefix: &str, value: &Value) -> Result<(), String> {
    fs::write(
        audit_path(paths, prefix),
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn run_yara_scan_at_root(
    root: &Path,
    case_path: &str,
    evidence_path: &str,
) -> Result<usize, String> {
    let paths = case_paths(case_path)?;
    let target = validate_target(&paths, evidence_path)?;
    let engine = root.join("active/yara-x/yr.exe");
    let rules = root.join("active/yara-core/packages/core/yara-rules-core.yar");
    if !engine.is_file() || !rules.is_file() {
        return Err("The YARA-X engine or YARA Core rules are missing.".into());
    }
    let mut command = Command::new(engine);
    command
        .arg("scan")
        .arg("--output-format")
        .arg("ndjson")
        .arg("--print-meta")
        .arg("--print-tags")
        .arg("--ignore-invalid-rules")
        .arg("--disable-warnings")
        .arg("--no-mmap")
        .arg("--cpu-limit")
        .arg("50")
        .arg("--threads")
        .arg("4")
        .arg("--timeout")
        .arg("3600")
        .arg("--skip-larger")
        .arg("2147483648");
    if target.is_dir() {
        command.arg("--recursive");
    }
    let output = command
        .arg(rules)
        .arg(&target)
        .output()
        .map_err(|error| format!("Could not start YARA-X: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "YARA-X failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let db = case_db(case_path)?;
    let mut inserted = 0;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let path = value["path"].as_str().unwrap_or_default();
        for rule in value["rules"].as_array().into_iter().flatten() {
            let id = rule["identifier"].as_str().unwrap_or("unknown");
            let title = metadata(rule, "description").unwrap_or_else(|| id.to_owned());
            let level = metadata(rule, "severity")
                .or_else(|| metadata(rule, "level"))
                .map(|value| severity(&value))
                .unwrap_or_else(|| "Unknown".into());
            inserted += insert_lead(
                &db,
                "YARA-X",
                id,
                &title,
                &level,
                path,
                "YARA Forge Core",
                &rule.to_string(),
                &[],
            )?;
        }
    }
    write_audit(
        &paths,
        "yara-x",
        &json!({
            "engine":"YARA-X", "rule_source":"YARA Forge Core", "target":target,
            "completed_utc":Utc::now().to_rfc3339(), "new_leads":inserted
        }),
    )?;
    Ok(inserted)
}

#[tauri::command]
pub async fn run_yara_scan(
    app: tauri::AppHandle,
    case_path: String,
    evidence_path: String,
) -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = rules_root(Some(&app));
        run_yara_scan_at_root(&root, &case_path, &evidence_path)
    })
    .await
    .map_err(|error| error.to_string())?
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn hayabusa_event_id(db: &Connection, value: &Value) -> Option<i64> {
    let computer = scalar(&value["Computer"]);
    let event_id = scalar(&value["EventID"]);
    let record_id = scalar(&value["RecordID"]);
    if event_id.is_empty() || record_id.is_empty() {
        return None;
    }
    db.query_row(
        "SELECT id FROM events WHERE artifact_type='evtx'
           AND (?1='' OR lower(coalesce(host,''))=lower(?1))
           AND summary LIKE ?2 AND source_row_id LIKE ?3 ORDER BY id LIMIT 1",
        params![
            computer,
            format!("% event {event_id}"),
            format!("%:{record_id}")
        ],
        |record| record.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

fn run_hayabusa_scan_at_root(
    root: &Path,
    case_path: &str,
    evidence_path: &str,
) -> Result<usize, String> {
    let paths = case_paths(case_path)?;
    let target = validate_target(&paths, evidence_path)?;
    if count_extension(&target, "evtx") == 0 {
        return Ok(0);
    }
    let engine = root.join("active/hayabusa-engine/hayabusa-4.0.0-win-x64.exe");
    let rule_tree = locate_tree(&root.join("active/hayabusa-rules"), "sigma")
        .ok_or_else(|| "Hayabusa event rules are missing.".to_string())?;
    if !engine.is_file() {
        return Err("The Hayabusa event engine is missing.".into());
    }
    let output_dir = paths.output.join("Hayabusa");
    fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    let output_file = output_dir.join(format!(
        "detections-{}.jsonl",
        Utc::now().format("%Y%m%d-%H%M%S-%3f")
    ));
    let output = Command::new(&engine)
        .arg("dfir-timeline")
        .arg("--directory")
        .arg(&target)
        .arg("--rules")
        .arg(&rule_tree)
        .arg("--rules-config")
        .arg(rule_tree.join("config"))
        .arg("--output")
        .arg(&output_file)
        .arg("--output-type")
        .arg("jsonl")
        .arg("--no-wizard")
        .arg("--quiet")
        .arg("--quiet-errors")
        .arg("--no-summary")
        .arg("--no-color")
        .arg("--iso-8601")
        .arg("--min-level")
        .arg("medium")
        .arg("--exclude-status")
        .arg("deprecated")
        .arg("--clobber")
        .output()
        .map_err(|error| format!("Could not start Hayabusa: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Hayabusa failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let db = case_db(case_path)?;
    let mut inserted = 0;
    for line in fs::read_to_string(&output_file).unwrap_or_default().lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let rule_id = scalar(&value["RuleID"]);
        let title = scalar(&value["RuleTitle"]);
        if rule_id.is_empty() || title.is_empty() {
            continue;
        }
        let target_text = format!(
            "{} | {} event {} | record {} | {}",
            scalar(&value["Computer"]),
            scalar(&value["Channel"]),
            scalar(&value["EventID"]),
            scalar(&value["RecordID"]),
            scalar(&value["Timestamp"])
        );
        let event_ids = hayabusa_event_id(&db, &value)
            .into_iter()
            .collect::<Vec<_>>();
        inserted += insert_lead(
            &db,
            "Hayabusa/Sigma",
            &rule_id,
            &title,
            &severity(&scalar(&value["Level"])),
            &target_text,
            "Yamato Security Hayabusa rules and SigmaHQ",
            line,
            &event_ids,
        )?;
    }
    write_audit(
        &paths,
        "hayabusa",
        &json!({
            "engine":"Hayabusa", "rule_source":"Hayabusa rules with SigmaHQ", "target":target,
            "result_file":output_file, "completed_utc":Utc::now().to_rfc3339(), "new_leads":inserted
        }),
    )?;
    Ok(inserted)
}

fn value_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    value.pointer(pointer).filter(|value| !value.is_null())
}

fn chainsaw_inner_path(value: &Value) -> String {
    [
        "/document/data/FullPath",
        "/document/data/Event/EventData/Image",
        "/document/data/Event/EventData/TargetFilename",
        "/document/data/Event/EventData/ServiceFileName",
    ]
    .iter()
    .find_map(|pointer| value_at(value, pointer).map(scalar))
    .unwrap_or_default()
}

fn chainsaw_quality_excluded(title: &str, value: &Value) -> bool {
    let title = title.to_ascii_lowercase();
    if title != "conhost.exe suspicious location" && title != "svchost.exe suspicious location" {
        return false;
    }
    let path = chainsaw_inner_path(value)
        .replace('\\', "/")
        .to_ascii_lowercase();
    path.contains("windows/winsxs/")
        || path.contains("windows/system32/")
        || path.contains("windows/syswow64/")
        || path.contains("windows/prefetch/")
}

fn purge_known_chainsaw_false_positives(db: &Connection) -> Result<(), String> {
    db.execute(
        "DELETE FROM detection_lead_events WHERE lead_id IN (
           SELECT id FROM detection_leads WHERE engine='Chainsaw'
             AND lower(title) IN ('conhost.exe suspicious location','svchost.exe suspicious location')
             AND (lower(raw) LIKE '%windows/prefetch/%' OR lower(raw) LIKE '%windows/winsxs/%'
                  OR lower(raw) LIKE '%windows/system32/%' OR lower(raw) LIKE '%windows/syswow64/%'))",
        [],
    ).map_err(|error| error.to_string())?;
    db.execute(
        "DELETE FROM detection_leads WHERE engine='Chainsaw'
           AND lower(title) IN ('conhost.exe suspicious location','svchost.exe suspicious location')
           AND (lower(raw) LIKE '%windows/prefetch/%' OR lower(raw) LIKE '%windows/winsxs/%'
                OR lower(raw) LIKE '%windows/system32/%' OR lower(raw) LIKE '%windows/syswow64/%')",
        [],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn stable_rule_id(prefix: &str, group: &str, title: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group.as_bytes());
    hasher.update([0]);
    hasher.update(title.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{prefix}-{}", &digest[..16])
}

fn run_chainsaw_scan_at_root(
    root: &Path,
    case_path: &str,
    evidence_path: &str,
) -> Result<usize, String> {
    let paths = case_paths(case_path)?;
    let target = validate_target(&paths, evidence_path)?;
    let engine = locate_file(&root.join("active/chainsaw-engine"), "chainsaw.exe")
        .ok_or_else(|| "The Chainsaw artifact engine is missing.".to_string())?;
    let rule_tree = locate_tree(&root.join("active/chainsaw-rules"), "rules")
        .ok_or_else(|| "Chainsaw artifact rules are missing.".to_string())?;
    let output = Command::new(&engine)
        .arg("hunt")
        .arg("--rule")
        .arg(rule_tree.join("rules"))
        .arg(&target)
        .arg("--jsonl")
        .arg("-q")
        .arg("--skip-errors")
        .output()
        .map_err(|error| format!("Could not start Chainsaw: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Chainsaw failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output_dir = paths.output.join("Chainsaw");
    fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    let output_file = output_dir.join(format!(
        "detections-{}.jsonl",
        Utc::now().format("%Y%m%d-%H%M%S-%3f")
    ));
    fs::write(&output_file, &output.stdout).map_err(|error| error.to_string())?;
    let db = case_db(case_path)?;
    purge_known_chainsaw_false_positives(&db)?;
    let mut inserted = 0;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let level = scalar(&value["level"]);
        let status = scalar(&value["status"]);
        if severity_rank(&level) < 2
            || matches!(
                status.to_ascii_lowercase().as_str(),
                "deprecated" | "unsupported"
            )
        {
            continue;
        }
        let title = scalar(&value["name"]);
        let group = scalar(&value["group"]);
        if title.is_empty() || chainsaw_quality_excluded(&title, &value) {
            continue;
        }
        let source_path = scalar(&value["document"]["path"]);
        let inner_path = chainsaw_inner_path(&value);
        let target_text = if inner_path.is_empty() {
            source_path
        } else {
            format!("{inner_path} | source: {source_path}")
        };
        inserted += insert_lead(
            &db,
            "Chainsaw",
            &stable_rule_id("CHAINSAW", &group, &title),
            &title,
            &severity(&level),
            &target_text,
            "WithSecureLabs Chainsaw rules",
            line,
            &[],
        )?;
    }
    write_audit(
        &paths,
        "chainsaw",
        &json!({
            "engine":"Chainsaw", "rule_source":"WithSecureLabs Chainsaw rules", "target":target,
            "result_file":output_file,
            "quality_gate":"medium or higher; deprecated, unsupported, and known system-path false positives excluded",
            "completed_utc":Utc::now().to_rfc3339(), "new_leads":inserted
        }),
    )?;
    Ok(inserted)
}

fn normalized_path(value: &str) -> String {
    value.replace('/', "\\").to_ascii_lowercase()
}

fn basename(value: &str) -> String {
    value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn extension(value: &str) -> String {
    basename(value)
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

fn event_path(event: &EventEvidence) -> String {
    if event.path.trim().is_empty() {
        event.process.clone()
    } else {
        event.path.clone()
    }
}

fn event_json(rule: &CorrelationRule, events: &[EventEvidence]) -> String {
    json!({
        "description": rule.description,
        "events": events.iter().map(|event| json!({
            "event_id":event.id, "timestamp":event.timestamp, "artifact":event.artifact,
            "path":event.path, "process":event.process, "summary":event.summary,
            "source_database":event.source_database, "source_table":event.source_table,
            "source_row_id":event.source_row_id
        })).collect::<Vec<_>>()
    })
    .to_string()
}

fn parse_time(value: Option<&str>) -> Option<DateTime<Utc>> {
    let value = value?;
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f UTC")
                .ok()
                .map(|value| value.and_utc())
        })
}

fn within_days(before: Option<&str>, after: Option<&str>, days: i64) -> bool {
    let (Some(before), Some(after)) = (parse_time(before), parse_time(after)) else {
        return false;
    };
    let difference = after.signed_duration_since(before);
    difference.num_seconds() >= 0 && difference.num_days() <= days
}

fn rule_by_kind<'a>(pack: &'a CorrelationPack, kind: &str) -> Option<&'a CorrelationRule> {
    pack.rules.iter().find(|rule| rule.kind == kind)
}

fn refresh_vamphunt_rules(db: &Connection, pack: &CorrelationPack) -> Result<(), String> {
    for rule in &pack.rules {
        db.execute(
            "DELETE FROM detection_lead_events WHERE lead_id IN (
               SELECT id FROM detection_leads
               WHERE title=?1 AND source LIKE '% cross-artifact rules'
                 AND engine NOT IN ('VampHunt','YARA-X','Hayabusa/Sigma','Chainsaw'))",
            params![rule.title],
        )
        .map_err(|error| error.to_string())?;
        db.execute(
            "DELETE FROM detection_leads
             WHERE title=?1 AND source LIKE '% cross-artifact rules'
               AND engine NOT IN ('VampHunt','YARA-X','Hayabusa/Sigma','Chainsaw')",
            params![rule.title],
        )
        .map_err(|error| error.to_string())?;
    }
    db.execute(
        "DELETE FROM detection_state
         WHERE name LIKE '%_rule_pack' AND name<>'vamphunt_rule_pack'",
        [],
    )
    .map_err(|error| error.to_string())?;
    let installed = db
        .query_row(
            "SELECT value FROM detection_state WHERE name='vamphunt_rule_pack'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if installed.as_deref() == Some(pack.version.as_str()) {
        return Ok(());
    }
    let tx = db
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    tx.execute(
        "DELETE FROM detection_lead_events WHERE lead_id IN (
           SELECT id FROM detection_leads WHERE engine='VampHunt')",
        [],
    )
    .map_err(|error| error.to_string())?;
    tx.execute("DELETE FROM detection_leads WHERE engine='VampHunt'", [])
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO detection_state(name,value,updated_utc)
         VALUES('vamphunt_rule_pack',?1,?2)
         ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_utc=excluded.updated_utc",
        params![pack.version, Utc::now().to_rfc3339()],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

fn run_correlation_scan_at_root(root: &Path, case_path: &str) -> Result<usize, String> {
    let pack = load_correlation_pack(root)?;
    let paths = case_paths(case_path)?;
    let db = case_db(case_path)?;
    refresh_vamphunt_rules(&db, &pack)?;
    let has_events = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !has_events {
        return Ok(0);
    }

    let single_rules = pack
        .rules
        .iter()
        .filter(|rule| {
            matches!(
                rule.kind.as_str(),
                "user_writable_executable"
                    | "named_file"
                    | "system_binary_location"
                    | "double_extension"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut pending = Vec::<(CorrelationRule, EventEvidence, String)>::new();
    let mut pending_counts = HashMap::<String, usize>::new();
    let mut seen = HashSet::<(String, String)>::new();
    let mut executions = HashMap::<String, Vec<EventEvidence>>::new();
    let mut deletions = HashMap::<String, Vec<EventEvidence>>::new();
    let mut writable = HashMap::<String, Vec<EventEvidence>>::new();
    let mut statement = db
        .prepare(
            "SELECT id,timestamp_utc,artifact_type,coalesce(path,''),coalesce(process,''),summary,
                source_database,source_table,source_row_id FROM events
         WHERE coalesce(path,'')<>'' OR coalesce(process,'')<>''",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(EventEvidence {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                artifact: row.get(2)?,
                path: row.get(3)?,
                process: row.get(4)?,
                summary: row.get(5)?,
                source_database: row.get(6)?,
                source_table: row.get(7)?,
                source_row_id: row.get(8)?,
            })
        })
        .map_err(|error| error.to_string())?;
    for row in rows {
        let event = row.map_err(|error| error.to_string())?;
        let candidate = event_path(&event);
        let path = normalized_path(&candidate);
        let name = basename(&candidate);
        let ext = extension(&candidate);
        for rule in &single_rules {
            if !rule.artifacts.iter().any(|item| item == &event.artifact) {
                continue;
            }
            let matched = match rule.kind.as_str() {
                "user_writable_executable" => {
                    rule.extensions.iter().any(|item| item == &ext)
                        && rule.path_markers.iter().any(|item| path.contains(item))
                }
                "named_file" => rule.file_names.iter().any(|item| item == &name),
                "system_binary_location" => {
                    rule.file_names.iter().any(|item| item == &name)
                        && path.contains('\\')
                        && !rule
                            .allowed_path_markers
                            .iter()
                            .any(|item| path.contains(item))
                }
                "double_extension" => {
                    let parts = name.split('.').collect::<Vec<_>>();
                    parts.len() >= 3
                        && rule.extensions.iter().any(|item| item == &ext)
                        && rule
                            .decoy_extensions
                            .iter()
                            .any(|item| item == parts[parts.len() - 2])
                }
                _ => false,
            };
            let key = (rule.id.clone(), format!("{}:{candidate}", event.artifact));
            let count = pending_counts.entry(rule.id.clone()).or_default();
            if matched && *count < 2_000 && seen.insert(key) {
                *count += 1;
                pending.push((rule.clone(), event.clone(), candidate.clone()));
            }
        }
        if name.is_empty() {
            continue;
        }
        if pack.rules.iter().any(|rule| {
            rule.kind == "execution_then_deletion"
                && rule
                    .execution_artifacts
                    .iter()
                    .any(|item| item == &event.artifact)
        }) {
            executions
                .entry(name.clone())
                .or_default()
                .push(event.clone());
        }
        if pack.rules.iter().any(|rule| {
            rule.kind == "execution_then_deletion"
                && rule
                    .deletion_artifacts
                    .iter()
                    .any(|item| item == &event.artifact)
        }) {
            deletions
                .entry(name.clone())
                .or_default()
                .push(event.clone());
        }
        if matches!(
            event.artifact.as_str(),
            "prefetch" | "shimcache" | "lnk" | "jump_list" | "amcache"
        ) && [
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\windows\\temp\\",
            "\\programdata\\",
            "\\users\\public\\",
        ]
        .iter()
        .any(|marker| path.contains(marker))
        {
            writable.entry(name).or_default().push(event);
        }
    }
    drop(statement);

    let mut inserted = 0;
    for (rule, event, candidate) in pending {
        inserted += insert_lead(
            &db,
            "VampHunt",
            &rule.id,
            &rule.title,
            &rule.severity,
            &format!("{} | {}", candidate, event.summary),
            "VampHunt cross-artifact rules",
            &event_json(&rule, std::slice::from_ref(&event)),
            &[event.id],
        )?;
    }

    if let Some(rule) = rule_by_kind(&pack, "execution_then_deletion") {
        for (name, deleted_events) in deletions {
            if !rule.extensions.iter().any(|item| item == &extension(&name)) {
                continue;
            }
            let Some(executed_events) = executions.get(&name) else {
                continue;
            };
            for deleted in deleted_events {
                let Some(executed) = executed_events.iter().find(|executed| {
                    within_days(
                        executed.timestamp.as_deref(),
                        deleted.timestamp.as_deref(),
                        rule.window_days,
                    )
                }) else {
                    continue;
                };
                let pair = vec![executed.clone(), deleted.clone()];
                let target = format!(
                    "{} | execution: {} | deletion: {}",
                    name,
                    executed.timestamp.as_deref().unwrap_or("unknown"),
                    deleted.timestamp.as_deref().unwrap_or("unknown")
                );
                inserted += insert_lead(
                    &db,
                    "VampHunt",
                    &rule.id,
                    &rule.title,
                    &rule.severity,
                    &target,
                    "VampHunt cross-artifact rules",
                    &event_json(rule, &pair),
                    &[executed.id, deleted.id],
                )?;
            }
        }
    }

    if let Some(rule) = rule_by_kind(&pack, "corroborated_user_writable") {
        for (name, mut related) in writable {
            if !rule.extensions.iter().any(|item| item == &extension(&name)) {
                continue;
            }
            if let Some(executed) = executions.get(&name) {
                related.extend(executed.iter().cloned());
            }
            related.sort_by_key(|event| event.id);
            related.dedup_by_key(|event| event.id);
            let mut artifacts = related
                .iter()
                .map(|event| event.artifact.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            artifacts.sort();
            if artifacts.len() < rule.minimum_artifact_types.max(2) {
                continue;
            }
            let event_ids = related.iter().map(|event| event.id).collect::<Vec<_>>();
            inserted += insert_lead(
                &db,
                "VampHunt",
                &rule.id,
                &rule.title,
                &rule.severity,
                &format!("{name} | artifacts: {}", artifacts.join(", ")),
                "VampHunt cross-artifact rules",
                &event_json(rule, &related),
                &event_ids,
            )?;
        }
    }
    inserted += artifact_detections::scan(&paths.root, &db, &pack)?;
    write_audit(
        &paths,
        "vamphunt-correlations",
        &json!({
            "engine":"VampHunt", "rule_source":"VampHunt cross-artifact rules",
            "completed_utc":Utc::now().to_rfc3339(), "rules":pack.rules.len(), "new_leads":inserted
        }),
    )?;
    Ok(inserted)
}

#[tauri::command]
pub async fn run_detection_scan(
    app: tauri::AppHandle,
    case_path: String,
    evidence_path: String,
) -> Result<DetectionRunSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = rules_root(Some(&app));
        let paths = case_paths(&case_path)?;
        let target = validate_target(&paths, &evidence_path)?;
        let files_considered = count_files(&target);
        let evtx_files = count_extension(&target, "evtx");
        let mut layers_run = Vec::new();
        let yara_new_leads = run_yara_scan_at_root(&root, &case_path, &evidence_path)?;
        layers_run.push("YARA-X file scan".into());
        let hayabusa_new_leads = if evtx_files > 0 {
            layers_run.push("Hayabusa and Sigma event scan".into());
            run_hayabusa_scan_at_root(&root, &case_path, &evidence_path)?
        } else {
            0
        };
        layers_run.push("Chainsaw artifact scan".into());
        let chainsaw_new_leads = run_chainsaw_scan_at_root(&root, &case_path, &evidence_path)?;
        layers_run.push("VampHunt cross-artifact scan".into());
        let correlation_new_leads = run_correlation_scan_at_root(&root, &case_path)?;
        let total_new_leads =
            yara_new_leads + hayabusa_new_leads + chainsaw_new_leads + correlation_new_leads;
        let summary = DetectionRunSummary {
            yara_new_leads,
            hayabusa_new_leads,
            chainsaw_new_leads,
            correlation_new_leads,
            total_new_leads,
            files_considered,
            evtx_files,
            layers_run,
        };
        write_audit(
            &paths,
            "detection-run",
            &serde_json::to_value(&summary).map_err(|e| e.to_string())?,
        )?;
        Ok(summary)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_detection_leads(case_path: String) -> Result<Vec<DetectionLead>, String> {
    let db = case_db(&case_path)?;
    let mut statement = db.prepare(
        "SELECT lead.id,lead.engine,lead.rule_id,lead.title,lead.severity,lead.target,
                lead.source,lead.created_utc,lead.raw,
                (SELECT count(*) FROM detection_lead_events link WHERE link.lead_id=lead.id)
         FROM detection_leads lead
         ORDER BY CASE lead.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END DESC,
                  lead.created_utc DESC,lead.id DESC"
    ).map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(DetectionLead {
                id: row.get(0)?,
                engine: row.get(1)?,
                rule_id: row.get(2)?,
                title: row.get(3)?,
                severity: row.get(4)?,
                target: row.get(5)?,
                source: row.get(6)?,
                created_utc: row.get(7)?,
                raw: row.get(8)?,
                supporting_events: row.get(9)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_levels() {
        assert_eq!(severity("med"), "Medium");
        assert_eq!(severity("critical"), "Critical");
        assert_eq!(severity_rank("info"), 1);
    }

    #[test]
    fn parses_the_bundled_correlation_pack() {
        let pack: CorrelationPack = serde_json::from_str(CORRELATION_PACK).unwrap();
        assert!(pack.rules.len() >= 29);
        let ids = pack
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), pack.rules.len());
        assert!(pack.rules.iter().all(|rule| !rule.description.is_empty()));
    }

    #[test]
    fn excludes_known_system_store_false_positives() {
        let match_value =
            json!({"document":{"data":{"FullPath":"Windows/WinSxS/component/conhost.exe"}}});
        assert!(chainsaw_quality_excluded(
            "conhost.exe Suspicious Location",
            &match_value
        ));
        let real_lead = json!({"document":{"data":{"FullPath":"Users/Public/conhost.exe"}}});
        assert!(!chainsaw_quality_excluded(
            "conhost.exe Suspicious Location",
            &real_lead
        ));
    }

    #[test]
    fn identifies_double_extensions() {
        let pack: CorrelationPack = serde_json::from_str(CORRELATION_PACK).unwrap();
        let rule = rule_by_kind(&pack, "double_extension").unwrap();
        let parts = "invoice.pdf.exe".split('.').collect::<Vec<_>>();
        assert!(rule.extensions.iter().any(|value| value == "exe"));
        assert!(rule
            .decoy_extensions
            .iter()
            .any(|value| value == parts[parts.len() - 2]));
    }

    #[test]
    fn cross_artifact_rules_keep_the_supporting_events() {
        let root =
            std::env::temp_dir().join(format!("vamphunt-detection-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for folder in ["EVIDENCE", "OUTPUT", "AUDIT", "DATABASE", "PROCESSED"] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }
        fs::write(root.join("case.json"), br#"{"id":"CASE-1"}"#).unwrap();
        let database = root.join("DATABASE/vamphunt.db");
        let db = Connection::open(&database).unwrap();
        db.execute_batch(
            "CREATE TABLE events(
               id INTEGER PRIMARY KEY,timestamp_utc TEXT,artifact_type TEXT,event_type TEXT,
               host TEXT,user TEXT,path TEXT,process TEXT,summary TEXT,parser TEXT,
               source_database TEXT,source_table TEXT,source_row_id TEXT,source_sql_rowid INTEGER);
             INSERT INTO events VALUES(1,'2026-09-01T10:00:00Z','prefetch','program_execution',NULL,NULL,'EVIL.EXE','EVIL.EXE','EVIL.EXE executed','prefetch','prefetch.db','prefetch_data','EVIL.EXE:1',1);
             INSERT INTO events VALUES(2,'2026-09-01T10:01:00Z','shimcache','application_observed',NULL,NULL,'C:\\Users\\Public\\evil.exe','evil.exe','evil.exe observed in Shimcache','shimcache','shimcache.db','shimcache_entries','2',2);
             INSERT INTO events VALUES(3,'2026-09-02T10:00:00Z','recycle_bin','file_deleted',NULL,NULL,'C:\\Users\\Public\\evil.exe',NULL,'evil.exe deleted','recycle-bin','recycle.db','recycle_bin_entries','3',3);",
        ).unwrap();
        drop(db);
        let rules = root.join("missing-rules-directory");
        let inserted = run_correlation_scan_at_root(&rules, &root.display().to_string()).unwrap();
        assert!(inserted >= 3);
        let db = Connection::open(database).unwrap();
        let linked: i64 = db.query_row(
            "SELECT count(*) FROM detection_lead_events link JOIN detection_leads lead ON lead.id=link.lead_id WHERE lead.rule_id IN ('VH-XART-006','VH-XART-007')",
            [], |row| row.get(0),
        ).unwrap();
        assert!(linked >= 4);
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires VAMPHUNT_TEST_CASE and VAMPHUNT_TEST_EVIDENCE"]
    fn real_collection_runs_every_detection_layer() {
        let case_path = std::env::var("VAMPHUNT_TEST_CASE").unwrap();
        let evidence_path = std::env::var("VAMPHUNT_TEST_EVIDENCE").unwrap();
        let rules = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("rules");
        let summary_only = std::env::var("VAMPHUNT_SUMMARY_ONLY").is_ok();
        let yara = if summary_only {
            0
        } else {
            run_yara_scan_at_root(&rules, &case_path, &evidence_path).unwrap()
        };
        let hayabusa = if summary_only {
            0
        } else {
            run_hayabusa_scan_at_root(&rules, &case_path, &evidence_path).unwrap()
        };
        let chainsaw = if summary_only {
            0
        } else {
            run_chainsaw_scan_at_root(&rules, &case_path, &evidence_path).unwrap()
        };
        let correlations = if summary_only {
            0
        } else {
            run_correlation_scan_at_root(&rules, &case_path).unwrap()
        };
        let db = case_db(&case_path).unwrap();
        let saved: i64 = db
            .query_row("SELECT count(*) FROM detection_leads", [], |row| row.get(0))
            .unwrap();
        let hayabusa_saved: i64 = db
            .query_row(
                "SELECT count(*) FROM detection_leads WHERE engine='Hayabusa/Sigma'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let chainsaw_saved: i64 = db
            .query_row(
                "SELECT count(*) FROM detection_leads WHERE engine='Chainsaw'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        eprintln!(
            "yara={yara} hayabusa={hayabusa} chainsaw={chainsaw} correlations={correlations} saved={saved}"
        );
        let mut groups = db
            .prepare(
                "SELECT engine,title,severity,count(*) FROM detection_leads GROUP BY engine,title,severity ORDER BY engine,count(*) DESC,title",
            )
            .unwrap();
        let rows = groups
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (engine, title, level, count) = row.unwrap();
            eprintln!("{engine} | {level} | {count} | {title}");
        }
        drop(groups);
        drop(db);
        let report = crate::reports::generate_html_report(case_path.clone(), vec![], vec![])
            .expect("the retained leads should produce a report");
        let html = fs::read_to_string(&report).unwrap();
        eprintln!("report={report}");
        assert!(html.contains("Rule matches requiring review"));
        assert!(html.contains("Windows Defender Real-time Protection Disabled"));
        assert!(html.contains("evtx_events"));
        assert!(
            hayabusa_saved > 0,
            "the EVTX corpus should produce event leads"
        );
        assert!(
            chainsaw_saved > 0,
            "the raw artifact corpus should produce leads"
        );
        assert!(saved > 0);
    }

    #[test]
    #[ignore = "requires VAMPHUNT_TEST_CASE"]
    fn real_collection_runs_artifact_correlations() {
        let case_path = std::env::var("VAMPHUNT_TEST_CASE").unwrap();
        let rules = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("rules");
        let inserted = run_correlation_scan_at_root(&rules, &case_path).unwrap();
        let db = case_db(&case_path).unwrap();
        let saved: i64 = db
            .query_row(
                "SELECT count(*) FROM detection_leads WHERE engine='VampHunt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        eprintln!("correlations_inserted={inserted} vamphunt_saved={saved}");
        let mut groups = db
            .prepare(
                "SELECT rule_id,title,severity,count(*) FROM detection_leads
                 WHERE engine='VampHunt'
                 GROUP BY rule_id,title,severity ORDER BY rule_id",
            )
            .unwrap();
        let rows = groups
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (rule_id, title, severity, count) = row.unwrap();
            eprintln!("{rule_id} | {severity} | {count} | {title}");
        }
        drop(groups);
        let unlinked: i64 = db
            .query_row(
                "SELECT count(*) FROM detection_leads lead
                 WHERE lead.engine='VampHunt'
                   AND NOT EXISTS(SELECT 1 FROM detection_lead_events link WHERE link.lead_id=lead.id)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unlinked, 0,
            "every local rule lead must link to parsed evidence"
        );
        assert!(saved > 0);
    }
}
