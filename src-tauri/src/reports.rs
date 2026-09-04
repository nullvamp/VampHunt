use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Write},
    path::Path,
};

#[cfg(target_os = "windows")]
use std::{os::windows::process::CommandExt, process::Command};

const REPORT_LOGO_BASE64: &str = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNjAiIGhlaWdodD0iMTYwIiB2aWV3Qm94PSIwIDAgNDAgNDAiPgogIDxnIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzhCODRGNyIgc3Ryb2tlLXdpZHRoPSI1LjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+CiAgICA8cGF0aCBkPSJNMjQgNiBMMTAuNSAxOS41IEwxMi40IDIxLjQiLz4KICAgIDxwYXRoIGQ9Ik0xNy4yIDMxLjIgTDI4LjIgMjAuMiIvPgogIDwvZz4KICA8cmVjdCB4PSIxOC4yIiB5PSIxNy45IiB3aWR0aD0iMy44IiBoZWlnaHQ9IjMuOCIgcng9IjAuNSIgZmlsbD0iIzhCODRGNyIvPgo8L3N2Zz4K";

const REPORT_CSS: &str = r#"
:root {
  color-scheme: dark;
  --bg: #090b10;
  --panel: #10141b;
  --panel-raised: #131821;
  --panel-soft: #171d27;
  --border: #262d39;
  --border-strong: #343d4c;
  --text: #e7eaf0;
  --text-soft: #b3bbc7;
  --muted: #778292;
  --accent: #8b84f7;
  --accent-soft: #1b1a31;
  --critical: #ff9aac;
  --high: #f2b078;
  --medium: #e4c56e;
  --low: #8cb7ff;
  --mono: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  color: var(--text);
  background: var(--bg);
  font: 14px/1.55 "Segoe UI", Arial, sans-serif;
}
a { color: #aaa6f1; text-decoration: none; }
a:hover { color: #d8d5ff; }
code, time { font-family: var(--mono); }
time { white-space: nowrap; }

.report-shell {
  width: min(1480px, calc(100% - 40px));
  margin: 32px auto 52px;
}

.report-cover,
.report-section {
  margin-bottom: 16px;
  overflow: hidden;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
}

.report-cover { padding: 24px 26px 26px; }
.brand-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.brand-row img { width: 42px; height: 42px; }
.brand-copy strong, .brand-copy span { display: block; }
.brand-copy strong { font-size: 15px; }
.brand-copy span { color: var(--muted); font-size: 11px; }
.report-label {
  margin-left: auto;
  padding: 5px 8px;
  color: #b9b6df;
  background: var(--accent-soft);
  border: 1px solid #35314f;
  border-radius: 3px;
  font: 700 10px var(--mono);
  letter-spacing: .12em;
}
.title-block { padding: 28px 0 24px; }
.eyebrow,
.section-kicker {
  margin: 0 0 7px;
  color: #9089ee;
  font: 700 10px var(--mono);
  letter-spacing: .14em;
}
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 7px; font-size: clamp(28px, 4vw, 42px); line-height: 1.08; }
.title-block > p:last-child { margin: 0; color: var(--text-soft); }

.case-meta {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 0;
  border: 1px solid var(--border);
  border-radius: 5px;
}
.case-meta div { min-width: 0; padding: 13px 15px; }
.case-meta div + div { border-left: 1px solid var(--border); }
.case-meta dt,
.detail-grid dt {
  margin-bottom: 5px;
  color: var(--muted);
  font: 700 9px var(--mono);
  letter-spacing: .12em;
}
.case-meta dd,
.detail-grid dd { margin: 0; overflow-wrap: anywhere; }
.case-meta dd { font: 12px var(--mono); }

.report-nav {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  padding: 7px;
  background: #0d1016;
  border: 1px solid var(--border);
  border-radius: 5px;
}
.report-nav a { padding: 7px 11px; border-radius: 3px; font-size: 12px; }
.report-nav a:hover { background: var(--panel-soft); }

.section-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  padding: 20px 22px;
  border-bottom: 1px solid var(--border);
}
.section-heading h2 { margin-bottom: 4px; font-size: 20px; }
.section-heading p { margin: 0; color: var(--muted); font-size: 12px; }
.section-count {
  flex: none;
  min-width: 34px;
  padding: 5px 8px;
  color: #c7c4ff;
  background: var(--accent-soft);
  border: 1px solid #35314f;
  border-radius: 3px;
  text-align: center;
  font: 700 11px var(--mono);
}

.metric-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
}
.metric {
  min-width: 0;
  padding: 20px 22px;
  background: var(--panel);
}
.metric + .metric { border-left: 1px solid var(--border); }
.metric span { display: block; color: var(--muted); font: 700 9px var(--mono); letter-spacing: .12em; }
.metric strong { display: block; margin-top: 8px; color: #a8a3ff; font: 700 24px var(--mono); }

.summary-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 13px 22px;
  color: var(--muted);
  background: #0d1117;
  border-top: 1px solid var(--border);
  font-size: 11px;
}
.severity-strip { display: flex; flex-wrap: wrap; gap: 7px; }
.severity-count { padding: 3px 7px; border: 1px solid var(--border-strong); border-radius: 3px; font: 10px var(--mono); }
.severity-count.critical { color: var(--critical); }
.severity-count.high { color: var(--high); }
.severity-count.medium { color: var(--medium); }
.severity-count.low { color: var(--low); }

.finding-list { padding: 14px; }
.finding-card { background: var(--panel-raised); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 5px; }
.finding-card + .finding-card { margin-top: 12px; }
.finding-card.severity-critical { border-left-color: var(--critical); }
.finding-card.severity-high { border-left-color: var(--high); }
.finding-card.severity-medium { border-left-color: var(--medium); }
.finding-card.severity-low { border-left-color: var(--low); }
.finding-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 17px 18px 14px;
  border-bottom: 1px solid var(--border);
}
.finding-header h3 { margin: 8px 0 0; font-size: 17px; }
.finding-identity { display: flex; align-items: center; gap: 8px; }
.record-id { color: var(--muted); font: 10px var(--mono); }
.severity-pill,
.status-pill {
  display: inline-flex;
  padding: 3px 7px;
  border: 1px solid;
  border-radius: 3px;
  font: 700 9px var(--mono);
  text-transform: uppercase;
  letter-spacing: .07em;
}
.severity-pill.critical { color: var(--critical); background: #27151b; border-color: #65313c; }
.severity-pill.high { color: var(--high); background: #241912; border-color: #60402c; }
.severity-pill.medium { color: var(--medium); background: #211d10; border-color: #5f5529; }
.severity-pill.low { color: var(--low); background: #101b2c; border-color: #2f4d78; }
.status-pill { flex: none; color: #c9ced7; background: #171c24; border-color: var(--border-strong); }
.finding-notes { padding: 15px 18px; }
.finding-notes strong { display: block; margin-bottom: 6px; color: var(--muted); font: 700 9px var(--mono); letter-spacing: .1em; }
.finding-notes p { margin: 0; color: var(--text-soft); white-space: pre-wrap; }
.evidence-title { padding: 0 18px 9px; color: var(--muted); font: 700 9px var(--mono); letter-spacing: .1em; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 11px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }
th { color: #8f99a8; background: #0d1117; font: 700 9px var(--mono); letter-spacing: .08em; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: #151a22; }
td { color: var(--text-soft); font-size: 12px; }
td strong { display: block; color: var(--text); }
td code { display: block; color: #9ca6b2; font-size: 10px; overflow-wrap: anywhere; }
.subtext { display: block; margin-top: 4px; color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
.context-list { display: grid; gap: 4px; min-width: 190px; }
.context-item { display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 6px; }
.context-item b { color: var(--muted); font: 700 9px var(--mono); text-transform: uppercase; }
.context-item span { overflow-wrap: anywhere; }
.source-ref { min-width: 190px; }
.source-ref span { display: block; margin-top: 4px; color: var(--muted); font: 10px var(--mono); }
.lead-table { min-width: 1040px; }
.lead-table td:nth-child(1) { width: 80px; }
.lead-table td:nth-child(2) { width: 240px; }
.lead-table td:nth-child(3) { width: 170px; }
.lead-table td:nth-child(6) { width: 155px; }
.review-notice {
  margin: 14px 14px 0;
  padding: 11px 13px;
  color: #d2b37d;
  background: #251f10;
  border: 1px solid #56491f;
  border-radius: 4px;
  font-size: 11px;
}
.empty-state { margin: 14px; padding: 24px; color: var(--muted); text-align: center; background: #0d1117; border: 1px dashed var(--border-strong); border-radius: 4px; }

.detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 0; }
.detail-grid div { padding: 15px 18px; border-bottom: 1px solid var(--border); }
.detail-grid div:nth-child(odd) { border-right: 1px solid var(--border); }
.report-note { margin: 16px; padding: 14px 16px; background: #0d1117; border: 1px solid var(--border); border-radius: 4px; }
.report-note strong { display: block; margin-bottom: 5px; }
.report-note p { margin: 0; color: var(--muted); font-size: 12px; }
.report-footer { display: flex; justify-content: space-between; gap: 20px; padding: 7px 2px 0; color: var(--muted); font: 10px var(--mono); }

@media (max-width: 820px) {
  .report-shell { width: min(100% - 20px, 1480px); margin-top: 10px; }
  .case-meta, .metric-grid, .detail-grid { grid-template-columns: 1fr; }
  .case-meta div + div, .metric + .metric { border-left: 0; border-top: 1px solid var(--border); }
  .detail-grid div:nth-child(odd) { border-right: 0; }
  .finding-header, .summary-foot, .report-footer { align-items: flex-start; flex-direction: column; }
}

@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { background: var(--bg); }
  .report-shell { width: 100%; margin: 0; }
  .report-nav { display: none; }
  .report-cover, .finding-card, tr { break-inside: avoid; }
  thead { display: table-header-group; }
  a { color: inherit; }
}
"#;

#[derive(Deserialize)]
struct CaseRecord {
    id: String,
    name: String,
    examiner: String,
    #[serde(default)]
    created_utc: Option<String>,
}

#[derive(Serialize)]
pub struct GeneratedReport {
    name: String,
    path: String,
    kind: String,
    bytes: u64,
    modified_utc: String,
}
fn esc(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn severity_class(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

fn count_severity(counts: &mut [usize; 4], value: &str) {
    let index = match severity_class(value) {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    };
    counts[index] += 1;
}

fn severity_summary(counts: &[usize; 4]) -> String {
    ["Critical", "High", "Medium", "Low"]
        .iter()
        .zip(counts)
        .map(|(label, count)| {
            format!(
                "<span class=\"severity-count {}\">{} {}</span>",
                label.to_ascii_lowercase(),
                count,
                label
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn event_context(host: &str, user: &str, process: &str, path: &str) -> String {
    let mut values = String::new();
    for (label, value) in [
        ("Host", host),
        ("User", user),
        ("Process", process),
        ("Path", path),
    ] {
        if !value.trim().is_empty() {
            values.push_str(&format!(
                "<div class=\"context-item\"><b>{}</b><span>{}</span></div>",
                label,
                esc(value.trim())
            ));
        }
    }
    if values.is_empty() {
        "<span class=\"subtext\">No host, user, process, or path recorded</span>".into()
    } else {
        format!("<div class=\"context-list\">{values}</div>")
    }
}

fn csv_field(value: &str) -> String {
    let protected = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", protected.replace('"', "\"\""))
}

fn case_root_and_reports(
    case_path: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let root = Path::new(case_path)
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    if !root.join("case.json").is_file() {
        return Err("This folder is not a VampHunt case.".into());
    }
    let reports = root
        .join("REPORTS")
        .canonicalize()
        .map_err(|_| "The case reports directory is unavailable.".to_string())?;
    if !reports.starts_with(&root) {
        return Err("The case reports directory points outside this case.".into());
    }
    Ok((root, reports))
}

fn case_database_and_reports(case_path: &str) -> Result<(Connection, std::path::PathBuf), String> {
    let (root, reports) = case_root_and_reports(case_path)?;
    let database_dir = root
        .join("DATABASE")
        .canonicalize()
        .map_err(|_| "The case database directory is unavailable.".to_string())?;
    if !database_dir.starts_with(&root) {
        return Err("The case database directory points outside this case.".into());
    }
    let database = crate::paths::case_database(&root)?
        .canonicalize()
        .map_err(|_| "No normalized evidence exists in this case yet.".to_string())?;
    if !database.starts_with(&database_dir) {
        return Err("The case database points outside this case.".into());
    }
    let db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| error.to_string())?;
    Ok((db, reports))
}

fn validated_report_output(
    case_path: &str,
    report_path: &str,
) -> Result<std::path::PathBuf, String> {
    let (_, reports) = case_root_and_reports(case_path)?;
    let requested = Path::new(report_path.trim());
    let metadata = fs::symlink_metadata(requested)
        .map_err(|_| "The generated report no longer exists.".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("The selected item is not a regular report file.".into());
    }
    let output = requested
        .canonicalize()
        .map_err(|error| format!("Could not verify the report path: {error}"))?;
    if output.parent() != Some(reports.as_path()) {
        return Err("The selected file is outside this case's REPORTS folder.".into());
    }
    let extension = output
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !extension.eq_ignore_ascii_case("html") && !extension.eq_ignore_ascii_case("csv") {
        return Err(
            "Only generated HTML reports and timeline CSV files can be managed here.".into(),
        );
    }
    Ok(output)
}

#[tauri::command]
pub fn list_generated_reports(case_path: String) -> Result<Vec<GeneratedReport>, String> {
    let (_, reports) = case_root_and_reports(&case_path)?;
    let mut outputs = Vec::new();
    for entry in fs::read_dir(&reports)
        .map_err(|error| format!("Could not read the case reports directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Could not read a report entry: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("Could not inspect a report entry: {error}"))?;
        if !metadata.is_file() || metadata.is_symlink() {
            continue;
        }
        let path = entry.path();
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let kind = if extension.eq_ignore_ascii_case("html") {
            "HTML report"
        } else if extension.eq_ignore_ascii_case("csv") {
            "Timeline CSV"
        } else {
            continue;
        };
        let metadata = entry
            .metadata()
            .map_err(|error| format!("Could not read report metadata: {error}"))?;
        let modified_utc = metadata
            .modified()
            .map(DateTime::<Utc>::from)
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|_| "Unknown".into());
        outputs.push(GeneratedReport {
            name: entry.file_name().to_string_lossy().into_owned(),
            path: crate::paths::display(&path),
            kind: kind.into(),
            bytes: metadata.len(),
            modified_utc,
        });
    }
    outputs.sort_by(|left, right| {
        right
            .modified_utc
            .cmp(&left.modified_utc)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(outputs)
}

#[cfg(target_os = "windows")]
fn open_with_explorer(path: &Path, reveal: bool) -> Result<(), String> {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new("explorer.exe");
    if reveal {
        command.arg(format!("/select,{}", path.display()));
    } else {
        command.arg(path);
    }
    command
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("Could not open Windows Explorer: {error}"))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn open_with_explorer(_path: &Path, _reveal: bool) -> Result<(), String> {
    Err("Opening generated reports is currently supported on Windows.".into())
}

#[tauri::command]
pub fn open_generated_report(case_path: String, report_path: String) -> Result<(), String> {
    let report = validated_report_output(&case_path, &report_path)?;
    open_with_explorer(&report, false)
}

#[tauri::command]
pub fn reveal_generated_report(case_path: String, report_path: String) -> Result<(), String> {
    let report = validated_report_output(&case_path, &report_path)?;
    open_with_explorer(&report, true)
}

#[tauri::command]
pub fn delete_generated_report(case_path: String, report_path: String) -> Result<String, String> {
    let report = validated_report_output(&case_path, &report_path)?;
    fs::remove_file(&report).map_err(|error| format!("Could not delete the report: {error}"))?;
    Ok(crate::paths::display(&report))
}

#[tauri::command]
pub fn export_timeline_csv(case_path: String) -> Result<String, String> {
    let (db, reports) = case_database_and_reports(&case_path)?;
    let output = reports.join(format!(
        "timeline-{}.csv",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .map_err(|error| format!("Could not create the timeline export: {error}"))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(b"\xef\xbb\xbftimestamp_utc,artifact_type,event_type,host,user,path,process,summary,parser,source_database,source_table,source_row_id\r\n")
        .map_err(|error| error.to_string())?;
    let mut statement = db
        .prepare("SELECT coalesce(timestamp_utc,''),artifact_type,event_type,coalesce(host,''),coalesce(user,''),coalesce(path,''),coalesce(process,''),summary,parser,source_database,source_table,source_row_id FROM events ORDER BY timestamp_utc IS NULL,timestamp_utc,id")
        .map_err(|error| error.to_string())?;
    let mut rows = statement.query([]).map_err(|error| error.to_string())?;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let fields = (0..12)
            .map(|index| {
                row.get::<_, String>(index).map(|value| {
                    let value = if index == 9 {
                        crate::paths::readable(&value)
                    } else {
                        value
                    };
                    csv_field(&value)
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        writer
            .write_all(format!("{}\r\n", fields.join(",")).as_bytes())
            .map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())?;
    Ok(crate::paths::display(&output))
}

#[tauri::command]
pub fn generate_html_report(
    case_path: String,
    excluded_finding_ids: Vec<i64>,
    excluded_lead_ids: Vec<i64>,
) -> Result<String, String> {
    let root = Path::new(&case_path)
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let case: CaseRecord =
        serde_json::from_slice(&fs::read(root.join("case.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let database_dir = root
        .join("DATABASE")
        .canonicalize()
        .map_err(|_| "The case database directory is unavailable.".to_string())?;
    if !database_dir.starts_with(&root) {
        return Err("The case database directory points outside this case.".into());
    }
    let database = crate::paths::case_database(&root)?
        .canonicalize()
        .map_err(|_| "No normalized evidence exists in this case yet.".to_string())?;
    if !database.starts_with(&database_dir) {
        return Err("The case database points outside this case.".into());
    }
    let db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let events: i64 = db
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let entities: i64 = db
        .query_row("SELECT count(*) FROM entities", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let excluded_finding_ids = excluded_finding_ids.into_iter().collect::<HashSet<_>>();
    let excluded_lead_ids = excluded_lead_ids.into_iter().collect::<HashSet<_>>();
    let mut finding_body = String::new();
    let mut finding_count = 0_usize;
    let mut finding_severities = [0_usize; 4];
    let mut excluded_finding_count = 0_usize;
    let has_findings: bool = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='findings'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if has_findings {
        let mut findings=db.prepare("SELECT id,title,severity,status,notes FROM findings ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC").map_err(|e|e.to_string())?;
        let rows = findings
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (id, title, severity, status, notes) = row.map_err(|e| e.to_string())?;
            if excluded_finding_ids.contains(&id) {
                excluded_finding_count += 1;
                continue;
            }
            finding_count += 1;
            count_severity(&mut finding_severities, &severity);
            let mut evidence=db.prepare("SELECT e.timestamp_utc,e.summary,coalesce(e.host,''),coalesce(e.user,''),coalesce(e.process,''),coalesce(e.path,''),e.source_database,e.source_table,e.source_row_id FROM events e JOIN finding_events fe ON fe.event_id=e.id WHERE fe.finding_id=?1 ORDER BY e.timestamp_utc").map_err(|e|e.to_string())?;
            let items = evidence
                .query_map([id], |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            let mut evidence_body = String::new();
            let mut evidence_count = 0_usize;
            for item in items {
                let (time, summary, host, user, process, path, database, table, row) =
                    item.map_err(|e| e.to_string())?;
                evidence_count += 1;
                evidence_body.push_str(&format!(
                    "<tr><td><time>{}</time></td><td><strong>{}</strong></td><td>{}</td><td><div class=\"source-ref\"><code>{}</code><span>{} · row {}</span></div></td></tr>",
                    esc(time.as_deref().unwrap_or("No timestamp")),
                    esc(&summary),
                    event_context(&host, &user, &process, &path),
                    esc(&crate::paths::readable(&database)),
                    esc(&table),
                    esc(&row)
                ));
            }
            if evidence_body.is_empty() {
                evidence_body.push_str("<tr><td colspan=\"4\" class=\"empty-state\">No supporting records are linked to this finding.</td></tr>");
            }
            let notes = if notes.trim().is_empty() {
                "No analyst notes recorded.".to_string()
            } else {
                esc(notes.trim())
            };
            let severity_style = severity_class(&severity);
            finding_body.push_str(&format!(
                "<article class=\"finding-card severity-{severity_style}\" id=\"finding-{id}\"><div class=\"finding-header\"><div><div class=\"finding-identity\"><span class=\"severity-pill {severity_style}\">{}</span><span class=\"record-id\">FINDING {id}</span></div><h3>{}</h3></div><span class=\"status-pill\">{}</span></div><div class=\"finding-notes\"><strong>ANALYST NOTES</strong><p>{notes}</p></div><div class=\"evidence-title\">SUPPORTING RECORDS · {evidence_count}</div><div class=\"table-wrap\"><table><thead><tr><th>TIME (UTC)</th><th>EVENT</th><th>CONTEXT</th><th>SOURCE RECORD</th></tr></thead><tbody>{evidence_body}</tbody></table></div></article>",
                esc(&severity),
                esc(&title),
                esc(&status),
            ));
        }
    }
    let mut lead_body = String::new();
    let mut lead_count = 0_usize;
    let mut lead_severities = [0_usize; 4];
    let mut excluded_lead_count = 0_usize;
    let has_leads: bool = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='detection_leads'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if has_leads {
        let has_lead_links: bool = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='detection_lead_events'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        let link_expression = if has_lead_links {
            "(SELECT group_concat(source_table||' / '||source_row_id,' | ') FROM events JOIN detection_lead_events link ON link.event_id=events.id WHERE link.lead_id=detection_leads.id)"
        } else {
            "NULL"
        };
        let lead_sql = format!("SELECT id,engine,rule_id,title,severity,target,source,created_utc,{link_expression} FROM detection_leads ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END DESC,created_utc DESC,id DESC");
        let mut leads = db.prepare(&lead_sql).map_err(|e| e.to_string())?;
        let rows = leads
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (id, engine, rule_id, title, severity, target, source, created, linked_sources) =
                row.map_err(|e| e.to_string())?;
            if excluded_lead_ids.contains(&id) {
                excluded_lead_count += 1;
                continue;
            }
            lead_count += 1;
            count_severity(&mut lead_severities, &severity);
            let severity_style = severity_class(&severity);
            lead_body.push_str(&format!(
                "<tr><td><span class=\"severity-pill {severity_style}\">{}</span></td><td><strong>{}</strong><code>{}</code></td><td><strong>{}</strong><span class=\"subtext\">{}</span></td><td><code>{}</code></td><td><code>{}</code></td><td><time>{}</time></td></tr>",
                esc(&severity),
                esc(&title),
                esc(&rule_id),
                esc(&engine),
                esc(&source),
                esc(&target),
                esc(linked_sources.as_deref().unwrap_or("Raw engine match; inspect the matched source in VampHunt")),
                esc(&created)
            ));
        }
    }
    if finding_count == 0 && lead_count == 0 {
        return Err("Everything is excluded. Include at least one finding or rule match.".into());
    }
    let generated = Utc::now();
    let generated_utc = generated.to_rfc3339();
    let finding_content = if finding_body.is_empty() {
        "<div class=\"empty-state\">No analyst findings are included in this report.</div>"
            .to_string()
    } else {
        format!("<div class=\"finding-list\">{finding_body}</div>")
    };
    let lead_content = if lead_body.is_empty() {
        "<div class=\"empty-state\">No rule matches are included in this report.</div>".to_string()
    } else {
        format!(
            "<div class=\"review-notice\">Rule matches are leads for analyst review. They are not confirmed findings.</div><div class=\"table-wrap\"><table class=\"lead-table\"><thead><tr><th>LEVEL</th><th>DETECTION</th><th>ENGINE AND SOURCE</th><th>MATCHED EVIDENCE</th><th>LINKED PARSED SOURCE</th><th>SAVED (UTC)</th></tr></thead><tbody>{lead_body}</tbody></table></div>"
        )
    };
    let mut included_severities = [0_usize; 4];
    for index in 0..included_severities.len() {
        included_severities[index] = finding_severities[index] + lead_severities[index];
    }
    let severity_counts = severity_summary(&included_severities);
    let excluded_count = excluded_finding_count + excluded_lead_count;
    let case_created = case.created_utc.as_deref().unwrap_or("Not recorded");
    let html = format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="VampHunt">
  <title>{title} - VampHunt report</title>
  <style>{css}</style>
</head>
<body>
  <main class="report-shell">
    <header class="report-cover">
      <div class="brand-row">
        <img src="data:image/svg+xml;base64,{logo}" alt="VampHunt logo">
        <div class="brand-copy"><strong>VampHunt</strong><span>Investigation report</span></div>
        <span class="report-label">CASE REPORT</span>
      </div>
      <div class="title-block">
        <p class="eyebrow">INVESTIGATION</p>
        <h1>{case_name}</h1>
        <p>Findings, rule matches, and source references saved from this case.</p>
      </div>
      <dl class="case-meta">
        <div><dt>CASE ID</dt><dd>{case_id}</dd></div>
        <div><dt>EXAMINER</dt><dd>{examiner}</dd></div>
        <div><dt>GENERATED (UTC)</dt><dd>{generated}</dd></div>
      </dl>
    </header>

    <nav class="report-nav" aria-label="Report sections">
      <a href="#case-summary">Case summary</a>
      <a href="#analyst-findings">Analyst findings</a>
      <a href="#rule-matches">Rule matches</a>
      <a href="#report-details">Report details</a>
    </nav>

    <section class="report-section" id="case-summary">
      <div class="section-heading">
        <div><p class="section-kicker">CASE SUMMARY</p><h2>Included material</h2><p>Counts reflect this report after the selected exclusions were applied.</p></div>
      </div>
      <div class="metric-grid">
        <div class="metric"><span>NORMALIZED EVENTS</span><strong>{events}</strong></div>
        <div class="metric"><span>ENTITIES</span><strong>{entities}</strong></div>
        <div class="metric"><span>ANALYST FINDINGS</span><strong>{finding_count}</strong></div>
        <div class="metric"><span>RULE MATCHES</span><strong>{lead_count}</strong></div>
      </div>
      <div class="summary-foot"><div class="severity-strip">{severity_counts}</div><span>{excluded_count} selections excluded from this export</span></div>
    </section>

    <section class="report-section" id="analyst-findings">
      <div class="section-heading">
        <div><p class="section-kicker">REVIEWED RESULTS</p><h2>Analyst findings</h2><p>Each finding includes the analyst notes and exact supporting parser records.</p></div>
        <span class="section-count">{finding_count}</span>
      </div>
      {finding_content}
    </section>

    <section class="report-section" id="rule-matches">
      <div class="section-heading">
        <div><p class="section-kicker">DETECTION RESULTS</p><h2>Rule matches</h2><p>Retained matches from file, log, artifact, and cross-artifact analysis.</p></div>
        <span class="section-count">{lead_count}</span>
      </div>
      {lead_content}
    </section>

    <section class="report-section" id="report-details">
      <div class="section-heading">
        <div><p class="section-kicker">REPORT DETAILS</p><h2>Scope and source references</h2><p>Information recorded when this standalone report was created.</p></div>
      </div>
      <dl class="detail-grid">
        <div><dt>CASE CREATED</dt><dd>{case_created}</dd></div>
        <div><dt>REPORT GENERATED</dt><dd>{generated}</dd></div>
        <div><dt>FINDINGS INCLUDED / EXCLUDED</dt><dd>{finding_count} / {excluded_findings}</dd></div>
        <div><dt>RULE MATCHES INCLUDED / EXCLUDED</dt><dd>{lead_count} / {excluded_leads}</dd></div>
      </dl>
      <div class="report-note"><strong>How to verify a record</strong><p>Supporting evidence is identified by its parser database, source table, and source row. Open the case in VampHunt to inspect the complete original parser row.</p></div>
    </section>

    <footer class="report-footer"><span>VampHunt · {case_id}</span><span>Generated {generated}</span></footer>
  </main>
</body>
</html>"##,
        title = esc(&case.name),
        css = REPORT_CSS,
        logo = REPORT_LOGO_BASE64,
        case_name = esc(&case.name),
        case_id = esc(&case.id),
        examiner = esc(&case.examiner),
        generated = esc(&generated_utc),
        events = events,
        entities = entities,
        finding_count = finding_count,
        lead_count = lead_count,
        severity_counts = severity_counts,
        excluded_count = excluded_count,
        finding_content = finding_content,
        lead_content = lead_content,
        case_created = esc(case_created),
        excluded_findings = excluded_finding_count,
        excluded_leads = excluded_lead_count,
    );
    let name = format!(
        "investigation-report-{}.html",
        generated.format("%Y%m%d-%H%M%S")
    );
    let reports = root
        .join("REPORTS")
        .canonicalize()
        .map_err(|_| "The case reports directory is unavailable.".to_string())?;
    if !reports.starts_with(&root) {
        return Err("The case reports directory points outside this case.".into());
    }
    let output = reports.join(name);
    fs::write(&output, html).map_err(|e| e.to_string())?;
    Ok(crate::paths::display(&output))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_report_values() {
        assert_eq!(esc("<script>&"), "&lt;script&gt;&amp;");
        assert_eq!(esc("O'Brien"), "O&#39;Brien");
        assert_eq!(csv_field("hello, \"world\""), "\"hello, \"\"world\"\"\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
    }
    #[test]
    fn builds_an_evidence_backed_report() {
        let root = std::env::temp_dir().join(format!("vamphunt-report-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("DATABASE")).unwrap();
        fs::create_dir(root.join("REPORTS")).unwrap();
        fs::write(
            root.join("case.json"),
            r#"{"id":"CASE-1","name":"Test Investigation","examiner":"Analyst"}"#,
        )
        .unwrap();
        let db = Connection::open(root.join("DATABASE/vamphunt.db")).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,timestamp_utc TEXT,artifact_type TEXT,event_type TEXT,host TEXT,user TEXT,path TEXT,process TEXT,summary TEXT,parser TEXT,source_database TEXT,source_table TEXT,source_row_id TEXT);CREATE TABLE entities(id INTEGER);CREATE TABLE findings(id INTEGER PRIMARY KEY,title TEXT,severity TEXT,status TEXT,notes TEXT);CREATE TABLE finding_events(finding_id INTEGER,event_id INTEGER);CREATE TABLE detection_leads(id INTEGER PRIMARY KEY,engine TEXT,rule_id TEXT,title TEXT,severity TEXT,target TEXT,source TEXT,created_utc TEXT,raw TEXT);CREATE TABLE detection_lead_events(lead_id INTEGER,event_id INTEGER);INSERT INTO events VALUES(1,'2026-09-02T10:00:00Z','evtx','windows_event','WS-42','alice',NULL,NULL,'=Remote logon','evtx','evtx.db','evtx_events','Security.evtx:42');INSERT INTO entities VALUES(1);INSERT INTO findings VALUES(1,'Possible lateral movement','High','Confirmed','Reviewed by analyst');INSERT INTO finding_events VALUES(1,1);INSERT INTO detection_leads VALUES(7,'Hayabusa/Sigma','RULE-7','Remote execution','High','WS-42 | Security event 4624','SigmaHQ','2026-09-02T10:05:00Z','{}');INSERT INTO detection_lead_events VALUES(7,1);").unwrap();
        drop(db);
        let report = generate_html_report(root.display().to_string(), vec![], vec![]).unwrap();
        let html = fs::read_to_string(&report).unwrap();
        assert!(html.contains("Possible lateral movement"));
        assert!(html.contains("Security.evtx:42"));
        assert!(html.contains("Test Investigation"));
        assert!(html.contains("Remote execution"));
        assert!(html.contains("RULE-7"));
        assert!(html.contains("data:image/svg+xml;base64,"));
        assert!(html.contains(REPORT_LOGO_BASE64));
        assert!(html.contains("--accent: #8b84f7"));
        assert!(html.contains("id=\"case-summary\""));
        assert!(html.contains("id=\"analyst-findings\""));
        assert!(html.contains("id=\"rule-matches\""));
        assert!(html.contains("How to verify a record"));
        let csv = export_timeline_csv(root.display().to_string()).unwrap();
        let csv_contents = fs::read_to_string(&csv).unwrap();
        assert!(csv_contents.contains("\"'=Remote logon\""));
        assert!(csv_contents.contains("\"Security.evtx:42\""));

        let generated = list_generated_reports(root.display().to_string()).unwrap();
        assert_eq!(generated.len(), 2);
        assert!(generated
            .iter()
            .any(|item| item.path == report && item.kind == "HTML report"));
        assert!(generated
            .iter()
            .any(|item| item.path == csv && item.kind == "Timeline CSV"));

        let outside = root.join("outside.html");
        fs::write(&outside, "not a managed report").unwrap();
        let error =
            delete_generated_report(root.display().to_string(), outside.display().to_string())
                .unwrap_err();
        assert!(error.contains("outside this case's REPORTS folder"));
        delete_generated_report(root.display().to_string(), csv.clone()).unwrap();
        assert!(!Path::new(&csv).exists());
        fs::remove_dir_all(root).unwrap();
    }
}
