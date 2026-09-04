use super::{
    basename, extension, insert_lead, normalized_path, parse_time, rule_by_kind, CorrelationPack,
    CorrelationRule, EventEvidence,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const MAX_LEADS_PER_RULE: usize = 500;

#[derive(Clone)]
struct ExecutionTrace {
    event: EventEvidence,
    candidate: String,
    name: String,
    time: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct SourceRef {
    database: String,
    table: String,
    rowid: i64,
}

#[derive(Clone)]
struct EvtxRecord {
    source: SourceRef,
    event_id: i64,
    provider: String,
    channel: String,
    computer: String,
    timestamp: String,
    data: Value,
    raw: String,
}

#[derive(Clone)]
struct UsnRecord {
    source: SourceRef,
    frn: String,
    file_name: String,
    timestamp: String,
    reason: String,
    volume: String,
}

fn table_exists(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
        [name],
        |_| Ok(()),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

fn source_event_id(db: &Connection, source: &SourceRef) -> Option<i64> {
    db.query_row(
        "SELECT id FROM events
         WHERE source_database=?1 AND source_table=?2 AND source_sql_rowid=?3
         ORDER BY id LIMIT 1",
        params![source.database, source.table, source.rowid],
        |row| row.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

fn source_event_ids(db: &Connection, sources: &[SourceRef]) -> Vec<i64> {
    let mut ids = sources
        .iter()
        .filter_map(|source| source_event_id(db, source))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn insert_source_lead(
    db: &Connection,
    rule: &CorrelationRule,
    target: &str,
    evidence: Value,
    sources: &[SourceRef],
    extra_event_ids: &[i64],
) -> Result<usize, String> {
    let mut event_ids = source_event_ids(db, sources);
    event_ids.extend_from_slice(extra_event_ids);
    event_ids.sort_unstable();
    event_ids.dedup();
    insert_lead(
        db,
        "VampHunt",
        &rule.id,
        &rule.title,
        &rule.severity,
        target,
        "VampHunt artifact correlation rules",
        &json!({
            "description": rule.description,
            "evidence": evidence,
            "source_records": sources.iter().map(|source| json!({
                "database": source.database,
                "table": source.table,
                "rowid": source.rowid
            })).collect::<Vec<_>>()
        })
        .to_string(),
        &event_ids,
    )
}

fn processed_databases(case_root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let processed = case_root.join("PROCESSED").canonicalize().map_err(|_| {
        "Parsed evidence is unavailable. Run the matching parsers first.".to_string()
    })?;
    if !processed.starts_with(case_root) {
        return Err("The parsed evidence directory points outside this case.".into());
    }
    let mut databases = Vec::new();
    for entry in WalkDir::new(&processed)
        .min_depth(2)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|value| value.to_str())
                    .map(|value| value.eq_ignore_ascii_case("db"))
                    .unwrap_or(false)
        })
    {
        let path = entry
            .path()
            .canonicalize()
            .map_err(|error| error.to_string())?;
        if !path.starts_with(&processed) {
            continue;
        }
        let parser = path
            .parent()
            .and_then(Path::file_name)
            .map(|value| value.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        databases.push((parser, path));
    }
    Ok(databases)
}

fn open_source(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("Could not read parsed evidence {}: {error}", path.display()))
}

fn rule<'a>(pack: &'a CorrelationPack, kind: &str) -> Option<&'a CorrelationRule> {
    rule_by_kind(pack, kind)
}

fn any_marker(value: &str, markers: &[String]) -> bool {
    let value = value.to_ascii_lowercase();
    markers
        .iter()
        .any(|marker| value.contains(&marker.to_ascii_lowercase()))
}

fn user_writable(pack: &CorrelationPack, value: &str) -> bool {
    rule(pack, "user_writable_executable")
        .map(|rule| any_marker(&normalized_path(value), &rule.path_markers))
        .unwrap_or(false)
}

fn executable_extension(pack: &CorrelationPack, value: &str) -> bool {
    let ext = extension(value);
    rule(pack, "user_writable_executable")
        .map(|rule| rule.extensions.iter().any(|candidate| candidate == &ext))
        .unwrap_or(false)
}

fn contains_executable_reference(pack: &CorrelationPack, value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    rule(pack, "user_writable_executable")
        .map(|rule| {
            rule.extensions
                .iter()
                .any(|extension| lower.contains(&format!(".{extension}")))
        })
        .unwrap_or(false)
}

fn suspicious_names(pack: &CorrelationPack) -> HashSet<String> {
    pack.rules
        .iter()
        .filter(|rule| rule.kind == "named_file")
        .flat_map(|rule| rule.file_names.iter().cloned())
        .collect()
}

fn load_executions(db: &Connection) -> Result<HashMap<String, Vec<ExecutionTrace>>, String> {
    let mut statement = db
        .prepare(
            "SELECT id,timestamp_utc,artifact_type,coalesce(path,''),coalesce(process,''),summary,
                    source_database,source_table,source_row_id
             FROM events
             WHERE artifact_type IN ('prefetch','shimcache','amcache','lnk','jump_list')
               AND (coalesce(path,'')<>'' OR coalesce(process,'')<>'')",
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
    let mut executions = HashMap::<String, Vec<ExecutionTrace>>::new();
    for row in rows {
        let event = row.map_err(|error| error.to_string())?;
        let candidate = if event.path.trim().is_empty() {
            event.process.clone()
        } else {
            event.path.clone()
        };
        let name = basename(&candidate);
        if name.is_empty() {
            continue;
        }
        let time = parse_time(event.timestamp.as_deref());
        executions
            .entry(name.clone())
            .or_default()
            .push(ExecutionTrace {
                event,
                candidate,
                name,
                time,
            });
    }
    Ok(executions)
}

fn source(path: &Path, table: &str, rowid: i64) -> SourceRef {
    SourceRef {
        database: crate::paths::display(path),
        table: table.to_string(),
        rowid,
    }
}

fn registry_data(value: &str) -> String {
    value
        .strip_prefix("String(\"")
        .and_then(|value| value.strip_suffix("\")"))
        .unwrap_or(value)
        .replace("\\\\", "\\")
        .replace("\\\"", "\"")
}

fn identity_mismatch(value_name: &str, command: &str) -> bool {
    let normalized_name = value_name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    let executable = command
        .split([' ', '\"'])
        .find(|part| {
            let lower = part.to_ascii_lowercase();
            lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".ps1")
        })
        .unwrap_or(command);
    let stem = basename(executable)
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    !normalized_name.is_empty()
        && !stem.is_empty()
        && !normalized_name.contains(&stem)
        && !stem.contains(&normalized_name)
}

fn scan_registry(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
) -> Result<usize, String> {
    if !table_exists(source_db, "registry_values") {
        return Ok(0);
    }
    let mut statement = source_db
        .prepare(
            "SELECT rowid,Hive,KeyPath,ValueName,cast(ValueData as text)
             FROM registry_values
             WHERE lower(KeyPath) LIKE '%\\currentversion\\run%'
                OR lower(KeyPath) LIKE '%\\explorer\\runmru'
                OR lower(KeyPath) LIKE '%image file execution options%'
                OR lower(KeyPath) LIKE '%silentprocessexit%'
                OR lower(KeyPath) LIKE '%\\windows nt\\currentversion\\windows%'
                OR lower(KeyPath) LIKE '%\\windows nt\\currentversion\\winlogon%'
                OR lower(KeyPath) LIKE '%\\services\\%'
                OR lower(KeyPath) LIKE '%windows defender\\exclusions%'",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut inserted = 0;
    let mut counts = HashMap::<String, usize>::new();
    for row in rows {
        let (rowid, hive, key, value_name, stored_data) = row.map_err(|error| error.to_string())?;
        let data = registry_data(&stored_data);
        let key_lower = key.to_ascii_lowercase();
        let value_lower = value_name.to_ascii_lowercase();
        let data_lower = data.to_ascii_lowercase();
        let record_source = source(source_path, "registry_values", rowid);
        let evidence = json!({
            "hive":hive, "key":key, "value_name":value_name, "value_data":data
        });
        let mut matched = Vec::<&CorrelationRule>::new();

        if let Some(rule) = rule(pack, "registry_run_command") {
            let exact_run = key_lower.ends_with("\\currentversion\\run")
                || key_lower.ends_with("\\currentversion\\runonce");
            let allowed = any_marker(&data_lower, &rule.allowed_path_markers);
            if exact_run
                && !data_lower.is_empty()
                && (any_marker(&data_lower, &rule.markers)
                    || (user_writable(pack, &data_lower)
                        && identity_mismatch(&value_name, &data)
                        && !allowed))
            {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "registry_execution_hijack") {
            if ((key_lower.contains("image file execution options") && value_lower == "debugger")
                || (key_lower.contains("silentprocessexit") && value_lower == "monitorprocess"))
                && !data_lower.is_empty()
            {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "registry_appinit_dll") {
            if key_lower.ends_with("\\windows nt\\currentversion\\windows")
                && value_lower == "appinit_dlls"
                && data_lower.contains(".dll")
            {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "registry_winlogon_change") {
            if key_lower.ends_with("\\windows nt\\currentversion\\winlogon") {
                let non_default = match value_lower.as_str() {
                    "shell" => data_lower.trim_matches([' ', '\"']) != "explorer.exe",
                    "userinit" => {
                        !data_lower.contains("\\windows\\system32\\userinit.exe")
                            && !data_lower.contains("%systemroot%\\system32\\userinit.exe")
                    }
                    _ => false,
                };
                if non_default {
                    matched.push(rule);
                }
            }
        }
        if let Some(rule) = rule(pack, "registry_service_user_path") {
            if key_lower.contains("\\services\\")
                && value_lower == "imagepath"
                && user_writable(pack, &data_lower)
                && contains_executable_reference(pack, &data_lower)
            {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "registry_defender_exclusion") {
            if key_lower.contains("windows defender\\exclusions")
                && !matches!(data_lower.as_str(), "" | "none" | "null" | "string(\"\")")
            {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "registry_runmru_command") {
            if key_lower.ends_with("\\explorer\\runmru")
                && value_lower != "mrulist"
                && any_marker(&data_lower, &rule.markers)
            {
                matched.push(rule);
            }
        }

        for rule in matched {
            let count = counts.entry(rule.id.clone()).or_default();
            if *count >= MAX_LEADS_PER_RULE {
                continue;
            }
            *count += 1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!("{hive}\\{key}\\{value_name} | {data}"),
                evidence.clone(),
                std::slice::from_ref(&record_source),
                &[],
            )?;
        }
    }
    Ok(inserted)
}

fn scan_links(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
) -> Result<usize, String> {
    if !table_exists(source_db, "LNK_Files") {
        return Ok(0);
    }
    let mut statement = source_db
        .prepare(
            "SELECT rowid,Source_Path,coalesce(Local_Path,''),
                    coalesce(Command_Line_Arguments,''),coalesce(Network_Share_Name,'')
             FROM LNK_Files
             WHERE coalesce(Command_Line_Arguments,'')<>'' OR coalesce(Network_Share_Name,'')<>''
                OR Local_Path LIKE '\\\\%'",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut inserted = 0;
    let mut counts = HashMap::<String, usize>::new();
    for row in rows {
        let (rowid, shortcut, local_path, arguments, network_share) =
            row.map_err(|error| error.to_string())?;
        let record_source = source(source_path, "LNK_Files", rowid);
        let evidence = json!({
            "shortcut":shortcut, "target":local_path,
            "arguments":arguments, "network_share":network_share
        });
        let mut matched = Vec::<&CorrelationRule>::new();
        if let Some(rule) = rule(pack, "lnk_suspicious_arguments") {
            if any_marker(&arguments, &rule.markers) {
                matched.push(rule);
            }
        }
        if let Some(rule) = rule(pack, "lnk_network_executable") {
            if (!network_share.trim().is_empty() || local_path.starts_with("\\\\"))
                && executable_extension(pack, &local_path)
            {
                matched.push(rule);
            }
        }
        for rule in matched {
            let count = counts.entry(rule.id.clone()).or_default();
            if *count >= MAX_LEADS_PER_RULE {
                continue;
            }
            *count += 1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!("{shortcut} -> {local_path} {arguments}"),
                evidence.clone(),
                std::slice::from_ref(&record_source),
                &[],
            )?;
        }
    }
    Ok(inserted)
}

fn source_time(value: &str) -> Option<DateTime<Utc>> {
    parse_time(Some(value))
}

fn scan_mft(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
) -> Result<usize, String> {
    if !table_exists(source_db, "mft_records") {
        return Ok(0);
    }
    let mut inserted = 0;
    if let Some(rule) = rule(pack, "mft_named_data_stream") {
        if table_exists(source_db, "mft_data_attributes") {
            let mut statement = source_db
                .prepare(
                    "SELECT record.rowid,record.record_number,record.volume_letter,record.file_name,
                            group_concat(DISTINCT data.attribute_name)
                     FROM mft_records record
                     JOIN mft_data_attributes data ON data.record_number=record.record_number
                     WHERE record.ads_count>1 AND coalesce(data.attribute_name,'')<>''
                       AND lower(data.attribute_name)<>'zone.identifier'
                     GROUP BY record.rowid,record.record_number,record.volume_letter,record.file_name
                     LIMIT 500",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            let mut count = 0;
            for row in rows {
                let (rowid, record_number, volume, file_name, streams) =
                    row.map_err(|error| error.to_string())?;
                if count >= MAX_LEADS_PER_RULE || !executable_extension(pack, &file_name) {
                    continue;
                }
                count += 1;
                let record_source = source(source_path, "mft_records", rowid);
                inserted += insert_source_lead(
                    case_db,
                    rule,
                    &format!("{volume}\\{file_name} | streams: {streams}"),
                    json!({"record_number":record_number,"file_name":file_name,"streams":streams}),
                    std::slice::from_ref(&record_source),
                    &[],
                )?;
            }
        }
    }
    if let Some(rule) = rule(pack, "mft_timestamp_mismatch") {
        if table_exists(source_db, "mft_file_names") {
            let mut statement = source_db
                .prepare(
                    "SELECT record.rowid,record.record_number,record.volume_letter,record.file_name,
                            record.created_time,names.created,cast(names.namespace as text)
                     FROM mft_records record
                     JOIN mft_file_names names ON names.record_number=record.record_number
                     WHERE record.created_time<>'' AND names.created<>''
                     LIMIT 250000",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            let mut count = 0;
            let threshold = rule.window_minutes.max(1);
            for row in rows {
                let (
                    rowid,
                    record_number,
                    volume,
                    file_name,
                    standard_created,
                    file_name_created,
                    namespace,
                ) = row.map_err(|error| error.to_string())?;
                if count >= MAX_LEADS_PER_RULE || !executable_extension(pack, &file_name) {
                    continue;
                }
                let (Some(standard_time), Some(file_name_time)) = (
                    source_time(&standard_created),
                    source_time(&file_name_created),
                ) else {
                    continue;
                };
                let difference = file_name_time
                    .signed_duration_since(standard_time)
                    .num_minutes();
                if difference < threshold {
                    continue;
                }
                count += 1;
                let record_source = source(source_path, "mft_records", rowid);
                inserted += insert_source_lead(
                    case_db,
                    rule,
                    &format!(
                        "{volume}\\{file_name} | standard creation precedes file-name creation by {difference} minutes"
                    ),
                    json!({
                        "record_number":record_number,"file_name":file_name,"namespace":namespace,
                        "standard_information_created":standard_created,
                        "file_name_created":file_name_created,"difference_minutes":difference
                    }),
                    std::slice::from_ref(&record_source),
                    &[],
                )?;
            }
        }
    }
    Ok(inserted)
}

fn scan_usn(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
    executions: &HashMap<String, Vec<ExecutionTrace>>,
    suspicious: &HashSet<String>,
) -> Result<usize, String> {
    if !table_exists(source_db, "journal_events") {
        return Ok(0);
    }
    let mut statement = source_db
        .prepare(
            "SELECT rowid,cast(frn as text),filename,coalesce(timestamp,''),coalesce(reason,''),
                    coalesce(volume_letter,'')
             FROM journal_events
             WHERE lower(reason) LIKE '%file_create%'
                OR lower(reason) LIKE '%file_delete%'
                OR lower(reason) LIKE '%rename_%'
             ORDER BY timestamp,rowid",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(UsnRecord {
                source: source(source_path, "journal_events", row.get(0)?),
                frn: row.get(1)?,
                file_name: row.get(2)?,
                timestamp: row.get(3)?,
                reason: row.get(4)?,
                volume: row.get(5)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut inserted = 0;

    if let Some(rule) = rule(pack, "usn_created_then_deleted") {
        let mut by_frn = HashMap::<String, Vec<&UsnRecord>>::new();
        for record in &rows {
            let name = basename(&record.file_name);
            let corroborated = executions
                .get(&name)
                .map(|traces| {
                    traces
                        .iter()
                        .any(|trace| suspicious_execution(pack, suspicious, trace))
                })
                .unwrap_or(false);
            if executable_extension(pack, &record.file_name) && corroborated {
                by_frn.entry(record.frn.clone()).or_default().push(record);
            }
        }
        let mut count = 0;
        for (frn, records) in by_frn {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let created = records
                .iter()
                .filter(|record| record.reason.to_ascii_lowercase().contains("file_create"))
                .min_by_key(|record| source_time(&record.timestamp));
            let deletes = records
                .iter()
                .filter(|record| record.reason.to_ascii_lowercase().contains("file_delete"))
                .collect::<Vec<_>>();
            let Some(created) = created else {
                continue;
            };
            if any_marker(&created.file_name, &rule.allowed_path_markers) {
                continue;
            }
            let Some(created_time) = source_time(&created.timestamp) else {
                continue;
            };
            let Some(deleted) = deletes.iter().copied().find(|deleted| {
                source_time(&deleted.timestamp)
                    .map(|deleted_time| {
                        let minutes = deleted_time
                            .signed_duration_since(created_time)
                            .num_minutes();
                        minutes >= 0 && minutes <= rule.window_minutes.max(1)
                    })
                    .unwrap_or(false)
            }) else {
                continue;
            };
            count += 1;
            let sources = vec![created.source.clone(), deleted.source.clone()];
            let execution_ids = executions
                .get(&basename(&created.file_name))
                .into_iter()
                .flatten()
                .filter(|trace| suspicious_execution(pack, suspicious, trace))
                .map(|trace| trace.event.id)
                .collect::<Vec<_>>();
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{} {} | created {} | deleted {}",
                    created.volume, created.file_name, created.timestamp, deleted.timestamp
                ),
                json!({
                    "frn":frn,"file_name":created.file_name,"created":created.timestamp,
                    "deleted":deleted.timestamp,"create_reason":created.reason,"delete_reason":deleted.reason
                }),
                &sources,
                &execution_ids,
            )?;
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
        }
    }

    if let Some(rule) = rule(pack, "usn_event_log_deleted") {
        for record in rows
            .iter()
            .filter(|record| {
                record.reason.to_ascii_lowercase().contains("file_delete")
                    && (rule
                        .extensions
                        .iter()
                        .any(|wanted| extension(&record.file_name) == *wanted)
                        || rule
                            .file_names
                            .iter()
                            .any(|wanted| record.file_name.eq_ignore_ascii_case(wanted)))
            })
            .take(MAX_LEADS_PER_RULE)
        {
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{}\\{} | {}",
                    record.volume, record.file_name, record.timestamp
                ),
                json!({"frn":record.frn,"file_name":record.file_name,"timestamp":record.timestamp,"reason":record.reason}),
                std::slice::from_ref(&record.source),
                &[],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "usn_registry_hive_deleted") {
        for record in rows
            .iter()
            .filter(|record| {
                record.reason.to_ascii_lowercase().contains("file_delete")
                    && rule
                        .file_names
                        .iter()
                        .any(|wanted| record.file_name.eq_ignore_ascii_case(wanted))
            })
            .take(MAX_LEADS_PER_RULE)
        {
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{} {} | {}",
                    record.volume, record.file_name, record.timestamp
                ),
                json!({"frn":record.frn,"file_name":record.file_name,"timestamp":record.timestamp,"reason":record.reason}),
                std::slice::from_ref(&record.source),
                &[],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "usn_mass_extension_change") {
        let bucket_seconds = rule.window_minutes.max(1) * 60;
        let mut by_frn = HashMap::<String, Vec<&UsnRecord>>::new();
        for record in &rows {
            if record.reason.to_ascii_lowercase().contains("rename_") {
                by_frn.entry(record.frn.clone()).or_default().push(record);
            }
        }
        let mut buckets = HashMap::<(i64, String), Vec<(&UsnRecord, &UsnRecord)>>::new();
        for records in by_frn.values() {
            for old in records.iter().filter(|record| {
                record
                    .reason
                    .to_ascii_lowercase()
                    .contains("rename_old_name")
            }) {
                let old_extension = extension(&old.file_name);
                if !rule
                    .extensions
                    .iter()
                    .any(|wanted| wanted == &old_extension)
                {
                    continue;
                }
                let Some(old_time) = source_time(&old.timestamp) else {
                    continue;
                };
                let Some(new) = records.iter().copied().find(|record| {
                    record
                        .reason
                        .to_ascii_lowercase()
                        .contains("rename_new_name")
                        && source_time(&record.timestamp)
                            .map(|time| {
                                let seconds = time.signed_duration_since(old_time).num_seconds();
                                (0..=60).contains(&seconds)
                            })
                            .unwrap_or(false)
                }) else {
                    continue;
                };
                let new_extension = extension(&new.file_name);
                if new_extension.is_empty()
                    || new_extension == old_extension
                    || rule
                        .allowed_path_markers
                        .iter()
                        .any(|allowed| allowed == &new_extension)
                {
                    continue;
                }
                buckets
                    .entry((old_time.timestamp() / bucket_seconds, new_extension))
                    .or_default()
                    .push((old, new));
            }
        }
        for ((_, new_extension), pairs) in buckets {
            let distinct = pairs
                .iter()
                .map(|(old, _)| old.file_name.to_ascii_lowercase())
                .collect::<HashSet<_>>();
            if distinct.len() < rule.minimum_count.max(1) {
                continue;
            }
            let sources = pairs
                .iter()
                .take(50)
                .flat_map(|(old, new)| [old.source.clone(), new.source.clone()])
                .collect::<Vec<_>>();
            let first = pairs.first().expect("non-empty bucket").0;
            let last = pairs.last().expect("non-empty bucket").1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{} documents renamed to .{} between {} and {}",
                    distinct.len(),
                    new_extension,
                    first.timestamp,
                    last.timestamp
                ),
                json!({
                    "distinct_files":distinct.len(),"new_extension":new_extension,
                    "first":first.timestamp,"last":last.timestamp,
                    "sample":distinct.iter().take(30).collect::<Vec<_>>()
                }),
                &sources,
                &[],
            )?;
        }
    }
    Ok(inserted)
}

fn event_field<'a>(record: &'a EvtxRecord, key: &str) -> Option<&'a str> {
    record.data.get(key).and_then(Value::as_str)
}

fn event_time(record: &EvtxRecord) -> Option<DateTime<Utc>> {
    source_time(&record.timestamp)
}

fn minutes_apart(first: &EvtxRecord, second: &EvtxRecord) -> Option<i64> {
    let difference = event_time(second)?.signed_duration_since(event_time(first)?);
    Some(difference.num_minutes())
}

fn matching_execution<'a>(
    pack: &CorrelationPack,
    executions: &'a HashMap<String, Vec<ExecutionTrace>>,
    path: &str,
) -> Option<&'a ExecutionTrace> {
    let lower = path.to_ascii_lowercase();
    let name = rule(pack, "user_writable_executable")
        .and_then(|rule| {
            rule.extensions.iter().find_map(|ext| {
                let marker = format!(".{ext}");
                lower.find(&marker).map(|offset| {
                    basename(
                        lower[..offset + marker.len()].trim_matches([' ', '\"', '\'', '(', ')']),
                    )
                })
            })
        })
        .unwrap_or_else(|| basename(path));
    executions.get(&name).and_then(|items| items.first())
}

fn suspicious_execution(
    pack: &CorrelationPack,
    suspicious: &HashSet<String>,
    trace: &ExecutionTrace,
) -> bool {
    suspicious.contains(&trace.name) || user_writable(pack, &trace.candidate)
}

fn scan_evtx(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
    executions: &HashMap<String, Vec<ExecutionTrace>>,
    suspicious: &HashSet<String>,
) -> Result<usize, String> {
    if !table_exists(source_db, "evtx_events") {
        return Ok(0);
    }
    let wanted = pack
        .rules
        .iter()
        .filter(|rule| rule.kind.starts_with("evtx_"))
        .flat_map(|rule| rule.event_ids.iter().copied())
        .collect::<HashSet<_>>();
    if wanted.is_empty() {
        return Ok(0);
    }
    let mut wanted = wanted.into_iter().collect::<Vec<_>>();
    wanted.sort_unstable();
    let placeholders = (1..=wanted.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = source_db
        .prepare(&format!(
            "SELECT rowid,EventID,coalesce(Provider,''),coalesce(Channel,''),coalesce(Computer,''),
                    coalesce(EventTimestampUTC,''),coalesce(EventData,''),coalesce(RawJSON,'')
             FROM evtx_events WHERE EventID IN ({placeholders}) ORDER BY EventTimestampUTC,rowid"
        ))
        .map_err(|error| error.to_string())?;
    let records = statement
        .query_map(params_from_iter(wanted.iter()), |row| {
            let event_data = row.get::<_, String>(6)?;
            Ok(EvtxRecord {
                source: source(source_path, "evtx_events", row.get(0)?),
                event_id: row.get(1)?,
                provider: row.get(2)?,
                channel: row.get(3)?,
                computer: row.get(4)?,
                timestamp: row.get(5)?,
                data: serde_json::from_str(&event_data).unwrap_or(Value::Null),
                raw: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut inserted = 0;

    if let Some(rule) = rule(pack, "evtx_account_privilege_sequence") {
        let creations = records.iter().filter(|record| record.event_id == 4720);
        let additions = records.iter().filter(|record| {
            rule.event_ids.contains(&record.event_id)
                && record.event_id != 4720
                && event_field(record, "TargetUserName")
                    .map(|group| any_marker(group, &rule.group_markers))
                    .unwrap_or(false)
        });
        let additions = additions.collect::<Vec<_>>();
        let mut count = 0;
        for created in creations {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let account = event_field(created, "TargetUserName").unwrap_or_default();
            if any_marker(account, &rule.allowed_path_markers) {
                continue;
            }
            let sid = event_field(created, "TargetSid").unwrap_or_default();
            let Some(added) = additions.iter().copied().find(|added| {
                !sid.is_empty()
                    && event_field(added, "MemberSid") == Some(sid)
                    && added.computer.eq_ignore_ascii_case(&created.computer)
                    && minutes_apart(created, added)
                        .map(|minutes| minutes.abs() <= rule.window_minutes.max(1))
                        .unwrap_or(false)
            }) else {
                continue;
            };
            count += 1;
            let group = event_field(added, "TargetUserName").unwrap_or("privileged group");
            let sources = vec![created.source.clone(), added.source.clone()];
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!("{} | account {account} added to {group}", created.computer),
                json!({"account_created":created.data,"group_membership":added.data,"timestamps":[created.timestamp,added.timestamp]}),
                &sources,
                &[],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "evtx_failed_then_success") {
        let security = |record: &&EvtxRecord| {
            record.channel.eq_ignore_ascii_case("security")
                && record
                    .provider
                    .eq_ignore_ascii_case("Microsoft-Windows-Security-Auditing")
        };
        let failures = records
            .iter()
            .filter(|record| record.event_id == 4625)
            .filter(security)
            .collect::<Vec<_>>();
        let successes = records
            .iter()
            .filter(|record| record.event_id == 4624)
            .filter(security)
            .collect::<Vec<_>>();
        let mut groups = HashMap::<(String, String, String), Vec<&EvtxRecord>>::new();
        for failed in failures {
            let user = event_field(failed, "TargetUserName").unwrap_or_default();
            let ip = event_field(failed, "IpAddress").unwrap_or_default();
            if user.is_empty() || matches!(user, "-" | "SYSTEM") || ip.is_empty() || ip == "-" {
                continue;
            }
            groups
                .entry((
                    failed.computer.to_ascii_lowercase(),
                    user.to_ascii_lowercase(),
                    ip.to_ascii_lowercase(),
                ))
                .or_default()
                .push(failed);
        }
        let mut count = 0;
        for ((computer, user, ip), failed) in groups {
            if failed.len() < rule.minimum_count.max(1) || count >= MAX_LEADS_PER_RULE {
                continue;
            }
            let Some(success) = successes.iter().copied().find(|success| {
                success.computer.eq_ignore_ascii_case(&computer)
                    && event_field(success, "TargetUserName")
                        .map(|value| value.eq_ignore_ascii_case(&user))
                        .unwrap_or(false)
                    && event_field(success, "IpAddress")
                        .map(|value| value.eq_ignore_ascii_case(&ip))
                        .unwrap_or(false)
                    && failed.iter().any(|failure| {
                        minutes_apart(failure, success)
                            .map(|minutes| minutes >= 0 && minutes <= rule.window_minutes.max(1))
                            .unwrap_or(false)
                    })
            }) else {
                continue;
            };
            count += 1;
            let mut sources = failed
                .iter()
                .take(50)
                .map(|record| record.source.clone())
                .collect::<Vec<_>>();
            sources.push(success.source.clone());
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{computer} | {user} from {ip} | {} failures followed by a success",
                    failed.len()
                ),
                json!({"failed_count":failed.len(),"success":success.data,"success_time":success.timestamp}),
                &sources,
                &[],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "evtx_service_execution_link") {
        let mut count = 0;
        for record in records
            .iter()
            .filter(|record| rule.event_ids.contains(&record.event_id))
        {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let image = event_field(record, "ImagePath").unwrap_or_default();
            let Some(trace) = matching_execution(pack, executions, image) else {
                continue;
            };
            if !user_writable(pack, image) && !suspicious.contains(&trace.name) {
                continue;
            }
            count += 1;
            let service = event_field(record, "ServiceName").unwrap_or("unknown service");
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!("{} | {service} -> {image}", record.computer),
                json!({"service_event":record.data,"execution_artifact":trace.candidate,"execution_summary":trace.event.summary}),
                std::slice::from_ref(&record.source),
                &[trace.event.id],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "evtx_task_execution_link") {
        let mut count = 0;
        for record in records
            .iter()
            .filter(|record| rule.event_ids.contains(&record.event_id))
        {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let text = format!("{} {}", record.data, record.raw).to_ascii_lowercase();
            let trace = executions.values().flatten().find(|trace| {
                text.contains(&trace.name) && suspicious_execution(pack, suspicious, trace)
            });
            let Some(trace) = trace else {
                continue;
            };
            count += 1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!("{} | task references {}", record.computer, trace.candidate),
                json!({"task_event":record.data,"execution_artifact":trace.candidate,"execution_summary":trace.event.summary}),
                std::slice::from_ref(&record.source),
                &[trace.event.id],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "evtx_powershell_artifact_link") {
        let mut count = 0;
        for record in records
            .iter()
            .filter(|record| rule.event_ids.contains(&record.event_id))
        {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let text = format!("{} {}", record.data, record.raw).to_ascii_lowercase();
            if !any_marker(&text, &rule.markers) {
                continue;
            }
            let trace = executions
                .values()
                .flatten()
                .find(|trace| text.contains(&trace.name));
            let Some(trace) = trace else {
                continue;
            };
            count += 1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{} | PowerShell references {}",
                    record.computer, trace.candidate
                ),
                json!({"powershell_event":record.data,"execution_artifact":trace.candidate,"execution_summary":trace.event.summary}),
                std::slice::from_ref(&record.source),
                &[trace.event.id],
            )?;
        }
    }

    if let Some(rule) = rule(pack, "evtx_defender_then_execution") {
        let mut count = 0;
        for record in records.iter().filter(|record| {
            rule.event_ids.contains(&record.event_id)
                && record.provider.to_ascii_lowercase().contains("defender")
        }) {
            if count >= MAX_LEADS_PER_RULE {
                break;
            }
            let Some(disabled_time) = event_time(record) else {
                continue;
            };
            let trace = executions.values().flatten().find(|trace| {
                let Some(execution_time) = trace.time else {
                    return false;
                };
                let minutes = execution_time
                    .signed_duration_since(disabled_time)
                    .num_minutes();
                minutes >= 0
                    && minutes <= rule.window_minutes.max(1)
                    && suspicious_execution(pack, suspicious, trace)
            });
            let Some(trace) = trace else {
                continue;
            };
            count += 1;
            inserted += insert_source_lead(
                case_db,
                rule,
                &format!(
                    "{} | protection change followed by {}",
                    record.computer, trace.candidate
                ),
                json!({"defender_event":record.data,"defender_time":record.timestamp,"execution_artifact":trace.candidate,"execution_time":trace.event.timestamp}),
                std::slice::from_ref(&record.source),
                &[trace.event.id],
            )?;
        }
    }
    Ok(inserted)
}

fn scan_srum(
    source_path: &Path,
    source_db: &Connection,
    case_db: &Connection,
    pack: &CorrelationPack,
    executions: &HashMap<String, Vec<ExecutionTrace>>,
    suspicious: &HashSet<String>,
) -> Result<usize, String> {
    let Some(rule) = rule(pack, "srum_network_execution_link") else {
        return Ok(0);
    };
    if !table_exists(source_db, "srum_records") {
        return Ok(0);
    }
    let mut statement = source_db
        .prepare(
            "SELECT rowid,TableName,RecordJSON FROM srum_records
             WHERE RecordJSON LIKE '%\"AppName\"%' AND RecordJSON LIKE '%\"BytesSent\"%'",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut grouped = HashMap::<String, (u64, u64, Vec<SourceRef>, Vec<Value>)>::new();
    for row in rows {
        let (rowid, table, raw) = row.map_err(|error| error.to_string())?;
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let app = value["AppName"].as_str().unwrap_or_default();
        let name = basename(app);
        if name.is_empty()
            || !executions.contains_key(&name)
            || any_marker(app, &rule.allowed_path_markers)
        {
            continue;
        }
        let trace = executions
            .get(&name)
            .and_then(|items| items.first())
            .expect("execution was checked");
        if !suspicious_execution(pack, suspicious, trace) {
            continue;
        }
        let sent = value["BytesSent"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let received = value["BytesRecvd"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if sent == 0 && received == 0 {
            continue;
        }
        let entry = grouped
            .entry(app.to_ascii_lowercase())
            .or_insert_with(|| (0, 0, Vec::new(), Vec::new()));
        entry.0 = entry.0.saturating_add(sent);
        entry.1 = entry.1.saturating_add(received);
        if entry.2.len() < 100 {
            entry.2.push(source(source_path, &table, rowid));
        }
        if entry.3.len() < 20 {
            entry.3.push(value);
        }
    }
    let mut inserted = 0;
    for (app, (sent, received, sources, samples)) in grouped.into_iter().take(MAX_LEADS_PER_RULE) {
        let name = basename(&app);
        let Some(trace) = executions.get(&name).and_then(|items| items.first()) else {
            continue;
        };
        inserted += insert_source_lead(
            case_db,
            rule,
            &format!("{app} | sent {sent} bytes | received {received} bytes"),
            json!({
                "application":app,"bytes_sent":sent,"bytes_received":received,
                "execution_artifact":trace.candidate,"execution_summary":trace.event.summary,
                "sample_records":samples
            }),
            &sources,
            &[trace.event.id],
        )?;
    }
    Ok(inserted)
}

pub(super) fn scan(
    case_root: &Path,
    case_db: &Connection,
    pack: &CorrelationPack,
) -> Result<usize, String> {
    let executions = load_executions(case_db)?;
    let suspicious = suspicious_names(pack);
    let mut inserted = 0;
    for (parser, path) in processed_databases(case_root)? {
        let source_db = open_source(&path)?;
        match parser.as_str() {
            "registry" => inserted += scan_registry(&path, &source_db, case_db, pack)?,
            "lnk" => inserted += scan_links(&path, &source_db, case_db, pack)?,
            "mft" => inserted += scan_mft(&path, &source_db, case_db, pack)?,
            "usn" => {
                inserted += scan_usn(&path, &source_db, case_db, pack, &executions, &suspicious)?
            }
            "evtx" => {
                inserted += scan_evtx(&path, &source_db, case_db, pack, &executions, &suspicious)?
            }
            "srum" => {
                inserted += scan_srum(&path, &source_db, case_db, pack, &executions, &suspicious)?
            }
            _ => {}
        }
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack() -> CorrelationPack {
        serde_json::from_str(super::super::CORRELATION_PACK).unwrap()
    }

    fn case_database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE events(
               id INTEGER PRIMARY KEY,timestamp_utc TEXT,artifact_type TEXT,event_type TEXT,
               host TEXT,user TEXT,path TEXT,process TEXT,summary TEXT,parser TEXT,
               source_database TEXT,source_table TEXT,source_row_id TEXT,source_sql_rowid INTEGER);",
        )
        .unwrap();
        super::super::ensure_detection_schema(&db).unwrap();
        db
    }

    fn add_event(db: &Connection, source_path: &Path, table: &str, rowid: i64) {
        db.execute(
            "INSERT INTO events(timestamp_utc,artifact_type,event_type,path,process,summary,parser,
                                source_database,source_table,source_row_id,source_sql_rowid)
             VALUES('2026-09-03T10:00:00Z','registry','test',NULL,NULL,'test','test',?1,?2,?3,?3)",
            params![source_path.display().to_string(), table, rowid],
        )
        .unwrap();
    }

    #[test]
    fn unwraps_registry_strings() {
        assert_eq!(
            registry_data(r#"String("C:\\Users\\Public\\tool.exe")"#),
            r#"C:\Users\Public\tool.exe"#
        );
    }

    #[test]
    fn spots_identity_mismatch() {
        assert!(identity_mismatch(
            "Realtek HD Audio Universal Service",
            r#"C:\Users\Alice\AppData\Roaming\SecurityHealthSystray.exe"#
        ));
        assert!(!identity_mismatch(
            "OneDrive",
            r#"C:\Users\Alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background"#
        ));
    }

    #[test]
    fn registry_and_shortcut_rules_keep_source_links() {
        let pack = pack();
        let case_db = case_database();
        let registry_path = Path::new(r"C:\case\PROCESSED\registry\registry.db");
        let registry = Connection::open_in_memory().unwrap();
        registry
            .execute_batch(
                "CREATE TABLE registry_values(
                   Hive TEXT,KeyPath TEXT,ValueName TEXT,ValueType TEXT,ValueData TEXT,
                   DataSHA256 TEXT,CellState TEXT);",
            )
            .unwrap();
        registry
            .execute(
                "INSERT INTO registry_values(Hive,KeyPath,ValueName,ValueData)
             VALUES('NTUSER.DAT','ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'Audio Driver',?1)",
                [r#"String("C:\\Users\\Public\\payload.exe")"#],
            )
            .unwrap();
        let registry_row = registry.last_insert_rowid();
        add_event(&case_db, registry_path, "registry_values", registry_row);
        assert_eq!(
            scan_registry(registry_path, &registry, &case_db, &pack).unwrap(),
            1
        );

        let lnk_path = Path::new(r"C:\case\PROCESSED\lnk\lnk.db");
        let lnk = Connection::open_in_memory().unwrap();
        lnk.execute_batch(
            "CREATE TABLE LNK_Files(
               Source_Path TEXT,Local_Path TEXT,Command_Line_Arguments TEXT,Network_Share_Name TEXT);",
        )
        .unwrap();
        lnk.execute(
            "INSERT INTO LNK_Files VALUES('invoice.lnk','C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','-encodedcommand AAAA','')",
            [],
        ).unwrap();
        let lnk_row = lnk.last_insert_rowid();
        add_event(&case_db, lnk_path, "LNK_Files", lnk_row);
        assert_eq!(scan_links(lnk_path, &lnk, &case_db, &pack).unwrap(), 1);

        let linked: i64 = case_db
            .query_row("SELECT count(*) FROM detection_lead_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(linked, 2);
    }

    #[test]
    fn mft_and_usn_rules_detect_named_streams_and_bulk_extension_changes() {
        let pack = pack();
        let case_db = case_database();
        let mft_path = Path::new(r"C:\case\PROCESSED\mft\mft.db");
        let mft = Connection::open_in_memory().unwrap();
        mft.execute_batch(
            "CREATE TABLE mft_records(
               record_number INTEGER,volume_letter TEXT,file_name TEXT,ads_count INTEGER,
               created_time TEXT);
             CREATE TABLE mft_data_attributes(record_number INTEGER,attribute_name TEXT);",
        )
        .unwrap();
        mft.execute(
            "INSERT INTO mft_records VALUES(42,'C:','payload.exe',2,'2026-09-03 10:00:00 UTC')",
            [],
        )
        .unwrap();
        let mft_row = mft.last_insert_rowid();
        mft.execute("INSERT INTO mft_data_attributes VALUES(42,'hidden')", [])
            .unwrap();
        add_event(&case_db, mft_path, "mft_records", mft_row);
        assert_eq!(scan_mft(mft_path, &mft, &case_db, &pack).unwrap(), 1);

        let usn_path = Path::new(r"C:\case\PROCESSED\usn\usn.db");
        let usn = Connection::open_in_memory().unwrap();
        usn.execute_batch(
            "CREATE TABLE journal_events(
               frn TEXT,filename TEXT,timestamp TEXT,reason TEXT,volume_letter TEXT);",
        )
        .unwrap();
        for index in 0..20 {
            usn.execute(
                "INSERT INTO journal_events VALUES(?1,?2,'2026-09-03 10:01:00 UTC','RENAME_OLD_NAME','C:')",
                params![format!("{index}-1"), format!("document-{index}.docx")],
            )
            .unwrap();
            let old_row = usn.last_insert_rowid();
            add_event(&case_db, usn_path, "journal_events", old_row);
            usn.execute(
                "INSERT INTO journal_events VALUES(?1,?2,'2026-09-03 10:01:01 UTC','RENAME_NEW_NAME','C:')",
                params![format!("{index}-1"), format!("document-{index}.docx.locked")],
            )
            .unwrap();
            let new_row = usn.last_insert_rowid();
            add_event(&case_db, usn_path, "journal_events", new_row);
        }
        assert_eq!(
            scan_usn(
                usn_path,
                &usn,
                &case_db,
                &pack,
                &HashMap::new(),
                &HashSet::new(),
            )
            .unwrap(),
            1
        );
        let linked: i64 = case_db
            .query_row(
                "SELECT count(*) FROM detection_lead_events link
                 JOIN detection_leads lead ON lead.id=link.lead_id
                 WHERE lead.rule_id='VH-USN-002'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked, 40);
    }

    #[test]
    fn all_event_correlation_kinds_trigger_on_correlated_fixtures() {
        let pack = pack();
        let case_db = case_database();
        let evtx_path = Path::new(r"C:\case\PROCESSED\evtx\evtx.db");
        let evtx = Connection::open_in_memory().unwrap();
        evtx.execute_batch(
            "CREATE TABLE evtx_events(
               EventID INTEGER,Provider TEXT,Channel TEXT,Computer TEXT,EventTimestampUTC TEXT,
               EventData TEXT,RawJSON TEXT);",
        )
        .unwrap();
        let insert_record = |event_id: i64, provider: &str, timestamp: &str, data: Value| {
            evtx.execute(
                "INSERT INTO evtx_events VALUES(?1,?2,'Security','WS-01',?3,?4,'{}')",
                params![event_id, provider, timestamp, data.to_string()],
            )
            .unwrap();
            let rowid = evtx.last_insert_rowid();
            add_event(&case_db, evtx_path, "evtx_events", rowid);
        };
        insert_record(
            4720,
            "Microsoft-Windows-Security-Auditing",
            "2026-09-03T10:00:00Z",
            json!({"TargetUserName":"alice","TargetSid":"S-1-5-21-1001"}),
        );
        insert_record(
            4732,
            "Microsoft-Windows-Security-Auditing",
            "2026-09-03T10:01:00Z",
            json!({"TargetUserName":"Administrators","MemberSid":"S-1-5-21-1001"}),
        );
        for minute in 2..7 {
            insert_record(
                4625,
                "Microsoft-Windows-Security-Auditing",
                &format!("2026-09-03T10:0{minute}:00Z"),
                json!({"TargetUserName":"alice","IpAddress":"10.0.0.9"}),
            );
        }
        insert_record(
            4624,
            "Microsoft-Windows-Security-Auditing",
            "2026-09-03T10:08:00Z",
            json!({"TargetUserName":"alice","IpAddress":"10.0.0.9"}),
        );
        insert_record(
            7045,
            "Service Control Manager",
            "2026-09-03T10:20:00Z",
            json!({"ServiceName":"Updater","ImagePath":"C:\\Users\\Public\\evil.exe -service"}),
        );
        insert_record(
            4698,
            "Microsoft-Windows-Security-Auditing",
            "2026-09-03T10:21:00Z",
            json!({"TaskName":"Update","TaskContent":"C:\\Users\\Public\\evil.exe"}),
        );
        insert_record(
            4104,
            "Microsoft-Windows-PowerShell",
            "2026-09-03T10:22:00Z",
            json!({"ScriptBlockText":"DownloadString('https://example.invalid/a'); evil.exe"}),
        );
        insert_record(
            5001,
            "Microsoft-Windows-Windows Defender",
            "2026-09-03T10:29:00Z",
            json!({"ProductName":"Microsoft Defender"}),
        );
        case_db.execute(
            "INSERT INTO events(timestamp_utc,artifact_type,event_type,path,process,summary,parser,
                                source_database,source_table,source_row_id,source_sql_rowid)
             VALUES('2026-09-03T10:30:00Z','shimcache','application_observed',
                    'C:\\Users\\Public\\evil.exe','evil.exe','evil.exe observed','shimcache',
                    'shimcache.db','shimcache_entries','1',1)",
            [],
        ).unwrap();
        let executions = load_executions(&case_db).unwrap();
        let suspicious = suspicious_names(&pack);
        assert_eq!(
            scan_evtx(evtx_path, &evtx, &case_db, &pack, &executions, &suspicious,).unwrap(),
            6
        );
        let linked: i64 = case_db
            .query_row(
                "SELECT count(*) FROM detection_lead_events link
                 JOIN detection_leads lead ON lead.id=link.lead_id
                 WHERE lead.rule_id LIKE 'VH-EVT-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(linked >= 13);
    }

    #[test]
    fn srum_network_rule_requires_a_risky_corroborated_program() {
        let pack = pack();
        let case_db = case_database();
        case_db.execute(
            "INSERT INTO events(timestamp_utc,artifact_type,event_type,path,process,summary,parser,
                                source_database,source_table,source_row_id,source_sql_rowid)
             VALUES('2026-09-03T10:00:00Z','shimcache','application_observed',
                    'C:\\Users\\Public\\odd.exe','odd.exe','odd.exe observed','shimcache',
                    'shimcache.db','shimcache_entries','1',1)",
            [],
        ).unwrap();
        let srum_path = Path::new(r"C:\case\PROCESSED\srum\srum.db");
        let srum = Connection::open_in_memory().unwrap();
        srum.execute_batch("CREATE TABLE srum_records(TableName TEXT,RecordJSON TEXT);")
            .unwrap();
        srum.execute(
            "INSERT INTO srum_records VALUES('{973F5D5C-1D90-4944-BE8E-24B94231A174}',?1)",
            [json!({
                "TimeStamp":"2026-09-03T10:00:00Z",
                "AppName":"C:\\Users\\Public\\odd.exe",
                "BytesSent":"512","BytesRecvd":"1024"
            })
            .to_string()],
        )
        .unwrap();
        let rowid = srum.last_insert_rowid();
        add_event(&case_db, srum_path, "srum_records", rowid);
        let executions = load_executions(&case_db).unwrap();
        assert_eq!(
            scan_srum(
                srum_path,
                &srum,
                &case_db,
                &pack,
                &executions,
                &suspicious_names(&pack),
            )
            .unwrap(),
            1
        );
    }
}
