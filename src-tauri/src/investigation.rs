use rusqlite::{params, types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Serialize)]
pub struct TimelineEvent {
    pub(crate) id: i64,
    timestamp_utc: Option<String>,
    artifact_type: String,
    event_type: String,
    host: Option<String>,
    user: Option<String>,
    path: Option<String>,
    process: Option<String>,
    summary: String,
    source_database: String,
    source_table: String,
    source_row_id: String,
}
#[derive(Deserialize)]
pub struct EventFilter {
    search: String,
    artifact_type: Vec<String>,
    event_type: Vec<String>,
    host: Vec<String>,
    user: Vec<String>,
    from_utc: String,
    to_utc: String,
    page: usize,
    page_size: usize,
}
#[derive(Serialize)]
pub struct EventPage {
    rows: Vec<TimelineEvent>,
    total: i64,
    page: usize,
    page_size: usize,
}
#[derive(Serialize)]
pub struct EventFilterOptions {
    artifact_types: Vec<String>,
    event_types: Vec<String>,
    hosts: Vec<String>,
    users: Vec<String>,
}
#[derive(Serialize)]
pub struct Relationship {
    pub(crate) source_type: String,
    pub(crate) source_value: String,
    pub(crate) target_type: String,
    pub(crate) target_value: String,
    pub(crate) relation: String,
    pub(crate) event_count: i64,
    pub(crate) first_seen: Option<String>,
    pub(crate) last_seen: Option<String>,
}
#[derive(Serialize)]
pub struct InvestigationOverview {
    pub(crate) events: i64,
    pub(crate) entities: i64,
    pub(crate) relationships: i64,
}
#[derive(Serialize)]
pub struct SourceRecord {
    event_id: i64,
    database: String,
    pub(crate) table: String,
    row_reference: String,
    pub(crate) fields: BTreeMap<String, serde_json::Value>,
}

fn database(case_path: &str) -> Result<Connection, String> {
    let root = Path::new(case_path)
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let directory = root
        .join("DATABASE")
        .canonicalize()
        .map_err(|_| "The case database directory is unavailable.".to_string())?;
    if !directory.starts_with(&root) {
        return Err("The case database directory points outside this case.".into());
    }
    let path = crate::paths::case_database(&root)?;
    if !path.is_file() {
        return Err("No normalized evidence exists in this case yet.".into());
    }
    let path = path
        .canonicalize()
        .map_err(|_| "The case database is unavailable.".to_string())?;
    if !path.starts_with(directory) {
        return Err("The case database points outside this case.".into());
    }
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn investigation_overview(case_path: String) -> Result<InvestigationOverview, String> {
    let db = database(&case_path)?;
    Ok(InvestigationOverview {
        events: db
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .map_err(|e| e.to_string())?,
        entities: db
            .query_row("SELECT count(*) FROM entities", [], |r| r.get(0))
            .map_err(|e| e.to_string())?,
        relationships: db
            .query_row("SELECT count(*) FROM relationships", [], |r| r.get(0))
            .map_err(|e| e.to_string())?,
    })
}

#[tauri::command]
pub fn timeline_events(
    case_path: String,
    search: String,
    limit: usize,
) -> Result<Vec<TimelineEvent>, String> {
    let db = database(&case_path)?;
    let pattern = format!("%{}%", search);
    let max = limit.clamp(1, 2000) as i64;
    let mut stmt=db.prepare("SELECT id,timestamp_utc,artifact_type,event_type,host,user,path,process,summary,source_database,source_table,source_row_id FROM events WHERE ?1='' OR summary LIKE ?2 OR coalesce(host,'') LIKE ?2 OR coalesce(user,'') LIKE ?2 OR coalesce(path,'') LIKE ?2 OR coalesce(process,'') LIKE ?2 ORDER BY timestamp_utc IS NULL,timestamp_utc DESC LIMIT ?3").map_err(|e|e.to_string())?;
    let result = stmt
        .query_map(params![search, pattern, max], |r| {
            Ok(TimelineEvent {
                id: r.get(0)?,
                timestamp_utc: r.get(1)?,
                artifact_type: r.get(2)?,
                event_type: r.get(3)?,
                host: r.get(4)?,
                user: r.get(5)?,
                path: r.get(6)?,
                process: r.get(7)?,
                summary: r.get(8)?,
                source_database: r.get(9)?,
                source_table: r.get(10)?,
                source_row_id: r.get(11)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string());
    result
}

#[tauri::command]
pub fn explore_events(case_path: String, filter: EventFilter) -> Result<EventPage, String> {
    let db = database(&case_path)?;
    let page_size = filter.page_size.clamp(25, 500);
    let page = filter.page;
    let mut clauses = Vec::<String>::new();
    let mut values = Vec::<String>::new();
    if !filter.search.trim().is_empty() {
        clauses.push("(summary LIKE ? OR coalesce(host,'') LIKE ? OR coalesce(user,'') LIKE ? OR coalesce(path,'') LIKE ? OR coalesce(process,'') LIKE ?)".into());
        let value = format!("%{}%", filter.search.trim());
        values.extend(std::iter::repeat_n(value, 5));
    }
    for (column, selected) in [
        ("artifact_type", filter.artifact_type),
        ("event_type", filter.event_type),
        ("host", filter.host),
        ("user", filter.user),
    ] {
        if !selected.is_empty() {
            clauses.push(format!(
                "{column} IN ({})",
                std::iter::repeat_n("?", selected.len())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            values.extend(selected);
        }
    }
    if !filter.from_utc.trim().is_empty() {
        clauses.push("timestamp_utc >= ?".into());
        values.push(filter.from_utc);
    }
    if !filter.to_utc.trim().is_empty() {
        clauses.push("timestamp_utc <= ?".into());
        values.push(filter.to_utc);
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let total: i64 = db
        .query_row(
            &format!("SELECT count(*) FROM events{where_sql}"),
            rusqlite::params_from_iter(values.iter()),
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    let sql=format!("SELECT id,timestamp_utc,artifact_type,event_type,host,user,path,process,summary,source_database,source_table,source_row_id FROM events{where_sql} ORDER BY timestamp_utc IS NULL,timestamp_utc DESC,id DESC LIMIT ? OFFSET ?");
    let mut query_values = values;
    query_values.push(page_size.to_string());
    query_values.push((page * page_size).to_string());
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(query_values.iter()), |r| {
            Ok(TimelineEvent {
                id: r.get(0)?,
                timestamp_utc: r.get(1)?,
                artifact_type: r.get(2)?,
                event_type: r.get(3)?,
                host: r.get(4)?,
                user: r.get(5)?,
                path: r.get(6)?,
                process: r.get(7)?,
                summary: r.get(8)?,
                source_database: r.get(9)?,
                source_table: r.get(10)?,
                source_row_id: r.get(11)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(EventPage {
        rows,
        total,
        page,
        page_size,
    })
}

fn distinct_values(db: &Connection, column: &str, limit: usize) -> Result<Vec<String>, String> {
    let column = match column {
        "artifact_type" => "artifact_type",
        "event_type" => "event_type",
        "host" => "host",
        "user" => "user",
        _ => return Err("Unsupported filter field.".into()),
    };
    let sql=format!("SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL AND {column}<>'' ORDER BY {column} COLLATE NOCASE LIMIT ?1");
    let mut statement = db.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([limit as i64], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn event_filter_options(case_path: String) -> Result<EventFilterOptions, String> {
    let db = database(&case_path)?;
    Ok(EventFilterOptions {
        artifact_types: distinct_values(&db, "artifact_type", 200)?,
        event_types: distinct_values(&db, "event_type", 500)?,
        hosts: distinct_values(&db, "host", 1000)?,
        users: distinct_values(&db, "user", 1000)?,
    })
}

#[tauri::command]
pub fn relationship_edges(case_path: String, limit: usize) -> Result<Vec<Relationship>, String> {
    let db = database(&case_path)?;
    let mut stmt=db.prepare("SELECT source_type,source_value,target_type,target_value,relation,event_count,first_seen,last_seen FROM relationships ORDER BY event_count DESC LIMIT ?1").map_err(|e|e.to_string())?;
    let result = stmt
        .query_map([limit.clamp(1, 1000) as i64], |r| {
            Ok(Relationship {
                source_type: r.get(0)?,
                source_value: r.get(1)?,
                target_type: r.get(2)?,
                target_value: r.get(3)?,
                relation: r.get(4)?,
                event_count: r.get(5)?,
                first_seen: r.get(6)?,
                last_seen: r.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string());
    result
}

fn allowed_source_table(table: &str) -> bool {
    matches!(
        table,
        "evtx_events"
            | "prefetch_data"
            | "mft_records"
            | "journal_events"
            | "registry_values"
            | "amcache_inventory"
            | "shimcache_entries"
            | "srum_records"
            | "recycle_bin_entries"
            | "LNK_Files"
            | "Automatic_JumpLists"
            | "Custom_JumpLists"
    )
}

#[tauri::command]
pub fn event_source_record(case_path: String, event_id: i64) -> Result<SourceRecord, String> {
    let root = Path::new(&case_path)
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let case_db = database(&case_path)?;
    let(database_path,table,row_reference,rowid):(String,String,String,Option<i64>)=case_db.query_row("SELECT source_database,source_table,source_row_id,source_sql_rowid FROM events WHERE id=?1",[event_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_|"Event not found.".to_string())?;
    if !allowed_source_table(&table) {
        return Err("The source table is not approved for inspection.".into());
    }
    let source = Path::new(&database_path)
        .canonicalize()
        .map_err(|_| "The original parser database is unavailable.".to_string())?;
    let processed = root
        .join("PROCESSED")
        .canonicalize()
        .map_err(|_| "The case processed directory is unavailable.".to_string())?;
    if !source.starts_with(processed) {
        return Err("The source database is outside this case.".into());
    }
    let rowid = rowid.ok_or_else(|| {
        "This event predates source-row inspection. Reparse the artifact to enable it.".to_string()
    })?;
    let db = Connection::open_with_flags(&source, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let sql = format!("SELECT * FROM \"{table}\" WHERE rowid=?1");
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let names = stmt
        .column_names()
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>();
    let fields = stmt
        .query_row([rowid], |row| {
            let mut values = BTreeMap::new();
            for (index, name) in names.iter().enumerate() {
                let value = match row.get_ref(index)? {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(v) => v.into(),
                    ValueRef::Real(v) => serde_json::json!(v),
                    ValueRef::Text(v) => String::from_utf8_lossy(v).into_owned().into(),
                    ValueRef::Blob(v) => format!("<{} binary bytes>", v.len()).into(),
                };
                values.insert(name.clone(), value);
            }
            Ok(values)
        })
        .map_err(|e| format!("Could not read the original source row: {e}"))?;
    Ok(SourceRecord {
        event_id,
        database: crate::paths::display(&source),
        table,
        row_reference,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_tables_are_restricted() {
        assert!(allowed_source_table("evtx_events"));
        assert!(!allowed_source_table("sqlite_master; DROP TABLE events"));
    }
}
