use chrono::Utc;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
pub struct Finding {
    id: i64,
    title: String,
    severity: String,
    status: String,
    notes: String,
    created_utc: String,
    updated_utc: String,
    evidence_count: i64,
}

fn db(case_path: &str) -> Result<Connection, String> {
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
        return Err("Parse evidence before creating a finding.".into());
    }
    let path = path
        .canonicalize()
        .map_err(|_| "The case database is unavailable.".to_string())?;
    if !path.starts_with(directory) {
        return Err("The case database points outside this case.".into());
    }
    let db = Connection::open(path).map_err(|e| e.to_string())?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,notes TEXT NOT NULL,created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL);CREATE TABLE IF NOT EXISTS finding_events(finding_id INTEGER NOT NULL,event_id INTEGER NOT NULL,PRIMARY KEY(finding_id,event_id),FOREIGN KEY(finding_id) REFERENCES findings(id),FOREIGN KEY(event_id) REFERENCES events(id));").map_err(|e|e.to_string())?;
    Ok(db)
}

fn valid_severity(value: &str) -> bool {
    matches!(value, "Low" | "Medium" | "High" | "Critical")
}

#[tauri::command]
pub fn create_finding(
    case_path: String,
    title: String,
    severity: String,
    notes: String,
    event_ids: Vec<i64>,
) -> Result<i64, String> {
    if title.trim().is_empty() {
        return Err("Enter a finding title.".into());
    }
    if !valid_severity(&severity) {
        return Err("Choose a valid severity.".into());
    }
    if event_ids.is_empty() {
        return Err("Select at least one supporting event.".into());
    }
    let mut db = db(&case_path)?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let now = Utc::now().to_rfc3339();
    tx.execute("INSERT INTO findings(title,severity,status,notes,created_utc,updated_utc)VALUES(?1,?2,'Under review',?3,?4,?4)",params![title.trim(),severity,notes.trim(),now]).map_err(|e|e.to_string())?;
    let id = tx.last_insert_rowid();
    let mut linked = 0;
    for event in event_ids {
        linked+=tx.execute("INSERT OR IGNORE INTO finding_events(finding_id,event_id) SELECT ?1,id FROM events WHERE id=?2",params![id,event]).map_err(|e|e.to_string())?
    }
    if linked == 0 {
        return Err("The selected events no longer exist.".into());
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command]
pub fn list_findings(case_path: String) -> Result<Vec<Finding>, String> {
    let db = db(&case_path)?;
    let mut stmt=db.prepare("SELECT f.id,f.title,f.severity,f.status,f.notes,f.created_utc,f.updated_utc,count(fe.event_id) FROM findings f LEFT JOIN finding_events fe ON fe.finding_id=f.id GROUP BY f.id ORDER BY CASE f.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC,f.created_utc DESC").map_err(|e|e.to_string())?;
    let result = stmt
        .query_map([], |r| {
            Ok(Finding {
                id: r.get(0)?,
                title: r.get(1)?,
                severity: r.get(2)?,
                status: r.get(3)?,
                notes: r.get(4)?,
                created_utc: r.get(5)?,
                updated_utc: r.get(6)?,
                evidence_count: r.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string());
    result
}

#[tauri::command]
pub fn update_finding_status(case_path: String, id: i64, status: String) -> Result<(), String> {
    if !matches!(status.as_str(), "Under review" | "Confirmed" | "Closed") {
        return Err("Choose a valid finding status.".into());
    }
    let db = db(&case_path)?;
    let changed = db
        .execute(
            "UPDATE findings SET status=?1,updated_utc=?2 WHERE id=?3",
            params![status, Utc::now().to_rfc3339(), id],
        )
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Finding not found.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn severity_is_restricted() {
        assert!(valid_severity("Critical"));
        assert!(!valid_severity("Urgent"));
    }
}
