use rusqlite::{params, Connection};
use std::{path::Path, time::Duration};

fn schema(db: &Connection) -> Result<(), String> {
    db.execute_batch("PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT, artifact_type TEXT NOT NULL,
        event_type TEXT NOT NULL, host TEXT, user TEXT, path TEXT, process TEXT, summary TEXT NOT NULL,
        parser TEXT NOT NULL, source_database TEXT NOT NULL, source_table TEXT NOT NULL,
        source_row_id TEXT NOT NULL, source_sql_rowid INTEGER, created_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(source_database,source_table,source_row_id,event_type));
      CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
      CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
      CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
      CREATE INDEX IF NOT EXISTS idx_events_process ON events(process);
      CREATE INDEX IF NOT EXISTS idx_events_source_database ON events(source_database);
      CREATE INDEX IF NOT EXISTS idx_events_source_record ON events(source_database,source_table,source_sql_rowid);
      CREATE INDEX IF NOT EXISTS idx_events_host_normalized ON events(lower(host));
      CREATE INDEX IF NOT EXISTS idx_events_user_normalized ON events(lower(user));
      CREATE INDEX IF NOT EXISTS idx_events_path_normalized ON events(lower(path));
      CREATE INDEX IF NOT EXISTS idx_events_process_normalized ON events(lower(process));
      CREATE TABLE IF NOT EXISTS entities(
        id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT NOT NULL, value TEXT NOT NULL,
        normalized_value TEXT NOT NULL, first_seen TEXT, last_seen TEXT, event_count INTEGER NOT NULL DEFAULT 0,
        UNIQUE(entity_type,normalized_value));
      CREATE TABLE IF NOT EXISTS relationships(
        id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL, source_value TEXT NOT NULL,
        target_type TEXT NOT NULL, target_value TEXT NOT NULL, relation TEXT NOT NULL,
        first_seen TEXT, last_seen TEXT, event_count INTEGER NOT NULL,
        UNIQUE(source_type,source_value,target_type,target_value,relation));") .map_err(|e| e.to_string())
}

fn refresh_entities(tx: &rusqlite::Transaction<'_>, source_database: &str) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS affected_entities(
           entity_type TEXT NOT NULL, normalized_value TEXT NOT NULL,
           PRIMARY KEY(entity_type,normalized_value)) WITHOUT ROWID;
         DELETE FROM affected_entities;",
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT OR IGNORE INTO affected_entities
         SELECT 'host',lower(host) FROM events WHERE source_database=?1 AND host IS NOT NULL AND host<>''
         UNION ALL SELECT 'user',lower(user) FROM events WHERE source_database=?1 AND user IS NOT NULL AND user<>''
         UNION ALL SELECT 'path',lower(path) FROM events WHERE source_database=?1 AND path IS NOT NULL AND path<>''
         UNION ALL SELECT 'process',lower(process) FROM events WHERE source_database=?1 AND process IS NOT NULL AND process<>''",
        params![source_database],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "DELETE FROM entities WHERE EXISTS(
           SELECT 1 FROM affected_entities affected
           WHERE affected.entity_type=entities.entity_type
             AND affected.normalized_value=entities.normalized_value)",
        [],
    )
    .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "INSERT INTO entities(entity_type,value,normalized_value,first_seen,last_seen,event_count)
         SELECT values_used.kind,min(values_used.value),values_used.normalized_value,min(values_used.timestamp_utc),max(values_used.timestamp_utc),count(*)
         FROM (
           SELECT 'host' kind,host value,lower(host) normalized_value,timestamp_utc FROM events
             WHERE host IS NOT NULL AND host<>''
           UNION ALL SELECT 'user',user,lower(user),timestamp_utc FROM events WHERE user IS NOT NULL AND user<>''
           UNION ALL SELECT 'path',path,lower(path),timestamp_utc FROM events WHERE path IS NOT NULL AND path<>''
           UNION ALL SELECT 'process',process,lower(process),timestamp_utc FROM events WHERE process IS NOT NULL AND process<>''
         ) values_used
         JOIN affected_entities affected
           ON affected.entity_type=values_used.kind
          AND affected.normalized_value=values_used.normalized_value
         GROUP BY values_used.kind,values_used.normalized_value;",
    )
    .map_err(|error| error.to_string())
}

fn refresh_relationships(
    tx: &rusqlite::Transaction<'_>,
    source_database: &str,
) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS affected_relationships(
           source_type TEXT NOT NULL, source_normalized TEXT NOT NULL,
           target_type TEXT NOT NULL, target_normalized TEXT NOT NULL, relation TEXT NOT NULL,
           PRIMARY KEY(source_type,source_normalized,target_type,target_normalized,relation)) WITHOUT ROWID;
         DELETE FROM affected_relationships;",
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT OR IGNORE INTO affected_relationships
         SELECT 'user',lower(user),'host',lower(host),'logged_on' FROM events
           WHERE source_database=?1 AND user IS NOT NULL AND user<>'' AND host IS NOT NULL AND host<>''
         UNION ALL
         SELECT 'process',lower(process),'path',lower(path),'referenced' FROM events
           WHERE source_database=?1 AND process IS NOT NULL AND process<>'' AND path IS NOT NULL AND path<>''",
        params![source_database],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "DELETE FROM relationships WHERE EXISTS(
           SELECT 1 FROM affected_relationships affected
           WHERE affected.source_type=relationships.source_type
             AND affected.source_normalized=lower(relationships.source_value)
             AND affected.target_type=relationships.target_type
             AND affected.target_normalized=lower(relationships.target_value)
             AND affected.relation=relationships.relation)",
        [],
    )
    .map_err(|error| error.to_string())?;
    tx.execute_batch(
        "INSERT INTO relationships(source_type,source_value,target_type,target_value,relation,first_seen,last_seen,event_count)
         SELECT 'user',min(user),'host',min(host),'logged_on',min(timestamp_utc),max(timestamp_utc),count(*)
         FROM events JOIN affected_relationships affected
           ON affected.source_type='user' AND affected.source_normalized=lower(events.user)
          AND affected.target_type='host' AND affected.target_normalized=lower(events.host)
          AND affected.relation='logged_on'
         WHERE user IS NOT NULL AND user<>'' AND host IS NOT NULL AND host<>''
         GROUP BY lower(user),lower(host)
         UNION ALL
         SELECT 'process',min(process),'path',min(path),'referenced',min(timestamp_utc),max(timestamp_utc),count(*)
         FROM events JOIN affected_relationships affected
           ON affected.source_type='process' AND affected.source_normalized=lower(events.process)
          AND affected.target_type='path' AND affected.target_normalized=lower(events.path)
          AND affected.relation='referenced'
         WHERE process IS NOT NULL AND process<>'' AND path IS NOT NULL AND path<>''
         GROUP BY lower(process),lower(path);",
    )
    .map_err(|error| error.to_string())
}

fn statements(parser: &str) -> Option<&'static [&'static str]> {
    match parser {
        "evtx" => Some(&["SELECT EventTimestampUTC,'evtx','windows_event',Computer,UserID,NULL,NULL,coalesce(Provider,'Unknown')||' event '||coalesce(EventID,'?'),'evtx_events',SourceFile||':'||RecordID,rowid FROM source.evtx_events"]),
        "prefetch" => Some(&["SELECT last_executed,'prefetch','program_execution',NULL,NULL,filename,executable_name,coalesce(executable_name,filename)||' executed','prefetch_data',filename||':'||hash,rowid FROM source.prefetch_data"]),
        "mft" => Some(&["SELECT modified_time,'mft','file_modified',NULL,NULL,volume_letter||'\\'||file_name,NULL,file_name||' modified','mft_records',volume_letter||':'||record_number,rowid FROM source.mft_records"]),
        "usn" => Some(&["SELECT timestamp,'usn','file_change',NULL,NULL,volume_letter||'\\'||filename,NULL,coalesce(reason,'File change')||': '||filename,'journal_events',volume_letter||':'||usn,rowid FROM source.journal_events"]),
        "registry" => Some(&["SELECT NULL,'registry','registry_value',NULL,NULL,KeyPath,NULL,Hive||'\\'||KeyPath||'\\'||ValueName,'registry_values',Hive||':'||KeyPath||':'||ValueName,rowid FROM source.registry_values"]),
        "amcache" => Some(&["SELECT NULL,'amcache','application_inventory',NULL,NULL,KeyPath,NULL,InventoryType||': '||coalesce(ValueData,ValueName),'amcache_inventory',rowid,rowid FROM source.amcache_inventory"]),
        "shimcache" | "shimcache-hive" => Some(&["SELECT last_modified,'shimcache','application_observed',NULL,NULL,path,filename,filename||' observed in Shimcache','shimcache_entries',id,rowid FROM source.shimcache_entries"]),
        "srum" => Some(&["SELECT NULL,'srum','resource_usage',NULL,NULL,NULL,NULL,'SRUM '||TableName||' record','srum_records',TableName||':'||RecordIndex,rowid FROM source.srum_records"]),
        "recycle-bin" => Some(&["SELECT deletion_time,'recycle_bin','file_deleted',NULL,user_sid,original_path,NULL,original_filename||' deleted','recycle_bin_entries',rowid,rowid FROM source.recycle_bin_entries"]),
        "lnk" => Some(&["SELECT Time_Access,'lnk','shortcut_accessed',Tracker_NetBIOS,NULL,Local_Path,NULL,Source_Name||' shortcut','LNK_Files',Source_Path,rowid FROM source.LNK_Files"]),
        "jump-lists" => Some(&[
            "SELECT Time_Access,'jump_list','recent_item',Tracker_NetBIOS,NULL,Local_Path,NULL,Source_Name||' recent item','Automatic_JumpLists',Source_Path||':'||entry_number,rowid FROM source.Automatic_JumpLists",
            "SELECT NULL,'jump_list','recent_item',Tracker_NetBIOS,NULL,Local_Path,NULL,Source_Name||' custom destination','Custom_JumpLists',entry_id,rowid FROM source.Custom_JumpLists"
        ]),
        _ => None,
    }
}

pub fn normalize(parser: &str, parser_db: &Path, case_db: &Path) -> Result<usize, String> {
    let queries =
        statements(parser).ok_or_else(|| format!("No normalizer is registered for {parser}"))?;
    let mut db = Connection::open(case_db).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    db.execute_batch(
        "PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-65536;",
    )
    .map_err(|error| error.to_string())?;
    schema(&db)?;
    let has_source_rowid = db
        .prepare("PRAGMA table_info(events)")
        .map_err(|e| e.to_string())?
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .any(|name| name == "source_sql_rowid");
    if !has_source_rowid {
        db.execute("ALTER TABLE events ADD COLUMN source_sql_rowid INTEGER", [])
            .map_err(|e| e.to_string())?;
    }
    let source_database = crate::paths::display(parser_db);
    db.execute("ATTACH DATABASE ?1 AS source", params![source_database])
        .map_err(|e| e.to_string())?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let mut inserted = 0;
    for query in queries {
        let sql = format!("WITH normalized(timestamp_utc,artifact_type,event_type,host,user,path,process,summary,source_table,source_row_id,source_sql_rowid) AS ({query}) INSERT OR IGNORE INTO events(timestamp_utc,artifact_type,event_type,host,user,path,process,summary,parser,source_database,source_table,source_row_id,source_sql_rowid) SELECT timestamp_utc,artifact_type,event_type,host,user,path,process,summary,?1,?2,source_table,CAST(source_row_id AS TEXT),source_sql_rowid FROM normalized");
        inserted += tx
            .execute(&sql, params![parser, source_database])
            .map_err(|e| format!("Could not normalize {parser}: {e}"))?;
    }
    refresh_entities(&tx, &source_database)?;
    refresh_relationships(&tx, &source_database)?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn normalizes_event_log_and_entities() {
        let root = std::env::temp_dir().join(format!("vamphunt-normalize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("PROCESSED/evtx")).unwrap();
        fs::create_dir(root.join("DATABASE")).unwrap();
        let source_path = root.join("PROCESSED/evtx/evtx.db");
        let case_path = root.join("DATABASE/vamphunt.db");
        let source = Connection::open(&source_path).unwrap();
        source.execute_batch("CREATE TABLE evtx_events(SourceFile TEXT,RecordID INTEGER,EventID INTEGER,Provider TEXT,Channel TEXT,Computer TEXT,UserID TEXT,Level TEXT,Task TEXT,Opcode TEXT,Keywords TEXT,EventTimestampUTC TEXT,EventData TEXT,RawJSON TEXT); INSERT INTO evtx_events VALUES('Security.evtx',42,4624,'Microsoft-Windows-Security-Auditing','Security','WS-042','S-1-5-21','0',NULL,NULL,NULL,'2026-09-02T10:00:00Z',NULL,'{}');").unwrap();
        drop(source);
        assert_eq!(normalize("evtx", &source_path, &case_path).unwrap(), 1);
        let case = Connection::open(&case_path).unwrap();
        let event: (String, String) = case
            .query_row("SELECT host,event_type FROM events", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(event, ("WS-042".into(), "windows_event".into()));
        let entities: i64 = case
            .query_row("SELECT count(*) FROM entities", [], |r| r.get(0))
            .unwrap();
        assert_eq!(entities, 2);
        let relationships: i64 = case
            .query_row("SELECT count(*) FROM relationships", [], |r| r.get(0))
            .unwrap();
        assert_eq!(relationships, 1);
        drop(case);

        let second_source_path = root.join("PROCESSED/evtx/evtx-second.db");
        let second_source = Connection::open(&second_source_path).unwrap();
        second_source.execute_batch("CREATE TABLE evtx_events(SourceFile TEXT,RecordID INTEGER,EventID INTEGER,Provider TEXT,Channel TEXT,Computer TEXT,UserID TEXT,Level TEXT,Task TEXT,Opcode TEXT,Keywords TEXT,EventTimestampUTC TEXT,EventData TEXT,RawJSON TEXT); INSERT INTO evtx_events VALUES('Security.evtx',43,4624,'Microsoft-Windows-Security-Auditing','Security','ws-042','s-1-5-21','0',NULL,NULL,NULL,'2026-09-02T11:00:00Z',NULL,'{}');").unwrap();
        drop(second_source);
        assert_eq!(
            normalize("evtx", &second_source_path, &case_path).unwrap(),
            1
        );
        assert_eq!(
            normalize("evtx", &second_source_path, &case_path).unwrap(),
            0
        );
        let case = Connection::open(&case_path).unwrap();
        let entity_events: i64 = case
            .query_row(
                "SELECT event_count FROM entities WHERE entity_type='host' AND normalized_value='ws-042'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(entity_events, 2);
        let relationship_events: i64 = case
            .query_row(
                "SELECT event_count FROM relationships WHERE relation='logged_on'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relationship_events, 2);
        drop(case);
        let source =
            crate::investigation::event_source_record(root.display().to_string(), 1).unwrap();
        assert_eq!(source.table, "evtx_events");
        assert_eq!(
            source.fields.get("Provider").unwrap(),
            "Microsoft-Windows-Security-Auditing"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
