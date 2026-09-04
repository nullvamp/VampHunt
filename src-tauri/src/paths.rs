use rusqlite::{Connection, OpenFlags};
use std::{
    fs,
    path::{Path, PathBuf},
};

const CASE_DATABASE_NAME: &str = "vamphunt.db";

pub(crate) fn readable(value: &str) -> String {
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else if let Some(path) = value.strip_prefix(r"\\?\") {
        path.to_owned()
    } else {
        value.to_owned()
    }
}

pub(crate) fn display(path: &Path) -> String {
    readable(&path.to_string_lossy())
}

fn contains_case_schema(path: &Path) -> bool {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|database| {
            database.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'",
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .is_ok_and(|count| count == 1)
}

pub(crate) fn case_database(root: &Path) -> Result<PathBuf, String> {
    let root = root
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let directory = root
        .join("DATABASE")
        .canonicalize()
        .map_err(|_| "The case database directory is unavailable.".to_string())?;
    if !directory.starts_with(&root) {
        return Err("The case database directory points outside this case.".into());
    }

    let preferred = directory.join(CASE_DATABASE_NAME);
    if preferred.is_file() {
        return Ok(preferred);
    }

    let mut compatible = Vec::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("Could not inspect the case database directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Could not inspect a case database: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("Could not inspect a case database: {error}"))?;
        let path = entry.path();
        if file_type.is_file()
            && !file_type.is_symlink()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("db"))
            && contains_case_schema(&path)
        {
            compatible.push(path);
        }
    }
    if compatible.len() > 1 {
        return Err("More than one investigation database was found in this case.".into());
    }
    let Some(existing) = compatible.pop() else {
        return Ok(preferred);
    };
    match fs::rename(&existing, &preferred) {
        Ok(()) => Ok(preferred),
        Err(_) => Ok(existing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_windows_verbatim_prefixes() {
        assert_eq!(readable(r"\\?\C:\DFIR\Cases"), r"C:\DFIR\Cases");
        assert_eq!(
            readable(r"\\?\UNC\server\share\case"),
            r"\\server\share\case"
        );
        assert_eq!(readable(r"C:\DFIR\Cases"), r"C:\DFIR\Cases");
    }

    #[test]
    fn migrates_a_compatible_case_database_to_the_current_name() {
        let root = std::env::temp_dir().join(format!(
            "vamphunt-database-migration-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("DATABASE")).unwrap();
        let original = root.join("DATABASE/previous.db");
        let database = Connection::open(&original).unwrap();
        database
            .execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(database);

        let migrated = case_database(&root).unwrap();

        assert_eq!(migrated.file_name().unwrap(), CASE_DATABASE_NAME);
        assert!(migrated.is_file());
        assert!(!original.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
