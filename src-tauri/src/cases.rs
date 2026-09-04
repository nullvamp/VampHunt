use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct CaseSummary {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) examiner: String,
    pub(crate) path: String,
    pub(crate) created_utc: String,
}

fn slug(value: &str) -> String {
    let result = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    result.chars().take(40).collect()
}

#[tauri::command]
pub fn create_case(
    base_path: String,
    name: String,
    examiner: String,
) -> Result<CaseSummary, String> {
    let base = Path::new(base_path.trim());
    if base_path.trim().is_empty() {
        return Err("Enter a cases directory.".into());
    }
    if !base.exists() {
        fs::create_dir_all(base)
            .map_err(|error| format!("Could not create the cases directory: {error}"))?;
    }
    if !base.is_dir() {
        return Err("The cases path is not a directory.".into());
    }
    if name.trim().is_empty() {
        return Err("Enter a case name.".into());
    }
    if examiner.trim().is_empty() {
        return Err("Enter the examiner name.".into());
    }
    let now = Utc::now();
    let id = format!("CASE-{}-{}", now.format("%Y%m%d-%H%M%S"), slug(&name));
    let root: PathBuf = base.join(&id);
    fs::create_dir(&root).map_err(|e| format!("Could not create case: {e}"))?;
    for folder in [
        "EVIDENCE",
        "OUTPUT",
        "PROCESSED",
        "DATABASE",
        "REPORTS",
        "AUDIT",
    ] {
        fs::create_dir(root.join(folder)).map_err(|e| format!("Could not create {folder}: {e}"))?;
    }
    let summary = CaseSummary {
        id,
        name: name.trim().to_owned(),
        examiner: examiner.trim().to_owned(),
        path: crate::paths::display(&root),
        created_utc: now.to_rfc3339(),
    };
    fs::write(
        root.join("case.json"),
        serde_json::to_vec_pretty(&summary).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Could not write case record: {e}"))?;
    Ok(summary)
}

#[tauri::command]
pub fn open_case(case_path: String) -> Result<CaseSummary, String> {
    let path = Path::new(case_path.trim()).join("case.json");
    let data = fs::read(path).map_err(|_| "This folder is not a VampHunt case.".to_string())?;
    let mut summary: CaseSummary =
        serde_json::from_slice(&data).map_err(|e| format!("The case record is invalid: {e}"))?;
    summary.path = crate::paths::readable(&summary.path);
    Ok(summary)
}

fn delete_case_blocking(case_path: String, expected_id: String) -> Result<CaseSummary, String> {
    let requested = PathBuf::from(case_path.trim());
    if case_path.trim().is_empty() {
        return Err("The case path is empty.".into());
    }

    let metadata = fs::symlink_metadata(&requested)
        .map_err(|_| "The case folder no longer exists.".to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("The selected path is not a regular case folder.".into());
    }

    let root = fs::canonicalize(&requested)
        .map_err(|error| format!("Could not verify the case path: {error}"))?;
    if root.parent().is_none() || root.file_name().is_none() {
        return Err("Refusing to delete a drive or filesystem root.".into());
    }

    let record_path = root.join("case.json");
    let record_data =
        fs::read(&record_path).map_err(|_| "This folder is not a VampHunt case.".to_string())?;
    let summary: CaseSummary = serde_json::from_slice(&record_data)
        .map_err(|error| format!("The case record is invalid: {error}"))?;

    if summary.id != expected_id {
        return Err("The selected case does not match the delete request.".into());
    }
    if !summary.id.starts_with("CASE-")
        || !root
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(&summary.id))
    {
        return Err("The case folder name does not match its case record.".into());
    }

    for required in ["EVIDENCE", "OUTPUT", "DATABASE", "AUDIT"] {
        if !root.join(required).is_dir() {
            return Err(format!(
                "Refusing to delete this folder because {required} is missing."
            ));
        }
    }

    fs::remove_dir_all(&root).map_err(|error| format!("Could not delete the case: {error}"))?;
    Ok(summary)
}

#[tauri::command]
pub async fn delete_case(case_path: String, expected_id: String) -> Result<CaseSummary, String> {
    tauri::async_runtime::spawn_blocking(move || delete_case_blocking(case_path, expected_id))
        .await
        .map_err(|error| format!("Case deletion stopped unexpectedly: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creates_safe_slug() {
        assert_eq!(slug("Incident: WS 42 / Admin"), "INCIDENT-WS-42-ADMIN");
    }
    #[test]
    fn creates_the_case_structure() {
        let base = std::env::temp_dir().join(format!("vamphunt-case-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        let case = create_case(
            base.display().to_string(),
            "Test case".into(),
            "Examiner".into(),
        )
        .unwrap();
        let root = Path::new(&case.path);
        for folder in [
            "EVIDENCE",
            "OUTPUT",
            "PROCESSED",
            "DATABASE",
            "REPORTS",
            "AUDIT",
        ] {
            assert!(root.join(folder).is_dir());
        }
        assert!(root.join("case.json").is_file());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn creates_a_missing_cases_directory() {
        let root = std::env::temp_dir().join(format!("vamphunt-new-root-{}", std::process::id()));
        let cases = root.join("nested/Cases");
        let _ = fs::remove_dir_all(&root);
        let case = create_case(
            cases.display().to_string(),
            "New directory".into(),
            "Examiner".into(),
        )
        .unwrap();
        assert!(cases.is_dir());
        assert!(Path::new(&case.path).join("case.json").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deletes_only_the_confirmed_case() {
        let base = std::env::temp_dir().join(format!(
            "vamphunt-delete-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        fs::create_dir_all(&base).unwrap();
        let case = create_case(
            base.display().to_string(),
            "Delete me".into(),
            "Examiner".into(),
        )
        .unwrap();
        let case_root = PathBuf::from(&case.path);

        let deleted = delete_case_blocking(case.path.clone(), case.id.clone()).unwrap();

        assert_eq!(deleted.id, case.id);
        assert!(!case_root.exists());
        assert!(base.is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rejects_a_delete_when_the_case_id_does_not_match() {
        let base = std::env::temp_dir().join(format!(
            "vamphunt-delete-mismatch-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        fs::create_dir_all(&base).unwrap();
        let case = create_case(
            base.display().to_string(),
            "Keep me".into(),
            "Examiner".into(),
        )
        .unwrap();

        let error = delete_case_blocking(case.path.clone(), "CASE-WRONG".into()).unwrap_err();

        assert!(error.contains("does not match"));
        assert!(Path::new(&case.path).is_dir());
        fs::remove_dir_all(base).unwrap();
    }
}
