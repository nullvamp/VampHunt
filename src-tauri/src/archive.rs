use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use walkdir::WalkDir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

const MANIFEST_NAME: &str = "vamphunt-manifest.json";
const MAX_ARCHIVE_FILES: usize = 1_000_000;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
struct ArchiveEntry {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
struct ArchiveManifest {
    format: String,
    version: u32,
    case_id: String,
    created_utc: String,
    files: Vec<ArchiveEntry>,
}

#[derive(Deserialize, Serialize)]
pub struct CaseRecord {
    id: String,
    name: String,
    examiner: String,
    path: String,
    created_utc: String,
}

#[derive(Serialize)]
pub struct ArchiveResult {
    path: String,
    files: usize,
    bytes: u64,
    sha256: String,
}

fn safe_case_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn archive_name(path: &Path, root: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "A case file escaped the case directory.".to_string())?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("A case file has an unsafe path.".into());
    }
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn read_case(root: &Path) -> Result<CaseRecord, String> {
    serde_json::from_slice(
        &fs::read(root.join("case.json"))
            .map_err(|_| "This folder is not a VampHunt case.".to_string())?,
    )
    .map_err(|error| format!("The case record is invalid: {error}"))
}

fn export_case_blocking(case_path: String, destination: String) -> Result<ArchiveResult, String> {
    let root = Path::new(case_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let case = read_case(&root)?;
    if !safe_case_id(&case.id) {
        return Err("The case identifier is unsafe.".into());
    }
    let destination = Path::new(destination.trim())
        .canonicalize()
        .map_err(|_| "Select an existing backup directory.".to_string())?;
    if !destination.is_dir() {
        return Err("Select an existing backup directory.".into());
    }
    if destination.starts_with(&root) {
        return Err("Store the backup outside the case directory.".into());
    }
    let output = destination.join(format!(
        "{}-{}.vhcase",
        case.id,
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let output_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .map_err(|error| format!("Could not create the backup: {error}"))?;
    let result = (|| {
        let mut zip = ZipWriter::new(output_file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .large_file(true);
        let mut manifest = ArchiveManifest {
            format: "VampHunt case archive".into(),
            version: 1,
            case_id: case.id,
            created_utc: Utc::now().to_rfc3339(),
            files: Vec::new(),
        };
        for item in WalkDir::new(&root).follow_links(false) {
            let item = item.map_err(|error| format!("Could not read the case: {error}"))?;
            if item.file_type().is_symlink() {
                return Err("Case backups do not include symbolic links.".into());
            }
            if !item.file_type().is_file() {
                continue;
            }
            if manifest.files.len() >= MAX_ARCHIVE_FILES {
                return Err("The case contains too many files to back up safely.".into());
            }
            let name = archive_name(item.path(), &root)?;
            if name == MANIFEST_NAME {
                return Err("The case contains a reserved archive filename.".into());
            }
            let size = item
                .metadata()
                .map_err(|error| format!("Could not read case metadata: {error}"))?
                .len();
            zip.start_file(&name, options)
                .map_err(|error| format!("Could not add {name}: {error}"))?;
            let mut source = fs::File::open(item.path())
                .map_err(|error| format!("Could not read {name}: {error}"))?;
            let mut digest = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = vec![0_u8; 1024 * 1024];
            loop {
                let count = source
                    .read(&mut buffer)
                    .map_err(|error| format!("Could not read {name}: {error}"))?;
                if count == 0 {
                    break;
                }
                zip.write_all(&buffer[..count])
                    .map_err(|error| format!("Could not write {name}: {error}"))?;
                digest.update(&buffer[..count]);
                copied += count as u64;
            }
            if copied != size {
                return Err(format!(
                    "{name} changed while the backup was being created."
                ));
            }
            manifest.files.push(ArchiveEntry {
                path: name,
                size,
                sha256: format!("{:x}", digest.finalize()),
            });
        }
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
        zip.start_file(MANIFEST_NAME, options)
            .map_err(|error| format!("Could not add the archive manifest: {error}"))?;
        zip.write_all(&manifest_bytes)
            .map_err(|error| format!("Could not write the archive manifest: {error}"))?;
        zip.finish()
            .map_err(|error| format!("Could not finish the backup: {error}"))?;
        let bytes = manifest.files.iter().map(|entry| entry.size).sum();
        Ok(ArchiveResult {
            path: crate::paths::display(&output),
            files: manifest.files.len(),
            bytes,
            sha256: sha256_file(&output)?,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&output);
    }
    result
}

fn safe_archive_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if name.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("The archive contains an unsafe path: {name}"));
    }
    Ok(path.to_path_buf())
}

fn read_archive_manifest(
    zip: &mut ZipArchive<fs::File>,
) -> Result<(String, ArchiveManifest), String> {
    let mut candidate = None;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| format!("Could not inspect the backup: {error}"))?;
        let name = entry.name().to_owned();
        if entry.is_dir()
            || name.contains('/')
            || name.contains('\\')
            || !name.ends_with("-manifest.json")
        {
            continue;
        }
        if entry.size() > 64 * 1024 * 1024 {
            return Err("The backup manifest is too large.".into());
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Could not read the backup manifest: {error}"))?;
        let Ok(manifest) = serde_json::from_slice::<ArchiveManifest>(&bytes) else {
            continue;
        };
        if manifest.version != 1 || !manifest.format.ends_with(" case archive") {
            continue;
        }
        if candidate.replace((name, manifest)).is_some() {
            return Err("The backup contains more than one valid manifest.".into());
        }
    }
    candidate.ok_or_else(|| "The backup manifest is missing.".to_string())
}

fn import_case_blocking(archive_path: String, cases_root: String) -> Result<CaseRecord, String> {
    let archive_path = Path::new(archive_path.trim())
        .canonicalize()
        .map_err(|_| "Select an existing .vhcase backup.".to_string())?;
    let cases_root = Path::new(cases_root.trim())
        .canonicalize()
        .map_err(|_| "Select an existing cases directory.".to_string())?;
    if !archive_path.is_file() || !cases_root.is_dir() {
        return Err("Select a valid backup and cases directory.".into());
    }
    let archive_hash = sha256_file(&archive_path)?;
    let file = fs::File::open(&archive_path).map_err(|error| error.to_string())?;
    let mut zip = ZipArchive::new(file).map_err(|error| format!("Invalid case backup: {error}"))?;
    if zip.len() > MAX_ARCHIVE_FILES + 1 {
        return Err("The archive contains too many files.".into());
    }
    let (manifest_name, manifest) = read_archive_manifest(&mut zip)?;
    if !safe_case_id(&manifest.case_id) {
        return Err("The backup contains an unsafe case identifier.".into());
    }
    let mut expected = BTreeMap::new();
    let mut total = 0_u64;
    for entry in &manifest.files {
        safe_archive_path(&entry.path)?;
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| "The backup size is invalid.".to_string())?;
        if total > MAX_ARCHIVE_BYTES || expected.insert(entry.path.clone(), entry).is_some() {
            return Err("The backup manifest is unsafe.".into());
        }
    }
    let target = cases_root.join(&manifest.case_id);
    if target.exists() {
        return Err("A case with this identifier already exists.".into());
    }
    let temporary = cases_root.join(format!(
        ".vamphunt-import-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis()
    ));
    fs::create_dir(&temporary).map_err(|error| format!("Could not start the import: {error}"))?;
    let result = (|| {
        let mut seen = HashSet::new();
        for index in 0..zip.len() {
            let mut entry = zip
                .by_index(index)
                .map_err(|error| format!("Could not read the backup: {error}"))?;
            let name = entry.name().to_owned();
            if name == manifest_name || entry.is_dir() {
                continue;
            }
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err("The backup contains a symbolic link.".into());
            }
            let relative = safe_archive_path(&name)?;
            let expected_entry = expected
                .get(&name)
                .ok_or_else(|| format!("The backup contains an unlisted file: {name}"))?;
            if entry.size() != expected_entry.size || !seen.insert(name.clone()) {
                return Err(format!(
                    "The backup entry does not match its manifest: {name}"
                ));
            }
            let output = temporary.join(relative);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("Could not create an import directory: {error}"))?;
            }
            let mut destination = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|error| format!("Could not create {name}: {error}"))?;
            let mut digest = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = vec![0_u8; 1024 * 1024];
            loop {
                let count = entry
                    .read(&mut buffer)
                    .map_err(|error| format!("Could not extract {name}: {error}"))?;
                if count == 0 {
                    break;
                }
                destination
                    .write_all(&buffer[..count])
                    .map_err(|error| format!("Could not write {name}: {error}"))?;
                digest.update(&buffer[..count]);
                copied += count as u64;
                if copied > expected_entry.size {
                    return Err(format!(
                        "The extracted file is larger than expected: {name}"
                    ));
                }
            }
            if copied != expected_entry.size
                || format!("{:x}", digest.finalize()) != expected_entry.sha256
            {
                return Err(format!("Backup verification failed for {name}"));
            }
        }
        if seen.len() != expected.len() {
            return Err("The backup is incomplete.".into());
        }
        let mut case = read_case(&temporary)?;
        if case.id != manifest.case_id {
            return Err("The case record does not match the backup manifest.".into());
        }
        case.path = crate::paths::display(&target);
        fs::write(
            temporary.join("case.json"),
            serde_json::to_vec_pretty(&case).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("Could not update the imported case: {error}"))?;
        fs::create_dir_all(temporary.join("AUDIT"))
            .map_err(|error| format!("Could not create the audit directory: {error}"))?;
        fs::write(
            temporary.join("AUDIT").join(format!(
                "import-{}.json",
                Utc::now().format("%Y%m%d-%H%M%S")
            )),
            serde_json::to_vec_pretty(&serde_json::json!({
                "archive": archive_path,
                "archive_sha256": archive_hash,
                "imported_utc": Utc::now().to_rfc3339(),
                "verified_files": seen.len()
            }))
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("Could not write the import audit record: {error}"))?;
        fs::rename(&temporary, &target)
            .map_err(|error| format!("Could not finish the case import: {error}"))?;
        Ok(case)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

#[tauri::command]
pub async fn export_case(case_path: String, destination: String) -> Result<ArchiveResult, String> {
    tauri::async_runtime::spawn_blocking(move || export_case_blocking(case_path, destination))
        .await
        .map_err(|error| format!("Case backup stopped unexpectedly: {error}"))?
}

#[tauri::command]
pub async fn import_case(archive_path: String, cases_root: String) -> Result<CaseRecord, String> {
    tauri::async_runtime::spawn_blocking(move || import_case_blocking(archive_path, cases_root))
        .await
        .map_err(|error| format!("Case import stopped unexpectedly: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_and_imports_a_verified_case() {
        let root = std::env::temp_dir().join(format!(
            "vamphunt-archive-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        let cases = root.join("cases");
        let backups = root.join("backups");
        let restored = root.join("restored");
        fs::create_dir_all(&cases).unwrap();
        fs::create_dir(&backups).unwrap();
        fs::create_dir(&restored).unwrap();
        let case = crate::cases::create_case(
            cases.display().to_string(),
            "Archive test".into(),
            "Examiner".into(),
        )
        .unwrap();
        fs::write(
            Path::new(&case.path).join("EVIDENCE/sample.bin"),
            b"evidence",
        )
        .unwrap();
        let archive = export_case_blocking(case.path, backups.display().to_string()).unwrap();
        assert_eq!(archive.sha256.len(), 64);
        let imported = import_case_blocking(archive.path, restored.display().to_string()).unwrap();
        assert_eq!(imported.id, case.id);
        assert_eq!(
            fs::read(Path::new(&imported.path).join("EVIDENCE/sample.bin")).unwrap(),
            b"evidence"
        );
        assert!(Path::new(&imported.path).join("AUDIT").is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_paths_that_escape_the_import_directory() {
        assert!(safe_archive_path("../outside.txt").is_err());
        assert!(safe_archive_path("C:/outside.txt").is_err());
        assert!(safe_archive_path("safe/folder/file.txt").is_ok());
    }
}
