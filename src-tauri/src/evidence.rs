use chrono::Utc;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const MAX_RETURNED_ARTIFACTS: usize = 10_000;

#[derive(Serialize)]
pub struct EvidenceInventory {
    pub(crate) files: u64,
    pub(crate) bytes: u64,
    pub(crate) detected: BTreeMap<String, u64>,
    pub(crate) artifacts: Vec<DiscoveredArtifact>,
    pub(crate) truncated: bool,
    pub(crate) unreadable: u64,
}

#[derive(Serialize)]
pub struct DiscoveredArtifact {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) parser: String,
    pub(crate) size: u64,
    pub(crate) confidence: &'static str,
}

#[derive(Serialize)]
pub struct EvidenceImport {
    path: String,
    files: u64,
    bytes: u64,
    manifest: String,
    reused: bool,
}

fn copy_and_hash(source: &Path, destination: &Path) -> Result<(u64, String), String> {
    let input =
        fs::File::open(source).map_err(|e| format!("Could not read {}: {e}", source.display()))?;
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| format!("Could not create {}: {e}", destination.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, input);
    let mut writer = BufWriter::with_capacity(1024 * 1024, output);
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|e| e.to_string())?;
        hash.update(&buffer[..read]);
        bytes += read as u64;
    }
    writer.flush().map_err(|e| e.to_string())?;
    Ok((bytes, format!("{:x}", hash.finalize())))
}

pub(crate) fn import_evidence_blocking(
    case_path: String,
    source_path: String,
) -> Result<EvidenceImport, String> {
    let case = Path::new(case_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    if !case.join("case.json").is_file() {
        return Err("Open a valid VampHunt case first.".into());
    }
    let evidence = case
        .join("EVIDENCE")
        .canonicalize()
        .map_err(|_| "The case EVIDENCE folder is unavailable.".to_string())?;
    let source = Path::new(source_path.trim())
        .canonicalize()
        .map_err(|_| "Select an existing evidence file or directory.".to_string())?;
    if source.starts_with(&evidence) {
        return Ok(EvidenceImport {
            path: crate::paths::display(&source),
            files: 0,
            bytes: 0,
            manifest: String::new(),
            reused: true,
        });
    }
    if source.starts_with(&case) {
        return Err("Only files already inside EVIDENCE may be used from this case.".into());
    }
    let base = source
        .file_name()
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty())
        .unwrap_or("evidence")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    let destination = evidence.join(format!("{}-{}", base, Utc::now().format("%Y%m%d-%H%M%S")));
    fs::create_dir(&destination)
        .map_err(|e| format!("Could not create the evidence import folder: {e}"))?;
    let mut records = Vec::new();
    let mut files = 0u64;
    let mut bytes = 0u64;
    let copy_result = (|| -> Result<(), String> {
        if source.is_file() {
            let name = source
                .file_name()
                .ok_or("The evidence filename is invalid.")?;
            let target = destination.join(name);
            let (size, sha256) = copy_and_hash(&source, &target)?;
            files = 1;
            bytes = size;
            records.push(
                serde_json::json!({"path":name.to_string_lossy(),"bytes":size,"sha256":sha256}),
            );
        } else {
            for entry in WalkDir::new(&source).follow_links(false) {
                let entry = entry.map_err(|e| e.to_string())?;
                let relative = entry
                    .path()
                    .strip_prefix(&source)
                    .map_err(|_| "Evidence path escaped its source.".to_string())?;
                if relative.as_os_str().is_empty() {
                    continue;
                }
                let target: PathBuf = destination.join(relative);
                if entry.file_type().is_symlink() {
                    continue;
                } else if entry.file_type().is_dir() {
                    fs::create_dir_all(&target).map_err(|e| e.to_string())?
                } else if entry.file_type().is_file() {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?
                    }
                    let (size, sha256) = copy_and_hash(entry.path(), &target)?;
                    files += 1;
                    bytes += size;
                    records.push(serde_json::json!({"path":relative.display().to_string(),"bytes":size,"sha256":sha256}));
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = copy_result {
        return Err(format!("Evidence import stopped after {files} files. The incomplete copy remains at {} for review. {error}",destination.display()));
    }
    let manifest = destination.join("evidence-import.json");
    let record = serde_json::json!({"source":source,"destination":destination,"imported_utc":Utc::now().to_rfc3339(),"files":files,"bytes":bytes,"items":records});
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let audit = case.join("AUDIT").join(format!(
        "evidence-import-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    fs::write(
        audit,
        serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(EvidenceImport {
        path: crate::paths::display(&destination),
        files,
        bytes,
        manifest: crate::paths::display(&manifest),
        reused: false,
    })
}

#[tauri::command]
pub async fn import_evidence(
    case_path: String,
    source_path: String,
) -> Result<EvidenceImport, String> {
    tauri::async_runtime::spawn_blocking(move || import_evidence_blocking(case_path, source_path))
        .await
        .map_err(|e| format!("Evidence import stopped unexpectedly: {e}"))?
}

fn read_header(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; 512];
    let count = file.read(&mut buffer)?;
    Ok(buffer[..count].to_vec())
}

fn has_prefix(bytes: &[u8], offset: usize, signature: &[u8]) -> bool {
    bytes.get(offset..offset.saturating_add(signature.len())) == Some(signature)
}

fn artifact_type(path: &Path, header: &[u8]) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    let evtx = has_prefix(header, 0, b"ElfFile\0");
    let registry = has_prefix(header, 0, b"regf");
    let prefetch = has_prefix(header, 4, b"SCCA") || has_prefix(header, 0, b"MAM");
    let mft = has_prefix(header, 0, b"FILE");
    let lnk = has_prefix(header, 0, &[0x4c, 0, 0, 0])
        && has_prefix(
            header,
            4,
            &[
                0x01, 0x14, 0x02, 0x00, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
            ],
        );
    let compound_file = has_prefix(header, 0, &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    let ese = has_prefix(header, 4, &[0xef, 0xcd, 0xab, 0x89]);
    let registry_transaction_log = name.ends_with(".log1")
        || name.ends_with(".log2")
        || name.ends_with(".blf")
        || name.ends_with(".regtrans-ms");

    if evtx {
        Some("Event Logs")
    } else if registry && !registry_transaction_log && name == "amcache.hve" {
        Some("Amcache")
    } else if registry && !registry_transaction_log {
        Some("Registry Hives")
    } else if prefetch {
        Some("Prefetch")
    } else if lnk {
        Some("LNK")
    } else if name.ends_with(".automaticdestinations-ms") && compound_file {
        Some("Automatic Jump Lists")
    } else if name.ends_with(".customdestinations-ms") {
        Some("Custom Jump Lists")
    } else if mft && matches!(name.as_str(), "$mft" | "mft") {
        Some("MFT")
    } else if name == "$j" || name.contains("usnjrnl") {
        Some("USN Journal")
    } else if ese && name == "srudb.dat" {
        Some("SRUM")
    } else if name.starts_with("$i") && header.len() >= 24 {
        Some("Recycle Bin")
    } else if extension.as_deref() == Some("evtx") {
        Some("Possible Event Log")
    } else if extension.as_deref() == Some("pf") {
        Some("Possible Prefetch")
    } else {
        None
    }
}

fn parser_for(kind: &str) -> &'static str {
    match kind {
        "Event Logs" | "Possible Event Log" => "evtx",
        "Registry Hives" => "registry",
        "Amcache" => "amcache",
        "Prefetch" | "Possible Prefetch" => "prefetch",
        "LNK" => "lnk",
        "Automatic Jump Lists" | "Custom Jump Lists" => "jump-lists",
        "MFT" => "mft",
        "USN Journal" => "usn",
        "SRUM" => "srum",
        "Recycle Bin" => "recycle-bin",
        _ => "",
    }
}

fn merge_inventory(mut left: EvidenceInventory, right: EvidenceInventory) -> EvidenceInventory {
    left.files += right.files;
    left.bytes += right.bytes;
    left.unreadable += right.unreadable;
    left.truncated |= right.truncated;
    for (kind, count) in right.detected {
        *left.detected.entry(kind).or_default() += count;
    }
    left.artifacts.extend(right.artifacts);
    if left.artifacts.len() > MAX_RETURNED_ARTIFACTS {
        left.artifacts.truncate(MAX_RETURNED_ARTIFACTS);
        left.truncated = true;
    }
    left
}

fn empty_inventory() -> EvidenceInventory {
    EvidenceInventory {
        files: 0,
        bytes: 0,
        detected: BTreeMap::new(),
        artifacts: Vec::new(),
        truncated: false,
        unreadable: 0,
    }
}

fn inventory_entry(entry: walkdir::DirEntry) -> EvidenceInventory {
    let mut result = empty_inventory();
    if !entry.file_type().is_file() {
        return result;
    }
    result.files = 1;
    let Ok(metadata) = entry.metadata() else {
        result.unreadable = 1;
        return result;
    };
    result.bytes = metadata.len();
    let Ok(header) = read_header(entry.path()) else {
        result.unreadable = 1;
        return result;
    };
    let Some(kind) = artifact_type(entry.path(), &header) else {
        return result;
    };
    *result.detected.entry(kind.to_owned()).or_default() += 1;
    result.artifacts.push(DiscoveredArtifact {
        path: crate::paths::display(entry.path()),
        kind: kind.to_owned(),
        parser: parser_for(kind).to_owned(),
        size: metadata.len(),
        confidence: if kind.starts_with("Possible ") {
            "filename"
        } else {
            "verified"
        },
    });
    if kind == "Registry Hives"
        && entry
            .path()
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("SYSTEM"))
    {
        *result.detected.entry("Shimcache".to_owned()).or_default() += 1;
        result.artifacts.push(DiscoveredArtifact {
            path: crate::paths::display(entry.path()),
            kind: "Shimcache".to_owned(),
            parser: "shimcache-hive".to_owned(),
            size: metadata.len(),
            confidence: "verified",
        });
    }
    result
}

pub(crate) fn inventory_evidence_blocking(case_path: String) -> Result<EvidenceInventory, String> {
    let root = Path::new(&case_path);
    if !root.is_dir() {
        return Err("Select an existing case or collection directory.".into());
    }
    let mut result = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .par_bridge()
        .map(|entry| match entry {
            Ok(entry) => inventory_entry(entry),
            Err(_) => {
                let mut result = empty_inventory();
                result.unreadable = 1;
                result
            }
        })
        .reduce(empty_inventory, merge_inventory);
    result.artifacts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.parser.cmp(&right.parser))
    });
    Ok(result)
}

#[tauri::command]
pub async fn inventory_evidence(case_path: String) -> Result<EvidenceInventory, String> {
    tauri::async_runtime::spawn_blocking(move || inventory_evidence_blocking(case_path))
        .await
        .map_err(|error| format!("Evidence discovery stopped unexpectedly: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn recognizes_core_windows_artifacts() {
        assert_eq!(
            artifact_type(Path::new("renamed.bin"), b"ElfFile\0"),
            Some("Event Logs")
        );
        assert_eq!(
            artifact_type(Path::new("random.dat"), b"regf"),
            Some("Registry Hives")
        );
        assert_eq!(
            artifact_type(Path::new("Amcache.hve"), b"regf"),
            Some("Amcache")
        );
        assert_eq!(artifact_type(Path::new("$MFT"), b"FILE"), Some("MFT"));
        assert_eq!(artifact_type(Path::new("NTUSER.DAT.LOG1"), b"regf"), None);
        assert_eq!(
            artifact_type(Path::new("fake.evtx"), b"not evtx"),
            Some("Possible Event Log")
        );
    }

    #[test]
    fn system_hive_offers_registry_and_shimcache_parsers() {
        let root = std::env::temp_dir().join(format!("vamphunt-system-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("SYSTEM"), b"regf").unwrap();
        let inventory = inventory_evidence_blocking(root.display().to_string()).unwrap();
        assert!(inventory
            .artifacts
            .iter()
            .any(|item| item.parser == "registry"));
        assert!(inventory
            .artifacts
            .iter()
            .any(|item| item.parser == "shimcache-hive"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imports_evidence_into_case_and_records_hash() {
        let base = std::env::temp_dir().join(format!("vamphunt-import-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let case = base.join("case");
        let source = base.join("source");
        fs::create_dir_all(case.join("EVIDENCE")).unwrap();
        fs::create_dir(case.join("AUDIT")).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(case.join("case.json"), "{}").unwrap();
        fs::write(source.join("sample.bin"), b"preserved evidence").unwrap();
        let imported =
            import_evidence_blocking(case.display().to_string(), source.display().to_string())
                .unwrap();
        assert_eq!(imported.files, 1);
        assert!(Path::new(&imported.path).join("sample.bin").is_file());
        let manifest = fs::read_to_string(imported.manifest).unwrap();
        assert!(manifest.contains("sha256"));
        assert!(manifest.contains("sample.bin"));
        fs::remove_dir_all(base).unwrap();
    }
}
