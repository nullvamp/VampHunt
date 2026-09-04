use chrono::Utc;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};
use walkdir::WalkDir;

const APPROVED_VAMPARSER_SHA256: &str =
    "004251b7e5423fae0d4674f909ff5ae7cd723639c325a8248f9580d16a35cab9";

static ACTIVE_JOBS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static CANCELLATIONS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn active_jobs() -> &'static Mutex<HashSet<String>> {
    ACTIVE_JOBS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn cancellations() -> &'static Mutex<HashSet<String>> {
    CANCELLATIONS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Serialize)]
pub struct ParserJobResult {
    pub(crate) job_id: String,
    pub(crate) parser: String,
    pub(crate) status: String,
    pub(crate) output: String,
    pub(crate) audit: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) normalized: usize,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ParserJobRecord {
    job_id: String,
    parser: String,
    status: String,
    phase: String,
    input: String,
    output: Option<String>,
    started_utc: String,
    updated_utc: String,
    completed_utc: Option<String>,
    normalized_events: usize,
    message: String,
}

#[derive(Serialize)]
struct SourceManifestEntry {
    path: String,
    size: u64,
    sha256: String,
}

fn allowed_parser(id: &str) -> bool {
    matches!(
        id,
        "evtx"
            | "registry"
            | "amcache"
            | "shimcache"
            | "shimcache-hive"
            | "prefetch"
            | "mft"
            | "usn"
            | "srum"
            | "recycle-bin"
            | "lnk"
            | "jump-lists"
    )
}

fn valid_job_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

#[cfg(test)]
fn generated_job_id() -> String {
    format!(
        "job-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S%3f"),
        std::process::id()
    )
}

fn canonical_descendant(child: &Path, parent: &Path, label: &str) -> Result<PathBuf, String> {
    let child = child
        .canonicalize()
        .map_err(|e| format!("Invalid {label} path: {e}"))?;
    let parent = parent
        .canonicalize()
        .map_err(|e| format!("Invalid parent path: {e}"))?;
    if !child.starts_with(&parent) {
        return Err(format!("The {label} path is outside its allowed folder."));
    }
    Ok(child)
}

fn case_subdir(case: &Path, name: &str) -> Result<PathBuf, String> {
    let expected = case.join(name);
    fs::create_dir_all(&expected).map_err(|e| format!("Could not create {name}: {e}"))?;
    canonical_descendant(&expected, case, name)
}

fn job_directory(case: &Path) -> Result<PathBuf, String> {
    let audit = case_subdir(case, "AUDIT")?;
    let jobs = audit.join("jobs");
    fs::create_dir_all(&jobs).map_err(|e| format!("Could not create job history: {e}"))?;
    canonical_descendant(&jobs, &audit, "job history")
}

fn job_path(directory: &Path, job_id: &str) -> Result<PathBuf, String> {
    if !valid_job_id(job_id) {
        return Err("The parser job identifier is invalid.".into());
    }
    Ok(directory.join(format!("{job_id}.json")))
}

fn save_job(directory: &Path, record: &ParserJobRecord) -> Result<(), String> {
    let path = job_path(directory, &record.job_id)?;
    fs::write(
        path,
        serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Could not save parser job state: {e}"))
}

fn set_job_state(
    directory: &Path,
    record: &mut ParserJobRecord,
    status: &str,
    phase: &str,
    message: impl Into<String>,
) -> Result<(), String> {
    record.status = status.to_owned();
    record.phase = phase.to_owned();
    record.message = message.into();
    record.updated_utc = Utc::now().to_rfc3339();
    if matches!(
        status,
        "completed" | "failed" | "normalization_failed" | "cancelled" | "interrupted"
    ) {
        record.completed_utc = Some(record.updated_utc.clone());
    }
    save_job(directory, record)
}

fn sha256(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read])
    }
    Some(format!("{:x}", hash.finalize()))
}

fn parser_source_file(parser: &str, path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    match parser {
        "evtx" => extension.as_deref() == Some("evtx"),
        "prefetch" => extension.as_deref() == Some("pf"),
        "lnk" => extension.as_deref() == Some("lnk"),
        "jump-lists" => {
            name.ends_with(".automaticdestinations-ms") || name.ends_with(".customdestinations-ms")
        }
        "recycle-bin" => name.starts_with("$i"),
        _ => false,
    }
}

fn cancellation_requested(job_id: &str) -> bool {
    cancellations()
        .lock()
        .is_ok_and(|jobs| jobs.contains(job_id))
}

fn join_output_reader(
    reader: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    stream_name: &str,
) -> Result<Vec<u8>, String> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    reader
        .join()
        .map_err(|_| format!("The Vamparser {stream_name} reader stopped unexpectedly"))?
        .map_err(|error| format!("Could not read Vamparser {stream_name}: {error}"))
}

fn directory_manifest(
    root: &Path,
    parser: &str,
    job_id: &str,
) -> Result<Vec<SourceManifestEntry>, String> {
    let mut paths = Vec::new();
    for candidate in WalkDir::new(root).follow_links(false) {
        if cancellation_requested(job_id) {
            return Err("Parser job cancelled.".into());
        }
        let candidate = candidate.map_err(|e| format!("Could not inventory parser input: {e}"))?;
        if !candidate.file_type().is_file() || !parser_source_file(parser, candidate.path()) {
            continue;
        }
        paths.push(candidate.into_path());
    }
    let mut entries = paths
        .par_iter()
        .map(|path| {
            if cancellation_requested(job_id) {
                return Err("Parser job cancelled.".to_string());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "A parser input escaped the evidence directory.".to_string())?;
            let size = path
                .metadata()
                .map_err(|error| format!("Could not read parser input metadata: {error}"))?
                .len();
            let hash = sha256(path)
                .ok_or_else(|| format!("Could not hash parser input: {}", path.display()))?;
            Ok(SourceManifestEntry {
                path: relative.display().to_string(),
                size,
                sha256: hash,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.is_empty() {
        return Err(format!(
            "No {parser} artifacts were found in that directory."
        ));
    }
    Ok(entries)
}

struct PreparedJob {
    case: PathBuf,
    evidence: PathBuf,
    input: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    audit_dir: PathBuf,
    jobs_dir: PathBuf,
}

fn prepare_job(
    case_path: &str,
    evidence_path: &str,
    input_path: &str,
    parser_path: &str,
    parser: &str,
) -> Result<PreparedJob, String> {
    if !allowed_parser(parser) {
        return Err("That parser is not approved.".into());
    }
    let case = Path::new(case_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    if !case.join("case.json").is_file() {
        return Err("Open a valid VampHunt case first.".into());
    }
    let evidence = Path::new(evidence_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid evidence folder first.".to_string())?;
    let input = canonical_descendant(Path::new(input_path.trim()), &evidence, "artifact")?;
    let executable = Path::new(parser_path.trim())
        .canonicalize()
        .map_err(|_| "Select vamparser.exe.".to_string())?;
    let executable_name = executable
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if !executable.is_file()
        || !(executable_name == "vamparser.exe"
            || (executable_name.starts_with("vamparser-") && executable_name.ends_with(".exe")))
    {
        return Err("Only vamparser.exe can be used by this runner.".into());
    }
    let executable_sha256 = sha256(&executable)
        .ok_or_else(|| "Could not verify the Vamparser executable.".to_string())?;
    if executable_sha256 != APPROVED_VAMPARSER_SHA256 {
        return Err("Vamparser failed integrity verification. Reinstall VampHunt or approve a reviewed parser release.".into());
    }
    let audit_dir = case_subdir(&case, "AUDIT")?;
    let jobs_dir = job_directory(&case)?;
    Ok(PreparedJob {
        case,
        evidence,
        input,
        executable,
        executable_sha256,
        audit_dir,
        jobs_dir,
    })
}

fn execute_job(
    prepared: PreparedJob,
    parser: String,
    mut job: ParserJobRecord,
) -> Result<ParserJobResult, String> {
    let started = Utc::now();
    let stamp = started.format("%Y%m%d-%H%M%S-%3f").to_string();
    set_job_state(
        &prepared.jobs_dir,
        &mut job,
        "running",
        "hashing",
        "Hashing source evidence",
    )?;
    let input_sha256 = if prepared.input.is_file() {
        sha256(&prepared.input)
    } else {
        None
    };
    let (input_manifest, input_manifest_sha256, input_files) = if prepared.input.is_dir() {
        let entries = directory_manifest(&prepared.input, &parser, &job.job_id)?;
        let bytes = serde_json::to_vec_pretty(&entries).map_err(|e| e.to_string())?;
        let manifest = prepared
            .audit_dir
            .join(format!("source-{parser}-{stamp}.json"));
        fs::write(&manifest, &bytes)
            .map_err(|e| format!("Could not write the source manifest: {e}"))?;
        let mut digest = Sha256::new();
        digest.update(&bytes);
        (
            Some(crate::paths::display(&manifest)),
            Some(format!("{:x}", digest.finalize())),
            entries.len(),
        )
    } else {
        (None, None, 1)
    };
    if cancellation_requested(&job.job_id) {
        return Err("Parser job cancelled.".into());
    }

    let processed = case_subdir(&prepared.case, "PROCESSED")?;
    let output_dir = processed.join(&parser);
    fs::create_dir_all(&output_dir).map_err(|e| format!("Could not create parser output: {e}"))?;
    let output_dir = canonical_descendant(&output_dir, &processed, "parser output")?;
    let output = output_dir.join(format!("{stamp}.db"));
    job.output = Some(crate::paths::display(&output));
    set_job_state(
        &prepared.jobs_dir,
        &mut job,
        "running",
        "parsing",
        "Vamparser is processing the selected evidence",
    )?;

    let mut child = Command::new(&prepared.executable)
        .arg("--json")
        .arg(&parser)
        .arg(&prepared.input)
        .arg("--output")
        .arg(&output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start Vamparser: {e}"))?;

    let stdout_reader = child.stdout.take().map(|mut stream| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream.read_to_end(&mut bytes);
            result.map(|_| bytes)
        })
    });
    let stderr_reader = child.stderr.take().map(|mut stream| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream.read_to_end(&mut bytes);
            result.map(|_| bytes)
        })
    });

    let (exit_status, cancelled) = loop {
        if cancellation_requested(&job.job_id) {
            let _ = child.kill();
            let status = child
                .wait()
                .map_err(|e| format!("Could not stop Vamparser: {e}"))?;
            break (status, true);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Could not monitor Vamparser: {e}"))?
        {
            break (status, false);
        }
        thread::sleep(Duration::from_millis(100));
    };

    let stdout_bytes = join_output_reader(stdout_reader, "output")?;
    let stderr_bytes = join_output_reader(stderr_reader, "errors")?;
    let stdout = String::from_utf8_lossy(&stdout_bytes).trim().to_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_owned();

    let mut status = if cancelled {
        "cancelled"
    } else if exit_status.success() {
        "completed"
    } else {
        "failed"
    }
    .to_owned();
    let mut normalized = 0;
    let mut normalization_error = None;
    if exit_status.success() && !cancelled {
        set_job_state(
            &prepared.jobs_dir,
            &mut job,
            "running",
            "normalizing",
            "Adding parser records to the investigation database",
        )?;
        let database = crate::paths::case_database(&prepared.case)?;
        match crate::normalize::normalize(&parser, &output, &database) {
            Ok(count) => normalized = count,
            Err(error) => {
                status = "normalization_failed".into();
                normalization_error = Some(error);
            }
        }
    }

    let completed = Utc::now();
    let output_sha256 = if output.is_file() {
        sha256(&output)
    } else {
        None
    };
    let audit_path = prepared
        .audit_dir
        .join(format!("parser-{parser}-{stamp}.json"));
    let audit = serde_json::json!({
        "job_id": job.job_id, "parser": parser, "executable": prepared.executable,
        "executable_sha256": prepared.executable_sha256, "evidence_root": prepared.evidence,
        "input": prepared.input, "input_sha256": input_sha256, "input_manifest": input_manifest,
        "input_manifest_sha256": input_manifest_sha256, "input_files": input_files,
        "output": output, "output_sha256": output_sha256, "started_utc": started.to_rfc3339(),
        "completed_utc": completed.to_rfc3339(), "duration_ms": (completed - started).num_milliseconds(),
        "status": status, "exit_code": exit_status.code(), "normalized_events": normalized,
        "normalization_error": normalization_error, "stdout": stdout, "stderr": stderr
    });
    fs::write(
        &audit_path,
        serde_json::to_vec_pretty(&audit).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Could not write audit record: {e}"))?;

    job.normalized_events = normalized;
    let phase = status.clone();
    let message = match status.as_str() {
        "completed" => format!("Parsed and normalized {normalized} events"),
        "cancelled" => "Cancelled by the analyst".to_string(),
        "normalization_failed" => "Parsing completed but normalization failed".to_string(),
        _ if stderr.is_empty() => "Vamparser exited with an error".to_string(),
        _ => stderr.clone(),
    };
    set_job_state(&prepared.jobs_dir, &mut job, &status, &phase, message)?;

    Ok(ParserJobResult {
        job_id: job.job_id,
        parser,
        status,
        output: crate::paths::display(&output),
        audit: crate::paths::display(&audit_path),
        stdout,
        stderr,
        normalized,
    })
}

fn run_parser_with_id(
    case_path: String,
    evidence_path: String,
    input_path: String,
    parser_path: String,
    parser: String,
    job_id: String,
) -> Result<ParserJobResult, String> {
    if !valid_job_id(&job_id) {
        return Err("The parser job identifier is invalid.".into());
    }
    let prepared = prepare_job(
        &case_path,
        &evidence_path,
        &input_path,
        &parser_path,
        &parser,
    )?;
    {
        let mut active = active_jobs()
            .lock()
            .map_err(|_| "The parser job registry is unavailable.".to_string())?;
        if !active.insert(job_id.clone()) {
            return Err("That parser job is already running.".into());
        }
    }
    let now = Utc::now().to_rfc3339();
    let mut job = ParserJobRecord {
        job_id: job_id.clone(),
        parser: parser.clone(),
        status: "running".into(),
        phase: "preparing".into(),
        input: crate::paths::display(&prepared.input),
        output: None,
        started_utc: now.clone(),
        updated_utc: now,
        completed_utc: None,
        normalized_events: 0,
        message: "Preparing parser job".into(),
    };
    if let Err(error) = save_job(&prepared.jobs_dir, &job) {
        active_jobs()
            .lock()
            .map_err(|_| "The parser job registry is unavailable.".to_string())?
            .remove(&job_id);
        return Err(error);
    }

    let result = execute_job(prepared, parser, job.clone());
    active_jobs()
        .lock()
        .map_err(|_| "The parser job registry is unavailable.".to_string())?
        .remove(&job_id);
    let was_cancelled = cancellations()
        .lock()
        .map_err(|_| "The parser cancellation registry is unavailable.".to_string())?
        .remove(&job_id);

    if let Err(error) = &result {
        let case = Path::new(case_path.trim())
            .canonicalize()
            .map_err(|_| "Open a valid case first.".to_string())?;
        let jobs = job_directory(&case)?;
        let cancelled = was_cancelled || error == "Parser job cancelled.";
        let status = if cancelled { "cancelled" } else { "failed" };
        let phase = status;
        let message = if cancelled {
            "Cancelled by the analyst".to_string()
        } else {
            error.clone()
        };
        let _ = set_job_state(&jobs, &mut job, status, phase, message);
    }
    result
}

#[cfg(test)]
pub(crate) fn run_parser_blocking(
    case_path: String,
    evidence_path: String,
    input_path: String,
    parser_path: String,
    parser: String,
) -> Result<ParserJobResult, String> {
    run_parser_with_id(
        case_path,
        evidence_path,
        input_path,
        parser_path,
        parser,
        generated_job_id(),
    )
}

#[tauri::command]
pub async fn run_parser(
    case_path: String,
    evidence_path: String,
    input_path: String,
    parser_path: String,
    parser: String,
    job_id: String,
) -> Result<ParserJobResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        run_parser_with_id(
            case_path,
            evidence_path,
            input_path,
            parser_path,
            parser,
            job_id,
        )
    })
    .await
    .map_err(|e| format!("Parser worker stopped unexpectedly: {e}"))?
}

#[tauri::command]
pub fn cancel_parser(case_path: String, job_id: String) -> Result<(), String> {
    if !valid_job_id(&job_id) {
        return Err("The parser job identifier is invalid.".into());
    }
    let is_active = active_jobs()
        .lock()
        .map_err(|_| "The parser job registry is unavailable.".to_string())?
        .contains(&job_id);
    if !is_active {
        return Err("That parser job is not running.".into());
    }
    cancellations()
        .lock()
        .map_err(|_| "The parser cancellation registry is unavailable.".to_string())?
        .insert(job_id.clone());
    let case = Path::new(case_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    let directory = job_directory(&case)?;
    let path = job_path(&directory, &job_id)?;
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(mut record) = serde_json::from_slice::<ParserJobRecord>(&bytes) {
            set_job_state(
                &directory,
                &mut record,
                "cancelling",
                "cancelling",
                "Stopping Vamparser",
            )?;
        }
    }
    Ok(())
}

#[tauri::command]
pub fn list_parser_jobs(case_path: String) -> Result<Vec<ParserJobRecord>, String> {
    let case = Path::new(case_path.trim())
        .canonicalize()
        .map_err(|_| "Open a valid case first.".to_string())?;
    if !case.join("case.json").is_file() {
        return Err("Open a valid VampHunt case first.".into());
    }
    let directory = job_directory(&case)?;
    let active = active_jobs()
        .lock()
        .map_err(|_| "The parser job registry is unavailable.".to_string())?
        .clone();
    let mut records = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(mut record) = serde_json::from_slice::<ParserJobRecord>(&bytes) else {
            continue;
        };
        record.input = crate::paths::readable(&record.input);
        record.output = record.output.as_deref().map(crate::paths::readable);
        if matches!(record.status.as_str(), "running" | "cancelling")
            && !active.contains(&record.job_id)
        {
            set_job_state(
                &directory,
                &mut record,
                "interrupted",
                "interrupted",
                "The application stopped before this job finished",
            )?;
        }
        records.push(record);
    }
    records.sort_by(|left, right| right.started_utc.cmp(&left.started_utc));
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_unknown_parser() {
        assert!(!allowed_parser("cmd.exe"));
        assert!(allowed_parser("evtx"));
    }

    #[test]
    fn approved_hash_has_sha256_length() {
        assert_eq!(APPROVED_VAMPARSER_SHA256.len(), 64);
        assert!(APPROVED_VAMPARSER_SHA256
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn restricts_job_identifiers() {
        assert!(valid_job_id("91c31d66-5f20-4e16-a24e-2e67ce0c1219"));
        assert!(!valid_job_id("../outside"));
        assert!(!valid_job_id("job.json"));
    }

    #[test]
    fn canonical_descendant_rejects_an_outside_path() {
        let root = std::env::temp_dir().join(format!("vamphunt-jobs-{}", std::process::id()));
        let evidence = root.join("evidence");
        let outside = root.join("outside");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&evidence).unwrap();
        fs::create_dir_all(&outside).unwrap();
        assert!(canonical_descendant(&outside, &evidence, "artifact").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_manifest_hashes_only_files_used_by_the_parser() {
        let root = std::env::temp_dir().join(format!("vamphunt-manifest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("Security.evtx"), b"event log").unwrap();
        fs::write(root.join("notes.txt"), b"ignore").unwrap();
        let manifest = directory_manifest(&root, "evtx", "manifest-test").unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].path, "Security.evtx");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_running_jobs_are_marked_interrupted() {
        let root = std::env::temp_dir().join(format!("vamphunt-stale-job-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("case.json"), b"{}").unwrap();
        fs::create_dir(root.join("AUDIT")).unwrap();
        let jobs = job_directory(&root).unwrap();
        let now = Utc::now().to_rfc3339();
        let record = ParserJobRecord {
            job_id: "stale-job".into(),
            parser: "evtx".into(),
            status: "running".into(),
            phase: "parsing".into(),
            input: "evidence".into(),
            output: None,
            started_utc: now.clone(),
            updated_utc: now,
            completed_utc: None,
            normalized_events: 0,
            message: String::new(),
        };
        save_job(&jobs, &record).unwrap();
        let records = list_parser_jobs(root.display().to_string()).unwrap();
        assert_eq!(records[0].status, "interrupted");
        fs::remove_dir_all(root).unwrap();
    }
}
