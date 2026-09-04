use serde::Serialize;
use std::{env, path::PathBuf};

#[derive(Serialize)]
pub struct ParserCapability {
    id: &'static str,
    name: &'static str,
    artifacts: &'static [&'static str],
}

#[tauri::command]
pub fn parser_capabilities() -> Vec<ParserCapability> {
    vec![
        ParserCapability {
            id: "evtx",
            name: "Event Logs",
            artifacts: &["evtx"],
        },
        ParserCapability {
            id: "registry",
            name: "Registry",
            artifacts: &[
                "system",
                "software",
                "sam",
                "security",
                "ntuser.dat",
                "usrclass.dat",
            ],
        },
        ParserCapability {
            id: "amcache",
            name: "Amcache",
            artifacts: &["amcache.hve"],
        },
        ParserCapability {
            id: "shimcache-hive",
            name: "Shimcache",
            artifacts: &["system"],
        },
        ParserCapability {
            id: "prefetch",
            name: "Prefetch",
            artifacts: &["pf"],
        },
        ParserCapability {
            id: "mft",
            name: "MFT",
            artifacts: &["$mft"],
        },
        ParserCapability {
            id: "usn",
            name: "USN Journal",
            artifacts: &["$j"],
        },
        ParserCapability {
            id: "srum",
            name: "SRUM",
            artifacts: &["srudb.dat"],
        },
        ParserCapability {
            id: "recycle-bin",
            name: "Recycle Bin",
            artifacts: &["$i"],
        },
        ParserCapability {
            id: "lnk",
            name: "LNK",
            artifacts: &["lnk"],
        },
        ParserCapability {
            id: "jump-lists",
            name: "Jump Lists",
            artifacts: &["automaticdestinations-ms", "customdestinations-ms"],
        },
    ]
}

#[tauri::command]
pub fn locate_vamparser() -> Option<String> {
    let mut candidates = Vec::new();
    if let Ok(current) = env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join("vamparser.exe"));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join("vamparser-x86_64-pc-windows-msvc.exe"),
    );
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| crate::paths::display(&path))
}
