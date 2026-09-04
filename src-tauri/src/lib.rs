mod archive;
mod cases;
mod detections;
mod evidence;
mod findings;
mod investigation;
mod jobs;
mod normalize;
mod parsers;
mod paths;
mod reports;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            evidence::inventory_evidence,
            evidence::import_evidence,
            cases::create_case,
            cases::open_case,
            cases::delete_case,
            detections::detection_status,
            detections::run_yara_scan,
            detections::run_detection_scan,
            detections::list_detection_leads,
            archive::export_case,
            archive::import_case,
            jobs::run_parser,
            jobs::cancel_parser,
            jobs::list_parser_jobs,
            parsers::parser_capabilities,
            parsers::locate_vamparser,
            investigation::investigation_overview,
            investigation::timeline_events,
            investigation::explore_events,
            investigation::event_filter_options,
            investigation::relationship_edges,
            investigation::event_source_record,
            findings::create_finding,
            findings::list_findings,
            findings::update_finding_status,
            reports::generate_html_report,
            reports::export_timeline_csv,
            reports::list_generated_reports,
            reports::open_generated_report,
            reports::reveal_generated_report,
            reports::delete_generated_report
        ])
        .run(tauri::generate_context!())
        .expect("failed to run VampHunt");
}

#[cfg(test)]
mod workflow_tests {
    use super::*;
    use std::{collections::BTreeMap, env, fs, path::Path};

    #[test]
    #[ignore = "requires VAMPHUNT_TEST_CORPUS and VAMPHUNT_TEST_VAMPARSER"]
    fn real_collection_runs_every_discovered_parser() {
        let corpus = env::var("VAMPHUNT_TEST_CORPUS")
            .expect("set VAMPHUNT_TEST_CORPUS to a copied forensic collection");
        let parser = env::var("VAMPHUNT_TEST_VAMPARSER")
            .expect("set VAMPHUNT_TEST_VAMPARSER to the reviewed release executable");
        let base = env::temp_dir().join(format!("vamphunt-parser-coverage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        let case = cases::create_case(
            base.display().to_string(),
            "Parser coverage".into(),
            "Automated test".into(),
        )
        .unwrap();
        let inventory = evidence::inventory_evidence_blocking(corpus.clone()).unwrap();
        let directory_parsers = ["evtx", "prefetch", "lnk", "jump-lists", "recycle-bin"];
        let mut inputs = BTreeMap::new();
        for artifact in inventory
            .artifacts
            .iter()
            .filter(|artifact| artifact.confidence == "verified" && !artifact.parser.is_empty())
        {
            inputs.entry(artifact.parser.clone()).or_insert_with(|| {
                if directory_parsers.contains(&artifact.parser.as_str()) {
                    corpus.clone()
                } else {
                    artifact.path.clone()
                }
            });
        }
        assert!(
            inputs.len() >= 5,
            "the corpus should cover several parser types"
        );
        let mut completed = Vec::new();
        for (parser_id, input) in inputs {
            let result = jobs::run_parser_blocking(
                case.path.clone(),
                corpus.clone(),
                input,
                parser.clone(),
                parser_id.clone(),
            )
            .unwrap_or_else(|error| panic!("{parser_id} failed: {error}"));
            assert_eq!(result.status, "completed", "{parser_id} did not complete");
            completed.push(parser_id);
        }
        assert!(completed.contains(&"evtx".to_string()));
        assert!(completed.contains(&"prefetch".to_string()));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    #[ignore = "requires VAMPHUNT_TEST_CORPUS and VAMPHUNT_TEST_VAMPARSER"]
    fn real_collection_reaches_an_evidence_backed_report() {
        let corpus = env::var("VAMPHUNT_TEST_CORPUS")
            .expect("set VAMPHUNT_TEST_CORPUS to a copied forensic collection");
        let parser = env::var("VAMPHUNT_TEST_VAMPARSER")
            .expect("set VAMPHUNT_TEST_VAMPARSER to the reviewed release executable");
        let base = env::temp_dir().join(format!("vamphunt-workflow-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();

        let case = cases::create_case(
            base.display().to_string(),
            "Workflow verification".into(),
            "Automated test".into(),
        )
        .unwrap();
        let inventory = evidence::inventory_evidence_blocking(corpus.clone()).unwrap();
        let artifact = inventory
            .artifacts
            .iter()
            .find(|item| item.parser == "prefetch" && item.confidence == "verified")
            .expect("the validation corpus must contain a valid Prefetch file");

        let job = jobs::run_parser_blocking(
            case.path.clone(),
            corpus.clone(),
            corpus,
            parser,
            artifact.parser.clone(),
        )
        .unwrap();
        assert_eq!(job.status, "completed");
        assert!(job.normalized > 0);
        assert!(Path::new(&job.output).is_file());
        assert!(Path::new(&job.audit).is_file());
        let audit: serde_json::Value =
            serde_json::from_slice(&fs::read(&job.audit).unwrap()).unwrap();
        assert!(audit["input_files"].as_u64().unwrap() > 1);
        assert!(Path::new(audit["input_manifest"].as_str().unwrap()).is_file());
        assert_eq!(audit["input_manifest_sha256"].as_str().unwrap().len(), 64);

        let overview = investigation::investigation_overview(case.path.clone()).unwrap();
        assert!(overview.events > 0);
        assert!(overview.entities > 0);
        assert!(overview.relationships > 0);
        let relationships = investigation::relationship_edges(case.path.clone(), 10).unwrap();
        assert!(!relationships.is_empty());

        let events = investigation::timeline_events(case.path.clone(), String::new(), 10).unwrap();
        let event = events.first().expect("normalization must create an event");
        let source = investigation::event_source_record(case.path.clone(), event.id).unwrap();
        assert_eq!(source.table, "prefetch_data");
        assert!(!source.fields.is_empty());

        let finding = findings::create_finding(
            case.path.clone(),
            "Verified program execution".into(),
            "Medium".into(),
            "Created by the workflow regression test.".into(),
            vec![event.id],
        )
        .unwrap();
        findings::update_finding_status(case.path.clone(), finding, "Confirmed".into()).unwrap();
        let report = reports::generate_html_report(case.path.clone(), vec![], vec![]).unwrap();
        let html = fs::read_to_string(report).unwrap();
        assert!(html.contains("Verified program execution"));
        assert!(html.contains("prefetch_data"));

        fs::remove_dir_all(base).unwrap();
    }
}
