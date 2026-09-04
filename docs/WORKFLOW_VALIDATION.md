# Workflow validation

Validated on 2026-09-02 against a read-only copy of the Opportunist Windows
forensic collection.

The collection contained 1,964 files (784,558,002 bytes), including 182
Prefetch files, 100 EVTX logs, registry hives, `$MFT`, `$J`, LNK files, and Jump
Lists.

The investigation regression test completed this chain:

1. Created a new VampHunt case and its case folders.
2. Inventoried the collection without assuming which tool collected it.
3. Detected valid Prefetch artifacts from their content and file context.
4. Hashed every Prefetch source and wrote a case-scoped source manifest.
5. Verified the bundled Vamparser executable against its approved SHA-256.
6. Parsed the collection directory into a case-scoped SQLite database.
7. Normalized parser records into the VampHunt event and entity tables.
8. Opened the exact original `prefetch_data` source row from a timeline event.
9. Created and confirmed a finding linked to that supporting event.
10. Generated an HTML report containing the finding and source reference.

The investigation workflow test passed. A second coverage test ran every distinct
verified parser discovered in the collection and passed in 75.35 seconds. Timing
is not a benchmark and will vary with storage, collection size, and antivirus
scanning.

The broader test caught a false positive where a registry transaction log named
`NTUSER.DAT.LOG1` was offered as a hive. Discovery now rejects `.LOG1`, `.LOG2`,
`.blf`, and `.regtrans-ms` files as primary registry hives.

The detection workflow was revalidated on 2026-09-03. The 29-rule local pack
retained 46 evidence-backed leads from the parsed collection, and the complete
four-layer result contained 98 reviewable leads. Every local lead resolved to at
least one exact parser source row. Synthetic fixtures also exercised all six EVTX
correlation types, suspicious Registry and shortcut records, named NTFS streams,
bulk document-extension changes, and SRUM network-to-execution linkage.

The real collection is not stored in Git. To repeat the test locally:

```powershell
$env:VAMPHUNT_TEST_CORPUS = "D:\Copied-Evidence"
$env:VAMPHUNT_TEST_VAMPARSER = "C:\Path\To\vamparser.exe"
cargo test --manifest-path src-tauri/Cargo.toml --locked workflow_tests::real_collection_reaches_an_evidence_backed_report -- --ignored --nocapture
cargo test --manifest-path src-tauri/Cargo.toml --locked workflow_tests::real_collection_runs_every_discovered_parser -- --ignored --nocapture
```

The parser executable must match the SHA-256 pinned by VampHunt. The test
creates its case under the Windows temporary directory and removes it on success.

