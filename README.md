<p align="center">
  <img src="docs/vamphunt-logo.svg" width="160" alt="VampHunt logo">
</p>

# VampHunt

VampHunt is a Windows-first investigation workspace for collected forensic evidence. It inventories an existing case or any collected evidence directory, identifies artifacts by content and context, runs approved native parsers, and connects the resulting events into timelines, relationships, findings, and reports.

The application works without AI. Any future assisted analysis remains optional and cannot create confirmed findings without analyst review.

## Detection rules

VampHunt runs four detection layers against the evidence kept in a case:

- YARA Forge Core through YARA-X for binaries, scripts, and other files.
- Hayabusa rules and SigmaHQ rules through Hayabusa for raw Windows EVTX files.
- WithSecureLabs Chainsaw rules for raw Windows artifacts, including EVTX and `$MFT`.
- 29 VampHunt rules for cross-artifact and parsed-record analysis across EVTX, Registry, Prefetch, Shimcache, Amcache, LNK, Jump Lists, MFT, USN, SRUM, and the Recycle Bin.

Install the current reviewed releases with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\sync-rules.ps1
```

The updater downloads the upstream releases, records their exact versions and
SHA-256 hashes in `rules/manifest.json`, removes development files that are not
needed at runtime, and leaves downloaded third-party content outside Git. The
Rule matches screen runs every applicable layer and saves case-scoped leads with
the raw engine result and linked parser records. Medium and higher community
matches are kept. A match is never a confirmed finding by itself.

## What it does

- Tauri 2 desktop shell
- TypeScript and React interface
- Self-contained case workspaces for evidence, parser output, investigation data, reports, and audit records
- Prerequisite-aware case workflow that keeps unavailable stages locked until the required evidence or parsed records exist
- Native Windows file and folder pickers for case, evidence, parser, and backup paths
- Rust evidence inventory
- Native parser capability registry
- Content-aware detection of common Windows artifacts in collected folders
- Controlled Vamparser execution with case-scoped output and audit records
- Per-file SHA-256 source manifests for directory parser jobs
- Common SQLite event, entity, and relationship database
- Searchable event explorer with multi-select filters and relationship views
- Interactive user, host, process, and path graph
- Read-only inspection of the exact original parser row
- Report workspace for documenting analyst-reviewed findings, choosing report content by result type and severity, and managing generated files
- Standalone evidence-backed HTML reports with linked finding and rule sources
- Timeline CSV exports with in-app open, folder reveal, and deletion controls
- Verified `.vhcase` backup and restore
- Durable parser jobs with status, cancellation, and restart recovery

VampHunt does not require a particular collection tool or directory layout. Collections from forensic suites, response agents, mounted images, scripts, or manual acquisition are handled through the same discovery process.

The parsing engine is maintained separately in the
[Vamparser](https://github.com/nullvamp/Vamparser) repository.

## Basic workflow

1. Create a case, open an existing case folder, or import an `.vhcase` backup.
2. Choose a collected-evidence directory and run **Import and discover**. VampHunt copies the source into the case, records SHA-256 hashes, and identifies supported artifacts by content and filename rather than collection-tool layout.
3. Review the discovered artifacts, then parse one artifact or run every discovered parser.
4. Use **Parser jobs** to monitor completed, running, failed, cancelled, or recovered jobs.
5. Use **Event explorer** to search normalized records, combine multiple field filters, choose visible columns, and inspect the exact original parser row.
6. Use **Rule matches** to scan copied evidence, Windows logs, raw artifacts, and parsed cross-artifact relationships.
7. Review retained leads and **Connections**, then use **Report > Manual findings** to document analyst-confirmed findings linked to their supporting records.
8. In **Report > Build report**, choose the result types and severity levels to include, then generate the standalone HTML report or timeline CSV.
9. Use **Report > Generated reports** to open an output, show it in Windows Explorer, or permanently delete it from the case `REPORTS` folder.
10. Create an `.vhcase` backup before moving or archiving the case.

The source collection is read only. Parser databases, normalized events, findings,
reports, job records, and audit records are written inside the active case.

## Case management

Each new case is created as a separate folder containing `EVIDENCE`, `OUTPUT`,
`PROCESSED`, `DATABASE`, `REPORTS`, and `AUDIT`. Recent cases can be reopened
without finding `case.json` manually, while moved cases can still be selected
through **Open case folder**.

Deleting a recent case requires confirmation and permanently removes the whole
case folder. Before deletion, the backend verifies the requested case ID, its
`case.json` record, the folder name, and the expected VampHunt directories.
The recent-case entry is removed only after filesystem deletion succeeds. Create
an `.vhcase` backup first if the investigation may be needed again.

## Case backups

An `.vhcase` file contains the complete case directory, including copied evidence,
parser output, the investigation database, findings, reports, and audit records.
Every archived file is recorded in a SHA-256 manifest. Import verifies the manifest
before the case is moved into the selected cases directory. Unsafe paths, links,
duplicate entries, missing files, and altered files are rejected.

Keep an independent copy of irreplaceable source evidence. A case backup is not a
replacement for the original acquisition or its chain-of-custody records.

## Tested collection

The release workflow was tested locally against a copied Windows forensic
collection containing 1,964 files (about 748 MB), including EVTX, Prefetch, registry
hives, `$MFT`, `$J`, LNK files, and Jump Lists. The full investigation workflow and
every parser discovered in that collection completed successfully. The same corpus
also exercises all four detection layers; its latest validated run retained 98
reviewable leads after the false-positive gates were applied. Local rules are
also tested against synthetic attack sequences so detections absent from this
collection still receive repeatable coverage.

## Development

Requirements:

- Node.js
- Rust through rustup
- Visual Studio Build Tools with the Desktop development with C++ workload
- Microsoft WebView2 Runtime

```powershell
npm ci
npm run build
npm run tauri dev
npm run tauri build
```

Evidence must be processed from collected folders or forensic images. The application is not designed to parse a live endpoint.

The parser sidecar is built from the separate Vamparser repository and is not
stored in Git. See [docs/PARSER_CONTRACT.md](docs/PARSER_CONTRACT.md) for its
fixed interface, [docs/WORKFLOW_VALIDATION.md](docs/WORKFLOW_VALIDATION.md) for
the real-corpus workflow test.

Code signing is not configured. Unsigned development installers may trigger a
Windows reputation warning until a signing certificate is added.
