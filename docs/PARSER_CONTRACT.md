# Native parser contract

VampHunt invokes the separately versioned `vamparser.exe` through a fixed subcommand allow-list. User-supplied executable names or arbitrary arguments are not accepted.

The packaged Vamparser release is pinned by SHA-256. VampHunt refuses to start a parser whose executable hash does not match the reviewed release.

Current command shape:

```text
vamparser.exe --json <artifact> <input> --output <database>
```

Supported artifact commands are obtained from the parser capability registry. Inputs must resolve inside a registered evidence source. Outputs must resolve inside the active case's `PROCESSED` directory.

Before execution, VampHunt records:

- Case identifier
- Parser executable version and SHA-256
- Source path, size and SHA-256
- Requested parser command
- Output destination
- Start time in UTC

After execution, it records the process exit code, completion time, output hash, parsed-record count, skipped-record count, warnings, and errors.

On success, Vamparser emits one JSON record on standard output:

```json
{"type":"complete","parser":"mft","parsed":139560,"output":"mft.db"}
```

Errors are returned through the process exit code and standard error. Future
protocol versions may add progress and warning records without changing the
completion record.

SQLite artifact tables preserve complete parser-specific fields. VampHunt separately normalizes relevant records into its common event and entity schema.

Normalization never replaces the parser database. Every common event retains the parser name, source database, source table, and original row identifier so the analyst can return to the producing record.

VampHunt also records the SQLite row address for supported Vamparser tables. Source inspection opens only databases beneath the active case's `PROCESSED` directory, uses a fixed table allow-list, and opens the database read-only.
