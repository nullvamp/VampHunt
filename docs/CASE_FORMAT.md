# Case format

VampHunt works with an existing DFIR Tools AIO case or creates an independent investigation directory using the same evidence/output split.

```text
<case-id>/
├── EVIDENCE/       Collected source material; never modified
├── OUTPUT/         Original output produced by external tools
├── PROCESSED/      Native parser databases and normalized records
├── DATABASE/       Investigation index and relationships
├── REPORTS/        Analyst-approved exports
├── AUDIT/          Job records, hashes, warnings and review history
└── case.json       Case identity and settings
```

Large source collections may remain outside the case. In that mode, the case stores a reference, source hash, size, and acquisition details rather than copying the collection.

VampHunt must not write into `EVIDENCE`. Every derived file belongs in `PROCESSED`, `DATABASE`, `REPORTS`, or `AUDIT`.

