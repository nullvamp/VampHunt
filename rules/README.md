# Detection rule store

VampHunt keeps downloaded third-party rules out of the source repository.
Run `powershell -ExecutionPolicy Bypass -File scripts/sync-rules.ps1` to install
the reviewed rule packages into `rules/active`.

The default feeds are YARA Forge Core, SigmaHQ Core, Yamato Security's
Hayabusa rules, and WithSecureLabs Chainsaw rules. The generated
`rules/manifest.json` records the exact release or commit, download URL,
SHA-256, and installation time. `vamphunt/correlations.json` contains the
local cross-artifact rules and is kept in Git for review.

Community matches below Medium are not saved. Known Windows component-store
and Prefetch false positives from the Chainsaw system-binary rules are removed
before leads are shown. VampHunt never treats a match as a confirmed
finding; every retained match remains an analyst-review lead with its source.
