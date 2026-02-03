# FHIR ZIP downloader + extractor + optional FHIR cleanup

This Bash script polls a FHIR server for `DocumentReference` resources whose `masterIdentifier.value` starts with a configurable prefix, downloads the referenced `Binary` payload (expected to be a ZIP), extracts its contents into a receiver/project folder structure, optionally applies **FileState delete logic**, and (if enabled) deletes the processed `DocumentReference` + `Binary` from the FHIR server **only after successful processing**.

---

## What it does (high level)

1. **Connects to a FHIR server** and checks reachability via `/metadata`.
2. **Lists `DocumentReference`** pages (`_count` configurable) and selects those where `masterIdentifier.value` begins with `SEARCH_PREFIX`.
3. For each match:
   - derives `receiver`, `project`, and optional `sha256` from `masterIdentifier.value`
   - downloads the referenced `Binary` (`attachment.url`) into a **temporary ZIP**
   - optional: checks ZIP sha256 (warns on mismatch)
   - extracts ZIP into `${OUTDIR}/{receiver}/{project}` (or `${OUTDIR_ROBIN}` for receiver `Robin`)
   - if ZIP contains **only** a `filestate.json`, applies FileState delete logic (delete local files not present in FileState)
   - deletes the ZIP file after extraction
   - optionally deletes the `DocumentReference` and `Binary` from FHIR (and their `_history`)

---

## Output folder structure

Files are extracted to:

- **Default:** `${OUTDIR}/{receiver}/{project}/...`
- **Receiver = Robin (case-insensitive):** `${OUTDIR_ROBIN}/{receiver}/{project}/...`

`receiver` and `project` are sanitized to contain only `A–Z a–z 0–9 . _ -`.

---

## How `receiver/project/hash` are derived

The script parses `DocumentReference.masterIdentifier.value` like this:

- It must start with `SEARCH_PREFIX` (default: `NCT-DKFZ-DE_`)
- After removing the prefix, it splits the remainder by `_`

Supported patterns:

1) `NCT-DKFZ-DE_<receiver>_<project>_<sha256...>`
- receiver = first segment  
- project  = second segment  
- hash     = remaining segments joined with `_` (optional)

2) `NCT-DKFZ-DE_<project>_<hash>`
- receiver defaults to `DKFZ`
- project  = first segment
- hash     = second segment

If parsing fails: receiver/project fall back to `DKFZ` / `UNKNOWN_PROJECT`.

---

## Requirements

Required commands:
- `bash`, `curl`, `jq`, `base64`, `sed`, `awk`, `unzip`, `find`

Optional (for better behavior):
- `flock` (prevents concurrent runs; fallback uses a lock directory)
- one of: `sha256sum` / `shasum` / `openssl` (SHA256 verification)

The script will exit early if `OUTDIR` or `OUTDIR_ROBIN` are not reachable or not writable.

---

## Quick start

```bash
# 1) Make executable
chmod +x download_unzip_deleteFhir.sh

# 2) Run with defaults
./download_unzip_deleteFhir.sh
