#!/usr/bin/env bash
set -euo pipefail
umask 0077

############################
# Paths relative to the project directory
############################
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd -P)"

RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
OUTDIR="${OUTDIR:-/mnt/OE0600-Projekte/MIC}"
TMP_DIR="${TMP_DIR:-$SCRIPT_DIR/tmp}"

mkdir -p "$RUN_DIR" "$LOG_DIR" "$TMP_DIR"

LOG="${LOG:-$LOG_DIR/download_unzip_deleteFhir.log}"

# Log retention configuration (in hours; default 72 = 3 days)
LOG_RETENTION_HOURS="${LOG_RETENTION_HOURS:-72}"

# Log retention: keep only lines from the last LOG_RETENTION_HOURS hours
if [ -f "$LOG" ]; then
  cutoff="$(date -d "${LOG_RETENTION_HOURS} hours ago" +%s)"

  tmp_log="${LOG}.tmp"

  # Keep only lines whose timestamp is within the last LOG_RETENTION_HOURS hours
  awk -v cutoff="$cutoff" '
    {
      # Format: 2025-12-11T13:22:05+01:00 [INFO] ...
      # Extract timestamp field
      ts = $1

      # Convert to format that date can parse: %Y-%m-%dT%H:%M:%S → Unix timestamp
      gsub(/T/, " ", ts)
      sub(/\+.*$/, "", ts)

      cmd = "date -d \"" ts "\" +%s"
      cmd | getline t
      close(cmd)

      if (t >= cutoff) print $0
    }
  ' "$LOG" > "$tmp_log"

  mv "$tmp_log" "$LOG"
fi

############################
# Configuration
############################
# Base URL of the FHIR server (must end with /fhir)
BASE="${FHIR_BASE:-https://blaze.sci.dkfz.de/fhir}"

# FHIR identifier filter (on DocumentReference)
IDENT_SYSTEM="http://medizininformatik-initiative.de/sid/project-identifier"
# Prefix for masterIdentifier.value (including underscore)
: "${SEARCH_PREFIX:=NCT-DKFZ-DE_}"

# Network / download parameters
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-120}"
RETRIES="${RETRIES:-2}"
RETRY_DELAY="${RETRY_DELAY:-2}"
MAX_PAGES="${MAX_PAGES:-50}"
PAGE_SIZE="${PAGE_SIZE:-200}"

# Delete in FHIR after successful processing?
: "${DELETE_AFTER_DOWNLOAD:=1}"
# Force delete-history even if capability is not advertised
: "${FORCE_HISTORY_DELETE:=1}"
# Apply FileState delete logic?
: "${FILESTATE_DELETE_ENABLED:=1}"
# Name/pattern of the FileState JSON inside the ZIP
: "${FILESTATE_JSON_PATTERN:=filestate.json}"

############################
# Helper functions
############################
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; NC=$'\033[0m'

ts(){
  if date -Iseconds >/dev/null 2>&1; then
    date -Iseconds
  else
    local d
    d="$(date "+%Y-%m-%dT%H:%M:%S%z")"
    printf '%s\n' "$d" | sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'
  fi
}

log(){ echo "$(ts) [$1] $2" | tee -a "$LOG"; }
die(){ log "ERROR" "$1"; exit 1; }
need_bin(){ command -v "$1" >/dev/null 2>&1 || die "missing program: $1"; }

if base64 --help 2>/dev/null | grep -q '\-d'; then B64_FLAG="-d"; else B64_FLAG="-D"; fi
b64d(){ base64 "$B64_FLAG"; }

mktemp_zip(){ mktemp -p "$TMP_DIR" -t dkfz_zip.XXXXXX; }
mktemp_tmp(){ mktemp -p "$TMP_DIR" -t dkfz_tmp.XXXXXX; }

curl_json(){
  curl -fsS \
    --connect-timeout "$CONNECT_TIMEOUT" \
    --max-time "$MAX_TIME" \
    --retry "$RETRIES" \
    --retry-delay "$RETRY_DELAY" \
    -H "Accept: application/fhir+json" \
    "$@"
}

curl_bin(){
  curl -fS -L \
    --connect-timeout "$CONNECT_TIMEOUT" \
    --max-time "$MAX_TIME" \
    --retry "$RETRIES" \
    --retry-delay "$RETRY_DELAY" \
    -H "Accept: application/octet-stream" \
    "$@"
}

normalize_rel(){
  sed -E 's#^https?://[^/]+(/fhir)?/##' | sed -E 's#^/##'
}

strip_history(){
  sed -E 's#/_history/[^/]+$##'
}

safe_name(){
  tr -cd 'A-Za-z0-9._-'
}

compute_sha256(){
  local f="$1" sum=""
  if command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum "$f" | awk '{print tolower($1)}')"
  elif command -v shasum >/dev/null 2>&1; then
    sum="$(shasum -a 256 "$f" | awk '{print tolower($1)}')"
  elif command -v openssl >/dev/null 2>&1; then
    sum="$(openssl dgst -sha256 -r "$f" | awk '{print tolower($1)}')"
  else
    echo ""
    return 1
  fi
  echo "$sum"
}

next_url(){
  local resp="$1" nxt
  if ! nxt="$(jq -r '.link[]? | select(.relation=="next") | .url // empty' "$resp" 2>/dev/null)"; then
    echo ""
    return 0
  fi
  [ -z "$nxt" ] && { echo ""; return 0; }
  echo "$nxt" | sed -E "s#^https?://[^/]+(/fhir)?#${BASE}#"
}

############################
# FHIR delete helpers
############################
_delete_ok(){
  case "${1-}" in
    200|202|204|404|410) return 0 ;;
    *) return 1 ;;
  esac
}

_http_delete(){
  local url="${1-}"
  [ -z "$url" ] && { echo "000"; return 0; }
  curl -sS -o /dev/null -w "%{http_code}" \
       --connect-timeout "$CONNECT_TIMEOUT" \
       --max-time "$MAX_TIME" \
       --retry "$RETRIES" \
       --retry-delay "$RETRY_DELAY" \
       --retry-connrefused \
       -H "Accept: application/fhir+json" \
       -H "Connection: close" \
       -X DELETE "$url" || echo "000"
}

_verify_gone(){
  local rtype="${1-}" rid="${2-}" code
  code="$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/${rtype}/${rid}" 2>/dev/null || echo "000")"
  case "$code" in
    404|410) return 0 ;;
    *) return 1 ;;
  esac
}

delete_with_verify(){
  local rtype="${1-}" rid="${2-}"
  if [ -z "$rtype" ] || [ -z "$rid" ]; then
    log "ERROR" "DELETE: missing parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi

  if _verify_gone "$rtype" "$rid"; then
    log "INFO" "${rtype}/${rid} already gone (verify=gone)"
    return 0
  fi

  local url="${BASE}/${rtype}/${rid}"
  local tries=0 code
  while :; do
    code="$(_http_delete "$url")"
    if [ "$code" = "000" ]; then
      log "WARN" "Transport error during DELETE (no HTTP code) - URL=$url"
    else
      log "INFO" "DELETE ${rtype}/${rid} → $code"
    fi

    if _verify_gone "$rtype" "$rid"; then
      log "INFO" "${rtype}/${rid} removed (verify=gone)"
      return 0
    fi

    tries=$((tries+1))
    [ "$tries" -ge 6 ] && break
    sleep 1
  done

  log "ERROR" "${rtype}/${rid} still present after DELETE (verify!=gone)"
  return 1
}

fhir_delete_history(){
  local rtype="${1-}" rid="${2-}"
  if [ -z "$rtype" ] || [ -z "$rid" ]; then
    log "ERROR" "DELETE _history: missing parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  if [ "${HAS_DELETE_HISTORY:-0}" != "1" ] && [ "${FORCE_HISTORY_DELETE}" != "1" ]; then
    log "INFO" "History delete not advertised - skipped for ${rtype}/${rid}"
    return 0
  fi
  local url="${BASE}/${rtype}/${rid}/_history"
  local code
  code="$(_http_delete "$url")"
  if _delete_ok "$code"; then
    log "INFO" "DELETE ${rtype}/${rid}/_history → $code"
  else
    log "WARN" "DELETE ${rtype}/${rid}/_history → $code"
  fi
}

############################
# FileState helpers
############################
cleanup_empty_dirs_under(){
  local root="$1"
  [ -d "$root" ] || return 0

  # Walk from bottom to top and remove empty directories,
  # but keep the project root directory itself.
  find "$root" -depth -type d 2>/dev/null | while IFS= read -r d; do
    # Do not delete the project root itself
    if [ "$d" = "$root" ]; then
      continue
    fi

    # rmdir only removes if the directory is empty
    if rmdir "$d" 2>/dev/null; then
      log "INFO" "FILESTATE: removed empty directory: $d"
    fi
  done
}

apply_filestate_json(){
  local json_file="$1" receiver="$2" project="$3"
  if [ "${FILESTATE_DELETE_ENABLED}" != "1" ]; then
    log "INFO" "FILESTATE: delete disabled - ignoring JSON: $json_file"
    return 0
  fi

  local fs_project fs_receiver
  fs_project="$(jq -r '.project // empty' "$json_file" 2>/dev/null || echo "")"
  fs_receiver="$(jq -r '.receiver // empty' "$json_file" 2>/dev/null || echo "")"

  local eff_project eff_receiver
  eff_project="${fs_project:-$project}"
  eff_receiver="${fs_receiver:-$receiver}"

  [ -z "$eff_project" ] && eff_project="UNKNOWN_PROJECT"
  [ -z "$eff_receiver" ] && eff_receiver="DKFZ"

  local safe_proj safe_recv proj_root
  safe_proj="$(printf '%s' "$eff_project" | safe_name)"; [ -z "$safe_proj" ] && safe_proj="UNKNOWN_PROJECT"
  safe_recv="$(printf '%s' "$eff_receiver" | safe_name)"; [ -z "$safe_recv" ] && safe_recv="UNKNOWN_RECEIVER"

  proj_root="${OUTDIR}/${safe_recv}/${safe_proj}"
  mkdir -p "$proj_root"

  log "INFO" "FILESTATE: apply for receiver='${eff_receiver}' project='${eff_project}' proj_root='${proj_root}'"

  local tmp_remote tmp_local
  tmp_remote="$(mktemp_tmp)"
  tmp_local="$(mktemp_tmp)"

  # Collect all relativePath entries recursively
  if ! jq -r '.. | objects | .relativePath? // empty' "$json_file" 2>/dev/null \
      | awk 'NF' \
      | sed 's#^\./##' \
      | sort -u > "$tmp_remote"; then
    log "ERROR" "FILESTATE: failed to evaluate relativePath entries: $json_file"
    rm -f "$tmp_remote" "$tmp_local"
    return 1
  fi

  if [ ! -s "$tmp_remote" ]; then
    log "WARN" "FILESTATE: no relativePath entries found - delete complete project directory"
    if [ -d "$proj_root" ]; then
      find "$proj_root" -type f ! -name '*.json' -print0 \
        | while IFS= read -r -d '' f; do
            log "INFO" "FILESTATE: deleting file (project empty): $f"
            rm -f -- "$f" || log "WARN" "FILESTATE: could not delete file: $f"
          done
      cleanup_empty_dirs_under "$proj_root"
    fi
    rm -f "$tmp_remote" "$tmp_local"
    return 0
  fi

  # Local files in the project (excluding JSON)
  if [ -d "$proj_root" ]; then
    ( cd "$proj_root" && find . -type f ! -name '*.json' -print | sed 's#^\./##' ) \
      | sort -u > "$tmp_local" || true
  else
    : > "$tmp_local"
  fi

  # Delete files that exist locally but are no longer present in the FileState
  local rel full
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    if ! grep -Fxq "$rel" "$tmp_remote"; then
      case "$rel" in
        *".."*) log "WARN" "FILESTATE: ignoring suspicious path with '..': $rel"; continue ;;
      esac
      full="${proj_root}/${rel}"
      if [ -f "$full" ]; then
        log "INFO" "FILESTATE: deleting file: $full"
        rm -f -- "$full" || log "WARN" "FILESTATE: could not delete file: $full"
      fi
    fi
  done < "$tmp_local"

  cleanup_empty_dirs_under "$proj_root"

  rm -f "$tmp_remote" "$tmp_local"
  return 0
}

############################
# Process ZIP file
############################
process_zip_for_receiver_project(){
  local zip_path="$1" receiver="$2" project="$3"

  local eff_receiver="$receiver" eff_project="$project"
  [ -z "$eff_receiver" ] && eff_receiver="DKFZ"
  [ -z "$eff_project" ] && eff_project="UNKNOWN_PROJECT"

  local safe_recv safe_proj proj_root
  safe_recv="$(printf '%s' "$eff_receiver" | safe_name)"; [ -z "$safe_recv" ] && safe_recv="UNKNOWN_RECEIVER"
  safe_proj="$(printf '%s' "$eff_project" | safe_name)"; [ -z "$safe_proj" ] && safe_proj="UNKNOWN_PROJECT"

  proj_root="${OUTDIR}/${safe_recv}/${safe_proj}"
  mkdir -p "$proj_root"

  log "INFO" "Processing ZIP: zip='${zip_path}' → receiver='${eff_receiver}' project='${eff_project}' proj_root='${proj_root}'"

  local entries files json_files normal_files
  mapfile -t entries < <(unzip -Z1 "$zip_path" 2>/dev/null || true)

  files=()
  for e in "${entries[@]}"; do
    # Directories end with /
    if [[ "$e" == */ ]]; then
      continue
    fi
    files+=("$e")
  done

  if [ "${#files[@]}" -eq 0 ]; then
    log "ERROR" "ZIP has no files (only directories?) - treated as error: ${zip_path}"
    return 1
  fi

  json_files=()
  normal_files=()
  local f
  for f in "${files[@]}"; do
    # Treat FILESTATE_JSON_PATTERN as (sub-)pattern
    if [[ "$f" == *"$FILESTATE_JSON_PATTERN" ]]; then
      json_files+=("$f")
    else
      normal_files+=("$f")
    fi
  done

  if [ "${#json_files[@]}" -eq 1 ] && [ "${#normal_files[@]}" -eq 0 ]; then
    # FileState ZIP
    local json_in_zip json_dir json_file
    json_in_zip="${json_files[0]}"
    json_dir="$(dirname "$json_in_zip")"
    [ "$json_dir" = "." ] && json_dir=""

    if [ -n "$json_dir" ]; then
      mkdir -p "${proj_root}/${json_dir}"
    fi

    log "INFO" "FileState ZIP detected (only JSON: ${json_in_zip}) - extracting to ${proj_root}"
    if ! unzip -oq "$zip_path" "$json_in_zip" -d "$proj_root" 2>/dev/null; then
      log "ERROR" "Could not extract FileState JSON: ${json_in_zip}"
      return 1
    fi

    json_file="${proj_root}/${json_in_zip}"
    if ! apply_filestate_json "$json_file" "$eff_receiver" "$eff_project"; then
      log "ERROR" "Applying FileState JSON failed: ${json_file}"
      return 1
    fi

    # Remove FileState JSON again and clean up empty directories
    rm -f -- "$json_file" || log "WARN" "Could not delete FileState JSON: ${json_file}"
    cleanup_empty_dirs_under "$proj_root"

    log "INFO" "FileState ZIP successfully applied: ${zip_path}"
  else
    # Normal data ZIP → just extract
    log "INFO" "Normal ZIP detected (files=${#files[@]}), extracting to ${proj_root}"
    if ! unzip -oq "$zip_path" -d "$proj_root" 2>/dev/null; then
      log "ERROR" "Extraction failed: ${zip_path}"
      return 1
    fi
  fi

  # Remove ZIP itself so that only contents remain
  rm -f -- "$zip_path" || log "WARN" "Could not delete ZIP: ${zip_path}"

  return 0
}

############################
# Download Binary into temporary ZIP
############################
download_binary_to_zip(){
  local rel="$1" target_zip="$2" expected_hash="$3"

  local rel_nover ver rel_ver got=0
  rel="${rel#/}"
  rel_nover="$(printf '%s' "$rel" | strip_history)"

  log "INFO" "Downloading Binary: ${rel}"

  # 1) Try FHIR JSON with .data
  if curl_json "${BASE}/${rel}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG"; then
    got=1
    log "INFO" "FHIR JSON download successful: ${rel}"
  elif curl_json "${BASE}/${rel_nover}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG"; then
    got=1
    log "INFO" "FHIR JSON download successful (without _history): ${rel_nover}"
  fi

  # 2) RAW download
  if [ "$got" -eq 0 ]; then
    if curl_bin "${BASE}/${rel}" -o "$target_zip" 2>>"$LOG" \
    || curl_bin "${BASE}/${rel_nover}" -o "$target_zip" 2>>"$LOG"; then
      got=1
      log "INFO" "RAW ZIP download successful: ${rel}"
    fi
  fi

  # 3) History fallback (latest version)
  if [ "$got" -eq 0 ]; then
    ver="$(curl_json "${BASE}/${rel_nover}/_history" 2>>"$LOG" \
          | jq -r '.entry[]?.resource?.meta?.versionId // empty' 2>/dev/null \
          | awk 'NF' | sort -n | tail -n1 || true)"
    if [ -n "$ver" ]; then
      rel_ver="${rel_nover}/_history/${ver}"
      if curl_json "${BASE}/${rel_ver}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG" \
      || curl_bin "${BASE}/${rel_ver}" -o "$target_zip" 2>>"$LOG"; then
        got=1
        log "INFO" "Versioned read successful: ${rel_ver}"
      fi
    fi
  fi

  if [ "$got" -eq 0 ]; then
    log "ERROR" "Download failed: ${rel}"
    return 1
  fi

  # SHA check (optional)
  if [ -n "$expected_hash" ]; then
    local exp act
    exp="$(printf '%s' "$expected_hash" | tr '[:upper:]' '[:lower:]')"
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
      act="$(compute_sha256 "$target_zip")"
      if [ -n "$act" ]; then
        if [ "$act" = "$exp" ]; then
          log "INFO" "${GREEN}SHA256 OK: $act${NC}"
        else
          log "WARN" "${RED}SHA256 MISMATCH: expected=$exp got=$act${NC}"
        fi
      else
        log "WARN" "Could not compute SHA256 (file=${target_zip})"
      fi
    else
      log "WARN" "No tool for SHA256 found - hash check skipped"
    fi
  else
    log "INFO" "No expected hash in masterIdentifier - hash check skipped"
  fi

  return 0
}

############################
# Delete DocRef and Binary (only on success)
############################
delete_doc_and_binary(){
  local dr_id="$1" rel="$2"

  if [ "${DELETE_AFTER_DOWNLOAD}" != "1" ]; then
    log "INFO" "DELETE_AFTER_DOWNLOAD!=1 - skipping FHIR delete (DocRef=${dr_id})"
    return 0
  fi

  if [ -z "$dr_id" ]; then
    log "WARN" "No DocRef ID known - skipping FHIR delete"
    return 0
  fi

  # Extract Binary ID from rel
  local rel_nover bid
  rel_nover="$(printf '%s' "$rel" | strip_history)"
  bid="$(printf '%s\n' "$rel_nover" | sed -nE 's#^Binary/([^/]+).*$#\1#p')"

  log "INFO" "Preparing FHIR delete: DocRef=${dr_id}, Binary=${bid:-unknown}"

  # Order: first DocumentReference, then Binary
  delete_with_verify "DocumentReference" "$dr_id" || log "WARN" "DocRef delete failed (DocRef=${dr_id})"
  fhir_delete_history "DocumentReference" "$dr_id" || true

  if [ -n "$bid" ]; then
    delete_with_verify "Binary" "$bid" || log "WARN" "Binary delete failed (Binary=${bid})"
    fhir_delete_history "Binary" "$bid" || true
  else
    log "WARN" "Could not derive Binary ID from rel - skipping Binary delete"
  fi
}

############################
# Check prerequisites
############################
need_bin curl
need_bin jq
need_bin base64
need_bin sed
need_bin awk
need_bin unzip
need_bin find

if command -v sha256sum >/dev/null 2>&1; then
  log "INFO" "SHA256 check via sha256sum enabled"
elif command -v shasum >/dev/null 2>&1; then
  log "INFO" "SHA256 check via shasum enabled"
elif command -v openssl >/dev/null 2>&1; then
  log "INFO" "SHA256 check via openssl enabled"
else
  log "WARN" "No tool for SHA256 found - hash check will be skipped"
fi

log "INFO" "Start; target: $OUTDIR"
log "INFO" "FHIR base: $BASE"

# Check if OUTDIR is available (e.g. CIFS mount)
if [ ! -d "$OUTDIR" ]; then
  log "ERROR" "OUTDIR not reachable: $OUTDIR - CIFS mount probably not available."
  exit 1
fi

# Check if OUTDIR is writable
if [ ! -w "$OUTDIR" ]; then
  log "ERROR" "OUTDIR is not writable: $OUTDIR"
  exit 1
fi

log "INFO" "Filter: system=$IDENT_SYSTEM | prefix=$SEARCH_PREFIX | exact=''"
log "INFO" "DELETE_AFTER_DOWNLOAD=${DELETE_AFTER_DOWNLOAD} FILESTATE_DELETE_ENABLED=${FILESTATE_DELETE_ENABLED} FORCE_HISTORY_DELETE=${FORCE_HISTORY_DELETE}"

curl_json "${BASE}/metadata" -o /dev/null || die "FHIR not reachable: ${BASE}/metadata"
log "INFO" "FHIR reachable"

# Capability check: delete-history
HAS_DELETE_HISTORY=0
if resp="$(curl -fsS "${BASE}/metadata" 2>/dev/null | jq -r '.rest[]?.resource[]? | {t:.type, i:([.interaction[]?.code]|join(","))} | @tsv' 2>/dev/null)"; then
  if printf '%s\n' "$resp" | grep -q 'delete-history'; then
    HAS_DELETE_HISTORY=1
  fi
fi
log "INFO" "delete-history advertised: ${HAS_DELETE_HISTORY}"

############################
# Lock
############################
LOCK_NAME="${RUN_DIR}/download_unzip_deleteFhir.lock"
LOCKDIR=""

cleanup_lock(){
  if [ -n "$LOCKDIR" ]; then
    rmdir "$LOCKDIR" >/dev/null 2>&1 || true
  fi
}
trap cleanup_lock EXIT

if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_NAME"
  if ! flock -n 9; then
    log "WARN" "already running, exiting"
    exit 0
  fi
  log "INFO" "Lock via flock active: $LOCK_NAME"
else
  LOCKDIR="${LOCK_NAME}.d"
  if ! mkdir "$LOCKDIR" 2>/dev/null; then
    log "WARN" "already running (lockdir), exiting"
    exit 0
  fi
  log "INFO" "Lock via lock directory active: $LOCKDIR"
fi

############################
# Collect candidates
############################
RELS=()   # "RECEIVER|||PROJECT|||DR_ID|||REL|||HASH"
TMP="$(mktemp_tmp)"
found_pages=0
found_urls=0

URL="${BASE}/DocumentReference?_count=${PAGE_SIZE}"
while [ -n "$URL" ] && [ "$found_pages" -lt "$MAX_PAGES" ]; do
  log "INFO" "Loading DocumentReference page: $URL"
  if ! curl_json "$URL" -o "$TMP"; then
    log "ERROR" "DocumentReference request failed: $URL"
    break
  fi
  found_pages=$((found_pages+1))

  lines_tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
    def parse_master(v; p):
      (v // "") as $v
      | if ($v | startswith(p)) then
          ($v | sub("^"+p; "") | split("_")) as $parts
          | ($parts | length) as $len
          | if $len >= 3 then
              { receiver: $parts[0], project: $parts[1], hash: ($parts[2:] | join("_")) }
            elif $len == 2 then
              { receiver: "DKFZ", project: $parts[0], hash: $parts[1] }
            else
              { receiver: "DKFZ", project: "UNKNOWN_PROJECT", hash: "" }
            end
        else
          empty
        end;
    .entry[]?.resource as $r
    | ($r.masterIdentifier.value // "") as $mi
    | parse_master($mi; $p) as $m
    | [$r.id,
       $m.receiver,
       $m.project,
       ($r.content[]? | .attachment.url // empty),
       $m.hash
      ]
    | select(.[3] != null)
    | @tsv
  ' "$TMP" 2>/dev/null || true)"

  if [ -n "$lines_tsv" ]; then
    while IFS=$'\t' read -r _drid _recv _proj _url _hash; do
      [ -z "$_url" ] && continue
      rel="$(printf '%s\n' "$_url" | normalize_rel)"
      RELS+=("${_recv}|||${_proj}|||${_drid}|||${rel}|||${_hash}")
      found_urls=$((found_urls+1))
    done <<< "$lines_tsv"
  fi

  URL="$(next_url "$TMP")"
done

rm -f "$TMP"

if [ "${#RELS[@]}" -eq 0 ]; then
  log "WARN" "No candidates found (pages=${found_pages}, urls=${found_urls})"
  log "INFO" "Done (nothing to do)"
  exit 0
else
  deduped="$(printf '%s\n' "${RELS[@]}" | awk 'NF' | sort -u)"
  RELS=()
  while IFS= read -r line; do
    [ -n "$line" ] && RELS+=("$line")
  done <<< "$deduped"
  log "INFO" "Total candidates (deduplicated): ${#RELS[@]}"
fi

############################
# Download + process + optional FHIR delete
############################
for entry in "${RELS[@]}"; do
  receiver="${entry%%|||*}"
  rest="${entry#*|||}"
  project="${rest%%|||*}"
  rest="${rest#*|||}"
  dr_id="${rest%%|||*}"
  rest="${rest#*|||}"
  rel="${rest%%|||*}"
  hash="${rest#*|||}"
  [ "$hash" = "$rest" ] && hash=""

  tmpzip="$(mktemp_zip)"

  if ! download_binary_to_zip "$rel" "$tmpzip" "$hash"; then
    log "ERROR" "Skipping DocRef='${dr_id}' due to download error"
    rm -f "$tmpzip"
    continue
  fi

  if ! process_zip_for_receiver_project "$tmpzip" "$receiver" "$project"; then
    log "ERROR" "Skipping DocRef='${dr_id}' due to processing error (FHIR delete suppressed)"
    rm -f "$tmpzip"
    continue
  fi

  rm -f "$tmpzip"

  delete_doc_and_binary "$dr_id" "$rel"
done

log "INFO" "Done"
