#!/usr/bin/env bash
set -euo pipefail

"""
Example for a FILESTATE:

{
  "project": "XY",
  "stateId": "2025-11-14T13:37:00+01:00",
  "generatedAt": "2025-11-14T13:37:00+01:00",
  "prefix": "NCT-DKFZ-DE",
  "targetReceiver": "NAME",

  "files": [
    {
      "relativePath": "Pseudo001/studyA/series01.zip",
      "masterIdentifier": "NCT-DKFZ-DE_DKFZ_XY_abcd1234...",
      "lastModified": "2025-11-14T12:30:00+01:00",
      "size": 123456
    },
    {
      "relativePath": "Pseudo001/studyA/series02.zip",
      "masterIdentifier": "NCT-DKFZ-DE_DKFZ_XY_efefefef...",
      "lastModified": "2025-11-14T12:32:00+01:00",
      "size": 234567
    }
  ]
}

"""

############################
# Konfiguration
############################
SSH_HOST="dsf-bpe-test"
SSH_USER="root"
LOCAL_PORT="${LOCAL_PORT:-8089}"
REMOTE_FHIR="10.128.129.159:8080"
BASE="https://blaze.sci.dkfz.de/fhir"

IDENT_SYSTEM="http://medizininformatik-initiative.de/sid/project-identifier"
: "${SEARCH_PREFIX:=NCT-DKFZ-DE_}"
IDENT_VALUE_EXACT="${IDENT_VALUE_EXACT:-}"

# Spezieller Receiver für FileState-Resourcen
: "${FILESTATE_RECEIVER:=FILESTATE}"
# Dateiname im ZIP, der das JSON enthält
: "${FILESTATE_JSON_NAME:=filestate.json}"

# Nach Download löschen?
: "${DELETE_AFTER_DOWNLOAD:=1}"      # 1=an, 0=aus
: "${FORCE_HISTORY_DELETE:=0}"       # 1=History-Delete auch ohne Capability versuchen

OUTDIR="$HOME/Desktop/celina/DKFZ_Zips"
STATE="$HOME/.dkfz_fetch_state.txt"
LOG="/tmp/fetch_dkfz_zips.log"

CONNECT_TIMEOUT=5
MAX_TIME=120
RETRIES=2
RETRY_DELAY=2
MAX_PAGES=50

############################
# Hilfsfunktionen
############################
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; NC=$'\033[0m'

ts(){
  if date -Iseconds >/dev/null 2>&1; then
    date -Iseconds
  else
    d="$(date "+%Y-%m-%dT%H:%M:%S%z")"
    printf '%s\n' "$d" | sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'
  fi
}
log(){ echo "$(ts) [$1] $2" | tee -a "$LOG"; }
die(){ log "ERROR" "$1"; exit 1; }
need_bin(){ command -v "$1" >/dev/null 2>&1 || die "fehlendes Programm: $1"; }

if base64 --help 2>/dev/null | grep -q '\-d'; then B64_FLAG="-d"; else B64_FLAG="-D"; fi
b64d(){ base64 "$B64_FLAG"; }

mktemp_zip(){ mktemp -t dkfz_zip.XXXXXX; }
mktemp_tmp(){ mktemp -t dkfz_tmp.XXXXXX; }
mktemp_dr(){  mktemp -t dkfz_dr.XXXXXX; }
mktemp_fs(){  mktemp -t dkfz_fs.XXXXXX; }

# Mapping DocRef-ID -> masterIdentifier.value für Fehlerlogs & Routing-Logs
DRMI_TMP="$(mktemp -t dkfz_drmi.XXXXXX)"
get_mi_value(){
  local id="${1-}"
  [ -z "$id" ] && { echo ""; return; }
  awk -F $'\t' -v id="$id" '($1==id){print $2; exit}' "$DRMI_TMP" 2>/dev/null || true
}

cleanup_all(){
  if [ -S "${CTRL:-}" ]; then ssh -S "$CTRL" -O exit "${SSH_USER}@${SSH_HOST}" >/dev/null 2>&1 || true; fi
  if [ -n "${LOCKDIR:-}" ]; then rmdir "$LOCKDIR" >/dev/null 2>&1 || true; fi
  rm -f "$DRMI_TMP" >/dev/null 2>&1 || true
  log "INFO" "SSH-Tunnel beendet und Lock freigegeben"
}
trap cleanup_all EXIT

curl_json(){ curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" -H "Accept: application/fhir+json" "$@"; }
curl_bin(){  curl -fS  -L --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" -H "Accept: application/octet-stream" "$@"; }

normalize_rel(){ sed -E 's#^https?://[^/]+/fhir/##' | sed -E 's#^/##'; }
strip_history(){ sed -E 's#/_history/[^/]+$##'; }
safe_project(){ tr -cd 'A-Za-z0-9._-'; }

compute_sha256(){
  local f="$1" sum=""
  if command -v sha256sum >/dev/null 2>&1; then sum="$(sha256sum "$f" | awk '{print tolower($1)}')"
  elif command -v shasum   >/dev/null 2>&1; then sum="$(shasum -a 256 "$f" | awk '{print tolower($1)}')"
  elif command -v openssl  >/dev/null 2>&1; then sum="$(openssl dgst -sha256 -r "$f" | awk '{print tolower($1)}')"
  else echo ""; return 1; fi
  echo "$sum"
}

next_url(){
  local resp="$1" nxt
  nxt="$(jq -r '.link[]? | select(.relation=="next") | .url // empty' "$resp")"
  [ -z "$nxt" ] && { echo ""; return; }
  echo "$nxt" | sed -E "s#^https?://[^/]+/fhir#${BASE}#"
}

# HTTP DELETE mit Retries; gibt Code oder 000
_http_delete(){
  local url="${1-}"
  [ -n "${url}" ] || { echo "000"; return 0; }
  curl -sS -o /dev/null -w "%{http_code}" \
       --connect-timeout "$CONNECT_TIMEOUT" \
       --max-time "$MAX_TIME" \
       --retry "$RETRIES" --retry-delay "$RETRY_DELAY" --retry-connrefused \
       -H "Accept: application/fhir+json" \
       -H "Connection: close" \
       -X DELETE "$url" || echo "000"
}
_delete_ok(){ case "${1-}" in 200|202|204|404|410) return 0 ;; *) return 1 ;; esac; }

# verify gone (404/410)
_verify_gone(){
  local rtype="${1-}" rid="${2-}"
  local s; s="$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/${rtype}/${rid}")" || s="000"
  case "$s" in 404|410) return 0 ;; *) return 1 ;; esac
}

# current delete mit Verify (max. 6 Versuche)
delete_with_verify(){
  local rtype="${1-}"; local rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log "ERROR" "DELETE: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"; return 1
  fi
  if _verify_gone "$rtype" "$rid"; then
    log "INFO" "${rtype}/${rid} bereits entfernt (verify=gone)"; return 0
  fi
  local url="${BASE}/${rtype}/${rid}"
  local tries=0 code=""
  while :; do
    code="$(_http_delete "$url")"
    [ "$code" = "000" ] && log "WARN" "Transportfehler beim DELETE (kein HTTP-Code) – URL=$url" || log "INFO" "DELETE ${rtype}/${rid} → $code"
    if _verify_gone "$rtype" "$rid"; then
      log "INFO" "${rtype}/${rid} entfernt (verify=gone)"; return 0
    fi
    tries=$((tries+1)); [ $tries -ge 6 ] && break
    sleep 1
  done
  log "ERROR" "${rtype}/${rid} nach DELETE noch vorhanden (verify!=gone)"
  return 1
}

fhir_delete_history(){
  local rtype="${1-}"; local rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log "ERROR" "DELETE _history: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  if [ "${HAS_DELETE_HISTORY}" != "1" ] && [ "${FORCE_HISTORY_DELETE}" != "1" ]; then
    log "INFO" "History-Delete nicht beworben – übersprungen für ${rtype}/${rid}"
    return 0
  fi
  local url="${BASE}/${rtype}/${rid}/_history"
  local code; code="$(_http_delete "$url")"
  if _delete_ok "$code"; then log "INFO" "DELETE ${rtype}/${rid}/_history → $code"; else log "WARN" "DELETE ${rtype}/${rid}/_history → $code"; fi
}

# Binary-ID-Parsing
binary_id_from_url(){
  local u="${1-}"
  [ -z "$u" ] && { echo ""; return; }
  u="${u%%\?*}"
  case "$u" in
    http://*|https://*)
      u="${u#*://}"; [[ "$u" == */fhir/* ]] && u="${u#*/fhir/}"
      ;;
  esac
  u="${u#/}"; u="$(printf '%s' "$u" | strip_history)"
  if [[ "$u" == Binary/* ]]; then printf '%s\n' "${u#Binary/}" | cut -d/ -f1; else echo ""; fi
}

############################
# Download eines Binaries zu einer Zieldatei per masterIdentifier
############################
download_by_masterid(){
  local mi="$1"
  local target_file="$2"

  if [ -z "$mi" ] || [ -z "$target_file" ]; then
    log "ERROR" "FileState: download_by_masterid mit fehlenden Parametern (mi='${mi-}', target='${target_file-}')"
    return 1
  fi

  local enc_sys enc_val url tmp
  enc_sys="$(printf '%s' "$IDENT_SYSTEM" | sed 's/|/%7C/g')"
  enc_val="$(printf '%s' "$mi" | sed 's/|/%7C/g')"
  url="${BASE}/DocumentReference?identifier=${enc_sys}%7C${enc_val}&_count=1"

  tmp="$(mktemp_tmp)"
  if ! curl_json "$url" -o "$tmp"; then
    log "ERROR" "FileState: Suche nach masterIdentifier fehlgeschlagen: ${mi}"
    rm -f "$tmp"
    return 1
  fi

  local dr_id att_url
  dr_id="$(jq -r '.entry[0].resource.id // empty' "$tmp")"
  att_url="$(jq -r '.entry[0].resource.content[]?.attachment.url // empty' "$tmp" | head -n1)"

  if [ -z "$dr_id" ] || [ -z "$att_url" ]; then
    log "ERROR" "FileState: Keine passende DocumentReference/Binary für masterIdentifier=${mi}"
    rm -f "$tmp"
    return 1
  fi

  local rel rel_nover bid tmpzip got ver rel_ver
  rel="$(printf '%s\n' "$att_url" | normalize_rel)"
  rel_nover="$(printf '%s' "$rel" | strip_history)"
  bid="$(binary_id_from_url "$rel_nover")"

  if [ -z "$bid" ]; then
    log "ERROR" "FileState: Konnte Binary-ID nicht aus URL ableiten (masterIdentifier=${mi}, url=${att_url})"
    rm -f "$tmp"
    return 1
  fi

  tmpzip="$(mktemp_zip)"
  got=0

  # 1) FHIR-JSON (.data)
  if curl_json "${BASE}/${rel}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FileState: FHIR-JSON erfolgreich: ${rel} (Binary=${bid})"
  elif curl_json "${BASE}/${rel_nover}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FileState: FHIR-JSON erfolgreich (ohne _history): ${rel_nover} (Binary=${bid})"
  fi

  # 2) RAW
  if [ "$got" -eq 0 ]; then
    if curl_bin "${BASE}/${rel}" -o "$tmpzip" 2>>"$LOG" \
    || curl_bin "${BASE}/${rel_nover}" -o "$tmpzip" 2>>"$LOG"; then
      got=1; log "INFO" "FileState: RAW-ZIP erfolgreich: ${rel} (Binary=${bid})"
    fi
  fi

  # 3) History-Fallback
  if [ "$got" -eq 0 ]; then
    ver="$(curl_json "${BASE}/${rel_nover}/_history" 2>>"$LOG" \
         | jq -r '.entry[]?.resource?.meta?.versionId // empty' | awk 'NF' | sort -n | tail -n1)"
    if [ -n "$ver" ]; then
      rel_ver="${rel_nover}/_history/${ver}"
      if curl_json "${BASE}/${rel_ver}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG" \
      || curl_bin "${BASE}/${rel_ver}" -o "$tmpzip" 2>>"$LOG"; then
        got=1; log "INFO" "FileState: Versioniertes Read erfolgreich: ${rel_ver} (Binary=${bid})"
      fi
    fi
  fi

  if [ "$got" -eq 0 ]; then
    log "ERROR" "FileState: Download Binary fehlgeschlagen (masterIdentifier=${mi}, Binary=${bid})"
    rm -f "$tmpzip" "$tmp"
    return 1
  fi

  # SHA-Check aus masterIdentifier (letzte Komponente)
  local expected_hash
  expected_hash="$(printf '%s' "$mi" | awk -F'_' '{print $NF}' | tr '[:upper:]' '[:lower:]')"
  if [ -n "$expected_hash" ]; then
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
      local act
      act="$(compute_sha256 "$tmpzip")"
      if [ -n "$act" ]; then
        if [ "$act" = "$expected_hash" ]; then
          log "INFO" "${GREEN}FileState: SHA256 OK (Binary=${bid}): $act${NC}"
        else
          log "WARN" "${RED}FileState: SHA256 MISMATCH (Binary=${bid}): expected=$expected_hash got=$act${NC}"
        fi
      else
        log "WARN" "FileState: SHA256 konnte nicht berechnet werden (Binary=${bid})"
      fi
    fi
  fi

  mkdir -p "$(dirname "$target_file")"
  mv "$tmpzip" "$target_file"
  log "SUCCESS" "FileState: Datei gespeichert: ${target_file} (Binary=${bid})"

  if [ "${DELETE_AFTER_DOWNLOAD}" = "1" ]; then
    delete_with_verify "Binary" "$bid" || true
    fhir_delete_history "Binary" "$bid" || true
    delete_with_verify "DocumentReference" "$dr_id" || true
    fhir_delete_history "DocumentReference" "$dr_id" || true
  fi

  rm -f "$tmp"
  return 0
}

############################
# FileState-JSON anwenden
############################
apply_filestate_json(){
  local json="$1"

  local project targetReceiver prefix_json
  project="$(jq -r '.project // empty' "$json")" || project=""
  targetReceiver="$(jq -r '.targetReceiver // empty' "$json")" || targetReceiver=""
  prefix_json="$(jq -r '.prefix // empty' "$json")" || prefix_json=""

  if [ -z "$project" ]; then
    log "ERROR" "FileState: JSON ohne 'project' – wird ignoriert"
    return 1
  fi

  local safe_proj safe_recv proj_root
  safe_proj="$(printf '%s' "$project" | safe_project)"
  [ -z "$safe_proj" ] && safe_proj="UNKNOWN"

  if [ -n "$targetReceiver" ]; then
    safe_recv="$(printf '%s' "$targetReceiver" | safe_project)"
    [ -z "$safe_recv" ] && safe_recv="UNKNOWN_RECEIVER"
    proj_root="${OUTDIR}/${safe_recv}/${safe_proj}"
  else
    proj_root="${OUTDIR}/${safe_proj}"
  fi

  mkdir -p "$proj_root"

  log "INFO" "FileState: anwenden auf project='${project}' targetReceiver='${targetReceiver}' proj_root='${proj_root}' prefix='${prefix_json}'"

  local files_tsv desired_paths actual_paths
  files_tsv="$(mktemp_fs)"
  desired_paths="$(mktemp_fs)"
  actual_paths="$(mktemp_fs)"

  if ! jq -r '.files[]? | [.relativePath, .masterIdentifier] | @tsv' "$json" > "$files_tsv"; then
    log "ERROR" "FileState: JSON ohne gültige files-Liste"
    rm -f "$files_tsv" "$desired_paths" "$actual_paths"
    return 1
  fi

  cut -f1 "$files_tsv" | awk 'NF' | sort -u > "$desired_paths"

  if [ -d "$proj_root" ]; then
    ( cd "$proj_root" && find . -type f | sed 's#^\./##' ) | awk 'NF' | sort -u > "$actual_paths"
  else
    : > "$actual_paths"
  fi

  # Löschen: Dateien, die im lokalen Projektordner existieren, aber nicht mehr im FileState sind
  local p
  while IFS= read -r p; do
    grep -Fxq "$p" "$desired_paths" && continue
    log "INFO" "FileState: lösche veraltete Datei: ${proj_root}/${p}"
    rm -f "${proj_root}/${p}" || log "WARN" "FileState: Konnte Datei nicht löschen: ${proj_root}/${p}"
  done < "$actual_paths"

  # Nachziehen: Dateien, die im FileState stehen, aber lokal noch fehlen
  local rel_path mi full_path
  while IFS=$'\t' read -r rel_path mi; do
    [ -z "$rel_path" ] && continue
    full_path="${proj_root}/${rel_path}"
    if [ -f "$full_path" ]; then
      continue
    fi
    log "INFO" "FileState: fehlende Datei, masterIdentifier='${mi}', pfad='${full_path}' – Suche im FHIR"
    download_by_masterid "$mi" "$full_path" || log "ERROR" "FileState: Download für masterIdentifier='${mi}' fehlgeschlagen"
  done < "$files_tsv"

  rm -f "$files_tsv" "$desired_paths" "$actual_paths"
  return 0
}

############################
# Vorbereitungen
############################
: > "$LOG"; mkdir -p "$OUTDIR"; touch "$STATE"
need_bin curl; need_bin jq; need_bin base64; need_bin ssh; need_bin sed; need_bin awk; need_bin lsof; need_bin unzip; need_bin find

if command -v sha256sum >/dev/null 2>&1; then log "INFO" "SHA256-Prüfung via sha256sum aktiv"
elif command -v shasum >/dev/null 2>&1; then   log "INFO" "SHA256-Prüfung via shasum aktiv"
elif command -v openssl >/dev/null 2>&1; then  log "INFO" "SHA256-Prüfung via openssl aktiv"
else log "WARN" "Kein Tool für SHA256 gefunden – Hash-Check wird übersprungen"; fi

log "INFO" "Start; Ziel: $OUTDIR, State: $STATE"
log "INFO" "Filter: system=$IDENT_SYSTEM | prefix=$SEARCH_PREFIX | exact='${IDENT_VALUE_EXACT:-}'"
log "INFO" "DELETE_AFTER_DOWNLOAD=${DELETE_AFTER_DOWNLOAD} FORCE_HISTORY_DELETE=${FORCE_HISTORY_DELETE} FILESTATE_RECEIVER=${FILESTATE_RECEIVER}"

############################
# Lock + SSH-Tunnel
############################
LOCK_NAME="/tmp/fetch_dkfz_zips.lock"; LOCKDIR=""
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_NAME"
  if ! flock -n 9; then log "WARN" "bereits laufend, Ende"; exit 0; fi
  log "INFO" "Lock via flock aktiv"
else
  LOCKDIR="${LOCK_NAME}.d"
  if ! mkdir "$LOCKDIR" 2>/dev/null; then log "WARN" "bereits laufend (Lockdir), Ende"; exit 0; fi
  log "INFO" "Lock via Lockdir aktiv"
fi

CTRL="/tmp/dkfz_fetch_${LOCAL_PORT}.sock"
if lsof -iTCP:${LOCAL_PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
  if curl_json "${BASE}/metadata" -o /dev/null; then
    log "INFO" "Tunnel bereits offen (Port ${LOCAL_PORT})"
  else
    log "WARN" "Port ${LOCAL_PORT} belegt, aber kein FHIR erreichbar – wechsle Port"
    for p in 8091 8092 8093 18089 18090 19001; do
      if ! lsof -iTCP:${p} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
        LOCAL_PORT="$p"; BASE="https://blaze.sci.dkfz.de/fhir"; CTRL="/tmp/dkfz_fetch_${LOCAL_PORT}.sock"
        log "INFO" "nutze LOCAL_PORT=${LOCAL_PORT}"
        break
      fi
    done
  fi
fi

if ! curl_json "${BASE}/metadata" -o /dev/null; then
  ssh -S "$CTRL" -O exit "${SSH_USER}@${SSH_HOST}" >/dev/null 2>&1 || true
  log "INFO" "baue SSH-Tunnel auf: ${LOCAL_PORT} -> ${REMOTE_FHIR} via ${SSH_USER}@${SSH_HOST}"
  ssh -o BatchMode=yes -o ExitOnForwardFailure=yes \
      -o ControlMaster=yes -o ControlPersist=no -S "$CTRL" \
      -f -N -L "${LOCAL_PORT}:${REMOTE_FHIR}" "${SSH_USER}@${SSH_HOST}" \
    || die "SSH-Tunnel fehlgeschlagen"
  curl_json "${BASE}/metadata" -o /dev/null || die "FHIR nicht erreichbar"
  log "INFO" "FHIR erreichbar: ${BASE}/metadata"
else
  log "INFO" "nutze bestehenden Tunnel auf Port ${LOCAL_PORT}"
fi

############################
# Capability-Check: delete-history
############################
HAS_DELETE_HISTORY=0
if resp="$(curl -fsS "${BASE}/metadata" | jq -r '.rest[]?.resource[]? | {t:.type, i:([.interaction[]?.code]|join(","))} | @tsv' 2>/dev/null)"; then
  if printf '%s\n' "$resp" | grep -q 'delete-history'; then HAS_DELETE_HISTORY=1; fi
fi
log "INFO" "delete-history beworben: ${HAS_DELETE_HISTORY}"

############################
# Kandidaten sammeln – nur FileState-DocumentReferences
############################
# Struktur: "RECEIVER|||PROJECT|||Binary/<id>|||HASH|||DR:<docref-id>"
RELS_FS=(); TMP="$(mktemp_tmp)"; found_pages=0; found_urls=0

# (A) Exakt (optional – wird nur verwendet, wenn IDENT_VALUE_EXACT gesetzt ist)
if [ -n "${IDENT_VALUE_EXACT:-}" ]; then
  URL="${BASE}/DocumentReference?identifier=$(printf '%s' "$IDENT_SYSTEM" | sed 's/|/%7C/g')%7C$(printf '%s' "$IDENT_VALUE_EXACT" | sed 's/|/%7C/g')&_count=200"
  while [ -n "$URL" ] && [ $found_pages -lt $MAX_PAGES ]; do
    log "INFO" "DR exakt laden: $URL"
    if ! curl_json "$URL" -o "$TMP"; then log "ERROR" "DR exakt fehlgeschlagen: $URL"; break; fi
    found_pages=$((found_pages+1))
    # Mapping DocRef-ID -> masterIdentifier.value
    jq -r '.entry[]?.resource | [.id, (.masterIdentifier.value // "")] | @tsv' "$TMP" >> "$DRMI_TMP"

    lines_tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
      def proj_receiver_proj_hash(v; p):
        ( if (p|length)>0
          then (v // "" | sub("^"+p; "") | split("_"))
          else (v // "" | split("_")[1:])
          end
        ) as $arr
        | ($arr | length) as $len
        | if   $len == 3 then [$arr[0], $arr[1], $arr[2]]
          elif $len == 2 then ["",       $arr[0], $arr[1]]
          else ["", "UNKNOWN", ""]
          end;
      .entry[]?.resource as $r
      | $r.masterIdentifier.value as $v
      | proj_receiver_proj_hash($v; $p) as $ph
      | [$r.id, $ph[0], $ph[1], ($r.content[]? | .attachment.url // empty), $ph[2]]
      | select(.[3] != null)
      | @tsv
    ' "$TMP")"

    if [ -n "$lines_tsv" ]; then
      while IFS=$'\t' read -r _drid _recv _proj _url _hash; do
        [ "$_recv" != "$FILESTATE_RECEIVER" ] && continue
        bid="$(binary_id_from_url "$_url")"
        [ -n "$bid" ] && RELS_FS+=("${_recv}|||${_proj}|||Binary/${bid}|||${_hash}|||DR:${_drid}") && found_urls=$((found_urls+1))
      done <<< "$lines_tsv"
    fi
    URL="$(next_url "$TMP")"
  done
fi

# (B) Vollscan (Prefix)
URL="${BASE}/DocumentReference?_count=200"
while [ -n "$URL" ] && [ $found_pages -lt $MAX_PAGES ]; do
  log "INFO" "DR-Seite laden: $URL"
  if ! curl_json "$URL" -o "$TMP"; then log "ERROR" "DR-Request fehlgeschlagen: $URL"; break; fi
  found_pages=$((found_pages+1))
  # Mapping DocRef-ID -> masterIdentifier.value
  jq -r '.entry[]?.resource | [.id, (.masterIdentifier.value // "")] | @tsv' "$TMP" >> "$DRMI_TMP"

  lines_tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
    def proj_receiver_proj_hash(v; p):
      ( if (p|length)>0
        then (v // "" | sub("^"+p; "") | split("_"))
        else (v // "" | split("_")[1:])
        end
      ) as $arr
      | ($arr | length) as $len
      | if   $len == 3 then [$arr[0], $arr[1], $arr[2]]
        elif $len == 2 then ["",       $arr[0], $arr[1]]
        else ["", "UNKNOWN", ""]
        end;
    .entry[]?.resource as $r
    | select( (($r.masterIdentifier.value // "") | startswith($p)) )
    | $r.masterIdentifier.value as $v
    | proj_receiver_proj_hash($v; $p) as $ph
    | [$r.id, $ph[0], $ph[1], ($r.content[]? | .attachment.url // empty), $ph[2]]
    | select(.[3] != null)
    | @tsv
  ' "$TMP")"

  if [ -n "$lines_tsv" ]; then
    while IFS=$'\t' read -r _drid _recv _proj _url _hash; do
      [ "$_recv" != "$FILESTATE_RECEIVER" ] && continue
      bid="$(binary_id_from_url "$_url")"
      [ -n "$bid" ] && RELS_FS+=("${_recv}|||${_proj}|||Binary/${bid}|||${_hash}|||DR:${_drid}") && found_urls=$((found_urls+1))
    done <<< "$lines_tsv"
  fi
  URL="$(next_url "$TMP")"
done

# Deduplizieren
if [ "${#RELS_FS[@]}" -eq 0 ]; then
  log "WARN" "keine FileState-Kandidaten gefunden (pages=$found_pages, urls=$found_urls)"
  log "INFO" "Fertig (nichts zu tun)"
  exit 0
else
  deduped="$(printf '%s\n' "${RELS_FS[@]}" | awk 'NF' | sort -u)"
  RELS_FS=()
  while IFS= read -r line; do [ -n "$line" ] && RELS_FS+=("$line"); done <<< "$deduped"
  log "INFO" "FileState-DocumentReferences gesamt (dedupliziert): ${#RELS_FS[@]}"
fi

############################
# FileState-Download + Anwendung + optionales Delete
############################
for entry in "${RELS_FS[@]}"; do
  receiver="${entry%%|||*}"
  rest="${entry#*|||}"
  project="${rest%%|||*}"
  rest2="${rest#*|||}"
  rel="${rest2%%|||*}"
  rest3="${rest2#*|||}"
  expected_hash="${rest3%%|||*}"
  meta="${rest3#*|||}"; [ "$meta" = "$rest3" ] && meta=""
  dr_id=""; [[ "$meta" == DR:* ]] && dr_id="${meta#DR:}"

  # FileState-ZIP (Binary) holen
  rel="${rel#/}"
  rel_nover="$(printf '%s' "$rel" | strip_history)"
  bid="$(binary_id_from_url "$rel_nover")"

  tmpzip="$(mktemp_zip)"
  got=0

  log "INFO" "FileState-DocRef=${dr_id:-?}, Binary-Rel=${rel}"

  # 1) FHIR-JSON (.data)
  if curl_json "${BASE}/${rel}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FileState: FHIR-JSON erfolgreich: $rel"
  elif curl_json "${BASE}/${rel_nover}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FileState: FHIR-JSON erfolgreich (ohne _history): $rel_nover"
  fi

  # 2) RAW
  if [ "$got" -eq 0 ]; then
    if curl_bin "${BASE}/${rel}" -o "$tmpzip" 2>>"$LOG" \
    || curl_bin "${BASE}/${rel_nover}" -o "$tmpzip" 2>>"$LOG"; then
      got=1; log "INFO" "FileState: RAW-ZIP erfolgreich: $rel"
    fi
  fi

  # 3) History-Fallback
  if [ "$got" -eq 0 ]; then
    ver="$(curl_json "${BASE}/${rel_nover}/_history" 2>>"$LOG" \
         | jq -r '.entry[]?.resource?.meta?.versionId // empty' | awk 'NF' | sort -n | tail -n1)"
    if [ -n "$ver" ]; then
      rel_ver="${rel_nover}/_history/${ver}"
      if curl_json "${BASE}/${rel_ver}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG" \
      || curl_bin "${BASE}/${rel_ver}" -o "$tmpzip" 2>>"$LOG"; then
        got=1; log "INFO" "FileState: Versioniertes Read erfolgreich: $rel_ver"
      fi
    fi
  fi

  if [ "$got" -eq 0 ]; then
    local_mi="$(get_mi_value "$dr_id")"
    log "ERROR" "FileState: Download fehlgeschlagen: rel=${rel} | DocRef=${dr_id:-?} | masterIdentifier='${local_mi:-unbekannt}'"
    rm -f "$tmpzip"
    continue
  fi

  # SHA-Check falls Hash im masterIdentifier des FileState-DocRefs hinterlegt war
  if [ -n "$expected_hash" ]; then
    exp="$(printf '%s' "$expected_hash" | tr '[:upper:]' '[:lower:]')"
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
      act="$(compute_sha256 "$tmpzip")"
      if [ -n "$act" ]; then
        [ "$act" = "$exp" ] && log "INFO" "${GREEN}FileState ZIP SHA256 OK (Binary=${bid:-unknown}): $act${NC}" \
                             || log "WARN" "${RED}FileState ZIP SHA256 MISMATCH (Binary=${bid:-unknown}): expected=$exp got=$act${NC}"
      else
        log "WARN" "FileState ZIP: SHA256 konnte nicht berechnet werden (Binary=${bid:-unknown})"
      fi
    fi
  fi

  # JSON aus dem ZIP holen
  fs_json="$(mktemp_fs)"
  if ! unzip -p "$tmpzip" "$FILESTATE_JSON_NAME" > "$fs_json" 2>/dev/null; then
    # Fallback: erste JSON-Datei im ZIP nehmen
    json_name="$(unzip -Z1 "$tmpzip" 2>/dev/null | awk '/\.json$/ {print; exit}')"
    if [ -z "${json_name:-}" ]; then
      log "ERROR" "FileState: ZIP enthält keine JSON-Datei"
      rm -f "$fs_json" "$tmpzip"
      continue
    fi
    if ! unzip -p "$tmpzip" "$json_name" > "$fs_json" 2>/dev/null; then
      log "ERROR" "FileState: JSON '${json_name}' konnte nicht extrahiert werden"
      rm -f "$fs_json" "$tmpzip"
      continue
    fi
  fi

  log "INFO" "FileState: JSON extrahiert, wende Zustand an (DocRef=${dr_id:-?})"
  apply_filestate_json "$fs_json" || log "ERROR" "FileState: Anwenden des JSON ist fehlgeschlagen"

  # FileState-ZIP optional in OUTDIR ablegen (für Debug)
  if [ -n "$project" ]; then
    safe_proj="$(printf '%s' "$project" | safe_project)"; [ -z "$safe_proj" ] && safe_proj="UNKNOWN"
    safe_recv="$(printf '%s' "$receiver" | safe_project)"; [ -z "$safe_recv" ] && safe_recv="UNKNOWN_RECEIVER"
    destdir="${OUTDIR}/${safe_recv}/${safe_proj}"
  else
    destdir="${OUTDIR}/${receiver:-FILESTATE}"
  fi
  mkdir -p "$destdir"
  mv "$tmpzip" "${destdir}/${bid:-filestate}.zip"
  log "SUCCESS" "FileState: ZIP gespeichert unter ${destdir}/${bid:-filestate}.zip"

  # FileState-DocRef + Binary im FHIR löschen
  if [ "${DELETE_AFTER_DOWNLOAD}" = "1" ]; then
    if [ -n "${dr_id:-}" ]; then
      if ! _verify_gone "DocumentReference" "$dr_id"; then
        delete_with_verify "DocumentReference" "$dr_id" || true
      else
        log "INFO" "DocumentReference/${dr_id} bereits entfernt (verify=gone)"
      fi
      fhir_delete_history "DocumentReference" "$dr_id" || true
    else
      log "WARN" "FileState: keine DocRef-ID bekannt – DocRef-DELETE übersprungen"
    fi

    if [ -n "${bid:-}" ]; then
      delete_with_verify "Binary" "$bid" || true
      fhir_delete_history "Binary" "$bid" || true
    else
      log "WARN" "FileState: keine Binary-ID bekannt – Binary-DELETE übersprungen"
    fi
  fi

  rm -f "$fs_json"
done

log "INFO" "Fertig"
