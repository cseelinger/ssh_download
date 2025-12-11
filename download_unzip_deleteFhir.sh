#!/usr/bin/env bash
set -euo pipefail
umask 0077

############################
# Pfade relativ zum Projektordner
############################
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd -P)"

RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
OUTDIR="${OUTDIR:-/mnt/OE0600-Projekte/MIC}"
TMP_DIR="${TMP_DIR:-$SCRIPT_DIR/tmp}"

mkdir -p "$RUN_DIR" "$LOG_DIR" "$TMP_DIR"

LOG="${LOG:-$LOG_DIR/download_unzip_deleteFhir.log}"

# Log-Retention: nur Zeilen der letzten 24 Stunden behalten
if [ -f "$LOG" ]; then
  cutoff="$(date -d '24 hours ago' +%s)"

  tmp_log="${LOG}.tmp"

  # Filtere nur Zeilen, deren Zeitstempel innerhalb der letzten 24h liegt
  awk -v cutoff="$cutoff" '
    {
      # Format: 2025-12-11T13:22:05+01:00 [INFO] ...
      # Extrahiere Timestamp-Feld
      ts = $1

      # +%Y-%m-%dT%H:%M:%S interpretieren → Unix timestamp
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
# Konfiguration
############################
# Basis-URL des FHIR-Servers (muss auf /fhir enden)
BASE="${FHIR_BASE:-https://blaze.sci.dkfz.de/fhir}"

# FHIR-Identifier-Filter (auf DocumentReference)
IDENT_SYSTEM="http://medizininformatik-initiative.de/sid/project-identifier"
# Präfix für masterIdentifier.value (inkl. Unterstrich)
: "${SEARCH_PREFIX:=NCT-DKFZ-DE_}"

# Netzwerk/Download-Parameter
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-120}"
RETRIES="${RETRIES:-2}"
RETRY_DELAY="${RETRY_DELAY:-2}"
MAX_PAGES="${MAX_PAGES:-50}"
PAGE_SIZE="${PAGE_SIZE:-200}"

# Löschen in FHIR nach erfolgreicher Verarbeitung?
: "${DELETE_AFTER_DOWNLOAD:=1}"
# delete-history erzwingen, auch wenn Capability nicht beworben
: "${FORCE_HISTORY_DELETE:=1}"
# FileState-Löschlogik aktiv?
: "${FILESTATE_DELETE_ENABLED:=1}"
# Name/Muster der FileState-JSON im ZIP
: "${FILESTATE_JSON_PATTERN:=filestate.json}"

############################
# Hilfsfunktionen
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
need_bin(){ command -v "$1" >/dev/null 2>&1 || die "fehlendes Programm: $1"; }

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
# FHIR-Delete-Helfer
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
    log "ERROR" "DELETE: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi

  if _verify_gone "$rtype" "$rid"; then
    log "INFO" "${rtype}/${rid} bereits entfernt (verify=gone)"
    return 0
  fi

  local url="${BASE}/${rtype}/${rid}"
  local tries=0 code
  while :; do
    code="$(_http_delete "$url")"
    if [ "$code" = "000" ]; then
      log "WARN" "Transportfehler beim DELETE (kein HTTP-Code) - URL=$url"
    else
      log "INFO" "DELETE ${rtype}/${rid} → $code"
    fi

    if _verify_gone "$rtype" "$rid"; then
      log "INFO" "${rtype}/${rid} entfernt (verify=gone)"
      return 0
    fi

    tries=$((tries+1))
    [ "$tries" -ge 6 ] && break
    sleep 1
  done

  log "ERROR" "${rtype}/${rid} nach DELETE noch vorhanden (verify!=gone)"
  return 1
}

fhir_delete_history(){
  local rtype="${1-}" rid="${2-}"
  if [ -z "$rtype" ] || [ -z "$rid" ]; then
    log "ERROR" "DELETE _history: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  if [ "${HAS_DELETE_HISTORY:-0}" != "1" ] && [ "${FORCE_HISTORY_DELETE}" != "1" ]; then
    log "INFO" "History-Delete nicht beworben - übersprungen für ${rtype}/${rid}"
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
# Filestate-Helfer
############################
cleanup_empty_dirs_under(){
  local root="$1"
  [ -d "$root" ] || return 0

  # Von unten nach oben durchlaufen und alle leeren Verzeichnisse entfernen,
  # aber den Projektordner selbst (root) stehen lassen.
  find "$root" -depth -type d 2>/dev/null | while IFS= read -r d; do
    # Projekt-Ordner selbst nicht löschen
    if [ "$d" = "$root" ]; then
      continue
    fi

    # rmdir löscht nur, wenn das Verzeichnis leer ist
    if rmdir "$d" 2>/dev/null; then
      log "INFO" "FILESTATE: leerer Ordner entfernt: $d"
    fi
  done
}

apply_filestate_json(){
  local json_file="$1" receiver="$2" project="$3"
  if [ "${FILESTATE_DELETE_ENABLED}" != "1" ]; then
    log "INFO" "FILESTATE: Delete deaktiviert - JSON wird ignoriert: $json_file"
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

  log "INFO" "FILESTATE: anwenden auf receiver='${eff_receiver}' project='${eff_project}' proj_root='${proj_root}'"

  local tmp_remote tmp_local
  tmp_remote="$(mktemp_tmp)"
  tmp_local="$(mktemp_tmp)"

  # Alle relativePath-Einträge rekursiv einsammeln
  if ! jq -r '.. | objects | .relativePath? // empty' "$json_file" 2>/dev/null \
      | awk 'NF' \
      | sed 's#^\./##' \
      | sort -u > "$tmp_remote"; then
    log "ERROR" "FILESTATE: relativePath-Auswertung fehlgeschlagen: $json_file"
    rm -f "$tmp_remote" "$tmp_local"
    return 1
  fi

  if [ ! -s "$tmp_remote" ]; then
    log "WARN" "FILESTATE: keine relativePath-Einträge gefunden - lösche komplettes Projektverzeichnis"
    if [ -d "$proj_root" ]; then
      find "$proj_root" -type f ! -name '*.json' -print0 \
        | while IFS= read -r -d '' f; do
            log "INFO" "FILESTATE: lösche Datei (Projekt leer): $f"
            rm -f -- "$f" || log "WARN" "FILESTATE: Konnte Datei nicht löschen: $f"
          done
      cleanup_empty_dirs_under "$proj_root"
    fi
    rm -f "$tmp_remote" "$tmp_local"
    return 0
  fi

  # Lokale Dateien im Projekt (ohne JSON)
  if [ -d "$proj_root" ]; then
    ( cd "$proj_root" && find . -type f ! -name '*.json' -print | sed 's#^\./##' ) \
      | sort -u > "$tmp_local" || true
  else
    : > "$tmp_local"
  fi

  # Dateien löschen, die lokal existieren, aber nicht mehr im FileState stehen
  local rel full
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    if ! grep -Fxq "$rel" "$tmp_remote"; then
      case "$rel" in
        *".."*) log "WARN" "FILESTATE: ignoriere verdächtigen Pfad mit '..': $rel"; continue ;;
      esac
      full="${proj_root}/${rel}"
      if [ -f "$full" ]; then
        log "INFO" "FILESTATE: lösche Datei: $full"
        rm -f -- "$full" || log "WARN" "FILESTATE: Konnte Datei nicht löschen: $full"
      fi
    fi
  done < "$tmp_local"

  cleanup_empty_dirs_under "$proj_root"

  rm -f "$tmp_remote" "$tmp_local"
  return 0
}

############################
# ZIP verarbeiten
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

  log "INFO" "ZIP-Verarbeitung: zip='${zip_path}' → receiver='${eff_receiver}' project='${eff_project}' proj_root='${proj_root}'"

  local entries files json_files normal_files
  mapfile -t entries < <(unzip -Z1 "$zip_path" 2>/dev/null || true)

  files=()
  for e in "${entries[@]}"; do
    # Verzeichnisse enden mit /
    if [[ "$e" == */ ]]; then
      continue
    fi
    files+=("$e")
  done

  if [ "${#files[@]}" -eq 0 ]; then
    log "ERROR" "ZIP hat keine Dateien (nur Verzeichnisse?) - wird als Fehler gewertet: ${zip_path}"
    return 1
  fi

  json_files=()
  normal_files=()
  local f
  for f in "${files[@]}"; do
    # FILESTATE_JSON_PATTERN als (Teil-)Muster behandeln
    if [[ "$f" == *"$FILESTATE_JSON_PATTERN" ]]; then
      json_files+=("$f")
    else
      normal_files+=("$f")
    fi
  done

  if [ "${#json_files[@]}" -eq 1 ] && [ "${#normal_files[@]}" -eq 0 ]; then
    # FileState-ZIP
    local json_in_zip json_dir json_file
    json_in_zip="${json_files[0]}"
    json_dir="$(dirname "$json_in_zip")"
    [ "$json_dir" = "." ] && json_dir=""

    if [ -n "$json_dir" ]; then
      mkdir -p "${proj_root}/${json_dir}"
    fi

    log "INFO" "FileState-ZIP erkannt (nur JSON: ${json_in_zip}) - extrahiere nach ${proj_root}"
    if ! unzip -oq "$zip_path" "$json_in_zip" -d "$proj_root" 2>/dev/null; then
      log "ERROR" "Konnte FileState-JSON nicht extrahieren: ${json_in_zip}"
      return 1
    fi

    json_file="${proj_root}/${json_in_zip}"
    if ! apply_filestate_json "$json_file" "$eff_receiver" "$eff_project"; then
      log "ERROR" "FileState-Anwendung fehlgeschlagen: ${json_file}"
      return 1
    fi

    # FileState-JSON wieder entfernen + leere Ordner bereinigen
    rm -f -- "$json_file" || log "WARN" "Konnte FileState-JSON nicht löschen: ${json_file}"
    cleanup_empty_dirs_under "$proj_root"

    log "INFO" "FileState-ZIP erfolgreich angewendet: ${zip_path}"
  else
    # Normale Daten-ZIP → einfach entpacken
    log "INFO" "Normales ZIP erkannt (Dateien=${#files[@]}), entpacke nach ${proj_root}"
    if ! unzip -oq "$zip_path" -d "$proj_root" 2>/dev/null; then
      log "ERROR" "Entpacken fehlgeschlagen: ${zip_path}"
      return 1
    fi
  fi

  # ZIP selbst entfernen, damit nur Inhalte übrig bleiben
  rm -f -- "$zip_path" || log "WARN" "Konnte ZIP nicht löschen: ${zip_path}"

  return 0
}

############################
# Binary herunterladen
############################
download_binary_to_zip(){
  local rel="$1" target_zip="$2" expected_hash="$3"

  local rel_nover ver rel_ver got=0
  rel="${rel#/}"
  rel_nover="$(printf '%s' "$rel" | strip_history)"

  log "INFO" "lade Binary: ${rel}"

  # 1) Versuche FHIR-JSON mit .data
  if curl_json "${BASE}/${rel}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG"; then
    got=1
    log "INFO" "FHIR-JSON erfolgreich: ${rel}"
  elif curl_json "${BASE}/${rel_nover}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG"; then
    got=1
    log "INFO" "FHIR-JSON erfolgreich (ohne _history): ${rel_nover}"
  fi

  # 2) RAW
  if [ "$got" -eq 0 ]; then
    if curl_bin "${BASE}/${rel}" -o "$target_zip" 2>>"$LOG" \
    || curl_bin "${BASE}/${rel_nover}" -o "$target_zip" 2>>"$LOG"; then
      got=1
      log "INFO" "RAW-ZIP erfolgreich: ${rel}"
    fi
  fi

  # 3) History-Fallback (neueste Version)
  if [ "$got" -eq 0 ]; then
    ver="$(curl_json "${BASE}/${rel_nover}/_history" 2>>"$LOG" \
          | jq -r '.entry[]?.resource?.meta?.versionId // empty' 2>/dev/null \
          | awk 'NF' | sort -n | tail -n1 || true)"
    if [ -n "$ver" ]; then
      rel_ver="${rel_nover}/_history/${ver}"
      if curl_json "${BASE}/${rel_ver}" | jq -er '.data' 2>/dev/null | b64d > "$target_zip" 2>>"$LOG" \
      || curl_bin "${BASE}/${rel_ver}" -o "$target_zip" 2>>"$LOG"; then
        got=1
        log "INFO" "Versioniertes Read erfolgreich: ${rel_ver}"
      fi
    fi
  fi

  if [ "$got" -eq 0 ]; then
    log "ERROR" "Download fehlgeschlagen: ${rel}"
    return 1
  fi

  # SHA-Check (optional)
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
        log "WARN" "SHA256 konnte nicht berechnet werden (Datei=${target_zip})"
      fi
    else
      log "WARN" "Kein Tool für SHA256 gefunden - Hash-Check übersprungen"
    fi
  else
    log "INFO" "Kein expected Hash im masterIdentifier - Check übersprungen"
  fi

  return 0
}

############################
# DocRef + Binary löschen (nur bei Erfolg)
############################
delete_doc_and_binary(){
  local dr_id="$1" rel="$2"

  if [ "${DELETE_AFTER_DOWNLOAD}" != "1" ]; then
    log "INFO" "DELETE_AFTER_DOWNLOAD!=1 - FHIR-Delete übersprungen (DocRef=${dr_id})"
    return 0
  fi

  if [ -z "$dr_id" ]; then
    log "WARN" "Keine DocRef-ID bekannt - FHIR-Delete übersprungen"
    return 0
  fi

  # Binary-ID aus rel extrahieren
  local rel_nover bid
  rel_nover="$(printf '%s' "$rel" | strip_history)"
  bid="$(printf '%s\n' "$rel_nover" | sed -nE 's#^Binary/([^/]+).*$#\1#p')"

  log "INFO" "FHIR-Delete vorbereiten: DocRef=${dr_id}, Binary=${bid:-unbekannt}"

  # Reihenfolge: zuerst DocRef, dann Binary
  delete_with_verify "DocumentReference" "$dr_id" || log "WARN" "DocRef-Delete fehlgeschlagen (DocRef=${dr_id})"
  fhir_delete_history "DocumentReference" "$dr_id" || true

  if [ -n "$bid" ]; then
    delete_with_verify "Binary" "$bid" || log "WARN" "Binary-Delete fehlgeschlagen (Binary=${bid})"
    fhir_delete_history "Binary" "$bid" || true
  else
    log "WARN" "Keine Binary-ID aus rel ableitbar - Binary-Delete übersprungen"
  fi
}

############################
# Voraussetzungen prüfen
############################
need_bin curl
need_bin jq
need_bin base64
need_bin sed
need_bin awk
need_bin unzip
need_bin find

if command -v sha256sum >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via sha256sum aktiv"
elif command -v shasum >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via shasum aktiv"
elif command -v openssl >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via openssl aktiv"
else
  log "WARN" "Kein Tool für SHA256 gefunden - Hash-Check wird übersprungen"
fi

log "INFO" "Start; Ziel: $OUTDIR"
log "INFO" "FHIR-Basis: $BASE"

# Prüfen, ob OUTDIR verfügbar ist (z. B. CIFS-Mount)
if [ ! -d "$OUTDIR" ]; then
  log "ERROR" "OUTDIR nicht erreichbar: $OUTDIR - vermutlich CIFS-Mount nicht vorhanden."
  exit 1
fi

# Prüfen, ob OUTDIR beschreibbar ist
if [ ! -w "$OUTDIR" ]; then
  log "ERROR" "OUTDIR ist nicht beschreibbar: $OUTDIR"
  exit 1
fi

log "INFO" "Filter: system=$IDENT_SYSTEM | prefix=$SEARCH_PREFIX | exact=''"
log "INFO" "DELETE_AFTER_DOWNLOAD=${DELETE_AFTER_DOWNLOAD} FILESTATE_DELETE_ENABLED=${FILESTATE_DELETE_ENABLED} FORCE_HISTORY_DELETE=${FORCE_HISTORY_DELETE}"

curl_json "${BASE}/metadata" -o /dev/null || die "FHIR nicht erreichbar: ${BASE}/metadata"
log "INFO" "FHIR erreichbar"

# Capability-Check delete-history
HAS_DELETE_HISTORY=0
if resp="$(curl -fsS "${BASE}/metadata" 2>/dev/null | jq -r '.rest[]?.resource[]? | {t:.type, i:([.interaction[]?.code]|join(","))} | @tsv' 2>/dev/null)"; then
  if printf '%s\n' "$resp" | grep -q 'delete-history'; then
    HAS_DELETE_HISTORY=1
  fi
fi
log "INFO" "delete-history beworben: ${HAS_DELETE_HISTORY}"

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
    log "WARN" "bereits laufend, Ende"
    exit 0
  fi
  log "INFO" "Lock via flock aktiv: $LOCK_NAME"
else
  LOCKDIR="${LOCK_NAME}.d"
  if ! mkdir "$LOCKDIR" 2>/dev/null; then
    log "WARN" "bereits laufend (Lockdir), Ende"
    exit 0
  fi
  log "INFO" "Lock via Lockdir aktiv: $LOCKDIR"
fi

############################
# Kandidaten sammeln
############################
RELS=()   # "RECEIVER|||PROJECT|||DR_ID|||REL|||HASH"
TMP="$(mktemp_tmp)"
found_pages=0
found_urls=0

URL="${BASE}/DocumentReference?_count=${PAGE_SIZE}"
while [ -n "$URL" ] && [ "$found_pages" -lt "$MAX_PAGES" ]; do
  log "INFO" "DR-Seite laden: $URL"
  if ! curl_json "$URL" -o "$TMP"; then
    log "ERROR" "DR-Request fehlgeschlagen: $URL"
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
  log "WARN" "keine Kandidaten gefunden (pages=${found_pages}, urls=${found_urls})"
  log "INFO" "Fertig (nichts zu tun)"
  exit 0
else
  deduped="$(printf '%s\n' "${RELS[@]}" | awk 'NF' | sort -u)"
  RELS=()
  while IFS= read -r line; do
    [ -n "$line" ] && RELS+=("$line")
  done <<< "$deduped"
  log "INFO" "Kandidaten gesamt (dedupliziert): ${#RELS[@]}"
fi

############################
# Download + Verarbeiten + optionales FHIR-Delete
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
    log "ERROR" "Überspringe DocRef='${dr_id}' wegen Downloadfehler"
    rm -f "$tmpzip"
    continue
  fi

  if ! process_zip_for_receiver_project "$tmpzip" "$receiver" "$project"; then
    log "ERROR" "Überspringe DocRef='${dr_id}' wegen Verarbeitungsfehler (FHIR-DELETE unterbleibt)"
    rm -f "$tmpzip"
    continue
  fi

  rm -f "$tmpzip"

  delete_doc_and_binary "$dr_id" "$rel"
done

log "INFO" "Fertig"
