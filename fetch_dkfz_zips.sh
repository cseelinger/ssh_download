#!/usr/bin/env bash
set -euo pipefail

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

extract_binary_ids_from_docref_json(){
  jq -r '.content[]? | .attachment.url? // empty' "$1" | while IFS= read -r u; do
    bid="$(binary_id_from_url "$u")"; [ -n "$bid" ] && echo "$bid"
  done | sort -u
}

############################
# Vorbereitungen
############################
: > "$LOG"; mkdir -p "$OUTDIR"; touch "$STATE"
need_bin curl; need_bin jq; need_bin base64; need_bin ssh; need_bin sed; need_bin awk; need_bin lsof

if command -v sha256sum >/dev/null 2>&1; then log "INFO" "SHA256-Prüfung via sha256sum aktiv"
elif command -v shasum >/dev/null 2>&1; then   log "INFO" "SHA256-Prüfung via shasum aktiv"
elif command -v openssl >/dev/null 2>&1; then  log "INFO" "SHA256-Prüfung via openssl aktiv"
else log "WARN" "Kein Tool für SHA256 gefunden – Hash-Check wird übersprungen"; fi

log "INFO" "Start; Ziel: $OUTDIR, State: $STATE"
log "INFO" "Filter: system=$IDENT_SYSTEM | prefix=$SEARCH_PREFIX | exact='${IDENT_VALUE_EXACT:-}'"
log "INFO" "DELETE_AFTER_DOWNLOAD=${DELETE_AFTER_DOWNLOAD} FORCE_HISTORY_DELETE=${FORCE_HISTORY_DELETE}"

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
# Kandidaten sammeln (nur DocumentReference)
############################
# Struktur: "RECEIVER|||PROJECT|||Binary/<id>|||HASH|||DR:<docref-id>"
RELS=(); TMP="$(mktemp_tmp)"; found_pages=0; found_urls=0

# (A) Exakt
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
        bid="$(binary_id_from_url "$_url")"
        [ -n "$bid" ] && RELS+=("${_recv}|||${_proj}|||Binary/${bid}|||${_hash}|||DR:${_drid}") && found_urls=$((found_urls+1))
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
      bid="$(binary_id_from_url "$_url")"
      [ -n "$bid" ] && RELS+=("${_recv}|||${_proj}|||Binary/${bid}|||${_hash}|||DR:${_drid}") && found_urls=$((found_urls+1))
    done <<< "$lines_tsv"
  fi
  URL="$(next_url "$TMP")"
done

# Deduplizieren
if [ "${#RELS[@]}" -eq 0 ]; then
  log "WARN" "keine Kandidaten gefunden (pages=$found_pages, urls=$found_urls)"
  exit 0
else
  deduped="$(printf '%s\n' "${RELS[@]}" | awk 'NF' | sort -u)"
  RELS=(); while IFS= read -r line; do [ -n "$line" ] && RELS+=("$line"); done <<< "$deduped"
  log "INFO" "Kandidaten gesamt (dedupliziert): ${#RELS[@]}"
fi

############################
# Download + optionales Delete
############################
for entry in "${RELS[@]}"; do
  receiver="${entry%%|||*}"
  rest="${entry#*|||}"
  project="${rest%%|||*}"
  rest2="${rest#*|||}"
  rel="${rest2%%|||*}"
  rest3="${rest2#*|||}"
  expected_hash="${rest3%%|||*}"
  meta="${rest3#*|||}"; [ "$meta" = "$rest3" ] && meta=""
  dr_id=""; [[ "$meta" == DR:* ]] && dr_id="${meta#DR:}"

  # Zielpfade: optional Empfänger als Überordner
  if [ -n "$project" ]; then
    safe_proj="$(printf '%s' "$project" | safe_project)"; [ -z "$safe_proj" ] && safe_proj="UNKNOWN"
    if [ -n "$receiver" ]; then
      safe_recv="$(printf '%s' "$receiver" | safe_project)"; [ -z "$safe_recv" ] && safe_recv="UNKNOWN_RECEIVER"
      destdir="${OUTDIR}/${safe_recv}/${safe_proj}"
    else
      destdir="${OUTDIR}/${safe_proj}"
    fi
  else
    destdir="${OUTDIR}"
  fi
  mkdir -p "$destdir"

  # Routing-Log: wie wurde der masterIdentifier aufgelöst?
  mi_val="$(get_mi_value "$dr_id")"
  if [ -n "${mi_val:-}" ]; then
    log "INFO" "Routing: masterIdentifier='${mi_val}' → receiver='${receiver:-}' project='${project:-}' destdir='${destdir}'"
  else
    log "INFO" "Routing: masterIdentifier=<unbekannt> → receiver='${receiver:-}' project='${project:-}' destdir='${destdir}'"
  fi

  rel="${rel#/}"; rel_nover="$(printf '%s' "$rel" | strip_history)"
  bid="$(binary_id_from_url "$rel_nover")"
  zip_path="${destdir}/${bid:-unknown}.zip"
  unpack_dir="${destdir}/${bid:-unknown}"
  marker="${zip_path}.done"

  # Bereits geladen?
  if [ -n "${bid}" ] && grep -qx "$bid" "$STATE"; then
    if [ -f "$zip_path" ]; then log "INFO" "skip ${bid} (bereits geladen; ZIP vorhanden)"; continue; fi
    if [ -d "$unpack_dir" ] || [ -f "$marker" ]; then log "INFO" "skip ${bid} (entpackt/Marker vorhanden)"; continue; fi
    log "INFO" "Re-Download: ${bid}"
  fi

  tmpzip="$(mktemp_zip)"
  log "INFO" "lade $rel (receiver=${receiver:-''}, project=${project:-''})"

  got=0
  # 1) FHIR-JSON (.data)
  if curl_json "${BASE}/${rel}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FHIR-JSON erfolgreich: $rel"
  elif curl_json "${BASE}/${rel_nover}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG"; then
    got=1; log "INFO" "FHIR-JSON erfolgreich (ohne _history): $rel_nover"
  fi

  # 2) RAW
  if [ "$got" -eq 0 ]; then
    if curl_bin "${BASE}/${rel}" -o "$tmpzip" 2>>"$LOG" \
    || curl_bin "${BASE}/${rel_nover}" -o "$tmpzip" 2>>"$LOG"; then
      got=1; log "INFO" "RAW-ZIP erfolgreich: $rel"
    fi
  fi

  # 3) History-Fallback (neueste versionId)
  if [ "$got" -eq 0 ]; then
    ver="$(curl_json "${BASE}/${rel_nover}/_history" 2>>"$LOG" \
         | jq -r '.entry[]?.resource?.meta?.versionId // empty' | awk 'NF' | sort -n | tail -n1)"
    if [ -n "$ver" ]; then
      rel_ver="${rel_nover}/_history/${ver}"
      if curl_json "${BASE}/${rel_ver}" | jq -er '.data' | b64d > "$tmpzip" 2>>"$LOG" \
      || curl_bin "${BASE}/${rel_ver}" -o "$tmpzip" 2>>"$LOG"; then
        got=1; log "INFO" "Versioniertes Read erfolgreich: $rel_ver"
      fi
    fi
  fi

  if [ "$got" -eq 0 ]; then
    mi="$(get_mi_value "$dr_id")"
    log "ERROR" "Download fehlgeschlagen: rel=${rel} | DocRef=${dr_id:-?} | masterIdentifier='${mi:-unbekannt}'"
    rm -f "$tmpzip"
    continue
  fi

  # SHA-256 Check (informativ)
  if [ -n "$expected_hash" ]; then
    exp="$(printf '%s' "$expected_hash" | tr '[:upper:]' '[:lower:]')"
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
      act="$(compute_sha256 "$tmpzip")"
      if [ -n "$act" ]; then
        [ "$act" = "$exp" ] && log "INFO" "${GREEN}SHA256 OK (ID=${bid:-unknown}): $act${NC}" \
                             || log "WARN" "${RED}SHA256 MISMATCH (ID=${bid:-unknown}): expected=$exp got=$act${NC}"
      else
        log "WARN" "SHA256 konnte nicht berechnet werden (ID=${bid:-unknown})"
      fi
    fi
  else
    log "INFO" "Kein expected Hash im masterIdentifier – Check übersprungen"
  fi

  mv "$tmpzip" "$zip_path"
  [ -n "${bid}" ] && echo "$bid" >> "$STATE"
  log "SUCCESS" "gespeichert: ${zip_path}"

  # --- optional: Löschen nach erfolgreichem Download ---
  if [ "${DELETE_AFTER_DOWNLOAD}" = "1" ]; then
    if [ -n "${dr_id:-}" ]; then
      if ! _verify_gone "DocumentReference" "$dr_id"; then
        delete_with_verify "DocumentReference" "$dr_id" || true
      else
        log "INFO" "DocumentReference/${dr_id} bereits entfernt (verify=gone)"
      fi
      fhir_delete_history "DocumentReference" "$dr_id" || true
    else
      log "WARN" "Keine DocRef-ID bekannt – überspringe DocRef-DELETE"
    fi

    if [ -n "${bid}" ]; then
      delete_with_verify "Binary" "$bid" || true
      fhir_delete_history "Binary" "$bid" || true
    else
      if [ -n "${dr_id:-}" ]; then
        tmp_dr="$(mktemp_dr)"
        if curl_json "${BASE}/DocumentReference/${dr_id}" -o "$tmp_dr"; then
          while IFS= read -r bbid; do
            [ -z "$bbid" ] && continue
            delete_with_verify "Binary" "$bbid" || true
            fhir_delete_history "Binary" "$bbid" || true
          done < <(extract_binary_ids_from_docref_json "$tmp_dr")
        else
          log "WARN" "DocRef/${dr_id} nicht lesbar – Binary-DELETE übersprungen"
        fi
        rm -f "$tmp_dr"
      else
        log "WARN" "Weder Binary-ID noch DocRef-ID verfügbar – Binary-DELETE übersprungen"
      fi
    fi
  fi
done

log "INFO" "Fertig"
