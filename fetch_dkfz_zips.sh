#!/usr/bin/env bash
set -euo pipefail

############################
# Konfiguration
############################
SSH_HOST="dsf-bpe-test"             # SSH-Hostname/IP des BPE-Servers
SSH_USER="root"                     # SSH-User
LOCAL_PORT="${LOCAL_PORT:-8089}"    # lokaler Port (per Env übersteuerbar)
REMOTE_FHIR="10.128.129.159:8080"   # FHIR-Endpunkt (aus Sicht des BPE-Servers)
BASE="http://127.0.0.1:${LOCAL_PORT}/fhir"

# FHIR-Identifier-Filter (auf DocumentReference!)
IDENT_SYSTEM="http://medizininformatik-initiative.de/sid/project-identifier"

# Präfix für masterIdentifier.value (Standard mit Unterstrich), per Env überschreibbar
SEARCH_PREFIX="${SEARCH_PREFIX:-NCT-DKFZ-DE_}"
IDENT_VALUE_EXACT="${IDENT_VALUE_EXACT:-}"

RELAXED_MATCH=1

# Ausgabe & State
OUTDIR="$HOME/Desktop/celina/DKFZ_Zips"
STATE="$HOME/.dkfz_fetch_state.txt"
LOG="/tmp/fetch_dkfz_zips.log"

# Netzwerk/Download-Parameter
CONNECT_TIMEOUT=5
MAX_TIME=120
RETRIES=2
RETRY_DELAY=2
MAX_PAGES=50

############################
# Hilfsfunktionen
############################
ts(){ if date -Iseconds >/dev/null 2>&1; then date -Iseconds; else d="$(date "+%Y-%m-%dT%H:%M:%S%z")"; printf '%s\n' "$d" | sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'; fi; }
log(){ echo "$(ts) [$1] $2" | tee -a "$LOG"; }
die(){ log "ERROR" "$1"; exit 1; }
need_bin(){ command -v "$1" >/dev/null 2>&1 || die "fehlendes Programm: $1"; }

if base64 --help 2>/dev/null | grep -q '\-d'; then B64_FLAG="-d"; else B64_FLAG="-D"; fi
b64d(){ base64 "$B64_FLAG"; }

mktemp_zip(){ mktemp -t dkfz_zip.XXXXXX; }
mktemp_tmp(){ mktemp -t dkfz_tmp.XXXXXX; }
mktemp_dr(){  mktemp -t dkfz_dr.XXXXXX; }

curl_json(){ curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" -H "Accept: application/fhir+json" "$@"; }
curl_bin(){  curl -fS  -L --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" -H "Accept: application/octet-stream" "$@"; }

normalize_rel(){ sed -E 's#^https?://[^/]+/fhir/##' | sed -E 's#^/##'; }
strip_history(){ sed -E 's#/_history/[^/]+$##'; }

safe_project(){
  # nur A-Z a-z 0-9 . _ -
  tr -cd 'A-Za-z0-9._-'
}

# SHA-256 einer Datei berechnen – lowercase Hex wie Python hexdigest()
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
  nxt="$(jq -r '.link[]? | select(.relation=="next") | .url // empty' "$resp")"
  [ -z "$nxt" ] && { echo ""; return; }
  echo "$nxt" | sed -E "s#^https?://[^/]+/fhir#${BASE}#"
}

fetch_rel(){
  # $1: rel (Binary/…)
  # $2: project (kann leer sein)
  # $3: expected_hash (kann leer sein)
  local rel="$1" project="${2:-}" expected_hash="${3:-}"
  local rel_nover id tmpzip got=0 destdir safe_proj zip_path unpack_dir marker

  rel="${rel#/}"
  rel_nover="$(printf '%s' "$rel" | strip_history)"

  id="$(printf '%s' "$rel" | sed -nE 's#^Binary/([^/]+).*$#\1#p')"
  [ -z "$id" ] && id="$(printf '%s' "$rel" | sed -nE 's#^.*/([^/]+)/_history/.*$#\1#p')"
  [ -z "$id" ] && id="$(printf '%s' "$rel_nover" | sed -nE 's#.*/([^/]+)$#\1#p')"

  # Zielpfade
  if [ -n "$project" ]; then
    safe_proj="$(printf '%s' "$project" | tr -cd 'A-Za-z0-9._-')"
    [ -z "$safe_proj" ] && safe_proj="UNKNOWN"
    destdir="${OUTDIR}/${safe_proj}"
  else
    destdir="${OUTDIR}"
  fi
  mkdir -p "$destdir"
  zip_path="${destdir}/${id}.zip"
  unpack_dir="${destdir}/${id}"
  marker="${zip_path}.done"

  # State/Heuristiken
  if grep -qx "$id" "$STATE"; then
    if [ -f "$zip_path" ]; then
      log "INFO" "skip $id (bereits geladen; ZIP vorhanden: $(basename "$zip_path"))"
      return 0
    fi
    if [ -d "$unpack_dir" ] || [ -f "$marker" ]; then
      log "INFO" "skip $id (ZIP fehlt, aber entpackt vorhanden: $(basename "$unpack_dir") oder Marker)"
      return 0
    fi
    log "INFO" "Re-Download: $id (ZIP und entpackter Ordner/Marker fehlen)"
  fi

  tmpzip="$(mktemp_zip)"
  log "INFO" "lade $rel (ID=$id; project=${project:-''})"

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
    log "ERROR" "Download fehlgeschlagen: $rel"
    rm -f "$tmpzip"
    return 1
  fi

  # === SHA-256 Check (falls erwarteter Hash vorhanden und Tool verfügbar) ===
  if [ -n "$expected_hash" ]; then
    exp="$(printf '%s' "$expected_hash" | tr '[:upper:]' '[:lower:]')"
    have_hash_tool=0
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1; then
      have_hash_tool=1
    fi
    if [ "$have_hash_tool" -eq 1 ]; then
      act="$(compute_sha256 "$tmpzip")"
      if [ -n "$act" ]; then
        if [ "$act" = "$exp" ]; then
          log "INFO" "SHA256 OK (ID=$id, project=${project:-''}): $act"
        else
          log "WARN" "SHA256 MISMATCH (ID=$id): expected=$exp got=$act"
        fi
      else
        log "WARN" "SHA256 konnte nicht berechnet werden (ID=$id)"
      fi
    else
      log "WARN" "Kein SHA256-Tool verfügbar – Check übersprungen (ID=$id, expected=$expected_hash)"
    fi
  else
    log "INFO" "Kein expected Hash im masterIdentifier – Check übersprungen (ID=$id)"
  fi

  mv "$tmpzip" "$zip_path"
  echo "$id" >> "$STATE"
  log "SUCCESS" "gespeichert: ${zip_path}"
}

############################
# Vorbereitungen
############################
: > "$LOG"
mkdir -p "$OUTDIR"
touch "$STATE"

need_bin curl; need_bin jq; need_bin base64; need_bin ssh; need_bin sed; need_bin awk; need_bin lsof

if command -v sha256sum >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via sha256sum aktiv"
elif command -v shasum >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via shasum aktiv"
elif command -v openssl >/dev/null 2>&1; then
  log "INFO" "SHA256-Prüfung via openssl aktiv"
else
  log "WARN" "Kein Tool für SHA256 gefunden (sha256sum/shasum/openssl) – Hash-Check wird übersprungen"
fi

CLIENT_EXACT=""
if [ -z "${SEARCH_PREFIX}" ] && [ -n "${IDENT_VALUE_EXACT}" ]; then
  CLIENT_EXACT="${IDENT_VALUE_EXACT}"
fi

log "INFO" "Start; Ziel: $OUTDIR, State: $STATE"
log "INFO" "Filter: system=$IDENT_SYSTEM | prefix=${SEARCH_PREFIX:-<leer>} | exact='${IDENT_VALUE_EXACT:-}'"

############################
# Lock + Cleanup
############################
LOCK_NAME="/tmp/fetch_dkfz_zips.lock"
LOCKDIR=""
cleanup_all(){
  if [ -S "${CTRL:-}" ]; then ssh -S "$CTRL" -O exit "${SSH_USER}@${SSH_HOST}" >/dev/null 2>&1 || true; fi
  if [ -n "$LOCKDIR" ]; then rmdir "$LOCKDIR" >/dev/null 2>&1 || true; fi
  log "INFO" "SSH-Tunnel beendet und Lock freigegeben"
}
trap cleanup_all EXIT

if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_NAME"
  if ! flock -n 9; then log "WARN" "bereits laufend, Ende"; exit 0; fi
  log "INFO" "Lock via flock aktiv"
else
  LOCKDIR="${LOCK_NAME}.d"
  if ! mkdir "$LOCKDIR" 2>/dev/null; then log "WARN" "bereits laufend (Lockdir), Ende"; exit 0; fi
  log "INFO" "Lock via Lockdir aktiv"
fi

#####################
# SSH-Tunnel
#####################
CTRL="/tmp/dkfz_fetch_${LOCAL_PORT}.sock"

if lsof -iTCP:${LOCAL_PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
  if curl_json "${BASE}/metadata" -o /dev/null; then
    log "INFO" "Tunnel bereits offen (Port ${LOCAL_PORT})"
  else
    log "WARN" "Port ${LOCAL_PORT} belegt, aber kein FHIR erreichbar – wechsle Port"
    for p in 8091 8092 8093 18089 18090 19001; do
      if ! lsof -iTCP:${p} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
        LOCAL_PORT="$p"; BASE="http://127.0.0.1:${LOCAL_PORT}/fhir"; CTRL="/tmp/dkfz_fetch_${LOCAL_PORT}.sock"
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
# Kandidaten sammeln (nur DocumentReference)
############################
RELS=()   # Elemente: "PROJECT|||URL|||HASH"
TMP="$(mktemp_tmp)"
found_pages=0
found_urls=0

# (A) Exakt (falls gesetzt) – inkl. DR-Read-Fallback; Project + Hash aus masterIdentifier.value
if [ -n "${IDENT_VALUE_EXACT:-}" ]; then
  URL="${BASE}/DocumentReference?identifier=$(printf '%s' "$IDENT_SYSTEM" | sed 's/|/%7C/g')%7C$(printf '%s' "$IDENT_VALUE_EXACT" | sed 's/|/%7C/g')&_count=200"
  while [ -n "$URL" ] && [ $found_pages -lt $MAX_PAGES ]; do
    log "INFO" "DR exakt laden: $URL"
    if ! curl_json "$URL" -o "$TMP"; then log "ERROR" "DR exakt fehlgeschlagen: $URL"; break; fi
    found_pages=$((found_pages+1))
    total="$(jq -r '.total // 0' "$TMP")"
    log "INFO" "Bundle total (exakt): $total"

    ids="$(jq -r '.entry[]?.resource?.id // empty' "$TMP" | awk 'NF')"
    [ -n "$ids" ] && log "INFO" "Treffer-DR IDs (exakt): $(echo "$ids" | xargs)"

    # WICHTIG: Keine 'as $arr' Bindung innerhalb der if-Zweige -> jq 1.5 kompatibel
    lines_tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
      def proj_hash_from(v; p):
        ( if (p|length)>0
          then (v // "" | sub("^"+p; "") | split("_"))
          else (v // "" | split("_")[1:])
          end
        )
        | if (length>=2) then [.[0], .[length-1]] else ["UNKNOWN",""] end;

      .entry[]?.resource as $r
      | $r.masterIdentifier.value as $v
      | proj_hash_from($v; $p) as $ph
      | [$r.id,
         $ph[0],
         ($r.content[]? | select(.attachment.contentType=="application/zip") | .attachment.url),
         $ph[1]]
      | select(.[2] != null)
      | @tsv
    ' "$TMP")"

    if [ -n "$lines_tsv" ]; then
      while IFS=$'\t' read -r _id _proj _url _hash; do
        [ -n "${_url:-}" ] && RELS+=("${_proj}|||${_url}|||${_hash}") && found_urls=$((found_urls+1))
      done <<< "$lines_tsv"
      log "INFO" "Seite $found_pages (exakt/zip-only): $(printf '%s\n' "$lines_tsv" | wc -l | awk '{print $1}') URLs"
    else
      log "INFO" "Seite $found_pages (exakt/zip-only): 0 URLs"
    fi

    # Fallback: DR-Read pro ID, falls Search-Bundle keine URLs enthielt
    if [ -z "$lines_tsv" ] && [ -n "$ids" ]; then
      log "INFO" "Exakt-Suche ohne URLs – lade DRs per ID nach"
      while IFS= read -r drid; do
        [ -z "$drid" ] && continue
        DR_ONE="$(mktemp_dr)"
        if curl_json "${BASE}/DocumentReference/${drid}" -o "$DR_ONE"; then
          tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
            def proj_hash_from(v; p):
              ( if (p|length)>0
                then (v // "" | sub("^"+p; "") | split("_"))
                else (v // "" | split("_")[1:])
                end
              )
              | if (length>=2) then [.[0], .[length-1]] else ["UNKNOWN",""] end;

            . as $r
            | $r.masterIdentifier.value as $v
            | proj_hash_from($v; $p) as $ph
            | [$ph[0], ($r.content[]? | select(.attachment.contentType=="application/zip") | .attachment.url), $ph[1]]
            | select(.[1] != null)
            | @tsv
          ' "$DR_ONE")"
          if [ -n "$tsv" ]; then
            IFS=$'\t' read -r _proj _url _hash <<< "$tsv"
            RELS+=("${_proj}|||${_url}|||${_hash}"); found_urls=$((found_urls+1))
            log "INFO" "DR ${drid}: URL+Hash gefunden"
          else
            log "WARN" "DR ${drid}: keine ZIP-URL"
          fi
        else
          log "WARN" "DR ${drid}: Read fehlgeschlagen"
        fi
        rm -f "$DR_ONE"
      done <<< "$ids"
    fi

    URL="$(next_url "$TMP")"
  done
fi

# (B) Vollscan: startswith(SEARCH_PREFIX) + ZIP-URL; Project + Hash aus masterIdentifier.value
URL="${BASE}/DocumentReference?_count=200"
while [ -n "$URL" ] && [ $found_pages -lt $MAX_PAGES ]; do
  log "INFO" "DR-Seite laden: $URL"
  if ! curl_json "$URL" -o "$TMP"; then log "ERROR" "DR-Request fehlgeschlagen: $URL"; break; fi
  found_pages=$((found_pages+1))

  PREF="$SEARCH_PREFIX"
  mi_total=$(jq -r '.entry[]?.resource.masterIdentifier // empty' "$TMP" | wc -l | awk '{print $1}')

  lines_tsv="$(jq -r --arg p "$PREF" '
    def proj_hash_from(v; p):
      ( if (p|length)>0
        then (v // "" | sub("^"+p; "") | split("_"))
        else (v // "" | split("_")[1:])
        end
      )
      | if (length>=2) then [.[0], .[length-1]] else ["UNKNOWN",""] end;

    .entry[]?.resource as $r
    | select( (($r.masterIdentifier.value // "") | startswith($p)) )
    | $r.masterIdentifier.value as $v
    | proj_hash_from($v; $p) as $ph
    | [$r.id,
       $ph[0],
       ($r.content[]? | select(.attachment.contentType=="application/zip") | .attachment.url),
       $ph[1]]
    | select(.[2] != null)
    | @tsv
  ' "$TMP")"

  if [ -n "$lines_tsv" ]; then
    match_ids="$(printf '%s\n' "$lines_tsv" | cut -f1 | sort -u | xargs)"
    [ -n "$match_ids" ] && log "INFO" "Treffer-DRs (prefix/zip-only): $match_ids"
    while IFS=$'\t' read -r _id _proj _url _hash; do
      [ -n "${_url:-}" ] && RELS+=("${_proj}|||${_url}|||${_hash}") && found_urls=$((found_urls+1))
    done <<< "$lines_tsv"
    page_keep=$(printf '%s\n' "$lines_tsv" | wc -l | awk '{print $1}')
  else
    page_keep=0
  fi

  log "INFO" "Seite $found_pages: masterId total=$mi_total | passend=$page_keep (Modus: prefix/zip-only)"
  URL="$(next_url "$TMP")"
done

# Deduplizieren (ganze Triple-Zeile)
if [ "${#RELS[@]}" -eq 0 ]; then
  log "WARN" "keine Kandidaten gefunden (pages=$found_pages, urls=$found_urls)"
  exit 0
else
  deduped="$(printf '%s\n' "${RELS[@]}" | awk 'NF' | sort -u)"
  RELS=(); while IFS= read -r line; do [ -n "$line" ] && RELS+=("$line"); done <<< "$deduped"
  log "INFO" "Kandidaten gesamt (dedupliziert): ${#RELS[@]}"
fi

############################
# Download (mit Projekt-Unterordner + Hash-Check)
############################
for entry in "${RELS[@]}"; do
  project="${entry%%|||*}"
  rest="${entry#*|||}"
  rel="${rest%%|||*}"
  expected_hash="${rest#*|||}"
  # Falls kein drittes Feld vorhanden war:
  if [ "$expected_hash" = "$rest" ]; then expected_hash=""; fi

  case "$rel" in
    Binary/*|Binary/*/_history/*)
      fetch_rel "$rel" "$project" "$expected_hash"
      ;;
    http*|https*)
      fetch_rel "$(printf '%s' "$rel" | normalize_rel)" "$project" "$expected_hash"
      ;;
    DocumentReference/*)
      DR_ONE="$(mktemp_dr)"
      rel_nover="$(printf '%s' "$rel" | strip_history)"
      if ! curl_json "${BASE}/${rel}" -o "$DR_ONE"; then
        log "WARN" "DR-Version nicht lesbar, versuche ohne _history"
        if ! curl_json "${BASE}/${rel_nover}" -o "$DR_ONE"; then log "ERROR" "DR fehlgeschlagen: $rel"; rm -f "$DR_ONE"; continue; fi
      fi
      tsv="$(jq -r --arg p "$SEARCH_PREFIX" '
        def proj_hash_from(v; p):
          ( if (p|length)>0
            then (v // "" | sub("^"+p; "") | split("_"))
            else (v // "" | split("_")[1:])
            end
          )
          | if (length>=2) then [.[0], .[length-1]] else ["UNKNOWN",""] end;
        . as $r
        | $r.masterIdentifier.value as $v
        | proj_hash_from($v; $p) as $ph
        | [$ph[0], ($r.content[]? | select(.attachment.contentType=="application/zip") | .attachment.url), $ph[1]]
        | select(.[1] != null)
        | @tsv
      ' "$DR_ONE")"
      rm -f "$DR_ONE"
      if [ -z "$tsv" ]; then log "WARN" "DR ohne ZIP-URL: $rel"; continue; fi
      IFS=$'\t' read -r proj2 binu hash2 <<< "$tsv"
      [ -z "$project" ] && project="$proj2"
      [ -z "$expected_hash" ] && expected_hash="$hash2"
      fetch_rel "$(printf '%s' "$binu" | normalize_rel)" "$project" "$expected_hash"
      ;;
    *)
      log "WARN" "unbekannter REL-Typ: $rel"
      ;;
  esac
done

log "INFO" "Fertig"
