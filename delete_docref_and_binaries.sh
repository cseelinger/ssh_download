#!/usr/bin/env bash
set -euo pipefail

# Basis-URL (per ENV überschreibbar)
BASE="https://blaze.sci.dkfz.de/fhir"

# Netzwerkparameter
CONNECT_TIMEOUT=5
MAX_TIME=60
RETRIES=2
RETRY_DELAY=2

ts(){ date -Iseconds 2>/dev/null || date "+%Y-%m-%dT%H:%M:%S%z"; }
log(){ echo "$(ts) [$1] $2"; }

need_bin(){ command -v "$1" >/dev/null 2>&1 || { log ERROR "fehlendes Programm: $1"; exit 1; }; }
need_bin curl
need_bin jq

curl_json(){
  curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
       --retry "$RETRIES" --retry-delay "$RETRY_DELAY" \
       -H "Accept: application/fhir+json" "$@"
}

# HTTP DELETE mit Retries; gibt immer einen Code zurück, bei Transportfehler "000"
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
strip_history(){ sed -E 's#/_history/[^/]+$##'; }

# Prüft, ob Ressource weg ist (404/410)
_verify_gone(){
  local rtype="${1-}" rid="${2-}"
  [ -n "${rtype}" ] && [ -n "${rid}" ] || { return 1; }
  local s; s="$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/${rtype}/${rid}")" || s="000"
  case "$s" in 404|410) return 0 ;; *) return 1 ;; esac
}

# Aktuelle Version löschen (mit Verify & Retries)
delete_with_verify(){
  local rtype="${1-}"; local rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log ERROR "DELETE: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi

  if _verify_gone "${rtype}" "${rid}"; then
    log INFO "${rtype}/${rid} bereits entfernt (verify=gone)"
    return 0
  fi

  local url="${BASE}/${rtype}/${rid}"
  local tries=0 code=""
  while :; do
    code="$(_http_delete "$url")"
    if [ "$code" = "000" ]; then
      log WARN "Transportfehler beim DELETE (kein HTTP-Code) – URL=$url"
    else
      log INFO "DELETE ${rtype}/${rid} → $code"
    fi
    if _verify_gone "${rtype}" "${rid}"; then
      log INFO "${rtype}/${rid} entfernt (verify=gone)"
      return 0
    fi
    tries=$((tries+1)); [ $tries -ge 6 ] && break
    sleep 1
  done
  log ERROR "${rtype}/${rid} nach DELETE noch vorhanden (verify!=gone)"
  return 1
}

# History-Delete (tolerant; optional)
fhir_delete_history(){
  local rtype="${1-}"; local rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log ERROR "DELETE _history: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  local url="${BASE}/${rtype}/${rid}/_history"
  local code; code="$(_http_delete "$url")"
  if _delete_ok "$code"; then
    log INFO "DELETE ${rtype}/${rid}/_history → $code"
    return 0
  else
    log WARN "DELETE ${rtype}/${rid}/_history → $code"
    return 1
  fi
}

# Binary-ID aus attachment.url extrahieren (relativ/absolut, mit/ohne _history, mit/ohne Query)
binary_id_from_url(){
  local u="${1-}"
  [ -z "$u" ] && { echo ""; return; }
  u="${u%%\?*}"
  case "$u" in
    http://*|https://*)
      u="${u#*://}"
      [[ "$u" == */fhir/* ]] && u="${u#*/fhir/}"
      ;;
  esac
  u="${u#/}"
  u="$(printf '%s' "$u" | strip_history)"
  if [[ "$u" == Binary/* ]]; then
    printf '%s\n' "${u#Binary/}" | cut -d/ -f1
  else
    echo ""
  fi
}

extract_binary_ids_from_docref_json(){
  jq -r '.content[]? | .attachment.url? // empty' "$1" | while IFS= read -r u; do
    bid="$(binary_id_from_url "$u")"; [ -n "$bid" ] && echo "$bid"
  done | sort -u
}

usage(){
  cat <<EOF
Usage: BASE=http://127.0.0.1:8089/fhir $(basename "$0") <DOCREF_ID> [<DOCREF_ID> ...]
Ablauf je DocumentReference:
  1) DocRef lesen und Binary-IDs ermitteln (oder History-Fallback)
  2) DELETE DocRef (current) mit Verify
  3) DELETE DocRef/_history (tolerant, falls aktiviert)
  4) DELETE Binary (current) mit Verify
  5) DELETE Binary/_history (tolerant, falls aktiviert)
EOF
}

[ $# -ge 1 ] || { usage; exit 1; }

for drid in "$@"; do
  log INFO "Bearbeite DocumentReference/${drid}"

  # DocRef lesen; wenn 410/404 → History-Bundle laden
  tmp="$(mktemp)"; have_docref=0
  if curl_json "${BASE}/DocumentReference/${drid}" -o "$tmp"; then
    have_docref=1
  else
    log WARN "DocumentReference/${drid} nicht lesbar – History-Fallback"
    if ! curl_json "${BASE}/DocumentReference/${drid}/_history?_count=200" -o "$tmp"; then
      log ERROR "History-Fallback fehlgeschlagen (${drid})"
      rm -f "$tmp"; continue
    fi
  fi

  # Binary-IDs sammeln
  bin_ids=()
  if [ "$have_docref" -eq 1 ]; then
    while IFS= read -r bid; do [ -n "$bid" ] && bin_ids+=("$bid"); done < <(extract_binary_ids_from_docref_json "$tmp")
  else
    while IFS= read -r bid; do [ -n "$bid" ] && bin_ids+=("$bid"); done < <(
      jq -r '.entry[]?.resource? // empty | .content[]? | .attachment.url? // empty' "$tmp" | \
      while IFS= read -r u; do binary_id_from_url "$u"; done | sort -u
    )
  fi
  rm -f "$tmp"

  if [ "${#bin_ids[@]}" -eq 0 ]; then
    log WARN "Keine Binary-IDs in DocumentReference/${drid} gefunden"
  else
    log INFO "Binary-IDs: ${bin_ids[*]}"
  fi

  # Löschen: DocRef → History → Binary → History
  delete_with_verify "DocumentReference" "$drid" || true
  fhir_delete_history "DocumentReference" "$drid" || true

  for bid in "${bin_ids[@]}"; do
    log INFO "Binary/${bid} (aus DocRef/${drid})"
    delete_with_verify "Binary" "$bid" || true
    fhir_delete_history "Binary" "$bid" || true
  done

  log INFO "Fertig: DocumentReference/${drid}"
done
