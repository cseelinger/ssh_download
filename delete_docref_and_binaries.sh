#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8089/fhir}"
CONNECT_TIMEOUT=5
MAX_TIME=60
RETRIES=2
RETRY_DELAY=2

ts(){ date -Iseconds 2>/dev/null || date "+%Y-%m-%dT%H:%M:%S%z"; }
log(){ echo "$(ts) [$1] $2"; }

curl_json(){ curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" -H "Accept: application/fhir+json" "$@"; }
_http_delete(){
  curl -sS -o /dev/null -w "%{http_code}" \
       --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
       -H "Accept: application/fhir+json" \
       -X DELETE "$1"
}
_delete_ok(){ case "$1" in 200|202|204|404|410) return 0 ;; *) return 1 ;; esac; }
strip_history(){ sed -E 's#/_history/[^/]+$##'; }

fhir_delete_current(){
  local type="$1" id="$2" url="${BASE}/${type}/${id}"
  local code; code="$(_http_delete "$url")" || code="$code"
  if _delete_ok "$code"; then log INFO "DELETE ${type}/${id} → $code"; else log ERROR "DELETE ${type}/${id} → $code"; fi
}
fhir_delete_history(){
  local type="$1" id="$2" url="${BASE}/${type}/${id}/_history"
  local code; code="$(_http_delete "$url")" || code="$code"
  if _delete_ok "$code"; then log INFO "DELETE ${type}/${id}/_history → $code"; else log WARN "DELETE ${type}/${id}/_history → $code"; fi
}

usage(){
  cat <<EOF
Usage: BASE=http://127.0.0.1:8089/fhir $(basename "$0") <DOCREF_ID> [<DOCREF_ID> ...]
Löscht je DocumentReference:
  1) DocumentReference (current)
  2) DocumentReference/_history
  3) Referenzierte Binary-IDs (current)
  4) Binary/_history
EOF
}

[ $# -ge 1 ] || { usage; exit 1; }

for drid in "$@"; do
  log INFO "Bearbeite DocumentReference/${drid}"

  # 1) DocRef lesen und Binary-URLs extrahieren (vor dem Löschen!)
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  if ! curl_json "${BASE}/DocumentReference/${drid}" -o "$tmp"; then
    log ERROR "DocumentReference/${drid} nicht lesbar (existiert sie noch?)"
    rm -f "$tmp"
    continue
  fi

  # mehrere Attachments möglich
  mapfile -t bin_urls < <(jq -r '.content[]? | select(.attachment.contentType=="application/zip") | .attachment.url // empty' "$tmp" | sed -E 's#^/##')
  rm -f "$tmp"

  # Binary-IDs ohne _history extrahieren
  bin_ids=()
  for u in "${bin_urls[@]:-}"; do
    u="${u#/}"
    u_nohist="$(printf '%s' "$u" | strip_history)"
    bid="$(printf '%s' "$u_nohist" | sed -nE 's#^Binary/([^/]+).*$#\1#p')"
    [ -n "$bid" ] && bin_ids+=("$bid")
  done

  # 2) DocRef löschen (current) + History
  fhir_delete_current "DocumentReference" "$drid" || true
  fhir_delete_history "DocumentReference" "$drid" || true

  # 3) Binaries löschen (current) + History
  for bid in "${bin_ids[@]:-}"; do
    log INFO "Binary/${bid} (aus DocRef/${drid})"
    fhir_delete_current "Binary" "$bid" || true
    fhir_delete_history "Binary" "$bid" || true
  done

  log INFO "Fertig: DocumentReference/${drid}"
done
