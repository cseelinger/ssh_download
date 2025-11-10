#!/usr/bin/env bash
set -euo pipefail

# Basis-URL (per ENV überschreibbar)
BASE="${BASE:-http://127.0.0.1:8089/fhir}"

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

_http_delete(){
  # gibt HTTP-Status zurück, nie mit -f (wir werten Status manuell aus)
  curl -sS -o /dev/null -w "%{http_code}" \
       --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
       -H "Accept: application/fhir+json" \
       -X DELETE "$1"
}

_delete_ok(){ case "$1" in 200|202|204|404|410) return 0 ;; *) return 1 ;; esac; }
strip_history(){ sed -E 's#/_history/[^/]+$##'; }

fhir_delete_current(){
  local rtype="${1-}" rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log ERROR "DELETE: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  local url="${BASE}/${rtype}/${rid}"
  local code; code="$(_http_delete "$url")" || code="$code"
  if _delete_ok "$code"; then
    log INFO "DELETE ${rtype}/${rid} → $code"
    return 0
  else
    log ERROR "DELETE ${rtype}/${rid} → $code"
    return 1
  fi
}

fhir_delete_history(){
  local rtype="${1-}" rid="${2-}"
  if [ -z "${rtype}" ] || [ -z "${rid}" ]; then
    log ERROR "DELETE _history: fehlender Parameter (rtype='${rtype-}', id='${rid-}')"
    return 1
  fi
  local url="${BASE}/${rtype}/${rid}/_history"
  local code; code="$(_http_delete "$url")" || code="$code"
  # Falls History-Delete nicht aktiviert ist: WARN, aber weiter
  if _delete_ok "$code"; then
    log INFO "DELETE ${rtype}/${rid}/_history → $code"
    return 0
  else
    log WARN "DELETE ${rtype}/${rid}/_history → $code"
    return 1
  fi
}

usage(){
  cat <<EOF
Usage: BASE=http://127.0.0.1:8089/fhir $(basename "$0") <DOCREF_ID> [<DOCREF_ID> ...]
Löscht je DocumentReference:
  1) DocRef (current)
  2) DocRef/_history
  3) referenzierte Binary-IDs (current)
  4) Binary/_history

Hinweis: DocRef wird VOR Binary gelöscht (Referenz-Integrität).
EOF
}

[ $# -ge 1 ] || { usage; exit 1; }

for drid in "$@"; do
  log INFO "Bearbeite DocumentReference/${drid}"

  # --- 1) Binary-URLs bestimmen (erst normale Read, sonst History-Fallback) ---
  tmp="$(mktemp)"
  got_docref=0
  if curl_json "${BASE}/DocumentReference/${drid}" -o "$tmp"; then
    got_docref=1
  else
    log WARN "DocumentReference/${drid} nicht lesbar – versuche History-Fallback"
    # Neueste (erste) History-Ressource ziehen, die eine content[].attachment.url hat
    if curl_json "${BASE}/DocumentReference/${drid}/_history?_count=200" \
      | jq -r '
          .entry[]?.resource
          | select(.content[]? // empty)
          | . as $r
          | $r.content[]?.attachment.url // empty
        ' > "$tmp"; then
      # Der Fallback schreibt direkt nur URLs (eine pro Zeile) ins tmp
      :
    else
      log ERROR "History-Fallback fehlgeschlagen für ${drid}"
      rm -f "$tmp"
      continue
    fi
  fi

  # URLs extrahieren (portabel, kein mapfile)
  bin_urls_raw=""
  if [ "$got_docref" -eq 1 ]; then
    bin_urls_raw="$(jq -r '.content[]? | select(.attachment.contentType=="application/zip")
                             | .attachment.url // empty' "$tmp")"
  else
    # tmp enthält bereits nur URLs (eine pro Zeile)
    bin_urls_raw="$(cat "$tmp")"
  fi
  rm -f "$tmp"

  # In IDs umwandeln (History-Teile entfernen, leading / entfernen)
  bin_ids=()
  while IFS= read -r u; do
    [ -z "${u}" ] && continue
    u="${u#/}"                             # führendes / weg
    u_nohist="$(printf '%s' "$u" | strip_history)"
    bid="$(printf '%s' "$u_nohist" | sed -nE 's#^Binary/([^/]+).*$#\1#p')"
    [ -n "$bid" ] && bin_ids+=("$bid")
  done <<< "$bin_urls_raw"

  # --- 2) Löschen: DocRef → History → Binary → History ---
  # Reihenfolge: erst DocRef (vermeidet Referenz-Integritätsfehler), dann Binary
  fhir_delete_current "DocumentReference" "$drid" || true
  fhir_delete_history "DocumentReference" "$drid" || true

  for bid in "${bin_ids[@]:-}"; do
    log INFO "Binary/${bid} (aus DocRef/${drid})"
    fhir_delete_current "Binary" "$bid" || true
    fhir_delete_history "Binary" "$bid" || true
  done

  log INFO "Fertig: DocumentReference/${drid}"
done
