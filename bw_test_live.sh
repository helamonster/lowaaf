#!/usr/bin/env bash
# Live WAF + bw CLI integration test.
# Exercises all major bw CLI commands against the local VW+OpenResty+WAF Docker stack
# and verifies no WAF blocks occur during normal client use.
#
# Usage:
#   bash bw_test_live.sh            # wipes VW volume, registers fresh account, runs tests
#   bash bw_test_live.sh --no-reset # skip volume wipe, reuse existing account (faster)
#
# Pre-requisites:
#   • Docker stack running: bash tools.sh docker-test-up
#   • bw CLI in PATH
#   • node in PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
REGISTER_JS="$SCRIPT_DIR/docker/register.js"

SERVER="https://localhost:8443"
EMAIL="waftest@example.com"
PASSWORD="WafTest1234!"
DATA_DIR="$(mktemp -d /tmp/bw-live-test-XXXXXX)"

RESET=true
for arg in "$@"; do [[ "$arg" == "--no-reset" ]] && RESET=false; done

PASS=0; FAIL=0
BW_SESSION=""

# ── helpers ───────────────────────────────────────────────────────────────────

G="\033[32m"; R="\033[31m"; B="\033[1m"; N="\033[0m"

ok()      { printf "  ${G}✓${N} %s\n" "$1"; PASS=$((PASS + 1)); }
fail()    { printf "  ${R}✗${N} %s — %s\n" "$1" "$2"; FAIL=$((FAIL + 1)); }
section() { printf "\n${B}── %s ──${N}\n" "$1"; }

# bw wrapper: isolated data dir, TLS bypass, session forwarded
bwx() {
  BITWARDENCLI_APPDATA_DIR="$DATA_DIR" \
  NODE_TLS_REJECT_UNAUTHORIZED=0 \
  BW_SESSION="$BW_SESSION" \
  bw "$@" 2>/dev/null
}

# Parse a top-level JSON field from a string.  Usage: jf "$json" field
jf() {
  printf '%s' "$1" | node -e "
try {
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(String(d['$2'] ?? ''));
} catch(e) {}" 2>/dev/null
}

# Parse a nested JSON field.  Usage: jf2 "$json" outer inner
jf2() {
  printf '%s' "$1" | node -e "
try {
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(String(d['$2']?.['$3'] ?? ''));
} catch(e) {}" 2>/dev/null
}

# Parse JSON array length from a string.
jlen() {
  printf '%s' "$1" | node -e "
try {
  const a = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(String(Array.isArray(a) ? a.length : '?'));
} catch(e) { process.stdout.write('0'); }" 2>/dev/null
}

# Assert a top-level field equals an expected value.
check() {
  local label="$1" field="$2" expected="$3" json="$4"
  local got; got=$(jf "$json" "$field")
  if [[ "$got" == "$expected" ]]; then ok "$label"
  else fail "$label" "expected '$expected', got '$got'"; fi
}

# ── pre-flight ────────────────────────────────────────────────────────────────

cleanup() { rm -rf "$DATA_DIR"; }
trap cleanup EXIT

echo ""
echo "Checking Docker stack…"
if ! docker compose -f "$COMPOSE_FILE" ps --quiet openresty 2>/dev/null | grep -q .; then
  printf "ERROR: Docker stack not running.\nStart it with: bash tools.sh docker-test-up\n"; exit 1
fi
echo "  Up."

# Record the nginx log offset so we only check WAF entries from this run.
LOG_OFFSET=$(docker compose -f "$COMPOSE_FILE" logs --no-log-prefix openresty 2>/dev/null | wc -l || echo 0)

# ── optional volume reset ─────────────────────────────────────────────────────

if $RESET; then
  echo ""
  echo "Resetting VW (wipe volume → fresh state)…"
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
  docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null
  echo "  Waiting for Vaultwarden to be healthy…"
  for _ in $(seq 1 30); do
    STATUS=$(docker inspect \
      "$(docker compose -f "$COMPOSE_FILE" ps -q vaultwarden 2>/dev/null)" \
      --format '{{.State.Health.Status}}' 2>/dev/null || echo "")
    [[ "$STATUS" == "healthy" ]] && break
    sleep 1
  done
  LOG_OFFSET=0
  echo "  Registering test account…"
  BW_EMAIL="$EMAIL" BW_PASSWORD="$PASSWORD" BW_SERVER="$SERVER" node "$REGISTER_JS" || {
    echo "ERROR: Registration failed"; exit 1; }
  echo "  Done."
fi

# ── auth ──────────────────────────────────────────────────────────────────────

section "Auth"

BITWARDENCLI_APPDATA_DIR="$DATA_DIR" NODE_TLS_REJECT_UNAUTHORIZED=0 \
  bw config server "$SERVER" 2>/dev/null || true

# bw login --raw returns the session key directly (vault is unlocked for this process).
SESSION=$(BITWARDENCLI_APPDATA_DIR="$DATA_DIR" NODE_TLS_REJECT_UNAUTHORIZED=0 \
  bw login "$EMAIL" "$PASSWORD" --raw 2>/dev/null || echo "")
if [[ -n "$SESSION" ]]; then
  ok "bw login"
  BW_SESSION="$SESSION"
else
  fail "bw login" "empty session — aborting"
  exit 1
fi

STATUS_JSON=$(bwx status 2>/dev/null || echo "{}")
check "bw status = unlocked" "status"    "unlocked" "$STATUS_JSON"
check "bw status server"     "serverUrl" "$SERVER"  "$STATUS_JSON"

if bwx sync 2>/dev/null; then ok "bw sync"; else fail "bw sync" "failed"; fi

# ── generate ──────────────────────────────────────────────────────────────────

section "Generate (local — no network)"

G1=$(bwx generate --length 24 2>/dev/null || echo "")
if [[ ${#G1} -eq 24 ]]; then ok "bw generate (24-char password)"
else fail "bw generate" "length=${#G1}, got='$G1'"; fi

G2=$(bwx generate --length 16 --uppercase --lowercase --number --special 2>/dev/null || echo "")
if [[ ${#G2} -eq 16 ]]; then ok "bw generate --uppercase --lowercase --number --special"
else fail "bw generate (flags)" "length=${#G2}, got='$G2'"; fi

G3=$(bwx generate --passphrase --words 4 --separator - 2>/dev/null || echo "")
DASHES=$(printf '%s' "$G3" | tr -cd '-' | wc -c)
if [[ "$DASHES" -eq 3 ]]; then ok "bw generate --passphrase --words 4"
else fail "bw generate --passphrase" "expected 3 dashes, got=$DASHES in '$G3'"; fi

# ── folders ───────────────────────────────────────────────────────────────────

section "Folders"

F_JSON=$(echo '{"name":"Test Folder"}' | bwx encode | bwx create folder 2>/dev/null || echo "")
F_ID=$(jf "$F_JSON" "id")
if [[ -n "$F_ID" ]]; then ok "bw create folder"
else fail "bw create folder" "$F_JSON"; fi

F_LIST=$(bwx list folders 2>/dev/null || echo "[]")
F_COUNT=$(jlen "$F_LIST")
if [[ "$F_COUNT" -ge 1 ]]; then ok "bw list folders ($F_COUNT)"
else fail "bw list folders" "count=$F_COUNT"; fi

if [[ -n "$F_ID" ]]; then
  F_EDIT=$(echo '{"name":"Renamed Folder"}' | bwx encode | bwx edit folder "$F_ID" 2>/dev/null || echo "")
  check "bw edit folder (rename)" "name" "Renamed Folder" "$F_EDIT"
fi

# ── cipher: login ─────────────────────────────────────────────────────────────

section "Cipher — Login"

LOGIN_PAYLOAD=$(cat <<'EOF'
{"type":1,"name":"My Login","folderId":null,"organizationId":null,"favorite":false,
"reprompt":0,"notes":null,"fields":[],"passwordHistory":[],"collectionIds":[],
"login":{"username":"user@example.com","password":"s3cr3t","totp":null,
"uris":[{"match":0,"uri":"https://example.com"}]}}
EOF
)

L_JSON=$(printf '%s' "$LOGIN_PAYLOAD" | bwx encode | bwx create item 2>/dev/null || echo "")
L_ID=$(jf "$L_JSON" "id")
if [[ -n "$L_ID" ]]; then ok "bw create login"
else fail "bw create login" "$L_JSON"; fi

if [[ -n "$L_ID" ]]; then
  GET_JSON=$(bwx get item "$L_ID" 2>/dev/null || echo "")
  check "bw get item (name)"            "name"     "My Login"         "$GET_JSON"

  L_USER=$(jf2 "$GET_JSON" "login" "username")
  if [[ "$L_USER" == "user@example.com" ]]; then ok "bw get item — login.username decrypted"
  else fail "login.username" "got '$L_USER'"; fi

  L_PW=$(jf2 "$GET_JSON" "login" "password")
  if [[ "$L_PW" == "s3cr3t" ]]; then ok "bw get item — login.password decrypted"
  else fail "login.password" "got '$L_PW'"; fi

  if [[ -n "$F_ID" ]]; then
    EDIT_JSON=$(bwx get item "$L_ID" 2>/dev/null | node -e "
      const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
      d.name = 'Edited Login'; d.folderId = '$F_ID'; d.favorite = true;
      process.stdout.write(JSON.stringify(d));" 2>/dev/null | \
      bwx encode | bwx edit item "$L_ID" 2>/dev/null || echo "")
    check "bw edit item (rename)"        "name"     "Edited Login" "$EDIT_JSON"
    check "bw edit item (folderId)"      "folderId" "$F_ID"        "$EDIT_JSON"
    check "bw edit item (favorite=true)" "favorite" "true"         "$EDIT_JSON"
  fi
fi

# ── cipher: secure note ───────────────────────────────────────────────────────

section "Cipher — Secure Note"

NOTE_PAYLOAD=$(cat <<'EOF'
{"type":2,"name":"My Note","folderId":null,"organizationId":null,"favorite":false,
"reprompt":0,"notes":"secret note text","fields":[],"passwordHistory":[],
"collectionIds":[],"secureNote":{"type":0}}
EOF
)

N_JSON=$(printf '%s' "$NOTE_PAYLOAD" | bwx encode | bwx create item 2>/dev/null || echo "")
N_ID=$(jf "$N_JSON" "id")
if [[ -n "$N_ID" ]]; then ok "bw create secure note"
else fail "bw create secure note" "$N_JSON"; fi

# ── cipher: card ──────────────────────────────────────────────────────────────

section "Cipher — Card"

CARD_PAYLOAD=$(cat <<'EOF'
{"type":3,"name":"My Card","folderId":null,"organizationId":null,"favorite":false,
"reprompt":0,"notes":null,"fields":[],"passwordHistory":[],"collectionIds":[],
"card":{"cardholderName":"John Doe","brand":"Visa","number":"4111111111111111",
"expMonth":"12","expYear":"2030","code":"123"}}
EOF
)

C_JSON=$(printf '%s' "$CARD_PAYLOAD" | bwx encode | bwx create item 2>/dev/null || echo "")
C_ID=$(jf "$C_JSON" "id")
if [[ -n "$C_ID" ]]; then ok "bw create card"
else fail "bw create card" "$C_JSON"; fi

# ── cipher: identity ──────────────────────────────────────────────────────────

section "Cipher — Identity"

IDENT_PAYLOAD=$(cat <<'EOF'
{"type":4,"name":"My Identity","folderId":null,"organizationId":null,"favorite":false,
"reprompt":0,"notes":null,"fields":[],"passwordHistory":[],"collectionIds":[],
"identity":{"title":"Mr","firstName":"John","middleName":null,"lastName":"Doe",
"address1":"123 Main St","address2":null,"address3":null,"city":"Anytown","state":"CA",
"postalCode":"12345","country":"US","company":null,"email":"john@example.com",
"phone":"555-1234","ssn":null,"username":"johndoe","passportNumber":null,
"licenseNumber":null}}
EOF
)

I_JSON=$(printf '%s' "$IDENT_PAYLOAD" | bwx encode | bwx create item 2>/dev/null || echo "")
I_ID=$(jf "$I_JSON" "id")
if [[ -n "$I_ID" ]]; then ok "bw create identity"
else fail "bw create identity" "$I_JSON"; fi

# ── list ──────────────────────────────────────────────────────────────────────

section "List"

# Sync before listing so the local cache reflects edits made above.
bwx sync 2>/dev/null || true

ALL=$(bwx list items 2>/dev/null || echo "[]")
ALL_COUNT=$(jlen "$ALL")
if [[ "$ALL_COUNT" -ge 4 ]]; then ok "bw list items ($ALL_COUNT total)"
else fail "bw list items" "count=$ALL_COUNT (expected ≥4)"; fi

FAV=$(bwx list items 2>/dev/null | node -e "
  try {
    const a = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
    process.stdout.write(JSON.stringify(a.filter(x => x.favorite)));
  } catch(e) { process.stdout.write('[]'); }" 2>/dev/null || echo "[]")
FAV_COUNT=$(jlen "$FAV")
if [[ "$FAV_COUNT" -ge 1 ]]; then ok "bw list items (favorites=$FAV_COUNT)"
else fail "bw list items (favorite filter)" "count=$FAV_COUNT"; fi

if [[ -n "$F_ID" ]]; then
  IN_FOLDER=$(bwx list items --folderid "$F_ID" 2>/dev/null || echo "[]")
  IF_COUNT=$(jlen "$IN_FOLDER")
  if [[ "$IF_COUNT" -ge 1 ]]; then ok "bw list items --folderid ($IF_COUNT in folder)"
  else fail "bw list items --folderid" "count=$IF_COUNT"; fi
fi

if bwx sync 2>/dev/null; then ok "bw sync (post-create)"; else fail "bw sync (post-create)" "failed"; fi

# ── sends ─────────────────────────────────────────────────────────────────────

section "Sends"

S_JSON=$(bwx send template send.text 2>/dev/null | node -e "
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  d.name = 'waf-test-send';
  d.notes = null;
  d.text.text = 'hello from WAF test';
  process.stdout.write(JSON.stringify(d));" 2>/dev/null | \
  bwx encode | bwx send create 2>/dev/null || echo "")
S_ID=$(jf "$S_JSON" "id")
if [[ -n "$S_ID" ]]; then ok "bw send create (text)"
else fail "bw send create" "$S_JSON"; fi

S_LIST=$(bwx send list 2>/dev/null || echo "[]")
S_COUNT=$(jlen "$S_LIST")
if [[ "$S_COUNT" -ge 1 ]]; then ok "bw send list ($S_COUNT)"
else fail "bw send list" "count=$S_COUNT"; fi

if [[ -n "$S_ID" ]]; then
  if bwx send delete "$S_ID" 2>/dev/null; then ok "bw send delete"
  else fail "bw send delete" "failed"; fi
fi

# ── delete / restore ──────────────────────────────────────────────────────────

section "Delete / Restore"

if [[ -n "$N_ID" ]]; then
  if bwx delete item "$N_ID" 2>/dev/null; then ok "bw delete item (soft — to trash)"
  else fail "bw delete item" "failed"; fi
  if bwx restore item "$N_ID" 2>/dev/null; then ok "bw restore item"
  else fail "bw restore item" "failed"; fi
  bwx delete item "$N_ID" 2>/dev/null || true
fi

if [[ -n "$C_ID" ]]; then
  if bwx delete item "$C_ID" --permanent 2>/dev/null; then ok "bw delete item --permanent"
  else fail "bw delete item --permanent" "failed"; fi
fi

# ── export ────────────────────────────────────────────────────────────────────

section "Export"

# Sync before export so the local cache is up to date.
bwx sync 2>/dev/null || true

JSON_OUT=$(mktemp /tmp/bw-export-XXXXXX.json)
if bwx export --format json --output "$JSON_OUT" 2>/dev/null; then
  ok "bw export --format json"
  EXPORTED=$(node -e "
    try {
      const d = JSON.parse(require('fs').readFileSync('$JSON_OUT','utf8'));
      process.stdout.write(String(d.items?.length ?? '?'));
    } catch(e) { process.stdout.write('err'); }" 2>/dev/null)
  if [[ "$EXPORTED" =~ ^[0-9]+$ ]]; then ok "export JSON valid ($EXPORTED items)"
  else fail "export JSON invalid" "$EXPORTED"; fi
else
  fail "bw export json" "failed"
fi
rm -f "$JSON_OUT"

CSV_OUT=$(mktemp /tmp/bw-export-XXXXXX.csv)
if bwx export --format csv --output "$CSV_OUT" 2>/dev/null; then
  ok "bw export --format csv"
  CSV_LINES=$(wc -l < "$CSV_OUT" 2>/dev/null || echo 0)
  if [[ "$CSV_LINES" -ge 1 ]]; then ok "export CSV has data ($CSV_LINES lines)"
  else fail "export CSV empty" "$CSV_LINES lines"; fi
else
  fail "bw export csv" "failed"
fi
rm -f "$CSV_OUT"

# ── cleanup ───────────────────────────────────────────────────────────────────

section "Cleanup"

if [[ -n "$F_ID" ]]; then
  if bwx delete folder "$F_ID" 2>/dev/null; then ok "bw delete folder"
  else fail "bw delete folder" "failed"; fi
fi

# ── WAF log check ─────────────────────────────────────────────────────────────

section "WAF"

ALL_LOGS=$(docker compose -f "$COMPOSE_FILE" logs --no-log-prefix openresty 2>/dev/null || echo "")
NEW_LOGS=$(printf '%s' "$ALL_LOGS" | tail -n +"$((LOG_OFFSET + 1))")

BLOCKS=$(printf '%s' "$NEW_LOGS" | grep -cE '\[waf\].*BLOCK|\[waf:block\]' 2>/dev/null || true)
DENIALS=$(printf '%s' "$NEW_LOGS" | grep -c 'HTTP/1\.[01]" 4[0-9][0-9]' 2>/dev/null || true)

if [[ "$BLOCKS" -eq 0 ]]; then ok "zero WAF blocks"
else
  fail "WAF blocks detected" "$BLOCKS"
  printf '%s' "$NEW_LOGS" | grep -E '\[waf\].*BLOCK|\[waf:block\]' | sed 's/^/    /'
fi

TOTAL_REQ=$(printf '%s' "$NEW_LOGS" | grep -c '"[A-Z]* /' 2>/dev/null || true)
printf "  %s requests proxied, %s 4xx responses\n" "$TOTAL_REQ" "$DENIALS"

# ── summary ───────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo ""
printf "${B}── %d passed, %d failed / %d total ──${N}\n" "$PASS" "$FAIL" "$TOTAL"
echo ""

[[ $FAIL -eq 0 ]]
