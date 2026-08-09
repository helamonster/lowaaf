#!/usr/bin/env bash

usage() {
	cat <<'EOF'
Usage: bash tools.sh <subcommand> [args]

Subcommands:
  offline-test [app|all] Run Lua WAF unit tests via resty. No app given, or 'all':
                         every app in turn, plus a summary table. One app name: just
                         that app, full detail, no table.

  online-test-full [app|all]
                         Live HTTP replay of the offline test suite against the Docker
                         stack.  WAF is temporarily forced to block mode for the run.
                         No app given, or 'all': runs vaultwarden (port 8443, HTTPS -
                         must match its DOMAIN config, see tools.sh), mediawiki (port
                         8889), gitea (port 8890), and jellyfin (port 8892) in turn -
                         the only apps with a real backend wired into the stack (see
                         docker/mediawiki/, docker/gitea/, docker/jellyfin/) - plus a
                         summary table. Any other app name
                         silently falls back to the vaultwarden backend (no real
                         backend wired up for it yet). Docker stack must be running.
  online-test-cli [--no-reset]
                         Run bw CLI live integration tests against the Docker stack
                         (--no-reset skips VW volume wipe and reuses existing account)
  online-test-web        (not yet implemented)
  online-test-android    (not yet implemented)
  online-test-desktop    (not yet implemented)
  online-test-browser    (not yet implemented)

  docker-test-up         Start the local OpenResty + Vaultwarden + MediaWiki Docker test
                         stack. First run builds the mediawiki image and extracts +
                         installs MediaWiki (~1-2 min); later runs reuse the same volume.
                         Configurable: MEDIAWIKI_TARBALL, MW_SERVER, MW_SITE_NAME,
                         MW_ADMIN_USER, MW_ADMIN_PASS (see docker/docker-compose.yml).
  docker-test-down       Stop the Docker test stack
  docker-test-reload     Restart OpenResty inside the container (picks up WAF code changes
                         AND nginx.conf changes - plain `-s reload` doesn't reliably pick
                         up the latter in this image)
  docker-test-logs [service]
                         Tail logs from a Docker test stack service (requires jq). Default:
                         openresty, filtered to WAF deny/warn/error lines. Any other service
                         name (e.g. mediawiki) tails its raw logs unfiltered - PHP-FPM's
                         access log and error log both go there, interleaved. Safe to leave
                         running across a docker-test-logs-clear or an online-test-full run:
                         it survives the log file being truncated out from under it (plain
                         `docker compose logs -f` does NOT - it silently goes stale the
                         moment that happens, which looks exactly like "no log output").
  docker-test-logs-clear [service|all]
                         Truncate a service's log file (default: openresty). "all" clears
                         openresty, mediawiki, and vaultwarden together. online-test-full
                         already does this automatically before each run.
  docker-test-mw-shell   Open a bash shell in the running mediawiki container
  docker-test-mw-reset   Wipe the mediawiki code+DB volume and reinstall from scratch
                         (use after changing docker/mediawiki/entrypoint.sh, or to get a
                         clean wiki state)
  docker-test-mw-rebuild Rebuild the mediawiki image (after Dockerfile changes) and
                         recreate the container, keeping the existing code+DB volume
  docker-test-mw-creds   Print the admin username/password the installer set up
  docker-test-block-on   Force WAF block mode for manual testing (via the /tmp/waf-block-mode
                         sentinel - affects EVERY app in the stack, not just mediawiki, since
                         it's one openresty container). Remember to turn it back off.
  docker-test-block-off  Return to each app's own configured mode (normally "log")
  docker-test-block-status
                         Show whether block mode is currently forced on

  diff                   Diff WAF sources against the deployed copy in /etc/openresty/waf/
  deploy                 rsync WAF sources to /etc/openresty/waf/ and restart openresty
  show-claude-md         Pretty-print CLAUDE.md with syntax highlighting
  migrate-to-github      Add GitHub remote and push main branch

  -- MediaWiki extraction pipeline: scripts live in notes/apps/mediawiki/,
  -- generated JSON/output files in notes/apps/mediawiki/mw-api-extract/.
  mw-extract [src] [out] Re-run the MediaWiki source scan (extract_mediawiki_api.py):
                         regenerates api-params.json / special-fields.json from the
                         MediaWiki source tree in app-sources/
  mw-dump-paraminfo      Query a running instance's action=paraminfo (live introspection
                         of every api.php action/query-submodule's real params - types,
                         min/max, resolved enums, wire prefixes) into paraminfo.json.
                         Requires the Docker test stack up (bash tools.sh docker-test-up).
  mw-gen-api-schema      Regenerate apps/mediawiki/api_schema.lua from paraminfo.json.
                         MW_WAF_API_HIGH_LIMITS=1 uses paraminfo's higher apihighlimits-
                         privileged cap for limit-type fields instead of the default
                         (off) lower cap - a one-time deployment-config choice, see the
                         script's own header. A standalone Lua module mediawiki.lua
                         `require`s, not spliced text.
  mw-gen-special-pages   Regenerate apps/mediawiki/special_pages.lua (dedicated routes for
                         all 132 core Special: pages) from special-fields.json. A
                         factory function mediawiki.lua `require`s and calls with
                         idx_common, not spliced text.
  mw-gen-edit-forms      Regenerate apps/mediawiki/edit_forms.lua (index_post_form -
                         EditPage.php's edit-submission form - plus one form per
                         index.php action=X POST target) from editpage-fields.json +
                         index-actions.json. A standalone Lua module mediawiki.lua
                         `require`s, not spliced text.
  mw-verify-routes       Sanity-check the real, loaded app.routes table: no duplicate
                         route names, full Special: page coverage
  mw-verify-regression   Sanity-check api-params.json for suspicious/missing params
  mw-list-core-pages     List SpecialPageFactory::CORE_LIST page keys from special-fields.json
  mw-regen-all           Full pipeline: mw-extract, dump-paraminfo + gen-api-schema,
                         gen-special-pages, gen-edit-forms, then verify + offline-test.
                         Requires the Docker test stack up (for mw-dump-paraminfo).

  -- Gitea extraction pipeline (Phase 1: REST API v1 only - see TODO.txt,
  -- "GITEA WAF POLICY - PHASE 1: REST API v1"). Scripts live in
  -- notes/apps/gitea/gitea-api-extract/. Unlike MediaWiki's api.php, Gitea
  -- ships a complete Swagger 2.0 spec checked into its own repo
  -- (app-sources/gitea/server/gitea/templates/swagger/v1_json.tmpl) - no live
  -- Docker dependency needed for structure, only for online-test-full.
  gitea-extract-swagger  Parse the checked-in swagger spec + cross-reference Go struct
                         binding tags (modules/structs, services/forms, models/activities,
                         modules/timeutil) into gitea-api-extracted.json.
  gitea-gen-api-schema   Regenerate apps/gitea/api_schema.lua from gitea-api-extracted.json -
                         one route per (method, swagger path), no MediaWiki-style
                         cross-action union needed (each REST path is already unique).
  gitea-verify-routes    Sanity-check the real, loaded app.routes table: no duplicate
                         route names, generated (Phase 1) route count matches the
                         extracted operation count.

  -- Gitea Phase 2 (web UI) pipeline: notes/apps/gitea/gitea-web-extract/.
  -- A brace/paren-depth-aware scanner over routers/web/web.go's
  -- registerWebRoutes(), cross-referenced against services/forms/*.go for
  -- bound-form field validation.
  gitea-extract-web-routes  Scan routers/web/web.go into gitea-web-extracted.json
                         (method/path/bound-form per route).
  gitea-gen-web-routes   Regenerate apps/gitea/web_routes.lua from
                         gitea-web-extracted.json + services/forms/*.go binding tags.

  gitea-regen-all        Full pipeline: extract-swagger, gen-api-schema,
                         extract-web-routes, gen-web-routes, verify-routes, then
                         offline-test. No Docker dependency (unlike mw-regen-all).
EOF
}

# Truncates one Docker test stack service's json-file log in place (works
# without sudo on rootless Docker, where the log file is owned by the
# current user - `docker logs`/`docker compose logs` just re-reads from
# empty). Used by both the standalone docker-test-logs-clear subcommand and
# online-test-full's automatic pre-run clear.
_clear_service_log() {
	local service="$1"
	local cid
	cid="$(docker compose -f docker/docker-compose.yml ps -q "$service" 2>/dev/null)"
	if [ -z "$cid" ]; then
		echo "  skip $service (not running)"
		return
	fi
	local logpath
	logpath="$(docker inspect --format='{{.LogPath}}' "$cid" 2>/dev/null)"
	if [ -n "$logpath" ] && [ -w "$logpath" ]; then
		: > "$logpath"
		echo "  cleared $service"
	else
		echo "  could not clear $service (no write access to $logpath - non-rootless Docker may need sudo)"
	fi
}

# Follows one service's raw json-file log, decoded to plain text.
# Deliberately NOT `docker compose logs -f`: reproducibly verified that an
# already-attached `docker compose logs -f` session goes silently stale the
# moment the underlying file is truncated (e.g. by docker-test-logs-clear, or
# online-test-full's automatic pre-run clear) and never shows another line -
# exactly the "ran a test but saw no log output" symptom this exists to fix.
# `tail -F` detects the file shrinking and reopens from the new EOF instead.
_follow_service_log() {
	local service="$1"
	local cid
	cid="$(docker compose -f docker/docker-compose.yml ps -q "$service" 2>/dev/null)"
	if [ -z "$cid" ]; then
		echo "ERROR: service '$service' not running" >&2
		return 1
	fi
	local logpath
	logpath="$(docker inspect --format='{{.LogPath}}' "$cid" 2>/dev/null)"
	if [ -z "$logpath" ]; then
		echo "ERROR: could not resolve log path for '$service'" >&2
		return 1
	fi
	tail -F -n 20 "$logpath" 2>/dev/null | while IFS= read -r line; do
		printf '%s\n' "$line" | jq -j '.log' 2>/dev/null
	done
}

# Renders the global $SUMMARY_LINES array - one "[app] N routes — X passed
# Y failed Z skipped (T total cases)" line per app, as printed by
# test/runner.lua - as a column-aligned table with thousands-separated
# numbers (printf's glibc "'" flag) plus a TOTAL row. Shared by
# offline-test's and online-test-full's all-apps modes so the two don't
# duplicate this formatting.
_print_summary_table() {
	local title="$1"
	local G=$'\033[32m' R=$'\033[31m' RS=$'\033[0m'   # matches test/runner.lua's palette
	local -a NAME=() ROUTES=() PASSV=() FAILV=() SKIPV=() CASESV=() STATUSV=()
	local TOTAL_ROUTES=0 TOTAL_PASS=0 TOTAL_FAIL=0 TOTAL_SKIP=0 TOTAL_CASES=0
	local line n r p f s c

	for line in "${SUMMARY_LINES[@]}"; do
		[ -z "$line" ] && continue
		n="$(grep -oP '(?<=^\[)[^]]+'                <<< "$line")"
		r="$(grep -oP '(?<=\] )\d+(?= routes)'       <<< "$line")"
		p="$(grep -oP '\d+(?= passed)'               <<< "$line")"
		f="$(grep -oP '\d+(?= failed)'                <<< "$line")"
		s="$(grep -oP '\d+(?= skipped)'              <<< "$line")"
		c="$(grep -oP '(?<=\()\d+(?= total cases)'   <<< "$line")"
		TOTAL_ROUTES=$((TOTAL_ROUTES + ${r:-0}))
		TOTAL_PASS=$((TOTAL_PASS + ${p:-0}))
		TOTAL_FAIL=$((TOTAL_FAIL + ${f:-0}))
		TOTAL_SKIP=$((TOTAL_SKIP + ${s:-0}))
		TOTAL_CASES=$((TOTAL_CASES + ${c:-0}))
		NAME+=("$n")
		ROUTES+=("$(printf "%'d" "${r:-0}")")
		PASSV+=("$(printf "%'d" "${p:-0}")")
		FAILV+=("$(printf "%'d" "${f:-0}")")
		SKIPV+=("$(printf "%'d" "${s:-0}")")
		CASESV+=("$(printf "%'d" "${c:-0}")")
		if [ "${f:-0}" -gt 0 ]; then STATUSV+=("${R}FAIL${RS}"); else STATUSV+=("${G}ok${RS}"); fi
	done

	# Column widths sized off the header + every data row (including TOTAL),
	# so the table stays aligned regardless of app-name length or how many
	# digits the numbers grow to.
	local w_name=4 w_routes=6 w_pass=6 w_fail=6 w_skip=7 w_cases=5 i
	for i in "${!NAME[@]}"; do
		(( ${#NAME[i]}   > w_name   )) && w_name=${#NAME[i]}
		(( ${#ROUTES[i]} > w_routes )) && w_routes=${#ROUTES[i]}
		(( ${#PASSV[i]}  > w_pass   )) && w_pass=${#PASSV[i]}
		(( ${#FAILV[i]}  > w_fail   )) && w_fail=${#FAILV[i]}
		(( ${#SKIPV[i]}  > w_skip   )) && w_skip=${#SKIPV[i]}
		(( ${#CASESV[i]} > w_cases  )) && w_cases=${#CASESV[i]}
	done
	local TOTAL_ROUTES_F TOTAL_PASS_F TOTAL_FAIL_F TOTAL_SKIP_F TOTAL_CASES_F
	TOTAL_ROUTES_F="$(printf "%'d" "$TOTAL_ROUTES")"; (( ${#TOTAL_ROUTES_F} > w_routes )) && w_routes=${#TOTAL_ROUTES_F}
	TOTAL_PASS_F="$(printf "%'d" "$TOTAL_PASS")";     (( ${#TOTAL_PASS_F}   > w_pass   )) && w_pass=${#TOTAL_PASS_F}
	TOTAL_FAIL_F="$(printf "%'d" "$TOTAL_FAIL")";     (( ${#TOTAL_FAIL_F}   > w_fail   )) && w_fail=${#TOTAL_FAIL_F}
	TOTAL_SKIP_F="$(printf "%'d" "$TOTAL_SKIP")";     (( ${#TOTAL_SKIP_F}   > w_skip   )) && w_skip=${#TOTAL_SKIP_F}
	TOTAL_CASES_F="$(printf "%'d" "$TOTAL_CASES")";   (( ${#TOTAL_CASES_F}  > w_cases  )) && w_cases=${#TOTAL_CASES_F}

	# Column order: APP, ROUTES, CASES, PASSED, FAILED, SKIPPED, STATUS -
	# CASES sits right after ROUTES since it's a property of the route set
	# (how many cases they expanded to), before the pass/fail/skip breakdown.
	row() {
		printf "  %-*s  %*s  %*s  %*s  %*s  %*s  %s\n" \
			"$w_name" "$1" "$w_routes" "$2" "$w_cases" "$3" "$w_pass" "$4" "$w_fail" "$5" "$w_skip" "$6" "$7"
	}
	rule() { printf '  %s\n' "$(printf -- '-%.0s' $(seq 1 $((w_name+w_routes+w_pass+w_fail+w_skip+w_cases+18))))"; }

	echo ""
	echo "── $title summary (all apps) ──"
	row "APP" "ROUTES" "CASES" "PASSED" "FAILED" "SKIPPED" "STATUS"
	rule
	for i in "${!NAME[@]}"; do
		row "${NAME[i]}" "${ROUTES[i]}" "${CASESV[i]}" "${PASSV[i]}" "${FAILV[i]}" "${SKIPV[i]}" "${STATUSV[i]}"
	done
	rule
	local TOTAL_STATUS="${G}ok${RS}"; [ "$TOTAL_FAIL" -gt 0 ] && TOTAL_STATUS="${R}FAIL${RS}"
	row "TOTAL" "$TOTAL_ROUTES_F" "$TOTAL_CASES_F" "$TOTAL_PASS_F" "$TOTAL_FAIL_F" "$TOTAL_SKIP_F" "$TOTAL_STATUS"
}

case "$1" in

	"diff")

		 diff --color  -r rootfs/etc/openresty/waf/ /etc/openresty/waf/

	;;

	"deploy")

		sudo rsync -var  rootfs/etc/openresty/waf/ /etc/openresty/waf/
		sudo systemctl restart openresty

	;;

	"offline-test")
		shift
		APP="$1"
		if [ -z "$APP" ] || [ "$APP" = "all" ] ; then

			# Run every app, but tee each run's output through a scratch file
			# so the per-app "[app] N routes — ..." summary line (printed by
			# test/runner.lua) can be pulled back out afterward and rolled up
			# into a single cross-app table - without losing the live,
			# full-detail output each run already prints as it goes.
			OVERALL_STATUS=0
			SUMMARY_LINES=()

			for APP in $(ls -1  rootfs/etc/openresty/waf/apps/*.lua | grep -oP '[^/]+(?=\.lua$)') ; do

				OUT_FILE="$(mktemp)"
				resty -I rootfs/etc/openresty test/runner.lua "$APP" 2>&1 | tee "$OUT_FILE"
				[ "${PIPESTATUS[0]}" -ne 0 ] && OVERALL_STATUS=1
				SUMMARY_LINES+=("$(grep -E '^\[[^]]+\] [0-9]+ routes' "$OUT_FILE")")
				rm -f "$OUT_FILE"

			done

			_print_summary_table "offline-test"

			exit "$OVERALL_STATUS"

		else

			if [ -e "rootfs/etc/openresty/waf/apps/$APP.lua" ] ; then
				resty -I rootfs/etc/openresty test/runner.lua "$APP"
			else
				echo "nope: '$APP'"
			fi

		fi

	;;


	"show-claude-md")

		highlight -O xterm256 --syntax markdown CLAUDE.md

	;;


	# ── Docker test environment ──────────────────────────────────────────────────
	# Runs a local OpenResty + Vaultwarden stack for WAF log-mode validation.
	# Web vault at http://localhost:8888 ; WAF logs via `docker-test-logs`.
	# WAF code AND nginx.conf are bind-mounted — run `docker-test-reload` to pick
	# up changes to either.

	"docker-test-up")
		# docker/certs is gitignored (self-signed, host-specific, no reason to
		# track it) but docker-compose.yml bind-mounts it into openresty and
		# nginx.conf's :443 server block hard-requires cert.pem/key.pem to
		# exist or the whole nginx process refuses to start - generate a
		# throwaway self-signed pair on first run if missing.
		if [ ! -f docker/certs/cert.pem ] || [ ! -f docker/certs/key.pem ]; then
			echo "Generating self-signed TLS cert for docker/certs (first run)..."
			mkdir -p docker/certs
			openssl req -x509 -nodes -newkey rsa:2048 \
				-keyout docker/certs/key.pem -out docker/certs/cert.pem \
				-days 3650 -subj "/CN=localhost" 2>/dev/null
		fi

		# gitea and jellyfin each live in their own compose file
		# (docker/gitea/docker-compose.yml, docker/jellyfin/docker-compose.yml)
		# rather than being folded into the main one, joined to the main
		# stack's "waf-test" network as external - brought up first so each
		# container (and its network attachment/DNS name) exists before
		# openresty starts, since a plain `proxy_pass http://gitea:3000` (or
		# http://jellyfin:8096) resolves the hostname at config-load time,
		# not per-request.
		docker compose -f docker/gitea/docker-compose.yml up -d
		docker compose -f docker/jellyfin/docker-compose.yml up -d
		docker compose -f docker/docker-compose.yml up -d

		# Unattended boot (GITEA__security__INSTALL_LOCK=true) skips the web
		# installer entirely but still needs one CLI call to create a test
		# admin user - same intent as MW_ADMIN_USER/MW_ADMIN_PASS, just done
		# from outside the container (no custom entrypoint.sh for gitea,
		# unlike mediawiki's). Idempotent: tolerates "already exists" on
		# every run after the first. Bounded retry loop since the container
		# needs a moment after `up -d` before its SQLite engine is ready.
		GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-Admin}"
		GITEA_ADMIN_PASS="${GITEA_ADMIN_PASS:-WafTestPass123!}"
		GITEA_READY=0
		for _ in $(seq 1 15); do
			OUT="$(docker exec gitea gitea admin user create \
				--username "$GITEA_ADMIN_USER" --password "$GITEA_ADMIN_PASS" \
				--email admin@waftest.local --admin --must-change-password=false 2>&1)" && GITEA_READY=1 && break
			echo "$OUT" | grep -qi "already exists" && GITEA_READY=1 && break
			sleep 1
		done
		if [ "$GITEA_READY" != "1" ]; then
			echo "WARNING: could not confirm/create the gitea admin user - it may not be ready yet:"
			echo "$OUT"
		fi

		echo "Vaultwarden web vault: http://localhost:8888"
		echo "MediaWiki:             http://localhost:8889  (bash tools.sh docker-test-mw-creds for login)"
		echo "Gitea:                 http://localhost:8890  (user: $GITEA_ADMIN_USER / pass: $GITEA_ADMIN_PASS)"
		echo "Jellyfin:               http://localhost:8892  (unconfigured - first-run wizard not run; that's fine for WAF testing)"
		echo "WAF logs: ./tools.sh docker-test-logs [service]"
	;;

	"docker-test-down")
		docker compose -f docker/docker-compose.yml down
		docker compose -f docker/gitea/docker-compose.yml down
		docker compose -f docker/jellyfin/docker-compose.yml down
	;;

	"docker-test-reload")
		# `openresty -s reload` does NOT reliably pick up docker/nginx.conf
		# changes in this image (reproducibly verified: editing nginx.conf and
		# reloading left the running config unchanged, while a full container
		# restart picked it up every time) - so this does a full restart
		# instead. Slower (~2s) but actually correct for both nginx.conf edits
		# and WAF Lua code changes (bind-mounted, freshly require()'d by the
		# fresh worker processes either way).
		docker compose -f docker/docker-compose.yml restart openresty
	;;

	"docker-test-logs")
		shift
		SERVICE="${1:-openresty}"
		if [ "$SERVICE" = "openresty" ]; then
			# Show WAF deny log entries in real time.
			_follow_service_log openresty | grep --color=always -E '\[waf:|error|warn|$'
		else
			# e.g. mediawiki: PHP-FPM sends both access.log and error_log to
			# stderr (see docker/mediawiki/Dockerfile's base image config), so
			# this one command shows both, interleaved.
			_follow_service_log "$SERVICE"
		fi
	;;

	"docker-test-logs-clear")
		shift
		SERVICE="${1:-openresty}"
		if [ "$SERVICE" = "all" ]; then
			for SVC in openresty mediawiki vaultwarden; do
				_clear_service_log "$SVC"
			done
		else
			_clear_service_log "$SERVICE"
		fi
	;;

	"docker-test-mw-shell")
		docker compose -f docker/docker-compose.yml exec mediawiki bash
	;;

	"docker-test-mw-reset")
		COMPOSE="docker compose -f docker/docker-compose.yml"
		$COMPOSE rm -sf mediawiki
		docker volume rm docker_mediawiki-code 2>&1 || true
		$COMPOSE up -d mediawiki
		echo "MediaWiki volume wiped - re-extracting + reinstalling from scratch."
		echo "Watch progress: bash tools.sh docker-test-logs mediawiki"
	;;

	"docker-test-mw-rebuild")
		COMPOSE="docker compose -f docker/docker-compose.yml"
		$COMPOSE build mediawiki
		$COMPOSE up -d mediawiki
	;;

	"docker-test-mw-creds")
		echo "Admin user: ${MW_ADMIN_USER:-Admin}"
		echo "Admin pass: ${MW_ADMIN_PASS:-WafTestPass123!}"
		echo "(these are only the *defaults* - if MW_ADMIN_USER/MW_ADMIN_PASS were set"
		echo " in the environment when the wiki was first installed, those win instead)"
	;;

	"docker-test-block-on")
		docker compose -f docker/docker-compose.yml exec -T openresty sh -c 'touch /tmp/waf-block-mode'
		echo "WAF block mode ON - affects every app behind this openresty container"
		echo "(vaultwarden and mediawiki alike), not just whichever one you're poking at."
		echo "Turn it off when done: bash tools.sh docker-test-block-off"
	;;

	"docker-test-block-off")
		docker compose -f docker/docker-compose.yml exec -T openresty sh -c 'rm -f /tmp/waf-block-mode'
		echo "WAF block mode OFF - back to each app's own configured mode (normally \"log\")."
	;;

	"docker-test-block-status")
		if docker compose -f docker/docker-compose.yml exec -T openresty sh -c '[ -e /tmp/waf-block-mode ]' 2>/dev/null; then
			echo "Block mode: ON"
		else
			echo "Block mode: off"
		fi
	;;

	"online-test-full")
		shift
		APP="$1"
		# Port 8443: vaultwarden, the HTTPS WAF listener - MUST match the
		#   vaultwarden container's own DOMAIN (docker/docker-compose.yml,
		#   currently "https://localhost:8443") exactly, scheme+host+port.
		#   vaultwarden.lua's vw_iss validates a Bearer JWT's `iss` claim
		#   against the CURRENT request's own Host header - and every token
		#   Vaultwarden issues carries `iss` derived from its DOMAIN config,
		#   never from whatever port a client happened to log in through.
		#   Confirmed live: testing real logged-in traffic through the
		#   plain-HTTP :8888 listener below made every authenticated request
		#   fail iss validation (denied), even though the token itself was
		#   perfectly valid - :8888 exists purely for fast anonymous bulk
		#   testing (no per-request TLS handshake) and must stay that way for
		#   any app name NOT explicitly listed here (the `*` case below), but
		#   for vaultwarden specifically, correctness requires :8443.
		# Port 8889: mediawiki, with a real MediaWiki (PHP-FPM + SQLite) backend
		#   too - see docker/mediawiki/.
		# Port 8890: gitea, with a real Gitea backend - see docker/gitea/
		#   (its own compose file, joined to this stack's network as external).
		#   Phase 1 only models /api/v1/*, so non-API paths will show as denies -
		#   expected until later phases widen coverage.
		# Port 8892: jellyfin, with a real Jellyfin backend - see
		#   docker/jellyfin/ (its own compose file, same external-network
		#   pattern as gitea). Any app name not explicitly listed here falls
		#   through to the plain-HTTP :8888 vaultwarden listener, which
		#   silently tests the wrong app against the wrong backend - add a
		#   case here whenever a new app gets a real backend wired into the
		#   stack.
		_default_base_for_app() {
			case "$1" in
				vaultwarden) echo "https://localhost:8443" ;;
				mediawiki)   echo "http://localhost:8889" ;;
				gitea)       echo "http://localhost:8890" ;;
				jellyfin)    echo "http://localhost:8892" ;;
				*)           echo "http://localhost:8888" ;;
			esac
		}
		COMPOSE="docker compose -f docker/docker-compose.yml"

		# Verify the Docker stack is up before starting.
		if ! $COMPOSE ps --status running 2>/dev/null | grep -q "openresty"; then
			echo "ERROR: Docker stack not running. Start it first:"
			echo "  bash tools.sh docker-test-up"
			exit 1
		fi

		if [ -z "$APP" ] || [ "$APP" = "all" ] ; then

			# Loop-all mode: only the apps with a real backend wired into the
			# stack above - looping over every apps/*.lua file the way
			# offline-test does would silently point an unlisted app at
			# vaultwarden's backend and report meaningless results for it.
			# WAF_HTTP_BASE is deliberately NOT honored here (unlike the
			# single-app path below) - one override can't sensibly apply to
			# four different apps' backends at once.
			OVERALL_STATUS=0
			SUMMARY_LINES=()

			$COMPOSE exec -T openresty sh -c 'touch /tmp/waf-block-mode'
			trap '$COMPOSE exec -T openresty sh -c "rm -f /tmp/waf-block-mode"' EXIT

			for APP in vaultwarden mediawiki gitea jellyfin; do

				BASE="$(_default_base_for_app "$APP")"
				_clear_service_log openresty
				_clear_service_log "$APP"

				OUT_FILE="$(mktemp)"
				WAF_HTTP_BASE="$BASE" resty -I rootfs/etc/openresty test/runner.lua "$APP" 2>&1 | tee "$OUT_FILE"
				[ "${PIPESTATUS[0]}" -ne 0 ] && OVERALL_STATUS=1
				SUMMARY_LINES+=("$(grep -E '^\[[^]]+\] [0-9]+ routes' "$OUT_FILE")")
				rm -f "$OUT_FILE"

			done

			_print_summary_table "online-test-full"

			exit "$OVERALL_STATUS"

		else

			BASE="${WAF_HTTP_BASE:-$(_default_base_for_app "$APP")}"

			# Start with a clean log slate.
			_clear_service_log openresty
			_clear_service_log "$APP"

			# Force block mode in the container for the duration of the test.
			$COMPOSE exec -T openresty sh -c 'touch /tmp/waf-block-mode'
			trap '$COMPOSE exec -T openresty sh -c "rm -f /tmp/waf-block-mode"' EXIT

			WAF_HTTP_BASE="$BASE" resty -I rootfs/etc/openresty test/runner.lua "$APP"

		fi
	;;

	"online-test-cli")
		shift
		bash "$(dirname "$0")/bw_test_live.sh" "$@"
	;;

	"online-test-web"|"online-test-android"|"online-test-desktop"|"online-test-browser")
		echo "  '$1' is not yet implemented."
		exit 1
	;;


	"mw-extract")
		shift
		python3 notes/apps/mediawiki/extract_mediawiki_api.py "$@"
	;;

	"mw-dump-paraminfo")
		COMPOSE="docker compose -f docker/docker-compose.yml"
		if ! $COMPOSE ps --status running 2>/dev/null | grep -q "openresty"; then
			echo "ERROR: Docker stack not running. Start it first:"
			echo "  bash tools.sh docker-test-up"
			exit 1
		fi
		python3 notes/apps/mediawiki/mw-api-extract/dump_paraminfo.py
	;;

	"mw-gen-api-schema")
		python3 notes/apps/mediawiki/mw-api-extract/gen_api_schema.py
	;;

	"mw-gen-special-pages")
		python3 notes/apps/mediawiki/mw-api-extract/gen_special_pages.py
	;;

	"mw-gen-edit-forms")
		python3 notes/apps/mediawiki/mw-api-extract/gen_edit_forms.py
	;;

	"mw-verify-routes")
		python3 notes/apps/mediawiki/mw-api-extract/verify_mediawiki_routes.py
	;;

	"mw-verify-regression")
		python3 notes/apps/mediawiki/mw-api-extract/verify_no_regression.py
	;;

	"mw-list-core-pages")
		python3 notes/apps/mediawiki/mw-api-extract/list_core_pages.py
	;;

	"mw-regen-all")
		set -e
		bash "$0" mw-extract
		bash "$0" mw-dump-paraminfo
		bash "$0" mw-gen-api-schema
		bash "$0" mw-gen-special-pages
		bash "$0" mw-gen-edit-forms
		bash "$0" mw-verify-routes
		bash "$0" offline-test mediawiki
	;;

	"gitea-extract-swagger")
		python3 notes/apps/gitea/gitea-api-extract/extract_swagger.py
	;;

	"gitea-gen-api-schema")
		python3 notes/apps/gitea/gitea-api-extract/gen_api_schema.py
	;;

	"gitea-verify-routes")
		python3 notes/apps/gitea/gitea-api-extract/verify_gitea_routes.py
	;;

	"gitea-extract-web-routes")
		python3 notes/apps/gitea/gitea-web-extract/extract_web_routes.py
	;;

	"gitea-gen-web-routes")
		python3 notes/apps/gitea/gitea-web-extract/gen_web_routes.py
	;;

	"gitea-regen-all")
		set -e
		bash "$0" gitea-extract-swagger
		bash "$0" gitea-gen-api-schema
		bash "$0" gitea-extract-web-routes
		bash "$0" gitea-gen-web-routes
		bash "$0" gitea-verify-routes
		bash "$0" offline-test gitea
	;;

	"migrate-to-github")

		URL_BASE="https://github.com/helamonster/lowaaf"
		URL_REPO="${URL_BASE}.git"

		git remote add origin "${URL_REPO}"
		git branch -M main
		git push -u origin main

	;;

	*)
		if [[ -n "$1" ]]; then
			echo "Unknown subcommand: '$1'"
			echo ""
		fi
		usage
		exit 1
	;;

esac
