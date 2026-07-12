#!/usr/bin/env bash

usage() {
	cat <<EOF
Usage: bash tools.sh <subcommand> [args]

Subcommands:
  offline-test [app]     Run Lua WAF unit tests via resty (all apps, or one by name)

  online-test-full [app] Live HTTP replay of the offline test suite against the Docker
                         stack.  WAF is temporarily forced to block mode for the run.
                         Default app: vaultwarden (port 8888). mediawiki (port 8889) has
                         a real MediaWiki (PHP-FPM + SQLite) backend too - see
                         docker/mediawiki/. Docker stack must be running.
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
		if [ -z "$APP" ] ; then

			for APP in $(ls -1  rootfs/etc/openresty/waf/apps/*.lua | grep -oP '[^/]+(?=\.lua$)') ; do

				resty -I rootfs/etc/openresty test/runner.lua "$APP" 

			done

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
		docker compose -f docker/docker-compose.yml up -d
		echo "Vaultwarden web vault: http://localhost:8888"
		echo "MediaWiki:             http://localhost:8889  (bash tools.sh docker-test-mw-creds for login)"
		echo "WAF logs: ./tools.sh docker-test-logs [service]"
	;;

	"docker-test-down")
		docker compose -f docker/docker-compose.yml down
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
		APP="${1:-vaultwarden}"
		# Port 8888: vaultwarden, plain-HTTP WAF listener with a real backend
		#   (no TLS per-request, ~50s for full suite). Override with
		#   WAF_HTTP_BASE=https://localhost:8443 to use the HTTPS listener instead.
		# Port 8889: mediawiki, with a real MediaWiki (PHP-FPM + SQLite) backend
		#   too - see docker/mediawiki/.
		case "$APP" in
			mediawiki) DEFAULT_BASE="http://localhost:8889" ;;
			*)         DEFAULT_BASE="http://localhost:8888" ;;
		esac
		BASE="${WAF_HTTP_BASE:-$DEFAULT_BASE}"
		COMPOSE="docker compose -f docker/docker-compose.yml"

		# Verify the Docker stack is up before starting.
		if ! $COMPOSE ps --status running 2>/dev/null | grep -q "openresty"; then
			echo "ERROR: Docker stack not running. Start it first:"
			echo "  bash tools.sh docker-test-up"
			exit 1
		fi

		# Start each run with a clean log slate.
		_clear_service_log openresty
		_clear_service_log "$APP"

		# Force block mode in the container for the duration of the test.
		$COMPOSE exec -T openresty sh -c 'touch /tmp/waf-block-mode'
		trap '$COMPOSE exec -T openresty sh -c "rm -f /tmp/waf-block-mode"' EXIT

		WAF_HTTP_BASE="$BASE" resty -I rootfs/etc/openresty test/runner.lua "$APP"
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
