#!/usr/bin/env bash

usage() {
	cat <<EOF
Usage: bash tools.sh <subcommand> [args]

Subcommands:
  offline-test [app]     Run Lua WAF unit tests via resty (all apps, or one by name)

  online-test-full [app] Live HTTP replay of the offline test suite against the Docker
                         stack.  WAF is temporarily forced to block mode for the run.
                         Default app: vaultwarden.  Docker stack must be running.
  online-test-cli [--no-reset]
                         Run bw CLI live integration tests against the Docker stack
                         (--no-reset skips VW volume wipe and reuses existing account)
  online-test-web        (not yet implemented)
  online-test-android    (not yet implemented)
  online-test-desktop    (not yet implemented)
  online-test-browser    (not yet implemented)

  docker-test-up         Start the local OpenResty + Vaultwarden Docker test stack
  docker-test-down       Stop the Docker test stack
  docker-test-reload     Reload OpenResty inside the container (picks up WAF code changes)
  docker-test-logs       Tail WAF deny log entries from the running OpenResty container

  diff                   Diff WAF sources against the deployed copy in /etc/openresty/waf/
  deploy                 rsync WAF sources to /etc/openresty/waf/ and restart openresty
  show-claude-md         Pretty-print CLAUDE.md with syntax highlighting
  migrate-to-github      Add GitHub remote and push main branch
EOF
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
	# WAF code is bind-mounted — run `docker-test-reload` to pick up changes.

	"docker-test-up")
		docker compose -f docker/docker-compose.yml up -d
		echo "Vaultwarden web vault: http://localhost:8888"
		echo "WAF logs: ./tools.sh docker-test-logs"
	;;

	"docker-test-down")
		docker compose -f docker/docker-compose.yml down
	;;

	"docker-test-reload")
		# Pick up WAF code changes without restarting the container.
		docker compose -f docker/docker-compose.yml exec openresty \
			/usr/local/openresty/bin/openresty -s reload
	;;

	"docker-test-logs")
		# Show WAF deny log entries in real time.
		docker compose -f docker/docker-compose.yml logs -f openresty 2>&1 \
			| grep --color=always -E '\[waf:|error|warn|$'
	;;

	"online-test-full")
		shift
		APP="${1:-vaultwarden}"
		# Port 8888: plain-HTTP WAF listener (no TLS per-request, ~50s for full suite)
		# Override with WAF_HTTP_BASE=https://localhost:8443 to use the HTTPS listener.
		BASE="${WAF_HTTP_BASE:-http://localhost:8888}"
		COMPOSE="docker compose -f docker/docker-compose.yml"

		# Verify the Docker stack is up before starting.
		if ! $COMPOSE ps --status running 2>/dev/null | grep -q "openresty"; then
			echo "ERROR: Docker stack not running. Start it first:"
			echo "  bash tools.sh docker-test-up"
			exit 1
		fi

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
