#!/usr/bin/env bash
# Standalone utility for the `vaultwarden` service in docker-compose.yml
# (vaultwarden has no Dockerfile/compose file of its own - off-the-shelf
# image). Version lives in exactly one place - the `image:` line in
# docker-compose.yml - every subcommand here defers to `docker compose`
# for that rather than hardcoding it again.
set -euo pipefail

cd "$(dirname "$0")"

SERVICE=vaultwarden

case "${1:-}" in
	pull)    docker compose pull "$SERVICE" ;;
	up)      docker compose up -d "$SERVICE" ;;
	down)    docker compose down "$SERVICE" ;;
	# `docker compose config --images <service>` isn't scoped to just that
	# service - it expands to the full depends_on closure. Query the
	# resolved config's own per-service image field instead.
	version) docker compose config --format json | jq -r ".services.$SERVICE.image" ;;
	*)
		echo "Usage: $0 {pull|up|down|version}" >&2
		exit 1
		;;
esac
