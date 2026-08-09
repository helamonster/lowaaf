#!/usr/bin/env bash
# Small standalone utility for docker/jellyfin/docker-compose.yml, independent
# of tools.sh's full-stack docker-test-up/down (which also brings up
# mediawiki/vaultwarden/gitea/openresty). The Jellyfin image version lives in
# exactly one place - the `image:` line in docker-compose.yml - every
# subcommand here defers to `docker compose` for that rather than hardcoding
# it again.
set -euo pipefail

cd "$(dirname "$0")"

case "${1:-}" in
	pull)
		docker compose pull
		;;
	up)
		docker compose up -d
		;;
	down)
		docker compose down
		;;
	version)
		# Matches the vaultwarden.sh/openresty.sh/gitea.sh pattern: `docker
		# compose config --images` isn't reliably scoped to one service when
		# depends_on chains exist elsewhere in a project, so every wrapper
		# here queries the resolved config's own per-service image field
		# instead, for consistency even though this compose file only has
		# the one "jellyfin" service.
		docker compose config --format json | jq -r '.services.jellyfin.image'
		;;
	*)
		echo "Usage: $0 {pull|up|down|version}" >&2
		exit 1
		;;
esac
