#!/usr/bin/env bash
# Small standalone utility for docker/gitea/docker-compose.yml, independent
# of tools.sh's full-stack docker-test-up/down (which also brings up
# mediawiki/vaultwarden/openresty). The Gitea image version lives in exactly
# one place - the `image:` line in docker-compose.yml - every subcommand
# here defers to `docker compose` for that rather than hardcoding it again.
set -euo pipefail

cd "$(dirname "$0")"

# Rootless Gitea image's internal UID/GID - not configurable via the
# USER_UID/USER_GID env vars in docker-compose.yml (those don't apply to the
# rootless variant). Bind-mounted config/data dirs need to be pre-owned by
# this UID/GID before first start, or Docker auto-creates them as root and
# the container fails to write into them.
DUID=100999
DGID=100999

case "${1:-}" in
	init)
		mkdir -p config data
		sudo chown "$DUID:$DGID" config data
		;;
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
		# Matches the vaultwarden.sh/openresty.sh/mediawiki.sh pattern:
		# `docker compose config --images` isn't reliably scoped to one
		# service when depends_on chains exist elsewhere in a project, so
		# every wrapper here queries the resolved config's own per-service
		# image field instead, for consistency even though this compose
		# file only has the one "server" service.
		docker compose config --format json | jq -r '.services.server.image'
		;;
	*)
		echo "Usage: $0 {init|pull|up|down|version}" >&2
		exit 1
		;;
esac
