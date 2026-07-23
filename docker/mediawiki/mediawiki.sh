#!/usr/bin/env bash
# Standalone utility for the `mediawiki` service in the shared
# ../docker-compose.yml. mediawiki's own version lives in exactly one
# place - the MEDIAWIKI_TARBALL default in docker-compose.yml - and its PHP
# runtime version lives in Dockerfile's FROM line; neither is duplicated
# here. No `init` subcommand (unlike gitea.sh): entrypoint.sh already
# handles first-boot setup (tarball extraction + installer) inside the
# container, no host-side bind-mount ownership step is needed.
set -euo pipefail

cd "$(dirname "$0")/.."

SERVICE=mediawiki

case "${1:-}" in
	pull)    docker compose pull "$SERVICE" ;;
	up)      docker compose up -d "$SERVICE" ;;
	down)    docker compose down "$SERVICE" ;;
	# `docker compose config --images <service>` isn't scoped to just that
	# service - it expands to the full depends_on closure. Query the
	# resolved config's own per-service image field instead. (This service
	# has no `image:` field at all - it's built from ./mediawiki/Dockerfile -
	# so the // fallback covers the resulting `null`.)
	version) docker compose config --format json | jq -r ".services.$SERVICE.image // \"built from ./mediawiki/Dockerfile (no fixed image tag; see Dockerfile's FROM line for the PHP runtime version)\"" ;;
	*)
		echo "Usage: $0 {pull|up|down|version}" >&2
		exit 1
		;;
esac
