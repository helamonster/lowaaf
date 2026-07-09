#!/usr/bin/env bash
# Extracts the MediaWiki source tarball into the shared code volume (once)
# and runs the CLI installer against a fresh SQLite DB (once), then starts
# whatever CMD was given (php-fpm by default).
#
# The source tree lives in a named volume, not baked into this image, so the
# openresty container can mount the same volume read-only and serve static
# assets (skins/resources/images) directly instead of proxying everything
# through PHP.
set -euo pipefail

MW_DIR=/var/www/mediawiki
TARBALL=/mediawiki-src.tar.gz

MW_SERVER="${MW_SERVER:-http://localhost:8889}"
MW_SITE_NAME="${MW_SITE_NAME:-WAF Test Wiki}"
MW_ADMIN_USER="${MW_ADMIN_USER:-Admin}"
MW_ADMIN_PASS="${MW_ADMIN_PASS:-WafTestPass123!}"

if [ ! -f "$MW_DIR/index.php" ]; then
	echo "[entrypoint] Extracting MediaWiki source from $TARBALL..."
	if [ ! -f "$TARBALL" ]; then
		echo "[entrypoint] ERROR: $TARBALL not found - check the MEDIAWIKI_TARBALL bind mount in docker-compose.yml" >&2
		exit 1
	fi
	mkdir -p "$MW_DIR"
	tar -xzf "$TARBALL" --strip-components=1 -C "$MW_DIR"
fi

if [ ! -f "$MW_DIR/LocalSettings.php" ]; then
	echo "[entrypoint] Running MediaWiki installer (dbtype=sqlite, server=$MW_SERVER)..."
	mkdir -p "$MW_DIR/data"
	cd "$MW_DIR"
	php maintenance/run.php install \
		--dbtype sqlite \
		--dbpath "$MW_DIR/data" \
		--server "$MW_SERVER" \
		--scriptpath "" \
		--lang en \
		--pass "$MW_ADMIN_PASS" \
		"$MW_SITE_NAME" "$MW_ADMIN_USER"
	echo "[entrypoint] Install complete. Admin: $MW_ADMIN_USER / $MW_ADMIN_PASS"
fi

chown -R www-data:www-data "$MW_DIR"
chmod -R a+rX "$MW_DIR"

exec "$@"
