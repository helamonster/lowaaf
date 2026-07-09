# PHP-FPM image for the MediaWiki online-test backend.
#
# The MediaWiki source tarball is NOT baked into the image - it's extracted
# by entrypoint.sh into a named volume shared with the openresty container
# (which needs direct filesystem access to serve skins/resources/images
# without proxying every static asset through PHP). Baking it into the image
# would mean nginx has no way to read the same files without duplicating the
# whole ~100MB tree into a second image.
FROM php:8.3-fpm

RUN apt-get update && apt-get install -y --no-install-recommends \
      libicu-dev \
      libsqlite3-dev \
      libpng-dev \
      libjpeg62-turbo-dev \
      libfreetype6-dev \
      libonig-dev \
      libxml2-dev \
      sqlite3 \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    # xmlreader's build #includes "ext/dom/dom_ce.h" as a path relative to the
    # php-src root, but docker-php-ext-install's per-extension compile flags
    # never add that root to the include path (only ext/xmlreader's own
    # subdirs) - dom_ce.h genuinely exists after dom builds, xmlreader's
    # compiler invocation just can't find it without this.
    # (No standalone `sqlite3` PHP extension here - MediaWiki's SQLite driver
    # only checks for pdo_sqlite, per includes/Installer/SqliteInstaller.php,
    # and the standalone one ships as an unprocessed config0.m4 in this PHP
    # version's source, which docker-php-ext-install can't build as-is.)
    && CPPFLAGS="-I/usr/src/php" docker-php-ext-install \
      calendar \
      intl \
      mbstring \
      dom \
      xml \
      xmlreader \
      pdo_sqlite \
      gd \
      opcache \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /var/www/mediawiki

ENTRYPOINT ["/entrypoint.sh"]
CMD ["php-fpm"]
