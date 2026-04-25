#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: configure_nginx.sh <source_dir> <prefix>" >&2
  exit 2
fi

src="$1"
prefix="$2"

if [ -x "$src/configure" ]; then
  conf="$src/configure"
elif [ -x "$src/auto/configure" ]; then
  conf="$src/auto/configure"
else
  echo "finalis_nginx_build: no configure script found under $src" >&2
  exit 1
fi

exec "$conf" \
  --prefix="$prefix" \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --without-http_rewrite_module \
  --without-http_gzip_module \
  --without-http_ssi_module \
  --without-http_userid_module \
  --without-http_autoindex_module \
  --without-http_geo_module \
  --without-http_split_clients_module \
  --without-http_memcached_module \
  --without-http_empty_gif_module \
  --without-http_browser_module \
  --without-http_fastcgi_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module
