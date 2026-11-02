#!/bin/sh
set -e
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data /config
  chown -R app:app /data /config 2>/dev/null || true
  exec gosu app "$@"
fi
exec "$@"
