# Docker

```bash
docker build -t osintkit .
docker run --rm -it \
  -e OPENROUTER_API_KEY=... \
  -v "$HOME/.osintkit:/data" -v "$HOME/.config/osintkit:/config" \
  osintkit lookup --domain example.com
```

The image runs as uid 10001. The entrypoint chowns `/data` and `/config` when started as root and
drops privileges through `gosu`, so mounted host directories work without manual `chown`.

`/data` holds cache, logs, and reports; `/config` holds `config.toml`. `osintkit init` inside the
container writes to `/config` and survives restarts.

## Host DNS trouble

If lookups hang with no output, the container cannot reach HTTPS. Some hosts, notably those using
`systemd-resolved` on `127.0.0.53`, break Docker's embedded resolver. Confirm with:

```bash
timeout 30 docker run --rm --entrypoint python osintkit -c "import socket; print(socket.getaddrinfo('openrouter.ai', 443)[0][4][0])"
```

`127.0.0.53` unreachable from the container means you need `--network host` (or `--dns` pointing at
a resolver that answers). Passing a proxy with `-e HTTPS_PROXY` also works.

## For scripts

`ENTRYPOINT` is `osintkit`, so arguments are subcommands. Override with
`--entrypoint python` or `--entrypoint sh` for debugging.
