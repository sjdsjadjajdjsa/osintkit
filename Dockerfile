FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 UV_LINK_MODE=copy
RUN pip install --no-cache-dir uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv venv /opt/venv --python 3.12 \
 && uv pip install --python /opt/venv/bin/python .

FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 app
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    OSINTKIT_HOME=/data \
    XDG_CONFIG_HOME=/config \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data /config && chown -R app:app /data /config
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
WORKDIR /home/app
HEALTHCHECK CMD ["osintkit", "--version"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh", "osintkit"]
