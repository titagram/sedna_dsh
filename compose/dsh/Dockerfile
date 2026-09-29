# The DSH service: the harness, the Sedna bridge it drives, and the engine behind it.
#
# Node 24 is not a preference. DSH checks for `import.meta.main` in dsh/lib/bin.js and on
# Node 22 it exits *silently* — no error, no server. That silent exit is why this base image
# is pinned rather than left to a distro default.
FROM node:24-bookworm-slim

ARG DSH_VERSION=0.1.5-rc.2
ARG DEBIAN_FRONTEND=noninteractive

# python3 for the Sedna engine (>=3.11,<3.14), curl for the healthcheck, ca-certificates for
# pip. No compiler: the engine's dependencies all publish wheels for this interpreter.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/*

# pnpm via corepack, so `dsh plugin add` works inside the image (it is how a user adds a
# capability later without rebuilding).
RUN corepack enable && corepack prepare pnpm@latest --activate

RUN npm install --global "@deepseek-ai/dsh@${DSH_VERSION}" \
 && dsh --version

# The engine is vendored whole, including its pyproject, so it is installed from its own
# declaration rather than from a list that drifts.
COPY engine/ /opt/sedna-engine/
RUN python3 -m venv /opt/sedna/venv \
 && /opt/sedna/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/sedna/venv/bin/pip install --no-cache-dir -e /opt/sedna-engine \
 && /opt/sedna/venv/bin/python -c "import sedna; print('engine importable')"

# The bridge plugin and its driver.
COPY plugin/sedna/driver.py /opt/sedna/driver.py
COPY plugin/sedna/index.mjs /opt/sedna/index.mjs
COPY plugin/sedna/plugin.json /opt/sedna/plugin.json

# Container-side glue: the knowledge-base bootstrap, the entrypoint, the host-composition
# patch (which is where the bind-all row for the web GUI lives) and a settings example.
COPY compose/bootstrap-kb.sh /opt/sedna/bootstrap-kb.sh
COPY compose/dsh/entrypoint.sh /opt/sedna/entrypoint.sh
COPY compose/dsh/cordis.patch.yml /opt/sedna/cordis.patch.yml
COPY compose/dsh/settings.example.yaml /opt/sedna/settings.example.yaml
RUN chmod +x /opt/sedna/bootstrap-kb.sh /opt/sedna/entrypoint.sh

# A fixed uid, because the bridge writes into the knowledge-base volume and the sessions
# directory. On Linux a bind-mounted workspace may be owned by a different uid; pass
# `user:` in compose or match the numbers (see compose/README.md).
RUN useradd --create-home --uid 1000 --shell /bin/bash dsh

ENV DSH_HOME=/home/dsh/.dsh \
    SEDNA_SRC=/opt/sedna-engine/src \
    SEDNA_PYTHON=/opt/sedna/venv/bin/python \
    SEDNA_DRIVER=/opt/sedna/driver.py \
    SEDNA_KB_ROOT=/data/kb \
    SEDNA_SEED_DIR=/seed \
    DSH_TELEMETRY_DISABLED=1

USER dsh
WORKDIR /workspace

# tini reaps the child processes: a container that runs an agent loop spawns plenty.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/sedna/entrypoint.sh"]
