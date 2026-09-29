# The DSH service: the harness, the Sedna bridge it drives, and the engine behind it.
#
# Node 24 is not a preference. DSH checks for `import.meta.main` in dsh/lib/bin.js and on
# Node 22 it exits *silently* — no error, no server. That silent exit is why this base image
# is pinned rather than left to a distro default.
FROM node:24-bookworm-slim

ARG DSH_VERSION=0.1.5-rc.2
ARG DEBIAN_FRONTEND=noninteractive

# python3 for the Sedna engine (>=3.11,<3.14), curl for the healthcheck, ca-certificates for
# pip, tini to reap the children an agent loop spawns. No compiler: the engine's dependencies
# all publish wheels for this interpreter.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/*

# pnpm via corepack, so `dsh plugin add` works inside the image (it is how a user adds a
# capability later without rebuilding).
RUN corepack enable && corepack prepare pnpm@latest --activate

# A flat install from a lock file -- not `npm install --global`, and not a floating range.
#
# Three failures got us here, each measured:
#
#   * A global install puts each package in its own tree, so a bundle cannot see its siblings.
#     The layout that works is the one npx produces: one node_modules holding the CLI and its
#     bundles side by side.
#   * `^0.1.5-rc.2` resolves to the newest prerelease, and that newer dsh-base depends on a
#     sandbox package version that was never published. npm installs the parent, silently
#     skips the impossible child, and DSH dies at boot with "plugin(s) failed to load:
#     @deepseek-ai/dsh-sandbox-local".
#   * Adding --legacy-peer-deps to make the two cordis peer ranges agree also makes npm skip
#     peers entirely, and then dsh-app-boot cannot find cordis-plugin-group -- and `npm ci`
#     with that flag skips them even when the lock lists them. Relaxing is not a direction:
#     with a pre-resolved lock the flag is unnecessary, because `ci` installs what the lock
#     says instead of resolving anything.
#
# So the tree is pinned: compose/dsh/install/package-lock.json is the resolution that works,
# and `npm ci` reproduces it exactly, peers included. It is also what makes the image
# reproducible, which is the property a portable install actually needs.
COPY compose/dsh/install/package.json compose/dsh/install/package-lock.json /opt/dsh/
RUN cd /opt/dsh \
 && npm ci --no-audit --no-fund \
 && node -e "for (const p of ['@deepseek-ai/dsh','@deepseek-ai/dsh-base','@deepseek-ai/dsh-web-app','@deepseek-ai/dsh-sandbox-local','@deepseek-ai/cordis-plugin-group']) { require.resolve(p + '/package.json'); console.log('  resolved', p); }" \
 && ln -sf /opt/dsh/node_modules/.bin/dsh /usr/local/bin/dsh \
 && dsh --version

# The bundles the `web` profile names. Installing a bundle that cannot resolve its own
# dependencies is the failure this build refuses to ship.
COPY compose/dsh/check-bundles.mjs /opt/dsh/check-bundles.mjs
RUN cd /opt/dsh && node check-bundles.mjs

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

# The bridge's own config, with the paths this image actually uses. Without it the plugin
# falls back to its host default (~/.dsh/plugins/sedna) and reports "driver.py missing" at
# boot -- a warning that leaves every sedna_* tool unable to do anything.
COPY compose/dsh/config.json /opt/sedna/config.json

# Container-side glue: the knowledge-base bootstrap, the entrypoint, the host-composition
# patch (which is where the bind-all row for the web GUI lives) and a settings example.
COPY compose/bootstrap-kb.sh /opt/sedna/bootstrap-kb.sh
COPY compose/dsh/entrypoint.sh /opt/sedna/entrypoint.sh
COPY compose/dsh/cordis.patch.yml /opt/sedna/cordis.patch.yml
COPY compose/dsh/settings.example.yaml /opt/sedna/settings.example.yaml
RUN chmod +x /opt/sedna/bootstrap-kb.sh /opt/sedna/entrypoint.sh

# The image already has `node` at uid 1000, and the build refused a second one rather than
# quietly shadowing it -- which is the right behaviour and worth keeping: on Linux a bind
# mounted workspace is usually owned by the first user, so uid 1000 is the one to reuse.
#
# Creating these directories here is not cosmetic. Docker seeds a fresh named volume from the
# image's directory at that path, ownership included: without them the volumes arrive owned by
# root and the container user cannot write the knowledge base or the sessions.
RUN mkdir -p /workspace /data/kb /home/node/.dsh /opt/dsh/bootcheck \
 && chown -R node:node /workspace /data/kb /home/node \
 && chmod 700 /data/kb

ENV DSH_HOME=/home/node/.dsh \
    DSH_SEDNA_DIR=/opt/sedna \
    SEDNA_SRC=/opt/sedna-engine/src \
    SEDNA_PYTHON=/opt/sedna/venv/bin/python \
    SEDNA_DRIVER=/opt/sedna/driver.py \
    SEDNA_KB_ROOT=/data/kb \
    SEDNA_SEED_DIR=/seed \
    DSH_TELEMETRY_DISABLED=1

# The last gate, and the one that matters: boot DSH once, in the image, with the real
# composition patch applied. It catches what every earlier check missed -- a patch row
# pointing at a file the image does not have, which no amount of dependency resolution
# notices and which the restart policy then hides as an endless clean exit.
COPY compose/dsh/boot-check.sh /opt/dsh/boot-check.sh
RUN chmod +x /opt/dsh/boot-check.sh && /opt/dsh/boot-check.sh

USER node
WORKDIR /workspace

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/sedna/entrypoint.sh"]
