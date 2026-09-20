FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
WORKDIR /app
# Apply Debian security updates and drop npm/npx/corepack: the broker, audit
# forwarder, and approval web UI are plain Node.js processes that never shell
# out to npm, so its bundled dependencies (a persistent source of Trivy
# HIGH/CRITICAL findings unrelated to AgentBox's own code) are dead weight.
# git is required at runtime by the repository mirror behind pre-forward content scanning
# (repositories[].scan): agentd shells out to it for fetch, index-pack, and rev-list.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
       /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
RUN mkdir -p /var/lib/agentgate /var/lib/agentgate-forward /var/lib/agentgate-control /var/lib/agentgate-mirrors /var/lib/agentgate-issuer /var/lib/agentgate-hosted \
    && chown node:node /var/lib/agentgate /var/lib/agentgate-forward /var/lib/agentgate-control /var/lib/agentgate-mirrors /var/lib/agentgate-issuer /var/lib/agentgate-hosted \
    && chmod 700 /var/lib/agentgate-control /var/lib/agentgate-mirrors /var/lib/agentgate-issuer /var/lib/agentgate-hosted
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node scripts/audit-forward.js scripts/audit-verify.js ./scripts/
USER node
ENV NODE_ENV=production AGENTGATE_HOST=0.0.0.0 AGENTGATE_STATE_DIR=/var/lib/agentgate
EXPOSE 7432
CMD ["node", "src/daemon.js"]
