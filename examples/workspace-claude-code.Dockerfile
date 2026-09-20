# Workspace image with Claude Code installed. Build the base first (or use the released image):
#   docker build --tag agentgate-workspace:local --file examples/workspace.Dockerfile .
#   docker build --tag agentgate-workspace-claude:local --file examples/workspace-claude-code.Dockerfile .
# Installation happens at build time, where the registry is reachable; at run time the workspace
# has no route to npm except the egress proxy, and none to api.anthropic.com except the gateway.
ARG AGENTGATE_WORKSPACE_IMAGE=agentgate-workspace:local
FROM ${AGENTGATE_WORKSPACE_IMAGE}
ARG CLAUDE_CODE_VERSION=2.1.275
USER root
# npm skips the package's postinstall for a root global install, which leaves a stub in place of
# the native binary; run that step explicitly, then prove the binary executes for the node user.
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && node "$(npm root -g)/@anthropic-ai/claude-code/install.cjs" \
    && npm cache clean --force \
    && su node -s /bin/sh -c 'claude --version' | grep -F "${CLAUDE_CODE_VERSION}"
USER node
# Defence in depth, not a boundary: managed settings deny Claude Code's own Read and Bash tools
# the workspace token, assertion, and gateway token files, so reaching them takes a deliberate
# act that the audit trail can show, rather than a casual file read. A shell can still read them;
# THREAT_MODEL.md "IDE attachment" states this plainly.
COPY --chmod=644 examples/claude-code-managed-settings.json /etc/claude-code/managed-settings.json
USER root
RUN chmod 755 /etc/claude-code
USER node
# Claude Code reads ANTHROPIC_BASE_URL and ANTHROPIC_AUTH_TOKEN, which compose.yaml and the
# workspace entrypoint point at the model gateway. Everything else it would call (telemetry, error
# reporting, the auto-updater, feature flags) is a host the egress proxy denies; turning it off
# keeps the proxy log clean and startup fast instead of waiting on refused tunnels.
ENV DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
