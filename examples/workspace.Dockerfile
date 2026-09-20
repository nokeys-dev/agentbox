FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
    git git-lfs gh openssh-client gnupg ca-certificates iproute2 \
    bash-completion less nano vim-tiny tmux ripgrep jq curl wget unzip zip \
    build-essential pkg-config patch diffutils python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && git lfs install --system \
    && mkdir /workspace && chown node:node /workspace
# Agent workspaces need npm (unlike the broker image); keep it current rather
# than the version bundled with the base image, to clear known-fixed CVEs in
# npm's own transitive dependencies (tar, pacote, picomatch, brace-expansion,
# ip-address, sigstore).
RUN npm install -g npm@12.0.2
COPY package.json /opt/agentgate/package.json
COPY src/workspace-*.js /opt/agentgate/src/
COPY --chmod=755 scripts/workspace-entrypoint.sh /usr/local/bin/workspace-entrypoint
COPY --chmod=644 scripts/agentgate-env.sh /etc/profile.d/agentgate.sh
COPY --chmod=755 scripts/agentgate /usr/local/bin/agentgate
COPY --chmod=755 scripts/egress-check.sh /usr/local/bin/agentgate-egress-check
ENV AGENTGATE_URL=http://agentd:7432 GIT_TERMINAL_PROMPT=0 EDITOR=nano
USER node
WORKDIR /workspace
ENTRYPOINT ["workspace-entrypoint"]
CMD ["sleep", "infinity"]
