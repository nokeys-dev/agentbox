import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const profiles = [{ file: 'examples/workspace-claude-code.Dockerfile', packages: ['@anthropic-ai/claude-code'] }];

for (const profile of profiles) {
  test(`${profile.file} derives from the workspace image, pins its tools, and ends as the workspace user`, () => {
    const lines = readFileSync(resolve(profile.file), 'utf8').split('\n').filter((line) => line.trim() && !line.startsWith('#'));
    assert.match(lines[0], /^ARG AGENTGATE_WORKSPACE_IMAGE=agentgate-workspace:/, 'base image is the workspace image, overridable for released digests');
    assert.equal(lines[1], 'FROM ${AGENTGATE_WORKSPACE_IMAGE}');
    for (const name of profile.packages) {
      const arg = lines.find((line) => /^ARG [A-Z_]+_VERSION=\d+\.\d+\.\d+$/.test(line));
      assert.ok(arg, `${name} version is pinned to an exact release via a build ARG`);
      assert.ok(lines.some((line) => line.includes(`"${name}@\${`)), `${name} installs at the pinned version`);
    }
    const users = lines.filter((line) => line.startsWith('USER ')).map((line) => line.slice(5).trim());
    assert.equal(users.at(-1), 'node', 'the image must not run the agent as root');
    for (const forbidden of ['ANTHROPIC_API_KEY', 'GITHUB_TOKEN', 'GH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN']) {
      assert.ok(!lines.some((line) => /^(ENV|ARG)\s/.test(line) && line.includes(forbidden)), `${forbidden} must come from Compose, never be baked into the image`);
    }
    assert.ok(!lines.some((line) => /curl .*\|\s*(ba)?sh/.test(line)), 'no piped installer scripts');
    const ci = readFileSync(resolve('.github/workflows/ci.yml'), 'utf8');
    assert.ok(ci.includes(`--file ${profile.file} .`), `${profile.file} is built in CI`);
  });
}

test('the Claude Code profile ships managed settings that deny the agent its own secret files', () => {
  const settings = JSON.parse(readFileSync(resolve('examples/claude-code-managed-settings.json'), 'utf8'));
  const deny = settings.permissions.deny;
  for (const rule of ['Read(/run/secrets/**)', 'Read(~/.config/agentgate/**)', 'Bash(cat /run/secrets*)', 'Bash(env*)']) assert.ok(deny.includes(rule), rule);
  assert.equal(settings.permissions.allow, undefined, 'the profile never widens permissions');
  const dockerfile = readFileSync(resolve('examples/workspace-claude-code.Dockerfile'), 'utf8');
  assert.match(dockerfile, /COPY --chmod=644 examples\/claude-code-managed-settings\.json \/etc\/claude-code\/managed-settings\.json/);
});

test('the prebuilt-image Compose override clears build so a profile tag cannot be silently rebuilt over', () => {
  const override = readFileSync(resolve('compose.workspace-image.yaml'), 'utf8');
  assert.match(override, /^\s+build: !reset null$/m);
  assert.match(override, /^\s+image: \$\{AGENTGATE_WORKSPACE_IMAGE:\?/m);
  const keys = [...override.matchAll(/^    ([a-z_]+):/gm)].map((match) => match[1]);
  assert.deepEqual(keys.sort(), ['build', 'image'], 'the override may choose the image and nothing else about the workspace service');
});
