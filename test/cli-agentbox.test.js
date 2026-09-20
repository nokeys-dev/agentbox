import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const execute = promisify(execFile);

// Packs the repository exactly as npm publish would, installs the tarball into a private prefix,
// and drives the installed `agentbox` command: the path a developer takes after `npm install -g`.
test('the published package installs an agentbox command that initialises a project and wires Compose to the package', { timeout: 180_000 }, async () => {
  const work = await mkdtemp(join(tmpdir(), 'agentbox-cli-'));
  const { stdout: packed } = await execute('npm', ['pack', '--pack-destination', work, '--silent'], { cwd: resolve('.') });
  const tarball = join(work, packed.trim().split('\n').at(-1));
  const prefix = join(work, 'prefix');
  await execute('npm', ['install', '-g', '--prefix', prefix, '--silent', '--no-audit', '--no-fund', tarball]);
  const agentbox = join(prefix, 'bin', 'agentbox');
  const env = { PATH: `${join(prefix, 'bin')}:${process.env.PATH}`, HOME: join(work, 'home') };
  const { stdout: help } = await execute(agentbox, ['--help'], { env });
  assert.match(help, /agentbox init/);
  assert.match(help, /agentbox up/);
  const { stdout: where } = await execute(agentbox, ['where'], { env });
  const pkg = where.trim();
  assert.ok(pkg.startsWith(join(prefix, 'lib', 'node_modules', '@nokeys', 'agentbox')), `package installed under the prefix: ${pkg}`);
  for (const file of ['compose.yaml', 'examples/config.json', 'scripts/bootstrap-dev.sh', 'Dockerfile', 'LICENSE']) assert.ok((await stat(join(pkg, file))).isFile(), file);
  assert.ok(!(await readdir(pkg)).includes('test'), 'tests are not shipped');

  const project = join(work, 'project');
  const { stdout: init } = await execute(agentbox, ['init', project], { env });
  assert.match(init, /Still needed/);
  assert.match(init, /Project ready/);
  const dotenv = await readFile(join(project, '.env'), 'utf8');
  assert.match(dotenv, new RegExp(`^AGENTGATE_CONFIG=${project}/config.local.json$`, 'm'), 'config path is absolute because Compose runs from the package');
  assert.match(dotenv, /^AGENTGATE_CLIENT_TOKEN_PATH=.*\/\.agentgate\/client-token$/m);
  assert.equal(((await stat(join(project, 'config.local.json'))).mode & 0o777), 0o600);
  // Each project is its own Compose project, and editors attach through a generated .devcontainer
  // that includes the package's Compose file with this project's .env.
  assert.match(dotenv, /^COMPOSE_PROJECT_NAME=agentbox-project$/m);
  const include = await readFile(join(project, '.devcontainer', 'compose.yaml'), 'utf8');
  assert.ok(include.includes(JSON.stringify(join(pkg, 'compose.yaml'))) && include.includes(JSON.stringify(join(project, '.env'))), include);
  const devcontainer = JSON.parse(await readFile(join(project, '.devcontainer', 'devcontainer.json'), 'utf8'));
  assert.deepEqual(devcontainer.dockerComposeFile, ['compose.yaml']);
  assert.equal(devcontainer.service, 'workspace');
  await execute(agentbox, ['init', project], { env });
  assert.equal((await readFile(join(project, '.env'), 'utf8')).match(/^(AGENTGATE_CONFIG|COMPOSE_PROJECT_NAME)=/gm).length, 2, 'init is idempotent');

  // Compose is wired to the package's files and the project's .env: with the platform-team
  // settings still missing it must fail on exactly those, not on a missing file.
  const composeCheck = await execute(agentbox, ['compose', 'config', '-q'], { env, cwd: project }).then(() => ({ code: 0, stderr: '' }), (error) => ({ code: error.code, stderr: error.stderr }));
  assert.notEqual(composeCheck.code, 0);
  // Compose names whichever unset variable it reaches first, in no fixed order.
  assert.match(composeCheck.stderr, /required variable [A-Z_]+ is missing a value/, "fails on a platform-team setting, not a missing file");
  const viaDevcontainer = await execute('docker', ['compose', '-f', join(project, '.devcontainer', 'compose.yaml'), 'config', '-q'], { env, cwd: project }).then(() => '', (error) => error.stderr);
  assert.match(viaDevcontainer, /required variable [A-Z_]+ is missing a value/, 'the editor path reaches the same Compose file');
  // The preflight names every unfilled setting at once instead of one Compose error at a time,
  // and "up" stops on it before touching Docker.
  for (const args of [['check'], ['up']]) {
    const result = await execute(agentbox, args, { env, cwd: project }).then(() => null, (error) => error);
    assert.equal(result.code, 1, args.join(' '));
    for (const expected of [/GITHUB_APP_ID is not set/, /ANTHROPIC_API_KEY_PATH is not set/, /AGENTGATE_GIT_EMAIL is not set/, /YOUR-ORG\/YOUR-REPO placeholder/]) assert.match(result.stderr, expected);
    assert.doesNotMatch(result.stderr, /AGENTGATE_TLS_KEY_PATH|AGENTGATE_CONFIG is not set/, 'generated settings are in place');
  }
  // A platform team's bundle is likely to name its files relatively; Compose would resolve them
  // inside the package, so the preflight asks for the absolute path and says which.
  const beforeRelative = await readFile(join(project, '.env'), 'utf8');
  const { writeFile: write } = await import('node:fs/promises');
  await write(join(project, '.env'), `${beforeRelative}AGENTGATE_EGRESS_CONFIG_PATH=./egress.json\n`);
  const relative = await execute(agentbox, ['check'], { env, cwd: project }).then(() => null, (error) => error);
  assert.ok(relative.stderr.includes(`AGENTGATE_EGRESS_CONFIG_PATH=./egress.json is a relative path, which Compose would resolve inside the agentbox package; use ${join(project, 'egress.json')}`), relative.stderr);
  await write(join(project, '.env'), beforeRelative);
  // Prebuilt images named in .env select the override files for every Compose call, and the
  // generated .devcontainer names the same files so an editor attach sees the same services.
  const { appendFile } = await import('node:fs/promises');
  await appendFile(join(project, '.env'), 'GITHUB_APP_ID=1\nGITHUB_PRIVATE_KEY_PATH=/dev/null\nANTHROPIC_API_KEY_PATH=/dev/null\nAGENTGATE_IMAGE=registry.example/broker@sha256:1\nAGENTGATE_WORKSPACE_IMAGE=registry.example/workspace@sha256:2\n');
  const { stdout: resolved } = await execute(agentbox, ['compose', 'config', '--format', 'json'], { env, cwd: project, maxBuffer: 1 << 24 });
  const resolvedServices = JSON.parse(resolved).services;
  for (const [name, service] of Object.entries(resolvedServices)) {
    assert.equal(service.build, undefined, `${name} is not built`);
    assert.equal(service.image, name === 'workspace' ? 'registry.example/workspace@sha256:2' : 'registry.example/broker@sha256:1');
  }
  await execute(agentbox, ['init', project], { env });
  const withImages = await readFile(join(project, '.devcontainer', 'compose.yaml'), 'utf8');
  for (const file of ['compose.yaml', 'compose.broker-image.yaml', 'compose.workspace-image.yaml']) assert.ok(withImages.includes(JSON.stringify(join(pkg, file))), file);
  // KMS signing is selected from .env for every command, and the generated .devcontainer describes
  // the same services. The enterprise services are the commercial edition: the published package is
  // open source only, so asking for them says so instead of failing on a missing file.
  await appendFile(join(project, '.env'), 'AGENTGATE_KMS_KEY_ID=alias/agentbox\nAWS_REGION=us-east-1\nAGENTBOX_ENTERPRISE=1\n');
  assert.ok(!(await readdir(pkg)).includes('enterprise'), 'the commercial edition is never in the published package');
  for (const args of [['compose', 'config', '-q'], ['up', '--no-check'], ['issuer'], ['demo:identity']]) {
    const refused = await execute(agentbox, args, { env, cwd: project }).then(() => null, (error) => error);
    assert.equal(refused?.code, 2, args.join(' '));
    assert.match(refused.stderr, /requires? the AgentBox commercial edition/, args.join(' '));
  }
  const envNow = await readFile(join(project, '.env'), 'utf8');
  await write(join(project, '.env'), envNow.replace('AGENTBOX_ENTERPRISE=1\n', ''));
  await execute(agentbox, ['init', project], { env });
  assert.ok((await readFile(join(project, '.devcontainer', 'compose.yaml'), 'utf8')).includes(JSON.stringify(join(pkg, 'compose.kms.yaml'))));
  const kmsOnly = JSON.parse((await execute(agentbox, ['compose', 'config', '--format', 'json'], { env, cwd: project, maxBuffer: 1 << 24 })).stdout).services.agentd;
  assert.equal(kmsOnly.environment.AGENTGATE_KMS_KEY_ID, 'alias/agentbox');
  assert.ok(!(kmsOnly.secrets ?? []).some((secret) => secret.source === 'github_app_key'), 'with KMS the key file is never mounted into agentd');

  // The assertion command refuses junk and expired assertions, and installs a valid one by
  // overwriting the existing file in place: the workspace mounts the inode, not the path, so a
  // replaced file would never be seen. With no workspace running it still saves and says so.
  const claims = (exp) => `${Buffer.from('{"alg":"EdDSA"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'rt-1', human: 'dev@example.com', exp })).toString('base64url')}.c2ln`;
  const incoming = join(work, 'incoming');
  const { writeFile } = await import('node:fs/promises');
  await writeFile(incoming, 'junk');
  assert.match((await execute(agentbox, ['assertion', incoming], { env, cwd: project }).then(() => null, (error) => error)).stderr, /is not a runtime assertion/);
  await writeFile(incoming, claims(Math.floor(Date.now() / 1000) - 60));
  assert.match((await execute(agentbox, ['assertion', incoming], { env, cwd: project }).then(() => null, (error) => error)).stderr, /this assertion expired on/);
  const installed = join(work, 'installed-assertion');
  await writeFile(installed, 'previous\n', { mode: 0o600 });
  await appendFile(join(project, '.env'), `AGENTGATE_RUNTIME_ASSERTION_PATH=${installed}\n`);
  const inodeBefore = (await stat(installed)).ino;
  const fresh = claims(Math.floor(Date.now() / 1000) + 3600);
  await writeFile(incoming, `${fresh}\n`);
  const saved = await execute(agentbox, ['assertion', incoming], { env, cwd: project });
  assert.match(saved.stderr, /saved .*installed-assertion, but the workspace is not running/);
  assert.equal(await readFile(installed, 'utf8'), `${fresh}\n`);
  assert.equal((await stat(installed)).ino, inodeBefore, 'overwritten in place, so a running workspace would see it');
  assert.equal(((await stat(installed)).mode & 0o777), 0o600);
  const noProject = await execute(agentbox, ['doctor'], { env, cwd: work }).then(() => 0, (error) => error.stderr);
  assert.match(noProject, /agentbox init/);
});

// The single-file executable is a copy of node with the launcher embedded, so process.execPath is
// the launcher itself. A launcher that spawns process.execPath to reach the CLI re-executes itself
// without end; this drives the real binary and the scripts it hands off to, under a hard timeout.
test('the single-file executable runs the CLI in-process and hands package scripts to itself without looping', { timeout: 300_000, skip: process.platform === 'win32' }, async () => {
  const work = await mkdtemp(join(tmpdir(), 'agentbox-sea-'));
  const binary = join(work, 'bin', 'agentbox');
  await execute(process.execPath, ['scripts/release/sea.js', binary], { cwd: resolve('.') });
  const env = { PATH: process.env.PATH, HOME: work, AGENTBOX_HOME: resolve('.') };
  const options = { env, timeout: 30_000, killSignal: 'SIGKILL' };
  const { stdout: version } = await execute(binary, ['--version'], options);
  assert.equal(version.trim(), JSON.parse(await readFile('package.json', 'utf8')).version);
  assert.equal((await execute(binary, ['where'], options)).stdout.trim(), resolve('.'));
  const unknown = await execute(binary, ['bogus'], options).then(() => null, (error) => error);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /unknown command "bogus"/, 'arguments reach the CLI unchanged');
  // `issue` runs another script of the package: it must load that script, not the CLI again.
  const issue = await execute(binary, ['issue'], options).then(() => null, (error) => error);
  assert.match(issue.stderr, /issue-runtime: --key is required/);
  // The backstop: a launcher that finds itself re-executed past the limit refuses to continue.
  const looped = await execute(binary, ['--version'], { ...options, env: { ...env, AGENTBOX_SEA_DEPTH: '3' } }).then(() => null, (error) => error);
  assert.equal(looped.code, 70);
  const missing = await execute(binary, ['--version'], { ...options, env: { PATH: process.env.PATH, HOME: work } }).then(() => null, (error) => error);
  assert.match(missing.stderr, /package files not found/);
});
