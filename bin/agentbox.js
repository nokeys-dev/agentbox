#!/usr/bin/env node
// The `agentbox` command: what `npm install -g @nokeys/agentbox` (or the brew, winget, and .deb builds of
// it) puts on the PATH. A project directory holds the developer's .env, config, and secrets; the
// package holds the Compose files, images, and source. `agentbox up` runs Compose with the
// package as the project directory and the project's .env, so nothing is copied out of the
// package and upgrades are `npm update -g @nokeys/agentbox`.
import { spawn, spawnSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSea } from 'node:sea';
import { parseEnv } from 'node:util';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const usage = `agentbox ${version} — everything your agent needs, nothing it shouldn't have

Usage:
  agentbox init [DIR]            create a project directory (.env, config, secrets) — default: current directory
  agentbox up [--enterprise] [--kms] [--image IMAGE] [--broker-image IMAGE] [compose args...]
                                 (AGENTBOX_ENTERPRISE=1 or AGENTGATE_KMS_KEY_ID in .env select those for every command)
                                 bring the stack up; --image runs a prebuilt workspace image and
                                 --broker-image a prebuilt broker image instead of building (or set
                                 AGENTGATE_WORKSPACE_IMAGE / AGENTGATE_IMAGE in .env)
  agentbox check [--kms]         verify Docker, Compose, and this project's settings; "up" runs it first (--no-check skips)
  agentbox down [-v]             stop it (with -v, delete its volumes)
  agentbox compose ...           any docker compose command against the project (ps, logs, exec ...)
  agentbox doctor                run agentgate doctor inside the workspace
  agentbox fingerprint           print the workspace token fingerprint for the issuer
  agentbox assertion FILE        install or renew the runtime assertion the issuer sent you
  agentbox shell                 open a shell in the workspace
  agentbox approvals | approve ID | deny ID
                                 review approvals on the broker
  agentbox daemon                run the broker without Docker (reads ./.env)
  agentbox issuer                run the issuing service without Docker (commercial edition)
  agentbox issue ...             issue a runtime assertion from a key (scripts/issue-runtime.js args)
  agentbox demo                  credential-free demo, no GitHub account needed
  agentbox demo:identity         the identity and issuing demo (commercial edition)
  agentbox where                 print the package directory (Compose files live there)

Environment: AGENTBOX_PROJECT overrides the project directory (default: current directory).
Docs: https://nokeys.dev/docs`;

const project = resolve(process.env.AGENTBOX_PROJECT || process.cwd());
const envFile = join(project, '.env');
// Like the overrides below, KMS signing and the enterprise services are properties of the project:
// AGENTGATE_KMS_KEY_ID or AGENTBOX_ENTERPRISE=1 in the project's .env select their files for every
// command, so a later "agentbox compose up -d" or an editor attach cannot quietly drop them. The
// "up" flags add them for one run.
const ENTERPRISE_COMPOSE = join('enterprise', 'compose.enterprise.yaml');
const commercial = existsSync(join(root, ENTERPRISE_COMPOSE));
const projectSettings = (directory = project) => (existsSync(join(directory, '.env')) ? parseEnv(readFileSync(join(directory, '.env'), 'utf8')) : {});
const baseFileNames = (settings, { enterprise = false, kms = false } = {}) => {
  const useKms = kms || Boolean(settings.AGENTGATE_KMS_KEY_ID);
  const useEnterprise = enterprise || /^(1|true|yes)$/i.test(settings.AGENTBOX_ENTERPRISE ?? '');
  // The enterprise services are the commercial edition (enterprise/); the open-source package has none.
  if (useEnterprise && !commercial) { console.error('agentbox: the enterprise services (--enterprise, AGENTBOX_ENTERPRISE) require the AgentBox commercial edition (https://nokeys.dev)'); process.exit(2); }
  return ['compose.yaml', ...(useKms ? ['compose.kms.yaml'] : []), ...(useEnterprise ? [ENTERPRISE_COMPOSE] : [])];
};
const composeFiles = (flags) => baseFileNames(projectSettings(), flags).map((file) => join(root, file));

function run(command, args, { env = process.env, cwd = project, capture = false } = {}) {
  const child = spawnSync(command, args, { stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit', encoding: 'utf8', env, cwd });
  if (capture && !child.error) return { status: child.status ?? 1, stdout: child.stdout };
  if (child.error) { console.error(`agentbox: could not run ${command}: ${child.error.message}`); return 127; }
  return child.status ?? 1;
}

// Runs another script of the package under the same runtime. Inside the single-file executable
// process.execPath is the launcher, not node, so the script is handed to it through the environment.
function runNode(script, args = [], { envFile: file, cwd = project } = {}) {
  if (!isSea()) return run(process.execPath, [...(file ? [`--env-file=${file}`] : []), script, ...args], { cwd });
  return run(process.execPath, args, { cwd, env: { ...process.env, AGENTBOX_SEA_SCRIPT: script, ...(file ? { AGENTBOX_SEA_ENV_FILE: file } : {}) } });
}

// Commands backed by the commercial edition say so when it is absent.
function commercialScript(script, args, options) {
  if (!existsSync(join(root, script))) { console.error('agentbox: this command requires the AgentBox commercial edition (https://nokeys.dev)'); return 2; }
  return runNode(join(root, script), args, options);
}

function requireProject() {
  if (!existsSync(envFile)) { console.error(`agentbox: no .env in ${project}. Run "agentbox init" here first, or set AGENTBOX_PROJECT.`); process.exit(2); }
}

// What a developer would otherwise learn one raw Compose error at a time: whether Docker and a
// recent enough Compose are there, and whether every setting the core stack needs is filled in and
// points at a real file. Returns the problems; an empty list means "up" can proceed.
const minimumCompose = [2, 24, 0]; // the generated .devcontainer uses include with env_file
function preflight({ kms = false } = {}) {
  const problems = [];
  const capture = (args) => spawnSync('docker', args, { encoding: 'utf8' });
  const composeVersion = capture(['compose', 'version', '--short']);
  if (composeVersion.error) problems.push('Docker is not installed or not on the PATH.');
  else if (composeVersion.status !== 0) problems.push('Docker Compose v2 is not available ("docker compose version" failed).');
  else {
    const found = composeVersion.stdout.trim().replace(/^v/, '').split(/[.+-]/).slice(0, 3).map(Number);
    const differs = minimumCompose.findIndex((part, index) => found[index] !== part);
    const older = !found.some(Number.isNaN) && differs >= 0 && found[differs] < minimumCompose[differs];
    if (older) problems.push(`Docker Compose ${composeVersion.stdout.trim()} is older than ${minimumCompose.join('.')}; upgrade Docker.`);
    if (capture(['info', '--format', '{{.ServerVersion}}']).status !== 0) problems.push('The Docker daemon is not reachable; start Docker (or check your permission to use it).');
  }
  if (!existsSync(envFile)) return [...problems, `No .env in ${project}; run "agentbox init" here first.`];
  const env = parseEnv(readFileSync(envFile, 'utf8'));
  // Compose runs with the package as its project directory, so a relative path in this .env would
  // resolve inside the package, not here. Every file setting has to be absolute.
  for (const [key, value] of Object.entries(env)) {
    if ((key.endsWith('_PATH') || key === 'AGENTGATE_CONFIG') && value && !isAbsolute(value)) problems.push(`${key}=${value} is a relative path, which Compose would resolve inside the agentbox package; use ${resolve(project, value)}`);
  }
  for (const key of ['GITHUB_APP_ID', 'AGENTGATE_GIT_NAME', 'AGENTGATE_GIT_EMAIL']) if (!env[key]) problems.push(`${key} is not set in .env.`);
  for (const key of ['GITHUB_PRIVATE_KEY_PATH', 'ANTHROPIC_API_KEY_PATH', 'AGENTGATE_CLIENT_TOKEN_PATH', 'AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH', 'AGENTGATE_CA_PATH', 'AGENTGATE_TLS_CERT_PATH', 'AGENTGATE_TLS_KEY_PATH', 'AGENTGATE_CONFIG']) {
    const value = env[key];
    if (!value) { problems.push(`${key} is not set in .env.`); continue; }
    if (key === 'GITHUB_PRIVATE_KEY_PATH' && (kms || env.AGENTGATE_KMS_KEY_ID) && value === '/dev/null') continue;
    const file = resolve(project, value);
    if (!existsSync(file) || !statSync(file).isFile()) { problems.push(`${key} points at ${file}, which is not a file.`); continue; }
    if (/KEY_PATH$|TOKEN_PATH$/.test(key) && process.platform !== 'win32' && (statSync(file).mode & 0o077)) problems.push(`${file} (${key}) is readable by other users; run: chmod 600 ${JSON.stringify(file)}`);
  }
  // The development certificates from "agentbox init" last 30 days; an expired one shows up only as
  // TLS failures inside the stack, so say so here and say what renews it.
  for (const key of ['AGENTGATE_TLS_CERT_PATH', 'AGENTGATE_CA_PATH']) {
    const file = env[key] && resolve(project, env[key]);
    if (!file || !existsSync(file) || !statSync(file).isFile()) continue;
    let certificate;
    try { certificate = new X509Certificate(readFileSync(file)); } catch { problems.push(`${file} (${key}) is not a PEM certificate.`); continue; }
    const daysLeft = Math.floor((new Date(certificate.validTo).getTime() - Date.now()) / 86_400_000);
    if (daysLeft >= 7) continue;
    const renewal = /CN=AgentBox Dev CA/.test(certificate.issuer) ? 'run "agentbox init" to renew it, then "agentbox up --force-recreate"' : 'get a new one from your PKI';
    problems.push(`${file} (${key}) ${daysLeft < 0 ? 'has expired' : `expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`}; ${renewal}.`);
  }
  if (env.AGENTGATE_CORPORATE_PROXY) {
    let proxy;
    try { proxy = new URL(env.AGENTGATE_CORPORATE_PROXY); } catch { /* reported below */ }
    if (!proxy || proxy.protocol !== 'http:' || !proxy.hostname) problems.push('AGENTGATE_CORPORATE_PROXY must be an http:// URL such as http://proxy.example.com:8080.');
  }
  if (env.AGENTGATE_CORPORATE_CA_PATH) {
    const file = resolve(project, env.AGENTGATE_CORPORATE_CA_PATH);
    try { new X509Certificate(readFileSync(file)); } catch { problems.push(`AGENTGATE_CORPORATE_CA_PATH points at ${file}, which is not a readable PEM certificate.`); }
  }
  const config = env.AGENTGATE_CONFIG && resolve(project, env.AGENTGATE_CONFIG);
  if (config && existsSync(config)) {
    try { if (JSON.stringify(JSON.parse(readFileSync(config, 'utf8'))).includes('YOUR-ORG/YOUR-REPO')) problems.push(`${config} still has the YOUR-ORG/YOUR-REPO placeholder; set your repository, its ID, and the installation ID.`); }
    catch (error) { problems.push(`${config} is not valid JSON: ${error.message}`); }
  }
  return problems;
}

function check(options) {
  const problems = preflight(options);
  if (problems.length === 0) { console.log('agentbox: Docker, Compose, and this project\'s settings look ready.'); return 0; }
  console.error(`agentbox: ${problems.length} thing${problems.length === 1 ? '' : 's'} to fix before "agentbox up":`);
  for (const problem of problems) console.error(`  - ${problem}`);
  return 1;
}

// Prebuilt images, the corporate proxy, and the corporate CA are properties of the project, not of
// one command: the settings in the project's .env (or the environment) select the override files
// for every Compose call, so "up", "ps", and "down" all see the same services, and the generated
// .devcontainer names the same files. The "up" image flags set them for one run.
function overrideFiles(settings, { enterprise = false } = {}) {
  const has = (key) => Boolean(settings[key] || process.env[key]);
  const pair = (name) => [`compose.${name}.yaml`, ...(enterprise ? [join('enterprise', `compose.${name}.enterprise.yaml`)] : [])];
  return [
    ...(has('AGENTGATE_IMAGE') ? pair('broker-image') : []),
    ...(has('AGENTGATE_WORKSPACE_IMAGE') ? ['compose.workspace-image.yaml'] : []),
    ...(has('AGENTGATE_CORPORATE_PROXY') ? pair('corporate-proxy') : []),
    ...(has('AGENTGATE_CORPORATE_CA_PATH') ? ['compose.corporate-ca.yaml'] : [])
  ];
}

function compose(files, args, { image, brokerImage, capture = false } = {}) {
  requireProject();
  const settings = { ...parseEnv(readFileSync(envFile, 'utf8')), ...(image ? { AGENTGATE_WORKSPACE_IMAGE: image } : {}), ...(brokerImage ? { AGENTGATE_IMAGE: brokerImage } : {}) };
  const env = { ...process.env, ...(image ? { AGENTGATE_WORKSPACE_IMAGE: image } : {}), ...(brokerImage ? { AGENTGATE_IMAGE: brokerImage } : {}) };
  const all = [...files, ...overrideFiles(settings, { enterprise: files.includes(join(root, ENTERPRISE_COMPOSE)) }).map((file) => join(root, file))];
  return run('docker', ['compose', '--project-directory', root, '--env-file', envFile, ...all.flatMap((file) => ['-f', file]), ...args], { env, cwd: root, capture });
}

// Editors attach through .devcontainer in the project. The Dev Containers tooling does not pass
// the project's .env to Compose when a Compose file is named, so the generated file includes the
// package's compose.yaml with its own directory and the project's .env stated explicitly.
// Rewritten on every init and up: the package path changes when the package is upgraded or
// moved, and the image settings in .env decide which override files it names.
function writeDevcontainer(directory) {
  const target = join(directory, '.devcontainer');
  mkdirSync(target, { recursive: true });
  // The same overrides "agentbox up" applies, so attaching an editor never sees a different
  // workspace definition and recreates the container.
  const settings = parseEnv(readFileSync(join(directory, '.env'), 'utf8'));
  // The editor's Compose project must describe the same services, or attaching would recreate them.
  const base = baseFileNames(settings);
  const files = [...base, ...overrideFiles(settings, { enterprise: base.includes(ENTERPRISE_COMPOSE) })];
  writeFileSync(join(target, 'compose.yaml'), `# Generated by "agentbox init" and "agentbox up"; do not edit.\ninclude:\n  - path:\n${files.map((file) => `      - ${JSON.stringify(join(root, file))}\n`).join('')}    project_directory: ${JSON.stringify(root)}\n    env_file: ${JSON.stringify(join(directory, '.env'))}\n`);
  const definition = JSON.parse(readFileSync(join(root, '.devcontainer', 'devcontainer.json'), 'utf8'));
  writeFileSync(join(target, 'devcontainer.json'), `${JSON.stringify({ ...definition, dockerComposeFile: ['compose.yaml'] }, null, 2)}\n`);
}

// Installs or renews the runtime assertion. The file reaches the workspace as a single-file bind
// mount, which follows the inode, not the path: a file replaced by a download, an editor save, or
// "mv" is never seen by the running container. So the installed copy is always overwritten in
// place, and the command ends by proving the workspace reads the new one.
function installAssertion(source) {
  requireProject();
  if (!source || !existsSync(source) || !statSync(source).isFile()) { console.error('Usage: agentbox assertion FILE   (the signed assertion file your platform team returned)'); return 2; }
  const assertion = readFileSync(source, 'utf8').trim();
  let claims;
  try { claims = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString('utf8')); } catch { /* reported below */ }
  if (assertion.split('.').length !== 3 || !claims || !Number.isSafeInteger(claims.exp)) { console.error(`agentbox: ${source} is not a runtime assertion.`); return 2; }
  const secondsLeft = claims.exp - Math.floor(Date.now() / 1000);
  if (secondsLeft <= 0) { console.error(`agentbox: this assertion expired on ${new Date(claims.exp * 1000).toISOString()}; ask its issuer for a new one.`); return 2; }

  const env = readFileSync(envFile, 'utf8');
  const configured = parseEnv(env).AGENTGATE_RUNTIME_ASSERTION_PATH;
  const target = configured ? resolve(project, configured) : join(homedir(), '.agentgate', `runtime-assertion-${basename(project).replace(/[^A-Za-z0-9._-]+/g, '-')}`);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  // "w" truncates and rewrites the existing inode; a new file is created owner-only.
  writeFileSync(target, `${assertion}\n`, { mode: 0o600, flag: 'w' });
  chmodSync(target, 0o600);
  const files = composeFiles({});
  let status;
  if (configured) status = compose(files, ['exec', '-T', 'workspace', 'agentgate', 'renew']);
  else {
    writeFileSync(envFile, `${env}${env.endsWith('\n') || env === '' ? '' : '\n'}AGENTGATE_RUNTIME_ASSERTION_PATH=${target}\n`);
    // The secret's source changed, which Compose does not count as a change to the service, so
    // the recreate has to be forced for the workspace to mount the new file.
    status = compose(files, ['up', '-d', '--no-deps', '--force-recreate', 'workspace']);
  }
  if (status !== 0) { console.error(`agentbox: saved ${target}, but the workspace is not running; it will load the assertion on "agentbox up".`); return 0; }
  const expected = createHash('sha256').update(`${assertion}\n`).digest('hex');
  const seen = compose(files, ['exec', '-T', 'workspace', 'sh', '-c', 'sha256sum "$AGENTGATE_RUNTIME_ASSERTION_FILE"'], { capture: true });
  if (!seen.stdout?.startsWith(expected)) { console.error('agentbox: the workspace still reads a different assertion; run "agentbox up --force-recreate".'); return 1; }
  console.log(`Installed the assertion for ${claims.sub ?? 'this runtime'} (${claims.human ?? 'unknown human'}), valid until ${new Date(claims.exp * 1000).toISOString()}. The workspace is using it.`);
  return 0;
}

function init(target) {
  // The bootstrap is a POSIX shell script that uses openssl. Say so plainly where they are missing
  // (a Windows prompt outside WSL or Git Bash) instead of failing on the first command.
  const lacking = ['sh', 'openssl'].filter((tool) => spawnSync(tool, tool === 'sh' ? ['-c', 'exit 0'] : ['version'], { stdio: 'ignore' }).status !== 0);
  if (lacking.length > 0) { console.error(`agentbox: init needs ${lacking.join(' and ')} on the PATH.${process.platform === 'win32' ? ' On Windows, run agentbox inside WSL 2 (where Docker Desktop also runs the containers) or from Git Bash.' : ''}`); return 2; }
  const directory = resolve(target || project);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const config = join(directory, 'config.local.json');
  if (!existsSync(config)) { copyFileSync(join(root, 'examples', 'config.json'), config); chmodSync(config, 0o600); console.log(`created ${config} (edit the repositories and rules)`); }
  // bootstrap-dev.sh writes secrets under ~/.agentgate and the matching lines into ./.env.
  const status = run('sh', [join(root, 'scripts', 'bootstrap-dev.sh')], { cwd: directory, env: { ...process.env, AGENTBOX_CLI: '1' } });
  if (status !== 0) return status;
  // Compose runs with the package as its project directory, so the config path must be absolute.
  const env = readFileSync(join(directory, '.env'), 'utf8');
  if (!/^AGENTGATE_CONFIG=/m.test(env)) writeFileSync(join(directory, '.env'), `${env}${env.endsWith('\n') ? '' : '\n'}AGENTGATE_CONFIG=${config}\n`);
  // One Compose project per project directory, so two projects on a machine never share
  // containers or volumes; the Dev Containers tooling reads the same name from this .env.
  const name = `agentbox-${basename(directory).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[^a-z0-9]+/, '') || 'project'}`;
  const current = readFileSync(join(directory, '.env'), 'utf8');
  if (!/^COMPOSE_PROJECT_NAME=/m.test(current)) writeFileSync(join(directory, '.env'), `${current}${current.endsWith('\n') ? '' : '\n'}COMPOSE_PROJECT_NAME=${name}\n`);
  writeDevcontainer(directory);
  console.log(`\nProject ready in ${directory}. Next: fill in the settings listed above, then "agentbox check" and "agentbox up" in that directory.`);
  return 0;
}

const [command, ...rest] = process.argv.slice(2);
const flags = new Set(rest.filter((arg) => arg.startsWith('--')));
const positional = rest.filter((arg) => !arg.startsWith('--'));
let status = 0;
switch (command) {
  case undefined: case '--help': case '-h': case 'help': console.log(usage); break;
  case '--version': case '-v': case 'version': console.log(version); break;
  case 'where': console.log(root); break;
  case 'init': status = init(positional[0]); break;
  case 'up': {
    const valued = ['--image', '--broker-image'];
    const value = (flag) => (rest.includes(flag) ? rest[rest.indexOf(flag) + 1] : undefined);
    if (valued.some((flag) => rest.includes(flag) && !value(flag))) { console.error('agentbox: --image and --broker-image need an image reference'); status = 2; break; }
    if (!flags.has('--no-check') && check({ kms: flags.has('--kms') }) !== 0) { status = 1; break; }
    const passthrough = rest.filter((arg, index) => !['--enterprise', '--kms', '--no-check', ...valued].includes(arg) && !valued.includes(rest[index - 1]));
    writeDevcontainer(project);
    // --build only rebuilds services that still have a build section; the image overrides clear it.
    status = compose(composeFiles({ enterprise: flags.has('--enterprise'), kms: flags.has('--kms') }), ['up', '-d', '--build', ...passthrough], { image: value('--image'), brokerImage: value('--broker-image') });
    break;
  }
  case 'check': status = check({ kms: flags.has('--kms') }); break;
  case 'down': status = compose(composeFiles({ enterprise: commercial, kms: false }), ['down', ...rest]); break;
  case 'compose': status = compose(composeFiles({ enterprise: flags.has('--enterprise'), kms: false }), rest.filter((arg) => arg !== '--enterprise')); break;
  case 'doctor': status = compose(composeFiles({}), ['exec', 'workspace', 'agentgate', 'doctor']); break;
  case 'fingerprint': status = compose(composeFiles({}), ['exec', 'workspace', 'agentgate', 'fingerprint']); break;
  case 'assertion': status = installAssertion(positional[0]); break;
  case 'shell': status = compose(composeFiles({}), ['exec', 'workspace', 'bash', '-l']); break;
  case 'approvals': status = compose(composeFiles({}), ['exec', 'agentd', 'node', 'src/cli.js', 'list']); break;
  case 'approve': case 'deny': status = compose(composeFiles({}), ['exec', 'agentd', 'node', 'src/cli.js', command, ...positional]); break;
  case 'daemon': requireProject(); status = runNode(join(root, 'src', 'daemon.js'), [], { envFile }); break;
  case 'issuer': requireProject(); status = commercialScript(join('enterprise', 'src', 'issuer-web.js'), [], { envFile }); break;
  case 'issue': status = runNode(join(root, 'scripts', 'issue-runtime.js'), rest); break;
  case 'demo': status = runNode(join(root, 'scripts', 'demo.js'), [], { cwd: root }); break;
  case 'demo:identity': status = commercialScript(join('enterprise', 'scripts', 'demo-identity.js'), [], { cwd: root }); break;
  default: console.error(`agentbox: unknown command "${command}"\n\n${usage}`); status = 2;
}
process.exit(status);
