// Builds a single-file `agentbox` executable with Node's single executable application support:
// the CLI bundled into a copy of the running node binary. The result needs no Node on the target
// machine; it still needs Docker for the workspace. Run on each target OS (the release workflow
// uses Linux, macOS, and Windows runners). Usage: node scripts/release/sea.js <output path>
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const output = resolve(process.argv[2] || `dist/agentbox${process.platform === 'win32' ? '.exe' : ''}`);
mkdirSync(dirname(output), { recursive: true });
// Intermediates go to a temporary directory so the build works from a clean checkout.
const work = mkdtempSync(join(tmpdir(), 'agentbox-sea-build-'));
// The SEA main must be CommonJS. It loads the ESM CLI in-process from the package tree that ships
// beside the binary (the .deb, brew, and winget packages install both), or from an explicit path.
// It must never spawn process.execPath expecting plain node: inside a single executable that is
// this launcher again. When the CLI needs to run another script of the package (daemon, issuer,
// demos) it re-executes the binary with AGENTBOX_SEA_SCRIPT set, and the launcher loads that
// script instead. AGENTBOX_SEA_DEPTH is a backstop against any re-execution loop.
const main = `const { existsSync } = require('node:fs');
const { join, dirname } = require('node:path');
const { pathToFileURL } = require('node:url');
const depth = Number(process.env.AGENTBOX_SEA_DEPTH || 0);
if (depth > 2) { console.error('agentbox: launcher re-executed itself; refusing to continue'); process.exit(70); }
process.env.AGENTBOX_SEA_DEPTH = String(depth + 1);
const candidates = [process.env.AGENTBOX_HOME, join(dirname(process.execPath), '..', 'lib', 'agentbox'), join(dirname(process.execPath), 'agentbox-package'), '/usr/lib/agentbox', '/usr/local/lib/agentbox'].filter(Boolean);
const home = candidates.find((dir) => existsSync(join(dir, 'bin', 'agentbox.js')));
if (!home) { console.error('agentbox: package files not found; set AGENTBOX_HOME to the @nokeys/agentbox package directory'); process.exit(2); }
let script = join(home, 'bin', 'agentbox.js');
if (process.env.AGENTBOX_SEA_SCRIPT) {
  script = process.env.AGENTBOX_SEA_SCRIPT;
  delete process.env.AGENTBOX_SEA_SCRIPT;
  if (process.env.AGENTBOX_SEA_ENV_FILE) { process.loadEnvFile(process.env.AGENTBOX_SEA_ENV_FILE); delete process.env.AGENTBOX_SEA_ENV_FILE; }
}
const args = process.argv.slice(2);
process.argv = [process.execPath, script, ...args];
import(pathToFileURL(script).href).catch((error) => { console.error(error); process.exit(1); });`;
writeFileSync(join(work, 'sea-main.cjs'), main);
writeFileSync(join(work, 'sea-config.json'), JSON.stringify({ main: join(work, 'sea-main.cjs'), output: join(work, 'sea-prep.blob'), disableExperimentalSEAWarning: true }));
execFileSync(process.execPath, ['--experimental-sea-config', join(work, 'sea-config.json')], { stdio: 'inherit' });
copyFileSync(process.execPath, output);
if (process.platform === 'darwin') execFileSync('codesign', ['--remove-signature', output], { stdio: 'inherit' });
execFileSync('npx', ['--yes', 'postject@1.0.0-alpha.6', output, 'NODE_SEA_BLOB', join(work, 'sea-prep.blob'), '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', ...(process.platform === 'darwin' ? ['--macho-segment-name', 'NODE_SEA'] : [])], { stdio: 'inherit' });
if (process.platform === 'darwin') execFileSync('codesign', ['--sign', '-', output], { stdio: 'inherit' });
rmSync(work, { recursive: true, force: true });
console.log(`built ${output} from node ${process.version}`);
