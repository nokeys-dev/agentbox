// Runs the test suite of whichever edition this tree is: test/ always, and enterprise/test/ when the
// commercial edition is present. Extra arguments go to `node --test` (for example a name pattern).
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const suites = ['test', join('enterprise', 'test')].filter((directory) => existsSync(directory));
const files = suites.flatMap((directory) => readdirSync(directory).filter((name) => name.endsWith('.test.js')).map((name) => join(directory, name)));
const result = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);
