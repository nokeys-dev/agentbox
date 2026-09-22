// Renders the package-manager manifests for a release from the npm tarball and the binaries:
// a Homebrew formula (installs the npm tarball with Node), a winget manifest set (installs the
// Windows single-file executable), and a Debian control file for the .deb. Usage:
//   node scripts/release/manifests.js <version> <npm tarball sha256> <win exe sha256> <out dir>
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [version, tarballSha, exeSha, out = 'dist/manifests'] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+/.test(version || '') || !/^[0-9a-f]{64}$/.test(tarballSha || '') || !/^[0-9a-f]{64}$/.test(exeSha || '')) {
  console.error('Usage: manifests.js <version> <npm tarball sha256> <windows exe sha256> [out dir]');
  process.exit(2);
}
mkdirSync(join(out, 'winget'), { recursive: true });
const repo = 'https://github.com/nokeys-dev/agentbox';
writeFileSync(join(out, 'agentbox.rb'), `require "language/node"

class Agentbox < Formula
  desc "Everything your agent needs, nothing it shouldn't have: governed workspace for AI agents"
  homepage "https://nokeys.dev"
  url "https://registry.npmjs.org/@nokeys/agentbox/-/agentbox-${version}.tgz"
  sha256 "${tarballSha}"
  license "Apache-2.0"

  depends_on "node"

  def install
    system "npm", "install", *Language::Node.std_npm_install_args(libexec)
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agentbox --version")
  end
end
`);
const wingetId = 'NoKeys.AgentBox';
writeFileSync(join(out, 'winget', `${wingetId}.yaml`), `PackageIdentifier: ${wingetId}
PackageVersion: ${version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
`);
writeFileSync(join(out, 'winget', `${wingetId}.installer.yaml`), `PackageIdentifier: ${wingetId}
PackageVersion: ${version}
InstallerType: portable
Commands:
  - agentbox
Installers:
  - Architecture: x64
    InstallerUrl: ${repo}/releases/download/v${version}/agentbox-windows-x64.exe
    InstallerSha256: ${exeSha.toUpperCase()}
ManifestType: installer
ManifestVersion: 1.6.0
`);
writeFileSync(join(out, 'winget', `${wingetId}.locale.en-US.yaml`), `PackageIdentifier: ${wingetId}
PackageVersion: ${version}
PackageLocale: en-US
Publisher: NoKeys
PublisherUrl: https://nokeys.dev
PackageName: AgentBox
PackageUrl: https://nokeys.dev
License: Apache-2.0
ShortDescription: Everything your agent needs, nothing it shouldn't have. A governed workspace for AI agents.
ManifestType: defaultLocale
ManifestVersion: 1.6.0
`);
writeFileSync(join(out, 'control'), `Package: agentbox
Version: ${version}
Section: devel
Priority: optional
Architecture: amd64
Recommends: docker-ce | docker.io | docker-ce-cli
Maintainer: NoKeys <hello@nokeys.dev>
Homepage: https://nokeys.dev
Description: AgentBox: a governed workspace for AI agents
 Everything your agent needs, nothing it shouldn't have. Identity, policy,
 approvals, and audit for AI agents; credentials never enter the workspace.
`);
console.log(`wrote manifests for ${version} to ${out}`);
