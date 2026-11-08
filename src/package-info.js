// Single source of truth for the published package identity, read from the
// package.json that ships next to src/ so CLI output, proxy serverInfo and the
// commands written by `hcp mcp protect` cannot drift from the real release.
import { readFileSync } from 'node:fs';

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

export const HCP_RUNTIME_PACKAGE_NAME = packageJson.name;
export const HCP_RUNTIME_VERSION = packageJson.version;
// Pinned specifier used in client configs so `npx` resolves exactly the
// release that wrote the config instead of whatever is newest on the registry.
export const HCP_RUNTIME_PACKAGE_SPEC = `${packageJson.name}@${packageJson.version}`;
