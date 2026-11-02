import semver from 'semver';
import * as pep440 from '@renovatebot/pep440';
import type { DependencyNode, Ecosystem } from '@traceguard/shared';

export const ecosystemOf = (node: Pick<DependencyNode, 'ecosystem'>): Ecosystem => node.ecosystem ?? 'npm';
export const normalizePythonName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');
export const pythonName = (name: string) => name.length <= 214 && /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(name);
export const exactVersion = (ecosystem: Ecosystem, version?: string) => !!version && version.length <= 200 && !!(ecosystem === 'Maven' ? /^[0-9][A-Za-z0-9_.-]*$/.test(version) && !/SNAPSHOT|LATEST|RELEASE/i.test(version) : ecosystem === 'PyPI' ? pep440.valid(version) : semver.valid(version));
export const compareVersions = (ecosystem: Ecosystem, a: string, b: string) => ecosystem === 'Maven' ? a.localeCompare(b) : ecosystem === 'PyPI' ? pep440.compare(a, b) : semver.compare(a, b);
export const stableVersion = (ecosystem: Ecosystem, version: string) => ecosystem === 'Maven' ? false : ecosystem === 'PyPI' ? !pep440.parse(version)?.is_prerelease && !pep440.parse(version)?.local : !semver.prerelease(version);
// Keep npm detail keys backward compatible while separating packages with the same name in PyPI.
export const advisoryKey = (id: string, name: string, ecosystem: Ecosystem) => JSON.stringify(ecosystem === 'npm' ? [id, name] : [id, name, ecosystem]);

/** Poetry caret/tilde are converted only for simple numeric releases; no environment resolution. */
export function pythonConstraint(spec: string): string | undefined {
  let value = spec.trim().replace(/^\((.*)\)$/, '$1').trim();
  if (value === '' || value === '*') return '';
  if (pep440.valid(value)) return `==${value}`;
  if (/^\d+(?:\.\d+)*\.\*$/.test(value)) value = `==${value}`;
  const poetry = /^([~^])(\d+(?:\.\d+){0,3})$/.exec(value);
  if (poetry) {
    const release = poetry[2].split('.').map(Number);
    const upper = [...release];
    const index = poetry[1] === '~' ? (release.length >= 2 ? 1 : 0) : Math.max(0, release.findIndex(n => n !== 0) < 0 ? release.length - 1 : release.findIndex(n => n !== 0));
    upper[index]++; for (let i = index + 1; i < upper.length; i++) upper[i] = 0;
    value = `>=${poetry[2]},<${upper.join('.')}`;
  }
  return pep440.validRange(value) ? value : undefined;
}
export function pythonSatisfies(version: string, spec: string): boolean | undefined {
  const constraint = pythonConstraint(spec);
  return constraint === undefined ? undefined : pep440.satisfies(version, constraint, { prereleases: true });
}
