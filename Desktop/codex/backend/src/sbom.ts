import { Ajv } from 'ajv';
import addFormats from 'ajv-formats';
import addInternationalFormats from 'ajv-formats-draft2019';
import semver from 'semver';
import { ecosystemOf, exactVersion } from './ecosystems.js';
import { packagePurl } from './canonical.js';
import type { CycloneDxBom, DependencyGraph, SbomComponent } from '@traceguard/shared';
import schema from './schemas/bom-1.6.schema.json' with { type: 'json' };
import spdxSchema from './schemas/spdx.schema.json' with { type: 'json' };
import signatureSchema from './schemas/jsf-0.82.schema.json' with { type: 'json' };

const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: true });
// ajv-formats is a CJS export; the named/default interop varies with NodeNext.
const formats = addFormats as unknown as (instance: Ajv) => void;
formats(ajv);
addInternationalFormats(ajv);
ajv.addSchema(spdxSchema);
ajv.addSchema(signatureSchema);
const validateSchema = ajv.compile(schema);

export function validateSbom(value: unknown): asserts value is CycloneDxBom {
  if (!validateSchema(value)) throw new Error(`Invalid CycloneDX SBOM: ${ajv.errorsText(validateSchema.errors)}`);
  const bom = value as unknown as CycloneDxBom;
  if (bom.specVersion !== '1.6') throw new Error('Unsupported CycloneDX version.');
  const refs = [bom.metadata.component['bom-ref'], ...bom.components.map(c => c['bom-ref'])];
  const known = new Set(refs);
  if (known.size !== refs.length) throw new Error('Duplicate SBOM component reference.');
  const dependencies = new Set<string>();
  for (const dependency of bom.dependencies) {
    if (!known.has(dependency.ref) || dependencies.has(dependency.ref)) throw new Error('Invalid SBOM dependency reference.');
    dependencies.add(dependency.ref);
    if (new Set(dependency.dependsOn).size !== dependency.dependsOn.length || dependency.dependsOn.some(ref => !known.has(ref))) throw new Error('Dangling or duplicate SBOM relationship.');
  }
  if (dependencies.size !== known.size) throw new Error('Missing SBOM dependency entries.');
}

export function generateSbom(graph: DependencyGraph, id: string, timestamp: string): CycloneDxBom {
  const rootRef = `urn:uuid:${id}`;
  const components: SbomComponent[] = graph.nodes.map(node => ({
    type: node.isProject ? 'application' : 'library',
    'bom-ref': node.id,
    name: node.name,
    ...(node.version ? { version: node.version } : {}),
    ...(packagePurl(node) ? { purl: packagePurl(node) } : {}),
    properties: [
      { name: 'traceguard:lockfile-or-manifest', value: node.project },
      { name: 'traceguard:install-path', value: node.installPath },
      { name: 'traceguard:direct', value: String(node.direct) },
      { name: 'traceguard:transitive', value: String(node.transitive) },
      { name: 'traceguard:ecosystem', value: ecosystemOf(node) },
      ...(node.ecosystem === 'PyPI' ? [{ name: 'traceguard:version-evidence', value: node.versionEvidence ?? 'unresolved' }, { name: 'traceguard:relationship-known', value: String(node.isProject || node.direct || node.transitive) }] : []),
    ],
  }));
  const children = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    const refs = children.get(edge.from) ?? new Set<string>();
    refs.add(edge.to); children.set(edge.from, refs);
  }
  const bom: CycloneDxBom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json', bomFormat: 'CycloneDX', specVersion: '1.6',
    serialNumber: rootRef, version: 1,
    metadata: {
      timestamp, component: { type: 'application', 'bom-ref': rootRef, name: 'TRACEGUARD scanned projects' },
      properties: [
        { name: 'traceguard:analysis', value: 'Static npm/Python dependency metadata analysis; no packages installed or executed.' },
        { name: 'traceguard:unresolved-count', value: String(graph.unresolved.length) },
        ...graph.warnings.map(value => ({ name: 'traceguard:warning', value })),
      ],
    },
    components,
    dependencies: [
      { ref: rootRef, dependsOn: [...new Set(graph.roots)].sort() },
      ...graph.nodes.map(node => ({ ref: node.id, dependsOn: [...(children.get(node.id) ?? [])].sort() })),
    ],
    compositions: [{ aggregate: graph.unresolved.length || graph.warnings.length ? 'incomplete' : 'complete', assemblies: [rootRef] }],
  };
  validateSbom(bom);
  return bom;
}
