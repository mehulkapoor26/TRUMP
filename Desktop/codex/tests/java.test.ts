import assert from 'node:assert/strict';
import test from 'node:test';
import { parseJavaDependencies, mavenExact } from '../backend/src/java-dependencies.js';

test('Maven parsing records explicit direct declarations and leaves unresolved versions open', () => {
  const graph = parseJavaDependencies([{ path: 'service/pom.xml', content: '<project><groupId>org.example</groupId><artifactId>service</artifactId><version>1.0</version><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.12</version></dependency><dependency><groupId>com.example</groupId><artifactId>managed</artifactId><version>${revision}</version></dependency></dependencies></project>' }]);
  const packages = graph.nodes.filter(node => !node.isProject);
  assert.equal(packages.length, 2);
  assert.equal(packages.find(node => node.name === 'org.slf4j:slf4j-api')?.version, '2.0.12');
  assert.equal(packages.find(node => node.name === 'org.slf4j:slf4j-api')?.direct, true);
  assert.equal(packages.find(node => node.name === 'com.example:managed')?.version, undefined);
  assert.equal(graph.unresolved.length, 1);
  assert.ok(graph.warnings.some(warning => warning.includes('not an effective resolved tree')));
});

test('Gradle lock records preserve exact versions without inventing relationship edges', () => {
  const graph = parseJavaDependencies([{ path: 'app/gradle.lockfile', content: 'org.slf4j:slf4j-api:2.0.12=runtimeClasspath\ncom.google.guava:guava:33.0.0-jre=compileClasspath' }]);
  assert.deepEqual(graph.nodes.filter(node => !node.isProject).map(node => node.version).sort(), ['2.0.12', '33.0.0-jre']);
  assert.equal(graph.edges.length, 0);
  assert.ok(graph.warnings.some(warning => warning.includes('do not establish direct/transitive edges')));
  assert.equal(mavenExact('1.2.3-SNAPSHOT'), false);
});
