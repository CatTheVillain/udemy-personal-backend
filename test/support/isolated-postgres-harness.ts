import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { promisify } from 'node:util';

import { Client } from 'pg';
import { DataSource } from 'typeorm';

const RESOURCE_PURPOSE = 'isolated-postgres';
const TEST_SUITE = 'identity-integration';
const LOOPBACK_HOST = '127.0.0.1';
const POSTGRES_IMAGE =
  'postgres:18.4@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636';
const POSTGRES_REPOSITORY_DIGEST =
  'postgres@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636';
const RUN_ID_PATTERN = /^[a-z0-9]{16,64}$/;
const COMPOSE_FILE = resolve(process.cwd(), 'test/infra/compose.postgres.yml');
const executeFile = promisify(execFile);

export interface IsolatedPostgresEnvironment {
  readonly COMPOSE_PROJECT_NAME: string;
  readonly IDENTITY_TEST_CONTAINER: string;
  readonly IDENTITY_TEST_DATABASE: string;
  readonly IDENTITY_TEST_DATABASE_PASSWORD: string;
  readonly IDENTITY_TEST_DATABASE_USER: string;
  readonly IDENTITY_TEST_NETWORK: string;
  readonly IDENTITY_TEST_POSTGRES_HOST: string;
  readonly IDENTITY_TEST_POSTGRES_PORT: string;
  readonly IDENTITY_TEST_RUN_ID: string;
  readonly IDENTITY_TEST_SCHEMA: string;
  readonly IDENTITY_TEST_VOLUME: string;
  readonly NODE_ENV: string;
}

export type IsolatedPostgresResourceKind = 'container' | 'network' | 'volume';

export interface IsolatedPostgresResource {
  readonly kind: IsolatedPostgresResourceKind;
  readonly labels: Readonly<Record<string, string>>;
  readonly name: string;
}

export interface IsolatedPostgresPlan {
  readonly containerName: string;
  readonly databaseName: string;
  readonly databaseUser: string;
  readonly environment: IsolatedPostgresEnvironment;
  readonly networkName: string;
  readonly projectName: string;
  readonly runId: string;
  readonly schemaName: string;
  readonly volumeName: string;
}

export interface IsolatedPostgresPreflightOperations {
  inspectOwnedResources(plan: IsolatedPostgresPlan): Promise<readonly IsolatedPostgresResource[]>;
}

export interface IsolatedPostgresDatabaseOptions {
  readonly database: string;
  readonly host: string;
  readonly password: string;
  readonly port: number;
  readonly schema: string;
  readonly username: string;
}

export interface IsolatedPostgresMigrationFactory {
  createDataSource(options: IsolatedPostgresDatabaseOptions): DataSource;
}

interface PostgresClientOptions {
  readonly connectionTimeoutMillis: number;
  readonly database: string;
  readonly host: string;
  readonly password: string;
  readonly port: number;
  readonly user: string;
}

export interface IsolatedPostgresRun {
  cleanup(): Promise<void>;
  migrate(factory: IsolatedPostgresMigrationFactory): Promise<void>;
  readonly plan: IsolatedPostgresPlan;
}

interface DerivedResourceNames {
  readonly containerName: string;
  readonly databaseName: string;
  readonly databaseUser: string;
  readonly networkName: string;
  readonly projectName: string;
  readonly schemaName: string;
  readonly volumeName: string;
}

export function createIsolatedPostgresEnvironment(
  runId: string,
  port: number,
): IsolatedPostgresEnvironment {
  assertRunId(runId);
  assertPort(port);

  const names = deriveResourceNames(runId);
  return {
    COMPOSE_PROJECT_NAME: names.projectName,
    IDENTITY_TEST_CONTAINER: names.containerName,
    IDENTITY_TEST_DATABASE: names.databaseName,
    IDENTITY_TEST_DATABASE_PASSWORD: randomBytes(32).toString('base64url'),
    IDENTITY_TEST_DATABASE_USER: names.databaseUser,
    IDENTITY_TEST_NETWORK: names.networkName,
    IDENTITY_TEST_POSTGRES_HOST: LOOPBACK_HOST,
    IDENTITY_TEST_POSTGRES_PORT: String(port),
    IDENTITY_TEST_RUN_ID: runId,
    IDENTITY_TEST_SCHEMA: names.schemaName,
    IDENTITY_TEST_VOLUME: names.volumeName,
    NODE_ENV: 'test',
  };
}

export function createIsolatedPostgresPlan(
  environment: IsolatedPostgresEnvironment,
): IsolatedPostgresPlan {
  assertRunId(environment.IDENTITY_TEST_RUN_ID);
  assertPortString(environment.IDENTITY_TEST_POSTGRES_PORT);
  assertEqual('NODE_ENV', environment.NODE_ENV, 'test');
  assertEqual(
    'IDENTITY_TEST_POSTGRES_HOST',
    environment.IDENTITY_TEST_POSTGRES_HOST,
    LOOPBACK_HOST,
  );
  assertCredential(environment.IDENTITY_TEST_DATABASE_PASSWORD);

  const names = deriveResourceNames(environment.IDENTITY_TEST_RUN_ID);
  assertEqual('COMPOSE_PROJECT_NAME', environment.COMPOSE_PROJECT_NAME, names.projectName);
  assertEqual('IDENTITY_TEST_CONTAINER', environment.IDENTITY_TEST_CONTAINER, names.containerName);
  assertEqual('IDENTITY_TEST_DATABASE', environment.IDENTITY_TEST_DATABASE, names.databaseName);
  assertEqual(
    'IDENTITY_TEST_DATABASE_USER',
    environment.IDENTITY_TEST_DATABASE_USER,
    names.databaseUser,
  );
  assertEqual('IDENTITY_TEST_NETWORK', environment.IDENTITY_TEST_NETWORK, names.networkName);
  assertEqual('IDENTITY_TEST_SCHEMA', environment.IDENTITY_TEST_SCHEMA, names.schemaName);
  assertEqual('IDENTITY_TEST_VOLUME', environment.IDENTITY_TEST_VOLUME, names.volumeName);

  return {
    containerName: names.containerName,
    databaseName: names.databaseName,
    databaseUser: names.databaseUser,
    environment,
    networkName: names.networkName,
    projectName: names.projectName,
    runId: environment.IDENTITY_TEST_RUN_ID,
    schemaName: names.schemaName,
    volumeName: names.volumeName,
  };
}

export async function prepareIsolatedPostgresRun(
  environment: IsolatedPostgresEnvironment,
  operations: IsolatedPostgresPreflightOperations,
): Promise<IsolatedPostgresPlan> {
  const plan = createIsolatedPostgresPlan(environment);
  const observedResources = await operations.inspectOwnedResources(plan);
  assertNoResourceCollision(observedResources);
  return plan;
}

export async function startIsolatedPostgres(
  plan: IsolatedPostgresPlan,
): Promise<IsolatedPostgresRun> {
  assertPlanIntegrity(plan);
  assertComposeFile();
  await assertDockerEngineAvailable();
  await assertNoDockerCollision(plan);

  try {
    await executeDocker(
      composeArguments(plan, [
        'up',
        '--detach',
        '--wait',
        '--wait-timeout',
        '45',
        '--pull',
        'missing',
      ]),
      plan,
    );
    await assertStartedDockerResources(plan);
    await waitForPostgres(plan);
  } catch {
    await cleanupPartialIsolatedPostgresRun(plan);
    throw new Error('Isolated PostgreSQL startup did not complete safely.');
  }

  return new StartedIsolatedPostgresRun(plan);
}

export async function cleanupIsolatedPostgresRun(plan: IsolatedPostgresPlan): Promise<void> {
  assertPlanIntegrity(plan);
  const resources = await inspectDockerResources(plan);
  assertSafeCleanupScope(plan, resources);
  await executeDocker(composeArguments(plan, ['down', '--volumes']), plan);
  if ((await inspectDockerResources(plan)).length !== 0) {
    throw new Error('Isolated PostgreSQL cleanup left owned resources behind.');
  }
}

export async function assertStartedIsolatedPostgresRun(plan: IsolatedPostgresPlan): Promise<void> {
  assertPlanIntegrity(plan);
  await assertStartedDockerResources(plan);
}

export async function migrateIsolatedPostgresSchema(
  plan: IsolatedPostgresPlan,
  factory: IsolatedPostgresMigrationFactory,
): Promise<void> {
  assertPlanIntegrity(plan);
  await assertStartedDockerResources(plan);
  const source = factory.createDataSource(createIsolatedPostgresDatabaseOptions(plan));

  try {
    await source.initialize();
    await source.query(`CREATE SCHEMA IF NOT EXISTS "${plan.schemaName}"`);
    await source.runMigrations();
  } finally {
    if (source.isInitialized) {
      await source.destroy();
    }
  }
}

export function assertSafeCleanupScope(
  plan: IsolatedPostgresPlan,
  observedResources: readonly IsolatedPostgresResource[],
): void {
  const expectedResources = new Map<IsolatedPostgresResourceKind, string>([
    ['container', plan.containerName],
    ['network', plan.networkName],
    ['volume', plan.volumeName],
  ]);

  if (observedResources.length !== expectedResources.size) {
    throw new Error(
      'Refusing cleanup because the owned resource set is incomplete or contains extras.',
    );
  }

  const seenKinds = new Set<IsolatedPostgresResourceKind>();
  for (const resource of observedResources) {
    const expectedName = expectedResources.get(resource.kind);
    if (
      seenKinds.has(resource.kind) ||
      expectedName !== resource.name ||
      !hasOwnedLabels(resource, plan)
    ) {
      throw new Error('Refusing cleanup outside the exact isolated PostgreSQL run.');
    }
    seenKinds.add(resource.kind);
  }
}

function assertNoResourceCollision(resources: readonly IsolatedPostgresResource[]): void {
  if (resources.length > 0) {
    throw new Error(
      'Refusing isolated PostgreSQL startup because a generated resource already exists.',
    );
  }
}

class StartedIsolatedPostgresRun implements IsolatedPostgresRun {
  public constructor(public readonly plan: IsolatedPostgresPlan) {}

  public async cleanup(): Promise<void> {
    await cleanupIsolatedPostgresRun(this.plan);
  }

  public async migrate(factory: IsolatedPostgresMigrationFactory): Promise<void> {
    await migrateIsolatedPostgresSchema(this.plan, factory);
  }
}

async function assertDockerEngineAvailable(): Promise<void> {
  try {
    await executeFile('docker', ['version', '--format', '{{.Server.Version}}'], {
      timeout: 10_000,
      windowsHide: true,
    });
  } catch {
    throw new Error('Docker engine is unavailable for the isolated PostgreSQL run.');
  }
}

async function assertNoDockerCollision(plan: IsolatedPostgresPlan): Promise<void> {
  const resources = await inspectDockerResources(plan);
  assertNoResourceCollision(resources);
}

async function assertStartedDockerResources(plan: IsolatedPostgresPlan): Promise<void> {
  const resources = await inspectDockerResources(plan);
  assertSafeCleanupScope(plan, resources);
  await assertApprovedContainerImage(plan);
  await assertContainerMount(plan);
  await assertLoopbackPortBinding(plan);
  await assertNetworkMembership(plan);
}

function assertComposeFile(): void {
  if (!existsSync(COMPOSE_FILE)) {
    throw new Error('Isolated PostgreSQL Compose definition is unavailable.');
  }
}

function assertPlanIntegrity(plan: IsolatedPostgresPlan): void {
  const expectedPlan = createIsolatedPostgresPlan(plan.environment);
  if (
    expectedPlan.containerName !== plan.containerName ||
    expectedPlan.databaseName !== plan.databaseName ||
    expectedPlan.databaseUser !== plan.databaseUser ||
    expectedPlan.networkName !== plan.networkName ||
    expectedPlan.projectName !== plan.projectName ||
    expectedPlan.runId !== plan.runId ||
    expectedPlan.schemaName !== plan.schemaName ||
    expectedPlan.volumeName !== plan.volumeName
  ) {
    throw new Error('Unsafe isolated PostgreSQL plan.');
  }
}

async function assertContainerMount(plan: IsolatedPostgresPlan): Promise<void> {
  const output = await executeDocker(
    ['container', 'inspect', '--format', '{{json .Mounts}}', plan.containerName],
    plan,
  );
  const mounts = parseJsonArray(output);
  const expected = mounts.some((mount) => {
    return (
      readString(mount, 'Type') === 'volume' &&
      readString(mount, 'Name') === plan.volumeName &&
      readString(mount, 'Destination') === '/var/lib/postgresql'
    );
  });
  if (!expected) {
    throw new Error('Isolated PostgreSQL volume mount is not exact.');
  }
}

async function assertApprovedContainerImage(plan: IsolatedPostgresPlan): Promise<void> {
  const containerImageId = await executeDocker(
    ['container', 'inspect', '--format', '{{.Image}}', plan.containerName],
    plan,
  );
  const imageId = await executeDocker(
    ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE],
    plan,
  );
  const repoDigests = await executeDocker(
    ['image', 'inspect', '--format', '{{json .RepoDigests}}', POSTGRES_IMAGE],
    plan,
  );
  if (
    containerImageId.trim() !== imageId.trim() ||
    !parseJsonStringArray(repoDigests).includes(POSTGRES_REPOSITORY_DIGEST)
  ) {
    throw new Error('Isolated PostgreSQL image is not the approved immutable digest.');
  }
}

async function assertLoopbackPortBinding(plan: IsolatedPostgresPlan): Promise<void> {
  const output = await executeDocker(['port', plan.containerName, '5432/tcp'], plan);
  if (output.trim() !== `${LOOPBACK_HOST}:${plan.environment.IDENTITY_TEST_POSTGRES_PORT}`) {
    throw new Error('Isolated PostgreSQL port binding is not loopback-only.');
  }
}

async function assertNetworkMembership(plan: IsolatedPostgresPlan): Promise<void> {
  const output = await executeDocker(
    ['network', 'inspect', '--format', '{{json .Containers}}', plan.networkName],
    plan,
  );
  const containers = parseJsonRecord(output);
  const names = Object.values(containers)
    .filter(isRecord)
    .map((container) => readString(container, 'Name'));
  if (names.length !== 1 || names[0] !== plan.containerName) {
    throw new Error('Isolated PostgreSQL network membership is not exact.');
  }
}

async function cleanupPartialIsolatedPostgresRun(plan: IsolatedPostgresPlan): Promise<void> {
  try {
    const resources = await inspectDockerResources(plan);
    if (resources.length === 0) {
      return;
    }
    assertSafePartialCleanupScope(plan, resources);
    await executeDocker(composeArguments(plan, ['down', '--volumes']), plan);
  } catch {
    throw new Error('Isolated PostgreSQL partial cleanup could not be proven safe.');
  }
}

function assertSafePartialCleanupScope(
  plan: IsolatedPostgresPlan,
  resources: readonly IsolatedPostgresResource[],
): void {
  const expected = new Map<IsolatedPostgresResourceKind, string>([
    ['container', plan.containerName],
    ['network', plan.networkName],
    ['volume', plan.volumeName],
  ]);
  const seenKinds = new Set<IsolatedPostgresResourceKind>();
  for (const resource of resources) {
    if (
      seenKinds.has(resource.kind) ||
      expected.get(resource.kind) !== resource.name ||
      !hasOwnedLabels(resource, plan)
    ) {
      throw new Error('Refusing partial cleanup outside the exact isolated PostgreSQL run.');
    }
    seenKinds.add(resource.kind);
  }
}

function composeArguments(plan: IsolatedPostgresPlan, action: readonly string[]): string[] {
  return ['compose', '--project-name', plan.projectName, '--file', COMPOSE_FILE, ...action];
}

async function executeDocker(args: readonly string[], plan: IsolatedPostgresPlan): Promise<string> {
  try {
    const result = await executeFile('docker', [...args], {
      env: composeEnvironment(plan),
      timeout: 180_000,
      windowsHide: true,
    });
    return result.stdout;
  } catch {
    throw new Error('Docker command failed for the isolated PostgreSQL run.');
  }
}

async function inspectDockerResources(
  plan: IsolatedPostgresPlan,
): Promise<readonly IsolatedPostgresResource[]> {
  const candidates: readonly IsolatedPostgresResource[] = [
    await inspectDockerResource('container', plan.containerName, plan),
    await inspectDockerResource('network', plan.networkName, plan),
    await inspectDockerResource('volume', plan.volumeName, plan),
  ].filter((resource): resource is IsolatedPostgresResource => resource !== undefined);
  return candidates;
}

async function inspectDockerResource(
  kind: IsolatedPostgresResourceKind,
  name: string,
  plan: IsolatedPostgresPlan,
): Promise<IsolatedPostgresResource | undefined> {
  const names = await listDockerResourceNames(kind, name, plan);
  if (!names.includes(name)) {
    return undefined;
  }
  const labelTemplate = kind === 'container' ? '{{json .Config.Labels}}' : '{{json .Labels}}';
  const output = await executeDocker([kind, 'inspect', '--format', labelTemplate, name], plan);
  return { kind, labels: parseStringRecord(output), name };
}

function parseJsonArray(value: string): readonly Record<string, unknown>[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => !isRecord(item))) {
    throw new Error('Unexpected Docker inspection result.');
  }
  const records: Record<string, unknown>[] = [];
  for (const item of parsed) {
    if (isRecord(item)) {
      records.push(item);
    }
  }
  return records;
}

function parseStringRecord(value: string): Readonly<Record<string, string>> {
  const parsed = JSON.parse(value) as unknown;
  if (!isRecord(parsed) || Object.values(parsed).some((item) => typeof item !== 'string')) {
    throw new Error('Unexpected Docker label inspection result.');
  }
  const labels: Record<string, string> = {};
  for (const [key, item] of Object.entries(parsed)) {
    if (typeof item === 'string') {
      labels[key] = item;
    }
  }
  return labels;
}

function parseJsonRecord(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (!isRecord(parsed)) {
    throw new Error('Unexpected Docker inspection result.');
  }
  return parsed;
}

function parseJsonStringArray(value: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== 'string')) {
    throw new Error('Unexpected Docker image inspection result.');
  }
  const values: string[] = [];
  for (const item of parsed) {
    if (typeof item === 'string') {
      values.push(item);
    }
  }
  return values;
}

async function listDockerResourceNames(
  kind: IsolatedPostgresResourceKind,
  name: string,
  plan: IsolatedPostgresPlan,
): Promise<readonly string[]> {
  const args =
    kind === 'container'
      ? ['container', 'ls', '--all', '--filter', `name=${name}`, '--format', '{{.Names}}']
      : [kind, 'ls', '--filter', `name=${name}`, '--format', '{{.Name}}'];
  const output = await executeDocker(args, plan);
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

async function waitForPostgres(plan: IsolatedPostgresPlan): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const client = new Client(createPostgresClientOptions(plan));
    try {
      await client.connect();
      await client.query('SELECT 1');
      await client.end();
      return;
    } catch {
      await client.end().catch(() => undefined);
      await delay(200);
    }
  }
  throw new Error('Isolated PostgreSQL readiness deadline elapsed.');
}

export function createIsolatedPostgresDatabaseOptions(
  plan: IsolatedPostgresPlan,
): IsolatedPostgresDatabaseOptions {
  assertPlanIntegrity(plan);
  return {
    database: plan.databaseName,
    host: plan.environment.IDENTITY_TEST_POSTGRES_HOST,
    password: plan.environment.IDENTITY_TEST_DATABASE_PASSWORD,
    port: Number(plan.environment.IDENTITY_TEST_POSTGRES_PORT),
    schema: plan.schemaName,
    username: plan.databaseUser,
  };
}

function composeEnvironment(plan: IsolatedPostgresPlan): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env, ...plan.environment };
  delete environment.COMPOSE_FILE;
  delete environment.COMPOSE_PATH_SEPARATOR;
  delete environment.COMPOSE_PROFILES;
  return environment;
}

function createPostgresClientOptions(plan: IsolatedPostgresPlan): PostgresClientOptions {
  return {
    connectionTimeoutMillis: 2_000,
    database: plan.databaseName,
    host: plan.environment.IDENTITY_TEST_POSTGRES_HOST,
    password: plan.environment.IDENTITY_TEST_DATABASE_PASSWORD,
    port: Number(plan.environment.IDENTITY_TEST_POSTGRES_PORT),
    user: plan.databaseUser,
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function assertCredential(value: string): void {
  if (value.length < 32 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid isolated PostgreSQL credential.');
  }
}

function assertEqual(name: string, value: string, expected: string): void {
  if (value !== expected) {
    throw new Error(`Unsafe isolated PostgreSQL configuration: ${name}.`);
  }
}

function assertPort(port: number): void {
  if (!Number.isInteger(port) || port < 1024 || port > 65_535) {
    throw new Error('Invalid isolated PostgreSQL port.');
  }
}

function assertPortString(value: string): void {
  const port = Number(value);
  if (!/^\d+$/.test(value)) {
    throw new Error('Invalid isolated PostgreSQL port.');
  }
  assertPort(port);
}

function assertRunId(runId: string): void {
  if (!RUN_ID_PATTERN.test(runId)) {
    throw new Error('Invalid isolated PostgreSQL run identity.');
  }
}

function deriveResourceNames(runId: string): DerivedResourceNames {
  const runKey = createHash('sha256').update(runId).digest('hex').slice(0, 24);
  const prefix = `identityit${runKey}`;

  return {
    containerName: `${prefix}-postgres`,
    databaseName: `${prefix}_db`,
    databaseUser: `${prefix}_user`,
    networkName: `${prefix}-network`,
    projectName: `${prefix}-project`,
    schemaName: `${prefix}_schema`,
    volumeName: `${prefix}-volume`,
  };
}

function hasOwnedLabels(resource: IsolatedPostgresResource, plan: IsolatedPostgresPlan): boolean {
  return (
    resource.labels['com.udemy.identity-test.suite'] === TEST_SUITE &&
    resource.labels['com.udemy.identity-test.run-id'] === plan.runId &&
    resource.labels['com.udemy.identity-test.project'] === plan.projectName &&
    resource.labels['com.udemy.identity-test.purpose'] === RESOURCE_PURPOSE
  );
}
