import {
  IsolatedPostgresPlan,
  IsolatedPostgresPreflightOperations,
  IsolatedPostgresResource,
  IsolatedPostgresResourceKind,
} from '../support/isolated-postgres-harness';

export class IsolatedPostgresPreflightSpy implements IsolatedPostgresPreflightOperations {
  public inspections = 0;

  public constructor(private readonly resources: readonly IsolatedPostgresResource[]) {}

  public async inspectOwnedResources(
    _plan: IsolatedPostgresPlan,
  ): Promise<readonly IsolatedPostgresResource[]> {
    this.inspections += 1;
    return this.resources;
  }
}

export function createOwnedResource(
  plan: IsolatedPostgresPlan,
  kind: IsolatedPostgresResourceKind,
): IsolatedPostgresResource {
  return {
    kind,
    labels: {
      'com.udemy.identity-test.project': plan.projectName,
      'com.udemy.identity-test.purpose': 'isolated-postgres',
      'com.udemy.identity-test.run-id': plan.runId,
      'com.udemy.identity-test.suite': 'identity-integration',
    },
    name: selectResourceName(plan, kind),
  };
}

function selectResourceName(
  plan: IsolatedPostgresPlan,
  kind: IsolatedPostgresResourceKind,
): string {
  if (kind === 'container') {
    return plan.containerName;
  }
  if (kind === 'network') {
    return plan.networkName;
  }
  return plan.volumeName;
}
