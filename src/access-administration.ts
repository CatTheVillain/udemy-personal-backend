import 'reflect-metadata';

import { INestApplicationContext } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { decodeCanonicalCredential } from './modules/identity/application/access-administration/config/access-administration-config';
import { AccessAdministrationOutcome } from './modules/identity/application/access-administration/contracts/access-administration.contracts';
import { AccessAdministrationOperatorAppModule } from './modules/identity/operator/access-administration-operator.module';
import { AccessAdministrationOperatorEntrypoint } from './modules/identity/operator/access-administration-operator.service';
import {
  OperatorInvocationInvalidError,
  OperatorInvocationParser,
} from './modules/identity/operator/operator-invocation-parser';

type AccessAdministrationExitCode = 0 | 2 | 3 | 4;

export async function runAccessAdministrationEntrypoint(
  argv: readonly string[],
  environment: NodeJS.ProcessEnv,
): Promise<AccessAdministrationExitCode> {
  let credential: Buffer | undefined;
  let app: INestApplicationContext | undefined;
  try {
    const input = new OperatorInvocationParser().parse(argv);
    credential = takeInvocationCredential(environment);
    app = await NestFactory.createApplicationContext(AccessAdministrationOperatorAppModule, {
      logger: false,
      abortOnError: false,
    });
    const outcome = await app
      .get(AccessAdministrationOperatorEntrypoint)
      .execute(input, credential);
    writeSafeCode(outcome.code);
    return exitCodeForOutcome(outcome);
  } catch (error: unknown) {
    const code =
      error instanceof OperatorInvocationInvalidError
        ? 'access_administration_invocation_invalid'
        : 'access_administration_operator_unavailable';
    writeSafeCode(code);
    return 2;
  } finally {
    try {
      await app?.close();
    } catch {
      // Context-close failure has no safe operator detail to report.
    } finally {
      credential?.fill(0);
    }
  }
}

function takeInvocationCredential(environment: NodeJS.ProcessEnv): Buffer {
  const raw = environment.IDENTITY_ACCESS_OPERATOR_CREDENTIAL;
  delete environment.IDENTITY_ACCESS_OPERATOR_CREDENTIAL;
  const credential = decodeCanonicalCredential(raw);
  if (credential === null) throw new OperatorInvocationInvalidError();
  return credential;
}

function writeSafeCode(code: string): void {
  process.stderr.write(`${code}\n`);
}

function exitCodeForOutcome(outcome: AccessAdministrationOutcome): AccessAdministrationExitCode {
  if (outcome.code === 'access_administration_completed') return 0;
  if (outcome.code === 'access_administration_unauthorized') return 3;
  if (outcome.code === 'access_administration_busy') return 4;
  return 4;
}

if (require.main === module) {
  void runAccessAdministrationEntrypoint(process.argv.slice(2), process.env).then((code) => {
    process.exitCode = code;
  });
}
