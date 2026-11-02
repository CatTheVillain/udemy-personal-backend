import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';

const root = fileURLToPath(new URL('..', import.meta.url));
const configFile = fileURLToPath(new URL('../eslint.config.mjs', import.meta.url));
const eslint = new ESLint({
  cwd: root,
  overrideConfigFile: configFile,
});

const forbiddenCases = [
  [
    'inline parameter object',
    'function read(input: { id: string }): void {}',
    'Use a named type or interface instead of an inline object type in a parameter signature.',
  ],
  [
    'inline return object',
    'function read(): { id: string } { return { id: "1" }; }',
    'Use a named type or interface instead of an inline object type in a return signature.',
  ],
  [
    'inline method parameter object',
    'interface Reader { read(input: { id: string }): void; }',
    'Use a named type or interface instead of an inline object type in a parameter signature.',
  ],
  [
    'inline method return object',
    'interface Reader { read(): { id: string }; }',
    'Use a named type or interface instead of an inline object type in a return signature.',
  ],
  [
    'inline parameter literal union',
    "function read(kind: 'draft' | 'published'): void {}",
    'Use a named literal-union type instead of an inline literal union in a parameter signature.',
  ],
  [
    'ReturnType',
    'type ReadResult = ReturnType<typeof read>;',
    'Write the readable named return type instead of ReturnType<...>.',
  ],
  [
    'indexed access',
    'interface Result { id: string }\ntype Identifier = Result["id"];',
    'Write the readable named type instead of an indexed-access type.',
  ],
];

for (const [name, source, expectedMessage] of forbiddenCases) {
  const [result] = await eslint.lintText(source, { filePath: 'src/policy-fixture.ts' });
  assert.ok(
    result.messages.some(
      (message) => message.ruleId === 'no-restricted-syntax' && message.message === expectedMessage,
    ),
    `${name} must fail the named-type policy`,
  );
}

const absenceForbiddenCases = [
  ['undefined union', 'type Value = string | undefined;'],
  ['null union', 'type Value = string | null;'],
  ['multiline null union', 'type Value =\n  | string\n  | null;'],
];

for (const [name, source] of absenceForbiddenCases) {
  const [result] = await eslint.lintText(source, { filePath: 'src/absence-policy-fixture.ts' });
  const absenceMessages = result.messages.filter(
    (message) =>
      message.ruleId === 'no-restricted-syntax' &&
      message.message ===
        'Use Optional<T> and Nullable<T> instead of raw null or undefined unions.',
  );
  assert.equal(absenceMessages.length, 1, `${name} must fail exactly once`);
}

for (const [name, source, filePath] of [
  [
    'named absence aliases',
    'type Value = Optional<string>;\ntype Other = Nullable<number>;',
    'src/absence-policy-fixture.ts',
  ],
  [
    'canonical absence owner',
    'export type Optional<T> = T | undefined;\nexport type Nullable<T> = T | null;',
    'src/shared/types/absence.types.ts',
  ],
  [
    'domain type-only absence import',
    "import type { Nullable, Optional } from '#shared/types/absence.types';\ntype Value = Optional<Nullable<string>>;",
    'src/modules/identity/domain/policy-fixture.ts',
  ],
]) {
  const [result] = await eslint.lintText(source, { filePath });
  assert.deepEqual(result.messages, [], `${name} must remain valid`);
}

const importBoundaryCases = [
  [
    'domain shared runtime import',
    "import { createPinoHttpOptions } from '#shared/logging/pino-http-options';",
    'src/modules/identity/domain/policy-fixture.ts',
  ],
  [
    'domain relative shared import',
    "import type { Nullable } from '../../../../shared/types/absence.types';",
    'src/modules/identity/domain/policy-fixture.ts',
  ],
  [
    'domain framework import',
    "import { Injectable } from '@nestjs/common';",
    'src/modules/identity/domain/policy-fixture.ts',
  ],
  [
    'application persistence import',
    "import { TypeOrmModule } from '@nestjs/typeorm';",
    'src/modules/identity/application/policy-fixture.ts',
  ],
  [
    'application HTTP exception import',
    "import { ServiceUnavailableException } from '@nestjs/common';",
    'src/modules/identity/application/policy-fixture.ts',
  ],
  [
    'infrastructure presentation import',
    "import { IdentityAuthController } from '../../presentation/http/controllers/identity-auth.controller';",
    'src/modules/identity/infrastructure/policy-fixture.ts',
  ],
  [
    'shared feature import',
    "import { Session } from '../modules/identity/domain/identity.types';",
    'src/shared/policy-fixture.ts',
  ],
  [
    'controller infrastructure import',
    "import { TypeOrmIdentityTransactionAdapter } from '../../../infrastructure/persistence/typeorm-identity-transaction.adapter';",
    'src/modules/identity/presentation/http/controllers/policy-fixture.ts',
  ],
];

for (const [name, source, filePath] of importBoundaryCases) {
  const [result] = await eslint.lintText(source, { filePath });
  assert.ok(
    result.messages.some((message) => message.ruleId === 'no-restricted-imports'),
    `${name} must fail the direct import-boundary policy`,
  );
}

for (const file of [
  'src/modules/identity/domain/identity.types.ts',
  'src/modules/identity/application/authentication/services/identity-authentication.service.ts',
  'src/modules/identity/infrastructure/persistence/entities/session.entity.ts',
  'src/modules/identity/presentation/http/controllers/identity-auth.controller.ts',
  'src/shared/http/request-correlation.ts',
]) {
  const config = await eslint.calculateConfigForFile(file);
  const imports = config.rules['no-restricted-imports'];
  assert.ok(Array.isArray(imports), `${file} must retain import restrictions`);
  const paths = imports[1].paths;
  assert.ok(
    paths.some(
      (entry) => entry.name === '@nestjs/common' && entry.importNames.includes('forwardRef'),
    ),
    `${file} must retain the forwardRef restriction`,
  );
}

const [validResult] = await eslint.lintText(
  "type Input = { id: string };\ntype Output = { id: string };\ntype Kind = 'draft' | 'published';\ninterface Reader { read(input: Input, kind: Kind): Output; }\nfunction read(input: Input, kind: Kind): Output { return input; }",
  { filePath: 'src/policy-fixture.ts' },
);
assert.deepEqual(
  validResult.messages,
  [],
  'named object and literal-union contracts must remain valid',
);
