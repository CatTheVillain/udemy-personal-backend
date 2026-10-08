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

const [validResult] = await eslint.lintText(
  "type Input = { id: string };\ntype Output = { id: string };\ntype Kind = 'draft' | 'published';\ninterface Reader { read(input: Input, kind: Kind): Output; }\nfunction read(input: Input, kind: Kind): Output { return input; }",
  { filePath: 'src/policy-fixture.ts' },
);
assert.deepEqual(
  validResult.messages,
  [],
  'named object and literal-union contracts must remain valid',
);
