import typescriptEslintPlugin from '@typescript-eslint/eslint-plugin';
import typescriptParser from '@typescript-eslint/parser';

const restrictedTypeSyntax = [
  {
    selector:
      ':matches(FunctionDeclaration, FunctionExpression, ArrowFunctionExpression, TSMethodSignature, TSCallSignatureDeclaration, TSFunctionType) > :matches(Identifier, ObjectPattern, ArrayPattern, AssignmentPattern, RestElement) > TSTypeAnnotation > TSTypeLiteral',
    message:
      'Use a named type or interface instead of an inline object type in a parameter signature.',
  },
  {
    selector:
      ':matches(FunctionDeclaration, FunctionExpression, ArrowFunctionExpression, TSMethodSignature, TSCallSignatureDeclaration, TSFunctionType) > TSTypeAnnotation > TSTypeLiteral',
    message:
      'Use a named type or interface instead of an inline object type in a return signature.',
  },
  {
    selector:
      ':matches(FunctionDeclaration, FunctionExpression, ArrowFunctionExpression, TSMethodSignature, TSCallSignatureDeclaration, TSFunctionType) > :matches(Identifier, ObjectPattern, ArrayPattern, AssignmentPattern, RestElement) > TSTypeAnnotation > TSUnionType > TSLiteralType',
    message:
      'Use a named literal-union type instead of an inline literal union in a parameter signature.',
  },
  {
    selector: "TSTypeReference[typeName.name='ReturnType']",
    message: 'Write the readable named return type instead of ReturnType<...>.',
  },
  {
    selector: 'TSIndexedAccessType',
    message: 'Write the readable named type instead of an indexed-access type.',
  },
];

const absenceUnionSyntax = {
  selector: 'TSUnionType:has(> :matches(TSUndefinedKeyword, TSNullKeyword))',
  message: 'Use Optional<T> and Nullable<T> instead of raw null or undefined unions.',
};

const forwardRefRestriction = {
  name: '@nestjs/common',
  importNames: ['forwardRef'],
  message: 'Repair the dependency direction instead of using forwardRef.',
};

function restrictedImports(patterns = [], paths = []) {
  return ['error', { paths: [forwardRefRestriction, ...paths], patterns }];
}

export default [
  {
    ignores: [
      '.agents/**',
      '.codex/**',
      '.project-mcp/**',
      '.tools/**',
      'dist/**',
      'node_modules/**',
      'coverage/**',
    ],
  },
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      parser: typescriptParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': typescriptEslintPlugin,
    },
    rules: {
      '@typescript-eslint/ban-ts-comment': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      'no-restricted-syntax': ['error', ...restrictedTypeSyntax],
      'no-restricted-imports': restrictedImports(),
    },
  },
  {
    files: ['src/**/*.ts'],
    ignores: ['src/shared/types/absence.types.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...restrictedTypeSyntax, absenceUnionSyntax],
    },
  },
  {
    files: ['src/**/*.ts'],
    rules: {
      '@typescript-eslint/explicit-function-return-type': [
        'error',
        {
          allowExpressions: true,
          allowTypedFunctionExpressions: true,
        },
      ],
    },
  },
  {
    files: ['src/modules/**/domain/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports(
        [
          {
            group: [
              '@nestjs/*',
              'typeorm',
              '@nestjs/typeorm',
              '**/application/**',
              '**/presentation/**',
              '**/infrastructure/**',
              '**/shared/**',
            ],
            message:
              'Domain code must remain independent of framework and outer layers; only type-only absence contracts use #shared.',
          },
          {
            regex: '^#shared/(?!types/absence\\.types$)',
            message:
              'Domain code must remain independent of framework and outer layers; only type-only absence contracts use #shared.',
          },
        ],
        [
          {
            name: '#shared/types/absence.types',
            allowTypeImports: true,
            message: 'Domain may import Nullable and Optional only as types.',
          },
        ],
      ),
    },
  },
  {
    files: ['src/modules/**/application/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports(
        [
          {
            group: [
              '**/presentation/**',
              '**/infrastructure/**',
              '**/shared/**',
              '#shared/http/**',
              '#shared/database/**',
              'typeorm',
              '@nestjs/typeorm',
            ],
            message:
              'Application code must not depend on presentation or persistence adapters; shared imports use #shared.',
          },
        ],
        [
          {
            name: '@nestjs/common',
            importNames: [
              'HttpException',
              'BadRequestException',
              'ConflictException',
              'ForbiddenException',
              'NotFoundException',
              'ServiceUnavailableException',
              'UnauthorizedException',
            ],
            message: 'Translate HTTP failures in presentation, not application.',
          },
        ],
      ),
    },
  },
  {
    files: ['src/modules/**/infrastructure/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports([
        {
          group: ['**/presentation/**', '**/shared/**'],
          message:
            'Infrastructure adapters must not depend on presentation; shared imports use #shared.',
        },
      ]),
    },
  },
  {
    files: ['src/shared/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports([
        { group: ['**/modules/**'], message: 'Shared code must not depend on feature ownership.' },
      ]),
    },
  },
  {
    files: ['src/modules/**/presentation/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports([
        {
          group: ['**/shared/**'],
          message: 'Presentation imports shared contracts through #shared.',
        },
      ]),
    },
  },
  {
    files: ['src/modules/**/presentation/**/controllers/**/*.ts'],
    rules: {
      'no-restricted-imports': restrictedImports([
        {
          group: ['**/infrastructure/**', '**/shared/**'],
          message:
            'Controllers use application contracts and #shared, not infrastructure adapters or relative shared imports.',
        },
      ]),
    },
  },
];
