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
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@nestjs/common',
              importNames: ['forwardRef'],
              message: 'Repair the dependency direction instead of using forwardRef.',
            },
          ],
        },
      ],
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
];
