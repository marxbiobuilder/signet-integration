module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: './tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint', 'prettier', 'simple-import-sort'],
  extends: [
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:prettier/recommended',
  ],
  env: { node: true, jest: true },
  ignorePatterns: ['dist/', 'coverage/'],
  rules: {
    '@typescript-eslint/no-unused-vars': [
      'error',
      { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
    ],
    // Local-time Date accessors and multi-argument constructors are banned:
    // the test harness pins TZ=UTC, so a local-time bug is invisible to the
    // suite and diverges only on a machine in another zone.
    'no-restricted-syntax': [
      'error',
      {
        selector:
          "CallExpression > MemberExpression.callee[property.name=/^(get|set)(Date|Day|FullYear|Hours|Milliseconds|Minutes|Month|Seconds)$/]",
        message:
          'Local-time Date accessors are banned. Use the getUTC*/setUTC* spelling.',
      },
      {
        selector: "NewExpression[callee.name='Date'][arguments.length>=2]",
        message:
          'Multi-argument `new Date(y, m, d)` constructs in local time. Use `new Date("YYYY-MM-DDT00:00:00Z")` or `Date.UTC(...)`.',
      },
    ],
    'simple-import-sort/exports': 'error',
    'simple-import-sort/imports': 'error',
  },
};
