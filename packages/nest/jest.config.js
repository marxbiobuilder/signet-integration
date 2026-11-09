process.env.TZ = 'UTC';

module.exports = {
  collectCoverageFrom: [
    '**/*.ts',
    '!**/index.ts',
    '!testing/**',
    '!__spec__/**',
  ],
  coverageDirectory: '../coverage',
  moduleFileExtensions: ['js', 'json', 'ts'],
  restoreMocks: true,
  rootDir: 'src',
  testEnvironment: 'node',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': ['ts-jest', { tsconfig: '<rootDir>/../tsconfig.json' }],
  },
};
