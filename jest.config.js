module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/app/lib/__tests__'],
  testMatch: ['**/__tests__/**/*.test.js'],
  collectCoverageFrom: [
    'app/lib/**/*.js',
    '!app/lib/__tests__/**',
  ],
  coverageDirectory: 'coverage',
  verbose: true,
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/app/$1',
  },
  transform: {},
  testTimeout: 30000, // 30 seconds for network tests
};