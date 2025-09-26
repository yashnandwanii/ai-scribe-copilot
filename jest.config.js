module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  testMatch: [
    '<rootDir>/tests/**/*.test.js'
  ],
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/config/**/*.js',
    '!src/**/*.config.js',
    '!src/**/index.js'
  ],
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  coverageDirectory: 'coverage',
  verbose: true,
  testTimeout: 30000,
  maxWorkers: 1, // Run tests sequentially to avoid database conflicts
  forceExit: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  transform: {},
  globals: {
    'process.env': {
      NODE_ENV: 'test',
      JWT_SECRET: 'test_jwt_secret_key',
      JWT_REFRESH_SECRET: 'test_jwt_refresh_secret_key',
      MONGODB_TEST_URI: 'mongodb://localhost:27017/medication_app_test',
      REDIS_URL: 'redis://localhost:6379/1'
    }
  }
};