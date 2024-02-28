module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  resolver: "jest-resolver-enhanced",
  moduleNameMapper: {
    '^jose/(.*)$': '<rootDir>/node_modules/jose/dist/node/cjs/$1',
    // "multiformats": require.resolve("multiformats"),
  },
  rootDir: '.',
  roots: ['<rootDir>/src/', '<rootDir>/test/'],
  testMatch: ['**/?(*.)+(spec|test).+(ts|tsx|js)'],
  transform: {
    '^.+\\.(ts|tsx)?$': 'ts-jest',
    '^.+\\.(js|jsx)$': [
      'babel-jest', {
        'presets': ['@babel/preset-env'],
        'plugins': [
          ['@babel/transform-runtime'],
          ['@babel/plugin-transform-modules-commonjs']
        ]
      }]
  },
  transformIgnorePatterns: ['/node_modules/(?!(@cef-ebsi|.*multiformats.*)/)'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  coverageDirectory: './coverage/',
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/schemas/**',
    '!src/**/*.d.ts',
    '!**/node_modules/**',
    '!jest.config.cjs',
    '!generator/**',
    '!index.ts'

  ],
  collectCoverage: true,
  reporters: ['default', ['jest-junit', { outputDirectory: './coverage' }]]
};
