import typescript from '@rollup/plugin-typescript';
import terser from '@rollup/plugin-terser';

export default {
  input: 'src/main/index.ts',
  output: {
    dir: 'dist/module',
    format: 'esm',
    entryFileNames: '[name].mjs'
  },
  plugins: [
    typescript( {
      tsconfig: 'tsconfig.module.json'
    }),
    terser({
      format: {
        comments: 'some',
        beautify: true,
        ecma: '2022',
      },
      compress: false,
      mangle: false,
      module: true,
    }),
  ]
};