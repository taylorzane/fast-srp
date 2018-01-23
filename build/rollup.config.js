// Shared
import replace from 'rollup-plugin-replace'

// Browser
import commonjs from 'rollup-plugin-commonjs'
import resolve from 'rollup-plugin-node-resolve'

const browser = {
  input: 'index.js',
  output: {
    file: 'dist/fast-srp.browser.js',
    format: 'es'
  },
  plugins: [
    commonjs(),
    resolve({
      main: false,
      browser: true,
      preferBuiltins: true
    })
  ]
}

const node = {
  input: 'index.js',
  output: {
    file: 'dist/fast-srp.node.js',
    format: 'umd',
    name: 'fastSRP'
  },
  external: ['crypto', 'scryptsy'],
  plugins: [
    replace({
      delimiters: ['/*', '*/'],
      values: {
        IMPORT_CRYPTO: `import crypt_ from 'crypto'`
      }
    })
  ]
}

export default [browser, node]
