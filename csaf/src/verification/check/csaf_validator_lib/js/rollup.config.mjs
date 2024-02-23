import {nodeResolve} from '@rollup/plugin-node-resolve';
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import terser from '@rollup/plugin-terser';

export default {
  input: 'main.js',
  output: [
    {
      file: 'bundle.js',
      format: 'es',
      plugins: [
        terser()
      ]
    },
    {
      file: 'bundle.debug.js',
      format: 'es',
      compact: false,
    }
  ],
  plugins: [
    nodeResolve({
      moduleDirectories: [
        "node_modules"
      ]
    }),
    commonjs(),
    json(),
  ]
};
