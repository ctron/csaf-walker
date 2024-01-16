import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import terser from '@rollup/plugin-terser';

export default {
  input: 'main.js',
  output: {
    file: 'bundle.js',
    format: 'cjs',
    compact: false,
  },
  plugins: [
      nodeResolve({
        moduleDirectories: [
            "node_modules",
            "build"
        ]
      }),
      commonjs(),
      json(),
      terser()
  ]
};
