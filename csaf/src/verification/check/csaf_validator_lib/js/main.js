// main script for the JS integration.
//
// Whenever you make changes to this script, you will need to re-run `npm build`.

import validateLib from '@secvisogram/csaf-validator-lib/validate';

import * as schema from '@secvisogram/csaf-validator-lib/schemaTests';
import * as mandatory from '@secvisogram/csaf-validator-lib/mandatoryTests';
import * as optional from '@secvisogram/csaf-validator-lib/optionalTests';

/**
 * Can be used for testing
 * @param msg a string to print.
 */
function print(msg) {
  Deno.core.print(msg);
}

const DEBUG = false;

async function runValidation(validations, doc, ignore) {
  let tests = [];

  for (const validation of validations) {
    switch (validation) {
      case "schema":
        tests = tests.concat(Object.values(schema));
        break;
      case "mandatory":
        tests = tests.concat(Object.values(mandatory));
        break;
      case "optional":
        tests = tests.concat(Object.values(optional));
        break;
      default:
        throw new Error(`Unknown validation set: ${validation}`);
    }
  }

  tests = tests.filter((test) => {
    return !ignore.has(test.name);
  });

  if (DEBUG) {
    tests = tests.map((test) => {
      return (doc) => {
        print(`starting: ${test.name}\n`);
        const result = test(doc);
        print(`completed: ${test.name}\n`);
        return result;
      }
    })
  }

  return validateLib(tests, doc);
}

Deno.core.ops.op_register_func(runValidation);
