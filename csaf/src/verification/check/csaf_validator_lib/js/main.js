import validateLib from '@secvisogram/csaf-validator-lib/validate';

import * as schema from '@secvisogram/csaf-validator-lib/schemaTests';
import * as mandatory from '@secvisogram/csaf-validator-lib/mandatoryTests';

const tests = Object.values(schema).concat(Object.values(mandatory))

globalThis.result = await validateLib(tests, globalThis.doc);

