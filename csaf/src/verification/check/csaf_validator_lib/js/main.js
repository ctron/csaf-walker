import validateStrict from 'csaf-validator-lib/validateStrict';
import * as mandatory from 'csaf-validator-lib/mandatoryTests';

export async function validate(doc) {
  await validateStrict(mandatory, doc)
}