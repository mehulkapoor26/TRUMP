import { template } from 'lodash';

// This source is read as data by the scanner. It is never executed by TRACEGUARD.
export function handler() {
  return template('Hello <%= name %>');
}
