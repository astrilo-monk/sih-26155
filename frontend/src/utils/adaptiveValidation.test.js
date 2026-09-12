import { describe, expect, it } from 'vitest';
import { validateInterpretation, validatePattern, validateValue } from './adaptiveValidation';

const FIELDS = [
  { field: 'management.ssh_version', value_type: 'optional_int' },
  { field: 'management.telnet_enabled', value_type: 'bool' },
  { field: 'logging.remote_hosts', value_type: 'list_str' },
];

describe('validateValue', () => {
  it('checks value types', () => {
    expect(validateValue('optional_int', '2')).toBeNull();
    expect(validateValue('optional_int', 'modern')).toMatch(/whole number/);
    expect(validateValue('bool', 'Enabled')).toBeNull();
    expect(validateValue('bool', 'perhaps')).not.toBeNull();
    expect(validateValue('list_str', ' , ')).not.toBeNull();
    expect(validateValue('optional_str', '   ')).toMatch(/required/);
  });
});

describe('validatePattern', () => {
  it('allows empty and safe templates', () => {
    expect(validatePattern('')).toBeNull();
    expect(validatePattern('secure-shell {any} {value}')).toBeNull();
  });

  it('rejects unsafe templates', () => {
    expect(validatePattern('{value}')).not.toBeNull();
    expect(validatePattern('ssh {value} {value}')).not.toBeNull();
    expect(validatePattern('ssh {regex}')).not.toBeNull();
  });
});

describe('validateInterpretation', () => {
  it('prevents empty and invalid submissions', () => {
    expect(validateInterpretation({ normalizedField: '', extractedValue: '', commandPattern: '' }, FIELDS).errors)
      .toEqual({ normalizedField: expect.any(String), extractedValue: expect.any(String) });
    expect(validateInterpretation({ normalizedField: 'made.up', extractedValue: '1', commandPattern: '' }, FIELDS).valid)
      .toBe(false);
  });

  it('accepts a valid submission', () => {
    expect(
      validateInterpretation({ normalizedField: 'management.ssh_version', extractedValue: '2', commandPattern: '' }, FIELDS),
    ).toEqual({ valid: true, errors: {} });
  });
});
