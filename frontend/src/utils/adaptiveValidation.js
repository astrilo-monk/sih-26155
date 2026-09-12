// Client-side checks for adaptive training submissions.
// The backend re-validates everything; this only prevents obviously bad input.

const TRUE_VALUES = ['true', 'enabled', 'yes', '1', 'on'];
const FALSE_VALUES = ['false', 'disabled', 'no', '0', 'off'];
const MAX_PATTERN_LENGTH = 256;

export function validateValue(valueType, rawValue) {
  const value = (rawValue ?? '').trim();
  if (!value) return 'Extracted value is required';

  switch (valueType) {
    case 'bool':
    case 'optional_bool':
      return [...TRUE_VALUES, ...FALSE_VALUES].includes(value.toLowerCase())
        ? null
        : 'Use true/false, enabled/disabled, yes/no or on/off';
    case 'int':
    case 'optional_int':
      return /^v?-?\d+$/i.test(value) ? null : 'Must be a whole number';
    case 'list_str':
      return value.split(',').some((part) => part.trim()) ? null : 'Provide at least one value';
    default:
      return null;
  }
}

export function validatePattern(rawPattern) {
  const pattern = (rawPattern ?? '').trim();
  if (!pattern) return null; // optional — the backend derives one from the line

  if (pattern.length > MAX_PATTERN_LENGTH) return `Pattern must be at most ${MAX_PATTERN_LENGTH} characters`;

  const tokens = pattern.split(/\s+/);
  const placeholders = tokens.filter((t) => t === '{value}' || t === '{any}');
  const literals = tokens.filter((t) => t !== '{value}' && t !== '{any}');

  if (literals.some((t) => t.includes('{') || t.includes('}'))) {
    return 'Only {value} and {any} placeholders are allowed';
  }
  if (literals.length === 0) return 'Pattern needs at least one keyword';
  if (placeholders.filter((t) => t === '{value}').length > 1) return 'Use {value} at most once';
  return null;
}

export function validateInterpretation(form, fields) {
  const errors = {};
  const field = fields.find((f) => f.field === form.normalizedField);

  if (!form.normalizedField) {
    errors.normalizedField = 'Choose a normalized field';
  } else if (!field) {
    errors.normalizedField = 'Not a supported normalized field';
  }

  const valueError = validateValue(field?.value_type, form.extractedValue);
  if (valueError) errors.extractedValue = valueError;

  const patternError = validatePattern(form.commandPattern);
  if (patternError) errors.commandPattern = patternError;

  return { valid: Object.keys(errors).length === 0, errors };
}
