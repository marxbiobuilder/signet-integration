// Strip everything that could break OUT of one field of an unquoted
// "key=value key=value" log record: C0 controls and DEL, all whitespace (the
// field separator), "=" (the key/value separator), and the double quote and
// backslash that consumers which do parse quoted values use for grouping and
// escaping. Applied to the values a caller chose or could influence --
// reasons, client ids, routes.
export function sanitiseLogToken(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\s\x00-\x1f\x7f="\\]/g, '_');
}

// Longest `route=` a refusal line will carry.
export const REFUSAL_ROUTE_MAX = 300;

// Clips a value to `max` characters and MARKS THE CUT, so a clipped value
// cannot be read as a whole one.
export function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…(truncated)`;
}
