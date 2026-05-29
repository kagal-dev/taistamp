/**
 * Single-label selector pattern: a leading letter,
 * optional inner letters / digits / `_` / `-`, ending in
 * a letter or digit, for a maximum length of 63
 * characters.
 *
 * Sourced from DKIM's selector grammar (RFC 6376 §3.1):
 * a `selector` is a dot-separated sequence of
 * `sub-domain` labels following RFC 5321 §4.1.2
 * (`Let-dig [Ldh-str Let-dig]`) plus DKIM's `_`
 * allowance. This module narrows that to a single such
 * label so the value is also a valid sf-token under
 * RFC 9651.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc6376#section-3.1}
 */
export const SELECTOR_PATTERN = /^[A-Za-z](?:[\dA-Za-z_-]{0,61}[\dA-Za-z])?$/;

/**
 * Test whether `value` matches {@link SELECTOR_PATTERN}.
 * Use this when the caller wants to branch on the
 * result; reach for {@link assertValidSelector} when
 * the caller wants to fail fast.
 */
export const isValidSelector = (value: string): boolean =>
  SELECTOR_PATTERN.test(value);

/**
 * Throw `TypeError` when `value` does not match
 * {@link SELECTOR_PATTERN}, naming the pattern and
 * quoting the offending input.
 *
 * @param value - candidate selector
 * @param context - optional prefix prepended to the
 *   error message, typically the calling function's
 *   name
 */
export const assertValidSelector = (
  value: string,
  context?: string,
): void => {
  if (!isValidSelector(value)) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(
      `${prefix}selector must match ${SELECTOR_PATTERN.source}, got "${value}"`,
    );
  }
};
