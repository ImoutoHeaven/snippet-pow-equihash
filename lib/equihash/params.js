const DECIMAL_RE = /^(0|[1-9][0-9]*)$/u;

export const EQ_N_MIN = 8;
export const EQ_N_MAX = 256;
export const EQ_K_MIN = 2;
export const EQ_K_MAX = 8;
export const EQ_DEFAULT_N = 96;
export const EQ_DEFAULT_K = 5;

const asStrictInt = (value) => {
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : null;
  if (typeof value !== "string" || !DECIMAL_RE.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
};

export const parseEquihashParams = (nRaw, kRaw) => {
  const n = asStrictInt(nRaw);
  const k = asStrictInt(kRaw);
  if (n === null || k === null) return null;
  if (n < EQ_N_MIN || n > EQ_N_MAX || n % 2 !== 0) return null;
  if (k < EQ_K_MIN || k > EQ_K_MAX || n % (k + 1) !== 0) return null;
  return { n, k };
};

export const isValidEquihashParams = (nRaw, kRaw) => parseEquihashParams(nRaw, kRaw) !== null;

export const normalizeEquihashParams = (nRaw, kRaw) => {
  const parsed = parseEquihashParams(
    nRaw === undefined ? EQ_DEFAULT_N : nRaw,
    kRaw === undefined ? EQ_DEFAULT_K : kRaw,
  );
  if (!parsed) throw new TypeError("invalid equihash params");
  return parsed;
};

export const collisionBitsFor = (nRaw, kRaw) => {
  const { n, k } = normalizeEquihashParams(nRaw, kRaw);
  return n / (k + 1);
};

export const defaultRowsFor = (nRaw, kRaw) => {
  const width = collisionBitsFor(nRaw, kRaw);
  const exponent = width + 1;
  if (exponent >= 32) return null;
  return 2 ** exponent;
};
