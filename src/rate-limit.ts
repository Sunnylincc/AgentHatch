/** Single-process fallback only. Production must also enforce shared ingress limits. */
export function sessionAdmission(limit = 60, windowMs = 60_000) {
  if (!Number.isInteger(limit) || limit < 1 || !Number.isFinite(windowMs) || windowMs < 1)
    throw Error("INVALID_ADMISSION_LIMIT");
  let reset = 0, attempts = 0;
  return () => {
    const now = Date.now();
    if (now >= reset) { reset = now + windowMs; attempts = 0; }
    return ++attempts <= limit;
  };
}
