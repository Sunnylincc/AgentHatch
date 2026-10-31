const codes = new Set(["ACCESS_DENIED","ACCOUNT_DENIED","SESSION_NOT_FOUND","SESSION_INACTIVE","TASK_DENIED","TASK_ASSERTION_FAILED","ORIGIN_DENIED","RESOURCE_LIMIT","START_FAILED","START_FAILED_CLEANUP_FAILED","CONFIG_DENIED","KEY_SUBSTITUTION_DENIED","PROXY_CONFIG_INVALID"]);
/** Never reflect raw upstream messages, selectors, or credentials to an untrusted caller. */
export function publicError(e: unknown) {
  return e instanceof Error && codes.has(e.message) ? e.message : "REQUEST_FAILED";
}
