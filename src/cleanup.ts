/** Always release local resources, including when remote revocation fails. */
export async function revokeAndClose(options: {
  revoke: () => Promise<void>;
  closeContext: () => Promise<void>;
  closeBrowser: () => Promise<void>;
}): Promise<void> {
  let failed = false;
  for (const operation of [options.revoke, options.closeContext, options.closeBrowser]) {
    try { await operation(); } catch { failed = true; }
  }
  if (failed) throw Error("SESSION_CLEANUP_FAILED");
}
