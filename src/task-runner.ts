import type { Page } from "playwright";
import type { Step } from "./core.js";
/** Run only allowlisted, owner-authored steps. */
export async function runSteps(page: Page, steps: Step[], origin: string) {
  for (const step of steps) {
    if (new URL(page.url()).origin !== origin) throw Error("ORIGIN_DENIED");
    const loc = page.locator(step.selector);
    if (step.kind === "visible") await loc.waitFor({ state: "visible" });
    else if (step.kind === "hidden") await loc.waitFor({ state: "hidden" });
    else if (step.kind === "click") await loc.click();
    else if (step.kind === "fill") await loc.fill(step.value);
    else if (step.kind === "assert-text") {
      const text = await loc.textContent({ timeout: 10000 });
      if (!text?.includes(step.value)) throw Error("TASK_ASSERTION_FAILED");
    }
    if (new URL(page.url()).origin !== origin) throw Error("ORIGIN_DENIED");
  }
}
