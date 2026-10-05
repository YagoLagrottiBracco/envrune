// The browser's half of `envrune login`, in a real browser: sign in on the
// panel with the link Supabase emails, land on the page the CLI opened, and
// press "Sign in the CLI", which posts the session to the CLI listening on
// this computer. cloud/e2e.sh runs it through the Go end-to-end test.
//
//   node e2e/login.mjs <address the CLI printed> <email>
//
// ENVRUNE_E2E_MAIL_URL is the local Supabase's mail catcher, and
// ENVRUNE_E2E_BROWSER_CHANNEL the installed browser to drive (chrome).

import { chromium } from "playwright-core";

const [address, email] = process.argv.slice(2);
const mail = (process.env.ENVRUNE_E2E_MAIL_URL ?? "http://127.0.0.1:54324").replace(/\/$/, "");
if (!address || !email) {
  console.error("usage: node e2e/login.mjs <address> <email>");
  process.exit(2);
}

/** The newest message to `email`, as text: Mailpit's API, or Inbucket's on an older Supabase CLI. */
async function message() {
  const list = await fetch(`${mail}/api/v1/search?query=${encodeURIComponent(`to:"${email}"`)}`);
  if (list.ok) {
    const found = (await list.json()).messages ?? [];
    if (found.length === 0) {
      return null;
    }
    const one = await (await fetch(`${mail}/api/v1/message/${found[0].ID}`)).json();
    return `${one.HTML ?? ""}\n${one.Text ?? ""}`;
  }
  const box = email.split("@")[0];
  const old = await fetch(`${mail}/api/v1/mailbox/${encodeURIComponent(box)}`);
  if (!old.ok) {
    throw new Error(`the mail catcher at ${mail} answered ${list.status} and ${old.status}`);
  }
  const found = await old.json();
  if (found.length === 0) {
    return null;
  }
  const one = await (await fetch(`${mail}/api/v1/mailbox/${encodeURIComponent(box)}/${found[found.length - 1].id}`)).json();
  return `${one.body?.html ?? ""}\n${one.body?.text ?? ""}`;
}

/** The sign-in link in the message Supabase sent, waited for. */
async function signInLink() {
  for (let attempt = 0; attempt < 60; attempt++) {
    const text = await message();
    const link = text?.match(/https?:\/\/[^\s"'<>]+\/auth\/v1\/verify[^\s"'<>]+/);
    if (link) {
      return link[0].replaceAll("&amp;", "&");
    }
    await new Promise((done) => setTimeout(done, 500));
  }
  throw new Error(`no sign-in message for ${email} arrived at ${mail}`);
}

const browser = await chromium.launch({ channel: process.env.ENVRUNE_E2E_BROWSER_CHANNEL ?? "chrome" });
try {
  const page = await (await browser.newContext()).newPage();
  page.setDefaultTimeout(30_000);

  // Not signed in yet: the page the CLI opened leads to the sign-in form.
  await page.goto(address);
  await page.waitForURL(/\/login\?next=/);
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Email me a sign-in link" }).click();
  await page.getByText(`Check ${email} for a sign-in link.`).waitFor();

  // The link signs this browser in and comes back to the CLI's page.
  await page.goto(await signInLink());
  await page.waitForURL(/\/cli\/authorize\?/);
  await page.getByText(email).waitFor();

  // The press that 1.0.0 lost: the session must reach the CLI's listener.
  await page.getByRole("button", { name: "Sign in the CLI" }).click();
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
  await page.getByText("The EnvRune CLI is signed in.").waitFor();
  console.log("the browser handed the session to the CLI");
} catch (error) {
  console.error(String(error));
  process.exitCode = 1;
} finally {
  await browser.close();
}
