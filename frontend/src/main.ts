import { AuthModule } from "./AuthModule";
import { UIManager } from "./UIManager";
import { UserClient } from "../openapi/generated/user";
import { TestCredsClient } from "../openapi/generated/testcreds";

const authModule: AuthModule = new AuthModule();

// Load auth module when browser window loads. Only required for redirect flows.
window.addEventListener("load", async () => {
  authModule.loadAuthModule();
});

export async function signIn(): Promise<void> {
  await authModule.login("loginPopup");
  const idToken = await authModule.getIDToken();
  if (!idToken) {
    alert("no ID token!");
    return;
  }
  const client = new UserClient({
    TOKEN: idToken,
    BASE: "http://localhost:8080",
    CREDENTIALS: 'include',
    WITH_CREDENTIALS: true,
  }).default;
  await client.login()
}

export async function getAPIKey(): Promise<void> {
  const idToken = await authModule.getIDToken();
  if (!idToken) {
    alert("no ID token!");
    return;
  }
  const client = new UserClient({
    TOKEN: idToken,
    BASE: "http://localhost:8080",
  }).default;
  const resp = await client.createApiKey();
  if ("message" in resp) {
    alert(`error generating API key: ${resp.message}`);
    return;
  }
  UIManager.showAPIKey(resp.id, resp.key);
}

export async function signOut(): Promise<void> {
  await authModule.logout();
  UIManager.signOut();
  const client = new UserClient({
    BASE: "http://localhost:8080",
    CREDENTIALS: 'include',
    WITH_CREDENTIALS: true,
  }).default;
  await client.logout()
}

export async function testAPIKey(): Promise<void> {
  const apiKey = UIManager.getEnteredAPIKey()
  if (!apiKey) {
    alert('no API key given')
    return
  }
  const client = new TestCredsClient({
    TOKEN: apiKey,
    CREDENTIALS: 'omit',
    BASE: "http://localhost:8080",
  }).default;
  const resp = await client.checkCredentials();
  UIManager.showTestAPIKey(JSON.stringify(resp))
}

export async function testAuthCookie(): Promise<void> {
  const client = new TestCredsClient({
    CREDENTIALS: 'include',
    WITH_CREDENTIALS: true,
    BASE: "http://localhost:8080",
  }).default;
  const resp = await client.checkCredentials();
  UIManager.showTestAuthCookie(JSON.stringify(resp))
}
