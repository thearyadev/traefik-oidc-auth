import { test, expect, Page, Response } from "@playwright/test";
import * as dockerCompose from "docker-compose";
import crypto from "crypto";
import { execFileSync } from "child_process";
import { configureTraefik } from "../../utils";

type BrowserCookie = Awaited<ReturnType<ReturnType<Page["context"]>["cookies"]>>[number];

test.use({
  ignoreHTTPSErrors: true
});

test.setTimeout(120000);

const cwd = __dirname;
const pocketIdUrl = "http://localhost:1411";
const appUrl = "http://localhost:9180";
const staticApiKey = "pocket-id-e2e-static-api-key";
const middlewareSecret = "PocketIdE2eMiddlewareSecret12345";
const clientId = "traefik-pocket-id-e2e";

let clientSecret = "";
let userId = "";

test.beforeAll("Starting Pocket ID e2e stack", async () => {
  test.setTimeout(300000);

  execFileSync("docker", ["compose", "down", "--volumes", "--remove-orphans"], { cwd, stdio: "inherit" });

  await configureTraefik(defaultTraefikConfig("temporary-secret"));

  await dockerCompose.upAll({
    cwd,
    log: true
  });

  await waitForPocketId();
  ({ userId, clientSecret } = await seedPocketId());
  await configureTraefik(defaultTraefikConfig(clientSecret));
});

test.afterEach("Container logs on test failure", async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await dockerCompose.logs("traefik", { cwd }));
    console.log(`${testInfo.title} failed, here are Pocket ID logs:`);
    console.log(await dockerCompose.logs("pocket-id", { cwd }));
  }
});

test.afterAll("Stopping Pocket ID e2e stack", async () => {
  await dockerCompose.downAll({
    cwd,
    log: true,
    commandOptions: ["--volumes", "--remove-orphans"]
  });
});

test("login through Pocket ID one-time code", async ({ page }) => {
  const response = await loginThroughPocketId(page, appUrl);

  expect(response.status()).toBe(200);
  await expect(page.locator("body")).toContainText(/Hostname:/);
});

test("attaches claims and tokens to upstream headers", async ({ page }) => {
  await configureTraefik(defaultTraefikConfig(clientSecret, {
    headers: true,
    useClaimsFromUserInfo: true
  }));

  const response = await loginThroughPocketId(page, appUrl);

  expect(response.status()).toBe(200);
  await expect(page.locator("body")).toContainText("X-Static-Header: pocket-id");
  await expect(page.locator("body")).toContainText("X-Oidc-Username: e2e-user");
  await expect(page.locator("body")).toContainText(/Authorization: Bearer ey/);
});

test("non-html request is rejected without starting browser auth", async () => {
  const response = await fetch(appUrl, {
    headers: {
      Accept: "application/json"
    },
    redirect: "manual"
  });

  expect(response.status).toBe(401);
});

test("tampered session cookie is rejected and cleared", async ({ page }) => {
  await loginThroughPocketId(page, appUrl);

  const cookieHeader = await sessionCookieHeader(page);
  const tamperedCookieHeader = `${cookieHeader.slice(0, -1)}${cookieHeader.endsWith("A") ? "B" : "A"}`;

  const response = await fetch(appUrl, {
    headers: {
      Cookie: tamperedCookieHeader,
      Accept: "application/json"
    },
    redirect: "manual"
  });

  expect(response.status).toBe(401);
  expect(response.headers.get("set-cookie")).toContain("TraefikOidcAuth.Session=");
});

test("logout clears the middleware session and returns to Pocket ID", async ({ page }) => {
  await loginThroughPocketId(page, appUrl);

  const logoutResponse = await page.goto(`${appUrl}/logout`);

  expect(logoutResponse?.status()).toBeLessThan(400);
  expect(page.url()).toMatch(/^http:\/\/localhost:1411\//);
});

test("parallel stale-session requests share one Pocket ID refresh", async ({ page }) => {
  test.setTimeout(120000);

  await configureTraefik(defaultTraefikConfig(clientSecret, {
    tokenValidation: "Introspection"
  }));

  await loginThroughPocketId(page, appUrl);

  const staleCookieHeader = await staleSessionCookieHeader(page);
  const responses = await Promise.all(
    Array.from({ length: 30 }, (_, index) =>
      fetch(`${appUrl}/refresh-race-${index}`, {
        headers: {
          Cookie: staleCookieHeader,
          Accept: "text/html"
        },
        redirect: "manual"
      })
    )
  );

  const statuses = responses.map((response) => response.status);
  expect(statuses.every((status) => status === 200)).toBeTruthy();

  const bodies = await Promise.all(responses.slice(0, 3).map((response) => response.text()));
  for (const body of bodies) {
    expect(body).toContain("Hostname:");
  }
});

test("parallel video-like requests survive a stale-session refresh race", async ({ page }) => {
  test.setTimeout(120000);

  await configureTraefik(defaultTraefikConfig(clientSecret, {
    tokenValidation: "Introspection"
  }));

  await loginThroughPocketId(page, appUrl);

  const staleCookieHeader = await staleSessionCookieHeader(page);
  const responses = await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      fetch(`${appUrl}/video-segment-${index}.m4s`, {
        headers: {
          Cookie: staleCookieHeader,
          Accept: "video/mp4,*/*;q=0.8",
          Range: "bytes=0-1023"
        },
        redirect: "manual"
      })
    )
  );

  expect(responses.every((response) => response.status === 200)).toBeTruthy();
  expect(responses.every((response) => response.headers.get("location") === null)).toBeTruthy();
  expect(responses.every((response) => !clearsSessionCookie(response))).toBeTruthy();

  const bodies = await Promise.all(responses.slice(0, 3).map((response) => response.text()));
  for (const body of bodies) {
    expect(body).toContain("Hostname:");
  }
});

test("invalid rotated refresh token does not clear a still-active media session", async ({ page }) => {
  await configureTraefik(defaultTraefikConfig(clientSecret, {
    tokenValidation: "Introspection"
  }));

  await loginThroughPocketId(page, appUrl);

  const poisonedCookieHeader = await staleSessionCookieHeader(page, (session) => {
    session.refresh_token = "invalid-refresh-token-from-another-replica";
  });

  const response = await fetch(`${appUrl}/video-segment-after-rotation.m4s`, {
    headers: {
      Cookie: poisonedCookieHeader,
      Accept: "video/mp4,*/*;q=0.8",
      Range: "bytes=0-1023"
    },
    redirect: "manual"
  });

  expect(response.status).toBe(200);
  expect(response.headers.get("location")).toBeNull();
  expect(clearsSessionCookie(response)).toBeFalsy();
  expect(await response.text()).toContain("Hostname:");
});

test("expired media session with invalid refresh token is rejected without clearing the cookie", async ({ page }) => {
  await configureTraefik(defaultTraefikConfig(clientSecret, {
    tokenValidation: "Introspection"
  }));

  await loginThroughPocketId(page, appUrl);

  const expiredCookieHeader = await staleSessionCookieHeader(page, (session) => {
    session.access_token = "expired-access-token-from-another-replica";
    session.refresh_token = "invalid-refresh-token-from-another-replica";
  });

  const response = await fetch(`${appUrl}/video-segment-after-expiry.m4s`, {
    headers: {
      Cookie: expiredCookieHeader,
      Accept: "video/mp4,*/*;q=0.8",
      Range: "bytes=0-1023"
    },
    redirect: "manual"
  });

  expect(response.status).toBe(401);
  expect(response.headers.get("location")).toBeNull();
  expect(clearsSessionCookie(response)).toBeFalsy();
});

function defaultTraefikConfig(secret: string, options?: {
  headers?: boolean;
  tokenValidation?: "IdToken" | "AccessToken" | "Introspection";
  useClaimsFromUserInfo?: boolean;
}) {
  const tokenValidation = options?.tokenValidation ?? "IdToken";
  const headers = options?.headers ? `
          Headers:
            - Name: "Authorization"
              Value: "{{\`Bearer {{ .accessToken }}\`}}"
            - Name: "X-Static-Header"
              Value: "pocket-id"
            - Name: "X-Oidc-Username"
              Value: "{{\`{{ .claims.preferred_username }}\`}}"
` : "";

  return `
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Secret: "${middlewareSecret}"
          Provider:
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "${clientId}"
            ClientSecret: "${secret}"
            UsePkce: false
            TokenValidation: "${tokenValidation}"
            UseClaimsFromUserInfo: "${options?.useClaimsFromUserInfo ? "true" : "false"}"
          Scopes: ["openid", "profile", "email", "offline_access"]
${headers}

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`;
}

async function waitForPocketId() {
  for (let i = 0; i < 120; i++) {
    try {
      const response = await fetch(`${pocketIdUrl}/healthz`);
      if (response.ok) return;
    } catch {}

    await new Promise(r => setTimeout(r, 1000));
  }

  throw new Error("Timeout occurred while waiting for Pocket ID to start.");
}

async function seedPocketId() {
  const user = await apiFetch("/api/users", {
    method: "POST",
    body: {
      username: "e2e-user",
      email: "e2e-user@example.com",
      emailVerified: true,
      firstName: "E2E",
      lastName: "User",
      displayName: "E2E User",
      isAdmin: false,
      disabled: false,
      userGroupIds: []
    },
    allowedStatuses: [201, 409]
  });

  let seededUserId = user?.id as string | undefined;
  if (!seededUserId) {
    const users = await apiFetch("/api/users?search=e2e-user");
    seededUserId = users.data.find((u: any) => u.username === "e2e-user")?.id;
  }
  if (!seededUserId) throw new Error("Failed to seed Pocket ID test user.");

  await apiFetch("/api/oidc/clients", {
    method: "POST",
    body: {
      id: clientId,
      name: "Traefik OIDC Auth E2E",
      description: "Created by traefik-oidc-auth e2e tests",
      callbackURLs: [`${appUrl}/oidc/callback`],
      logoutCallbackURLs: [`${appUrl}/oidc/callback`],
      isPublic: false,
      pkceEnabled: false,
      requiresReauthentication: false,
      requiresPushedAuthorizationRequests: false,
      skipConsent: true,
      credentials: {},
      isGroupRestricted: false
    },
    allowedStatuses: [201, 409]
  });

  const secretResponse = await apiFetch(`/api/oidc/clients/${clientId}/secret`, {
    method: "POST"
  });

  return {
    userId: seededUserId,
    clientSecret: secretResponse.secret as string
  };
}

async function apiFetch(path: string, options?: {
  method?: string;
  body?: unknown;
  allowedStatuses?: number[];
}) {
  const response = await fetch(`${pocketIdUrl}${path}`, {
    method: options?.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": staticApiKey
    },
    body: options?.body ? JSON.stringify(options.body) : undefined
  });

  const allowedStatuses = options?.allowedStatuses ?? [200, 201, 204];
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : undefined;

  if (!allowedStatuses.includes(response.status)) {
    throw new Error(`Pocket ID API ${path} failed with ${response.status}: ${text}`);
  }

  return parsed;
}

async function createOneTimeCode() {
  const response = await apiFetch(`/api/users/${userId}/one-time-access-token`, {
    method: "POST",
    body: {
      ttl: "5m"
    }
  });

  return response.token as string;
}

async function loginThroughPocketId(page: Page, targetUrl: string): Promise<Response> {
  await page.context().clearCookies();

  await page.goto(targetUrl);

  const currentUrl = new URL(page.url());
  expect(currentUrl.origin).toBe(pocketIdUrl);

  const code = await createOneTimeCode();
  const redirectPath = currentUrl.pathname + currentUrl.search;
  await page.goto(`${pocketIdUrl}/lc/${code}?redirect=${encodeURIComponent(redirectPath)}`);
  await page.waitForLoadState("domcontentloaded");

  if (page.url().startsWith(`${pocketIdUrl}/login/alternative/code`)) {
    await page.getByRole("button", { name: /submit/i }).click();
  }

  await page.waitForURL(
    (url) => url.toString().startsWith(`${pocketIdUrl}/interaction`) || url.toString().startsWith(targetUrl),
    { timeout: 30000 }
  );

  for (let i = 0; i < 4 && page.url().startsWith(`${pocketIdUrl}/interaction`); i++) {
    const navigation = page.waitForURL(
      (url) => url.toString().startsWith(`${pocketIdUrl}/interaction`) || url.toString().startsWith(targetUrl),
      { timeout: 30000 }
    );
    const click = page.getByRole("button", { name: /sign in/i }).click({ timeout: 10000 });

    const [clickResult, navigationResult] = await Promise.allSettled([click, navigation]);
    if (clickResult.status === "rejected" && !page.url().startsWith(targetUrl)) {
      throw clickResult.reason;
    }
    if (navigationResult.status === "rejected" && !page.url().startsWith(targetUrl)) {
      throw navigationResult.reason;
    }
  }

  await page.waitForURL((url) => url.toString().startsWith(targetUrl), { timeout: 30000 });
  const response = await page.goto(targetUrl);
  if (!response) throw new Error(`Expected app response after Pocket ID login. Current URL: ${page.url()}`);
  return response;
}

async function sessionCookieHeader(page: Page) {
  const cookies = await page.context().cookies(appUrl);
  const relevantCookies = cookies
    .filter((cookie) => cookie.name === "TraefikOidcAuth.Session" || cookie.name.startsWith("TraefikOidcAuth.Session."))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (relevantCookies.length === 0) {
    throw new Error("No Traefik OIDC session cookies found.");
  }

  return relevantCookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

async function staleSessionCookieHeader(page: Page, mutate?: (session: any) => void) {
  const cookies = await page.context().cookies(appUrl);
  const encryptedSession = readSessionCookieValue(cookies);
  const session = JSON.parse(decryptSession(encryptedSession));

  session.created_at = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  session.token_expires_in = 2;
  mutate?.(session);

  const staleEncryptedSession = encryptSession(JSON.stringify(session));
  return chunkCookieHeader("TraefikOidcAuth.Session", staleEncryptedSession);
}

function clearsSessionCookie(response: globalThis.Response) {
  return response.headers.get("set-cookie")?.includes("TraefikOidcAuth.Session=;") ?? false;
}

function readSessionCookieValue(cookies: BrowserCookie[]) {
  const sessionCookie = cookies.find((cookie) => cookie.name === "TraefikOidcAuth.Session");
  if (sessionCookie) return sessionCookie.value;

  const chunksCookie = cookies.find((cookie) => cookie.name === "TraefikOidcAuth.Session.Chunks");
  if (!chunksCookie) throw new Error("No Traefik OIDC session cookie found.");

  const chunkCount = Number(chunksCookie.value);
  let value = "";
  for (let i = 1; i <= chunkCount; i++) {
    const chunk = cookies.find((cookie) => cookie.name === `TraefikOidcAuth.Session.${i}`);
    if (!chunk) throw new Error(`Missing Traefik OIDC session cookie chunk ${i}.`);
    value += chunk.value;
  }

  return value;
}

function chunkCookieHeader(name: string, value: string) {
  const chunkSize = 3072;
  if (value.length <= chunkSize) return `${name}=${value}`;

  const chunks: string[] = [`${name}.Chunks=${Math.ceil(value.length / chunkSize)}`];
  for (let index = 0; index < value.length; index += chunkSize) {
    const chunkNumber = Math.floor(index / chunkSize) + 1;
    chunks.push(`${name}.${chunkNumber}=${value.slice(index, index + chunkSize)}`);
  }
  return chunks.join("; ");
}

function decryptSession(value: string) {
  const payload = Buffer.from(value, "base64");
  const nonce = payload.subarray(0, 12);
  const ciphertext = payload.subarray(12, payload.length - 16);
  const authTag = payload.subarray(payload.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(middlewareSecret), nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function encryptSession(value: string) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(middlewareSecret), nonce);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString("base64");
}
