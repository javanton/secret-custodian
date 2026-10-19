const test = require("node:test");
const assert = require("node:assert/strict");
const { install } = require("./fakedom.js");

const { store } = install();
const app = require("../../../../web/app.js");

const HOSTILE = "<img src=x onerror=alert(1)>";

test("parseFragment extracts only a well-formed #t= token", () => {
  assert.equal(app.parseFragment("#t=abcdef0123456789"), "abcdef0123456789");
  assert.equal(app.parseFragment(""), null);
  assert.equal(app.parseFragment("#x=1"), null);
  assert.equal(app.parseFragment("#t="), null);
  assert.equal(app.parseFragment("#t=<script>"), null);
});

test("el() never interprets HTML and refuses style attributes", () => {
  const n = app.el("p", { class: "x", title: HOSTILE }, HOSTILE, null, [HOSTILE]);
  assert.equal(n.children.length, 2);
  assert.ok(n.children.every((c) => c.constructor.name === "Text"));
  assert.equal(n.textContent, HOSTILE + HOSTILE);
  assert.equal(n.getAttribute("title"), HOSTILE);
  assert.throws(() => app.el("p", { style: "color:red" }));
});

test("table cells holding hostile strings stay text", () => {
  const t = app.table(["Name"], [[HOSTILE], [app.el("b", {}, HOSTILE)]]);
  assert.equal(t.find("img").length, 0);
  assert.equal(t.find("td")[0].textContent, HOSTILE);
  assert.equal(t.find("b")[0].textContent, HOSTILE);
});

test("parseTtl converts units and rejects bad input", () => {
  assert.equal(app.parseTtl(""), null);
  assert.equal(app.parseTtl("30m"), 1800);
  assert.equal(app.parseTtl("12h"), 43200);
  assert.equal(app.parseTtl("7d"), 604800);
  assert.equal(app.parseTtl("90s"), 90);
  assert.throws(() => app.parseTtl("5"));
  assert.throws(() => app.parseTtl("0h"));
  assert.throws(() => app.parseTtl("abc"));
  assert.throws(() => app.parseTtl("3651d"));
  assert.equal(app.parseTtl("3650d"), 315360000);
});

test("proxyEnv percent-encodes credentials", () => {
  const env = app.proxyEnv("my box:1/@'", "a.b-c_d");
  assert.match(env, /^HTTPS_PROXY=http:\/\/my%20box%3A1%2F%40%27:a\.b-c_d@127\.0\.0\.1:8080$/m);
  assert.match(env, /^HTTP_PROXY=/m);
  assert.match(env, /^NO_PROXY=/m);
});

test("tokenStatus", () => {
  const now = 1000;
  assert.equal(app.tokenStatus({ revoked_at: 5, expires_at: null }, now), "revoked");
  assert.equal(app.tokenStatus({ revoked_at: null, expires_at: 999 }, now), "expired");
  assert.equal(app.tokenStatus({ revoked_at: null, expires_at: 2000 }, now), "active");
  assert.equal(app.tokenStatus({ revoked_at: null, expires_at: null }, now), "active");
});

test("api sends the bearer session without credentials and handles 401", async () => {
  store.set("sg_session", "sess123");
  let seen;
  global.fetch = async (url, opts) => {
    seen = { url, opts };
    return { ok: false, status: 401, text: async () => JSON.stringify({ error: "login required" }) };
  };
  let expired = 0;
  app.setOnExpired(() => expired++);
  await assert.rejects(app.api("GET", "/secrets"), (e) => e.unauthorized === true);
  assert.equal(seen.url, "/api/secrets");
  assert.equal(seen.opts.credentials, "omit");
  assert.equal(seen.opts.headers.Authorization, "Bearer sess123");
  assert.equal(store.has("sg_session"), false, "session cleared on 401");
  assert.equal(expired, 1);
});

test("api surfaces the server error message verbatim", async () => {
  store.set("sg_session", "s");
  global.fetch = async () => ({ ok: false, status: 400, text: async () => JSON.stringify({ error: HOSTILE }) });
  await assert.rejects(app.api("POST", "/roles", { a: 1 }), (e) => e.message === HOSTILE && !e.unauthorized);
  global.fetch = async () => {
    throw new TypeError("failed to fetch");
  };
  await assert.rejects(app.api("GET", "/ca"), /network error/);
});

test("api sends JSON content type on writes", async () => {
  store.set("sg_session", "s");
  let opts;
  global.fetch = async (_u, o) => {
    opts = o;
    return { ok: true, status: 204, text: async () => "" };
  };
  assert.equal(await app.api("DELETE", "/secrets/x"), null);
  assert.equal(opts.headers["Content-Type"], "application/json");
});

test("renderChrome puts one real button per section in the nav bar", () => {
  app.renderChrome();
  const tabs = document.getElementById("tabs");
  const labels = tabs.find("button").map((b) => b.textContent);
  assert.deepEqual(labels, ["Secrets", "Roles & rules", "Tokens", "CA", "Audit"]);
  assert.equal(tabs.find("button")[0].getAttribute("aria-current"), "page");
});
