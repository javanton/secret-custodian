"use strict";
// Secret Guardian admin UI. No framework, no build step.
// Every piece of DOM is built with createElement/textContent (see el()); no markup is ever
// parsed from a string, so server-supplied values cannot become HTML or script.
// Authentication: the login token arrives in the URL fragment, is traded once for a session id
// kept in sessionStorage, and is sent as `Authorization: Bearer`. There are no cookies.

// ---- helpers --------------------------------------------------------------------------------

const SESSION_KEY = "sg_session";
const PROXY_ADDR = "127.0.0.1:8080";
const MAX_TTL_SECS = 315360000; // 10 years, same cap as the server

/** Build an element. Children are text unless they are Nodes; attributes never take markup. */
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "style") throw new Error("inline styles are blocked by the CSP: use a class");
    if (v === false || v === null || v === undefined) continue;
    if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** A table whose cells are strings (rendered as text) or ready-made Nodes. */
function table(headers, rows, caption) {
  return el(
    "div",
    { class: "tablewrap" },
    el(
      "table",
      {},
      caption ? el("caption", {}, caption) : null,
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c))))),
    ),
  );
}

function fmtTime(secs) {
  if (secs === null || secs === undefined) return "-";
  return new Date(secs * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z";
}

/** The login token from `#t=<token>`, or null when absent or malformed. */
function parseFragment(hash) {
  const t = new URLSearchParams(String(hash || "").replace(/^#/, "")).get("t");
  return t && /^[A-Za-z0-9_-]{8,256}$/.test(t) ? t : null;
}

/** "30m", "12h", "7d" -> seconds. Empty -> null (no expiry). Throws a readable Error. */
function parseTtl(text) {
  const s = String(text || "").trim();
  if (s === "") return null;
  const m = /^(\d+)\s*([smhdw])$/i.exec(s);
  if (!m) throw new Error("TTL must look like 30m, 12h or 7d (units: s, m, h, d, w)");
  const unit = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[m[2].toLowerCase()];
  const secs = Number(m[1]) * unit;
  if (!(secs > 0)) throw new Error("TTL must be greater than zero");
  if (secs > MAX_TTL_SECS) throw new Error("TTL must be at most 10 years (3650d)");
  return secs;
}

/** Percent-encode for a URL userinfo part; also the sub-delims shells and URLs care about. */
function encodeUserinfo(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function proxyEnv(machine, token) {
  const url = `http://${encodeUserinfo(machine)}:${encodeUserinfo(token)}@${PROXY_ADDR}`;
  return [`HTTPS_PROXY=${url}`, `HTTP_PROXY=${url}`, "NO_PROXY=localhost,127.0.0.1"].join("\n");
}

function tokenStatus(t, now) {
  if (t.revoked_at !== null && t.revoked_at !== undefined) return "revoked";
  if (t.expires_at !== null && t.expires_at !== undefined && t.expires_at <= now) return "expired";
  return "active";
}

/** The wire form of one rule from raw form values (see `ruleFields`). */
function buildRule(v) {
  return {
    role: v.role,
    host_pattern: v.host.trim(),
    path_pattern: v.path.trim() || "*",
    methods: v.methods,
    kind: v.kind,
    target_name: v.target.trim(),
    template: v.template,
  };
}

/** Upper-cases the first letter of an API notice so it reads as a sentence after "added.". */
function capitalise(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
}

/** Confirmation label for deleting a secret: its rules go with it. */
function deleteSecretLabel(rules) {
  const n = Number(rules);
  if (!Number.isFinite(n) || n <= 0) return "Yes, delete";
  return `Yes, delete (and its ${n} ${n === 1 ? "rule" : "rules"})`;
}

/** Body for `POST /secrets`: a secret is only useful with at least one rule. */
function secretBody(name, value, rules) {
  if (!rules.length) throw new Error("a secret needs at least one rule");
  return { name, value, rules };
}

// ---- session and API ------------------------------------------------------------------------

let onExpired = () => {};
function setOnExpired(fn) {
  onExpired = fn;
}

function getSession() {
  try {
    return sessionStorage.getItem(SESSION_KEY);
  } catch (_) {
    return null;
  }
}
function setSession(id) {
  try {
    sessionStorage.setItem(SESSION_KEY, id);
  } catch (_) {
    /* storage blocked: the session just will not survive a reload */
  }
}
function clearSession() {
  try {
    sessionStorage.removeItem(SESSION_KEY);
  } catch (_) {
    /* nothing stored */
  }
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
    this.unauthorized = status === 401;
  }
}

async function errorMessage(resp) {
  const text = await resp.text().catch(() => "");
  try {
    const j = JSON.parse(text);
    if (j && typeof j.error === "string") return j.error;
  } catch (_) {
    /* not JSON */
  }
  return text.trim() || `request failed (HTTP ${resp.status})`;
}

/** Call `/api<path>` with the Bearer session. Resolves to parsed JSON (null if empty). */
async function api(method, path, body, opts) {
  const headers = { Authorization: "Bearer " + (getSession() || "") };
  if (method !== "GET") headers["Content-Type"] = "application/json";
  let resp;
  try {
    resp = await fetch("/api" + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
    });
  } catch (e) {
    throw new ApiError("network error: " + (e && e.message ? e.message : e), 0);
  }
  if (resp.status === 401) {
    clearSession();
    onExpired();
    throw new ApiError(await errorMessage(resp), 401);
  }
  if (!resp.ok) throw new ApiError(await errorMessage(resp), resp.status);
  if (opts && opts.blob) return resp.blob();
  const text = await resp.text();
  return text ? JSON.parse(text) : null;
}

/** Trade the one-time fragment token for a session id. */
async function login(token) {
  let resp;
  try {
    resp = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      credentials: "omit",
    });
  } catch (e) {
    throw new Error("could not reach the server: " + (e && e.message ? e.message : e));
  }
  if (!resp.ok) throw new Error(await errorMessage(resp));
  const data = await resp.json();
  if (!data || typeof data.session !== "string") throw new Error("unexpected login response");
  setSession(data.session);
}

// ---- notices, focus and event plumbing ------------------------------------------------------

const $ = (id) => document.getElementById(id);

function notify(message, kind) {
  $("notices").replaceChildren(el("p", { class: kind || "success" }, message));
}
function clearNotices() {
  $("notices").replaceChildren();
}

/** Wrap an async handler: errors become a visible message, never an unhandled rejection. */
function safe(fn) {
  return async (ev) => {
    if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
    try {
      await fn(ev);
    } catch (e) {
      if (!(e && e.unauthorized)) notify(e && e.message ? e.message : String(e), "error");
    }
  };
}

function focusHeading() {
  const view = $("view");
  const h = view.querySelector ? view.querySelector("h2") : null;
  const target = h || view;
  if (target && target.focus) {
    if (h) h.setAttribute("tabindex", "-1");
    target.focus();
  }
}

function field(label, input, hint) {
  const id = input.getAttribute("id");
  return el("div", { class: "field" }, el("label", { for: id }, label), input, hint ? el("span", { class: "help" }, hint) : null);
}

let idSeq = 0;
function input(type, attrs) {
  return el("input", { type, id: "f" + ++idSeq, ...attrs });
}
function select(options, attrs) {
  return el(
    "select",
    { id: "f" + ++idSeq, ...attrs },
    options.map(([value, text]) => el("option", { value }, text ?? value)),
  );
}

/** A button that asks "Sure?" before running `onConfirm`. */
function confirmButton(label, confirmLabel, onConfirm) {
  const box = el("span", { class: "row-actions" });
  const show = (focus) => {
    const b = el("button", { type: "button", class: "danger", onclick: ask }, label);
    box.replaceChildren(b);
    if (focus) b.focus();
  };
  function ask() {
    const yes = el("button", { type: "button", class: "danger", onclick: safe(onConfirm) }, confirmLabel);
    const no = el("button", { type: "button", onclick: () => show(true) }, "Cancel");
    box.replaceChildren(el("span", {}, "Sure? "), yes, no);
    no.focus();
  }
  show(false);
  return box;
}

// ---- views: secrets -------------------------------------------------------------------------

async function viewSecrets(root) {
  const [secrets, roles] = await Promise.all([api("GET", "/secrets"), api("GET", "/roles")]);
  root.append(
    el("h2", {}, "Secrets"),
    el("p", { class: "help" }, "Secret values are write-only: you can add or rotate them, but they are never shown again, not even here."),
  );
  const rows = secrets.map((s) => [
    s.name,
    s.rules ? String(s.rules) : el("span", { class: "bad" }, "none: never injected"),
    fmtTime(s.created_at),
    fmtTime(s.rotated_at),
    secretActions(s),
  ]);
  root.append(
    rows.length ? table(["Name", "Rules", "Created", "Rotated", "Actions"], rows, "Stored secrets (metadata only)") : el("p", { class: "muted" }, "No secrets yet."),
  );

  const name = input("text", { required: true, autocomplete: "off", maxlength: "64", pattern: "[a-z0-9._\\-]+", spellcheck: "false" });
  const value = input("password", { required: true, autocomplete: "off" });
  const blocks = [];
  const list = el("div", { class: "rule-list" });
  const addBlock = (removable) => {
    const b = ruleFields(roles, removable ? { onRemove: () => remove(b) } : undefined);
    blocks.push(b);
    list.append(b.node);
    return b;
  };
  const remove = (b) => {
    blocks.splice(blocks.indexOf(b), 1);
    b.node.remove();
  };
  addBlock(false);
  root.append(
    el("h3", {}, "Add a secret"),
    el(
      "form",
      {
        onsubmit: safe(async () => {
          const rules = blocks.map((b) => b.read());
          const body = secretBody(name.value, value.value, rules);
          value.value = ""; // clear immediately: the value must not linger in the page
          if (!roles.length) {
            try {
              await api("POST", "/roles", { name: "default", unmatched: "passthrough" });
            } catch (e) {
              if (!/already exists/.test(e.message)) throw e;
            }
          }
          const res = await api("POST", "/secrets", body);
          await refresh();
          if (res && res.notice) notify(`Secret "${body.name}" added. ${capitalise(res.notice)}`, "notice");
          else notify(`Secret "${body.name}" added.`);
        }),
      },
      field("Name", name, "lowercase letters, digits, . _ -"),
      field("Value (write-only)", value),
      el("p", { class: "help rule-intro" }, "A secret is injected only where a rule says so. Add at least one rule."),
      list,
      el("div", { class: "row-actions rule-actions" },
        el("button", { type: "button", onclick: () => addBlock(true) }, "Add another rule"),
        el("button", { type: "submit", class: "primary" }, "Add secret"),
      ),
    ),
  );
}

function secretActions(s) {
  const box = el("div", { class: "row-actions" });
  const rotateBtn = el("button", { type: "button", onclick: openRotate }, "Rotate");
  const del = confirmButton("Delete", deleteSecretLabel(s.rules), async () => {
    await api("DELETE", "/secrets/" + encodeURIComponent(s.name));
    notify(`Secret "${s.name}" deleted.`);
    await refresh();
  });
  function openRotate() {
    const v = input("password", { required: true, autocomplete: "off", "aria-label": `New value for ${s.name}` });
    const form = el(
      "form",
      {
        onsubmit: safe(async () => {
          const body = { value: v.value };
          v.value = "";
          await api("PUT", "/secrets/" + encodeURIComponent(s.name), body);
          notify(`Secret "${s.name}" rotated.`);
          await refresh();
        }),
      },
      v,
      el("button", { type: "submit", class: "primary" }, "Save"),
      el("button", { type: "button", onclick: () => { v.value = ""; box.replaceChildren(rotateBtn, del); rotateBtn.focus(); } }, "Cancel"),
    );
    box.replaceChildren(form);
    v.focus();
  }
  box.append(rotateBtn, del);
  return box;
}

// ---- views: roles and rules -----------------------------------------------------------------

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

async function viewRoles(root) {
  const [roles, rules, secrets] = await Promise.all([api("GET", "/roles"), api("GET", "/rules"), api("GET", "/secrets")]);
  const secretName = new Map(secrets.map((s) => [s.id, s.name]));
  root.append(el("h2", {}, "Roles & rules"));

  // roles
  root.append(
    el("h3", {}, "Roles"),
    el(
      "p",
      { class: "help" },
      "Unmatched policy: what happens to a request from this role when no rule matches. passthrough forwards it unchanged, without any credential. deny blocks it.",
    ),
    roles.length
      ? table(
          ["Role", "Unmatched policy", "Actions"],
          roles.map((r) => [
            r.name,
            r.unmatched,
            confirmButton("Delete", "Yes, delete", async () => {
              await api("DELETE", "/roles/" + encodeURIComponent(r.name));
              notify(`Role "${r.name}" deleted.`);
              await refresh();
            }),
          ]),
          "Roles",
        )
      : el("p", { class: "muted" }, "No roles yet."),
  );
  const rname = input("text", { required: true, autocomplete: "off", maxlength: "64", pattern: "[a-z0-9._\\-]+" });
  const unmatched = select([["deny", "deny"], ["passthrough", "passthrough"]]);
  root.append(
    el(
      "form",
      {
        onsubmit: safe(async () => {
          await api("POST", "/roles", { name: rname.value, unmatched: unmatched.value });
          notify(`Role "${rname.value}" added.`);
          await refresh();
        }),
      },
      field("New role name", rname),
      field("Unmatched policy", unmatched),
      el("button", { type: "submit", class: "primary" }, "Add role"),
    ),
  );

  // rules
  root.append(
    el("h3", {}, "Rules"),
    rules.length
      ? table(
          ["ID", "Role", "Host", "Path", "Methods", "Injection", "Secret", "Actions"],
          rules.map((r) => [
            String(r.id),
            r.role,
            r.host_pattern,
            r.path_pattern,
            r.methods.length ? r.methods.join(", ") : "any",
            `${r.kind}:${r.target_name} = ${r.template}`,
            secretName.get(r.secret_id) ?? `(deleted secret #${r.secret_id})`,
            confirmButton("Delete", "Yes, delete", async () => {
              await api("DELETE", "/rules/" + r.id);
              notify(`Rule ${r.id} deleted.`);
              await refresh();
            }),
          ]),
          "Injection rules",
        )
      : el("p", { class: "muted" }, "No rules yet."),
  );
  root.append(ruleForm(roles, secrets));
}

/** The fields of one rule. `read()` returns the wire form; `onRemove` adds a remove button. */
function ruleFields(roles, opts) {
  const role = select(roles.length ? roles.map((r) => [r.name]) : [["default", "default (created automatically)"]]);
  const host = input("text", { required: true, autocomplete: "off", placeholder: "api.example.com or *.example.com" });
  const path = input("text", { required: true, autocomplete: "off", value: "*" });
  const kind = select([["header"], ["query"]]);
  const target = input("text", { required: true, autocomplete: "off", placeholder: "Authorization or api_key" });
  const template = input("text", { required: true, autocomplete: "off", value: "Bearer {secret}" });
  const checks = METHODS.map((m) => ({ m, box: el("input", { type: "checkbox", id: "f" + ++idSeq, value: m }) }));
  const syncKind = () => {
    if (kind.value === "query") {
      template.value = "{secret}";
      template.setAttribute("readonly", "");
    } else {
      template.removeAttribute("readonly");
      if (template.value === "{secret}") template.value = "Bearer {secret}";
    }
  };
  kind.addEventListener("change", syncKind);
  const node = el(
    "fieldset",
    { class: "rule-block" },
    el("legend", {}, "Rule"),
    field("Role", role),
    field("Host pattern", host),
    field("Path pattern", path),
    el(
      "fieldset",
      {},
      el("legend", {}, "Methods (none checked = any method)"),
      checks.map((c) => el("label", { for: c.box.getAttribute("id") }, c.box, " " + c.m)),
    ),
    field("Inject into", kind),
    field("Header or parameter name", target),
    field("Template", template, "{secret} is replaced by the secret value; it is read-only for query parameters."),
    opts && opts.onRemove ? el("button", { type: "button", class: "danger", onclick: opts.onRemove }, "Remove this rule") : null,
  );
  const read = () =>
    buildRule({
      role: role.value,
      host: host.value,
      path: path.value,
      methods: checks.filter((c) => c.box.checked).map((c) => c.m),
      kind: kind.value,
      target: target.value,
      template: template.value,
    });
  return { node, read };
}

function ruleForm(roles, secrets) {
  if (!roles.length || !secrets.length) {
    return el("p", { class: "notice" }, "Add at least one role and one secret before creating a rule.");
  }
  const secret = select(secrets.map((s) => [String(s.id), s.name]));
  const fields = ruleFields(roles);
  return el(
    "form",
    {
      onsubmit: safe(async () => {
        const res = await api("POST", "/rules", { ...fields.read(), secret_id: Number(secret.value) });
        await refresh();
        if (res && res.notice) notify(res.notice, "notice");
        else notify("Rule added.");
      }),
    },
    el("h3", {}, "Add a rule"),
    fields.node,
    field("Secret", secret),
    el("button", { type: "submit", class: "primary" }, "Add rule"),
  );
}

// ---- views: tokens --------------------------------------------------------------------------

let freshToken = null; // shown exactly once, never re-fetchable

async function viewTokens(root) {
  const [tokens, roles] = await Promise.all([api("GET", "/tokens"), api("GET", "/roles")]);
  const now = Math.floor(Date.now() / 1000);
  root.append(el("h2", {}, "Tokens"));
  if (freshToken) root.append(freshTokenPanel(freshToken));

  const rows = tokens.map((t) => {
    const status = tokenStatus(t, now);
    return [
      t.machine,
      t.role,
      fmtTime(t.created_at),
      t.expires_at === null ? "never" : fmtTime(t.expires_at),
      el("span", { class: "status-" + status }, status),
      status === "active"
        ? confirmButton("Revoke", "Yes, revoke", async () => {
            await api("DELETE", "/tokens/" + encodeURIComponent(t.jti));
            notify("Token revoked.");
            await refresh();
          })
        : "",
    ];
  });
  root.append(rows.length ? table(["Machine", "Role", "Created", "Expires", "Status", "Actions"], rows, "Proxy tokens") : el("p", { class: "muted" }, "No tokens yet."));

  const machines = [...new Set(tokens.map((t) => t.machine))];
  if (machines.length) {
    const m = select(machines.map((x) => [x]));
    const box = el("div", { class: "row-actions" });
    box.append(
      el("label", { for: m.getAttribute("id") }, "Revoke all tokens of machine"),
      m,
      confirmButton("Revoke all", "Yes, revoke all", async () => {
        const res = await api("POST", "/machines/" + encodeURIComponent(m.value) + "/revoke");
        notify(`Revoked ${res ? res.revoked : 0} token(s) of "${m.value}".`);
        await refresh();
      }),
    );
    root.append(el("h3", {}, "Revoke by machine"), box);
  }

  if (!roles.length) {
    root.append(el("p", { class: "notice" }, "Create a role before issuing tokens."));
    return;
  }
  const machine = input("text", { required: true, autocomplete: "off", maxlength: "128" });
  const role = select(roles.map((r) => [r.name]));
  const ttl = input("text", { autocomplete: "off", placeholder: "e.g. 30m, 12h, 7d" });
  root.append(
    el("h3", {}, "Create a token"),
    el(
      "form",
      {
        onsubmit: safe(async () => {
          const ttlSecs = parseTtl(ttl.value);
          const body = { machine: machine.value, role: role.value };
          if (ttlSecs !== null) body.ttl_secs = ttlSecs;
          const res = await api("POST", "/tokens", body);
          freshToken = { machine: res.machine, token: res.token };
          await refresh();
        }),
      },
      field("Machine", machine, "a label for the agent or host that will use it"),
      field("Role", role),
      field("Lifetime (optional)", ttl, "empty = does not expire; max 10 years"),
      el("button", { type: "submit", class: "primary" }, "Create token"),
    ),
  );
}

function freshTokenPanel(t) {
  const env = proxyEnv(t.machine, t.token);
  const dismiss = el("button", { type: "button", onclick: () => { freshToken = null; refresh().catch(() => {}); } }, "Dismiss");
  const copy =
    typeof navigator !== "undefined" && navigator.clipboard
      ? el(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: safe(async () => {
              await navigator.clipboard.writeText(env);
              notify("Copied to the clipboard.");
            }),
          },
          "Copy",
        )
      : null;
  return el(
    "section",
    { class: "panel", "aria-label": "New token" },
    el("h3", {}, "New token for " + t.machine),
    el("p", { class: "notice" }, "Copy it now: this token is shown only once and cannot be recovered."),
    el("pre", {}, env),
    el("div", { class: "row-actions" }, copy, dismiss),
    copy ? null : el("p", { class: "help" }, "Clipboard access is unavailable: select the text above and copy it manually."),
  );
}

// ---- views: CA ------------------------------------------------------------------------------

async function viewCa(root) {
  const ca = await api("GET", "/ca");
  root.append(
    el("h2", {}, "CA"),
    el("p", { class: "help" }, "The local CA signs certificates for the permitted domains so the proxy can inject credentials into HTTPS requests. Agents must trust its certificate."),
    el("p", { class: "help" }, "Domains are derived from your rules: adding a rule for a new host permits it here. When the list changes, agents must reload the CA certificate."),
    el("h3", {}, "Permitted domains"),
    ca.domains.length ? el("ul", {}, ca.domains.map((d) => el("li", {}, el("code", {}, d)))) : el("p", { class: "muted" }, "No domains yet: they appear when you add a rule."),
  );
  root.append(
    el("h3", {}, "Certificate"),
    el(
      "p",
      {},
      el(
        "button",
        {
          type: "button",
          onclick: safe(async () => {
            const blob = await api("GET", "/ca/cert", undefined, { blob: true });
            const url = URL.createObjectURL(blob);
            const a = el("a", { href: url, download: "secret-guardian-ca.pem" });
            document.body.append(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
          }),
        },
        "Download CA certificate",
      ),
    ),
    el("h3", {}, "Trusting it in an agent process"),
    el("p", { class: "help" }, "Trust is per process, not system-wide. SSL_CERT_FILE, REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE replace the default bundle for that process; NODE_EXTRA_CA_CERTS adds to it. Replace the path with where you saved the file."),
    el(
      "pre",
      {},
      [
        "export SSL_CERT_FILE=/path/to/secret-guardian-ca.pem",
        "export NODE_EXTRA_CA_CERTS=/path/to/secret-guardian-ca.pem",
        "export REQUESTS_CA_BUNDLE=/path/to/secret-guardian-ca.pem",
        "export CURL_CA_BUNDLE=/path/to/secret-guardian-ca.pem",
      ].join("\n"),
    ),
  );
}

// ---- views: audit ---------------------------------------------------------------------------

const BAD_DECISION = /den(y|ied)|forbid|refus|mismatch|bad-request/i;
const SINCE = [["", "any time"], ["3600", "last hour"], ["86400", "last 24 hours"], ["604800", "last 7 days"]];
let auditFilter = { role: "", host: "", since: "", limit: "200" };

async function viewAudit(root) {
  const q = new URLSearchParams({ limit: auditFilter.limit });
  if (auditFilter.role) q.set("role", auditFilter.role);
  if (auditFilter.host) q.set("host", auditFilter.host);
  if (auditFilter.since) q.set("since", String(Math.floor(Date.now() / 1000) - Number(auditFilter.since)));
  const entries = (await api("GET", "/audit?" + q)).slice().sort((a, b) => b.ts - a.ts);

  const role = input("text", { autocomplete: "off", value: auditFilter.role });
  const host = input("text", { autocomplete: "off", value: auditFilter.host });
  const since = select(SINCE);
  since.value = auditFilter.since;
  const limit = select([["50"], ["200"], ["1000"]]);
  limit.value = auditFilter.limit;
  root.append(
    el("h2", {}, "Audit"),
    el(
      "form",
      {
        onsubmit: safe(async () => {
          auditFilter = { role: role.value.trim(), host: host.value.trim(), since: since.value, limit: limit.value };
          await refresh();
        }),
      },
      field("Role", role),
      field("Host", host),
      field("Since", since),
      field("Limit", limit),
      el("button", { type: "submit", class: "primary" }, "Apply"),
    ),
    entries.length
      ? table(
          ["Time", "Machine", "Role", "Method", "Host", "Path", "Rule", "Decision", "Status"],
          entries.map((e) => [
            fmtTime(e.ts),
            e.machine ?? "-",
            e.role ?? "-",
            e.method,
            e.host,
            e.path,
            e.rule_id === null || e.rule_id === undefined ? "-" : String(e.rule_id),
            el("span", { class: BAD_DECISION.test(e.decision) ? "bad" : "" }, e.decision),
            e.status === null || e.status === undefined ? "-" : String(e.status),
          ]),
          `Audit log, newest first (${entries.length} shown)`,
        )
      : el("p", { class: "muted" }, "No audit entries match."),
  );
}

// ---- shell ----------------------------------------------------------------------------------

const TABS = [
  ["secrets", "Secrets", viewSecrets],
  ["roles", "Roles & rules", viewRoles],
  ["tokens", "Tokens", viewTokens],
  ["ca", "CA", viewCa],
  ["audit", "Audit", viewAudit],
];
let current = "secrets";
let renderSeq = 0;

function renderChrome() {
  $("tabs").replaceChildren(
    ...TABS.map(([id, label]) =>
      el("button", { type: "button", "aria-current": id === current ? "page" : false, onclick: () => selectTab(id) }, label),
    ),
  );
  $("session").replaceChildren(
    el("button", { type: "button", onclick: logout }, "Log out"),
  );
}

function selectTab(id) {
  if (id !== current) {
    current = id;
    freshToken = null;
    clearNotices();
  }
  renderChrome();
  refresh();
}

/** Re-render the current view from fresh server data. Never rejects. */
async function refresh() {
  const seq = ++renderSeq;
  const root = el("div", {});
  const view = TABS.find((t) => t[0] === current)[2];
  try {
    await view(root);
  } catch (e) {
    if (e && e.unauthorized) return;
    root.replaceChildren(el("h2", {}, "Error"), el("p", { class: "error" }, e && e.message ? e.message : String(e)));
  }
  if (seq === renderSeq) {
    $("view").replaceChildren(root);
    focusHeading();
  }
}

function showHelp(message) {
  clearNotices();
  $("tabs").replaceChildren();
  $("session").replaceChildren();
  $("view").replaceChildren(
    el(
      "div",
      { class: "helpscreen" },
      el("h2", {}, "Sign in required"),
      message ? el("p", { class: "error" }, message) : null,
      el("p", {}, "This interface needs a one-time login link. Run ", el("code", {}, "sg login-url"), " in a terminal on this machine and open the printed link in this browser."),
      el("p", { class: "help" }, "Links work once and the session lasts only while this tab stays open."),
    ),
  );
  focusHeading();
}

function logout() {
  clearSession();
  freshToken = null;
  showHelp("You are logged out.");
}

async function boot() {
  setOnExpired(() => {
    freshToken = null;
    showHelp("Session expired: run `sg login-url` and open the printed link.");
  });
  const hash = location.hash;
  const token = parseFragment(hash);
  if (hash) history.replaceState(null, "", location.pathname + location.search); // out of the bar and history
  if (token) {
    try {
      await login(token);
    } catch (e) {
      clearSession();
      showHelp("Login failed: " + e.message + ". Run `sg login-url` for a fresh link.");
      return;
    }
  }
  if (!getSession()) {
    showHelp();
    return;
  }
  renderChrome();
  await refresh();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { renderChrome, el, table, parseFragment, parseTtl, proxyEnv, tokenStatus, api, setOnExpired, encodeUserinfo, buildRule, secretBody, capitalise, deleteSecretLabel };
}
if (typeof window !== "undefined") {
  boot().catch((e) => showHelp("Unexpected error: " + (e && e.message ? e.message : e)));
}
