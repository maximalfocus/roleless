"use strict";

const API_BASES = Object.freeze([
  "http://127.0.0.1:8000",
  "http://127.0.0.1:8001",
]);

const ACTORS = Object.freeze({
  viewer: { id: "viewer-1", token: "demo-viewer-token" },
  agent: { id: "agent-1", token: "demo-agent-token" },
  supervisor: { id: "supervisor-1", token: "demo-supervisor-token" },
  admin: { id: "admin-1", token: "demo-admin-token" },
  contractor: { id: "contractor-1", token: "demo-contractor-token" },
});

const CAPABILITIES = Object.freeze([
  ["Read tickets", ["viewer", "agent", "supervisor", "admin", "contractor"]],
  ["Create tickets", ["agent", "supervisor", "admin"]],
  ["Comment on assigned tickets", ["agent", "supervisor", "admin"]],
  ["Reassign tickets", ["supervisor", "admin"]],
  ["Grant roles", ["admin"]],
  ["Bulk-close tickets", ["admin"]],
  ["Export customers", ["admin"]],
  ["Read customer contacts", ["admin"]],
]);

const ACTIONS = Object.freeze({
  "grant-current": (actor) => ({
    method: "POST",
    path: `/admin/users/${actor.id}/role`,
    headers: {},
    body: { role: "admin" },
  }),
  "post-export": () => ({ method: "POST", path: "/admin/export", headers: {}, body: null }),
  "legacy-grant": (actor) => ({
    method: "POST",
    path: `/api/v1/users/${actor.id}/role`,
    headers: {},
    body: { role: "admin" },
  }),
  "bulk-close": () => ({
    method: "POST",
    path: "/admin/tickets/bulk-close",
    headers: {},
    body: null,
  }),
  "forged-contact": () => ({
    method: "POST",
    path: "/admin/customers/customer-1/contact",
    headers: { "X-Actor-Role": "admin" },
    body: null,
  }),
});

const roleSelect = document.querySelector("#role-select");
const applicationSelect = document.querySelector("#application-select");
const actionSelect = document.querySelector("#action-select");
const adminControls = document.querySelector("#admin-controls");
const hiddenNote = document.querySelector("#hidden-note");

function selection() {
  const base = applicationSelect.value;
  if (!API_BASES.includes(base)) throw new Error("Refused API destination");
  return { base, actor: ACTORS[roleSelect.value] };
}

async function callApi(request) {
  const { base, actor } = selection();
  const headers = {
    Authorization: `Bearer ${actor.token}`,
    ...request.headers,
  };
  if (request.body !== null) headers["Content-Type"] = "application/json";
  const response = await fetch(`${base}${request.path}`, {
    method: request.method,
    headers,
    body: request.body === null ? undefined : JSON.stringify(request.body),
  });
  return { response, headers, text: await response.text() };
}

function renderFunctions(role) {
  const list = document.querySelector("#function-list");
  list.replaceChildren();
  for (const [name, roles] of CAPABILITIES) {
    const intended = roles.includes(role);
    const item = document.createElement("li");
    const label = document.createElement("span");
    const status = document.createElement("span");
    label.textContent = name;
    status.textContent = intended ? "intended" : "not intended";
    status.className = intended ? "allowed" : "not-intended";
    item.append(label, status);
    list.append(item);
  }
}

async function refreshIdentity() {
  const { base } = selection();
  const vulnerable = base.endsWith(":8001");
  document.querySelector("#application-state").textContent = vulnerable
    ? "Selected: VULNERABLE application · explicit opt-in required"
    : "Selected: SECURE application · deny by default";
  try {
    const { response, text } = await callApi({ method: "GET", path: "/me", headers: {}, body: null });
    if (!response.ok) throw new Error(`${response.status} ${text}`);
    const identity = JSON.parse(text);
    document.querySelector("#identity-name").textContent = `${identity.name} (${identity.id})`;
    document.querySelector("#identity-role").textContent = identity.role;
    renderFunctions(identity.role);
    const isAdmin = identity.role === "admin";
    adminControls.hidden = !isAdmin;
    hiddenNote.hidden = isAdmin;
  } catch (error) {
    document.querySelector("#identity-name").textContent = "Application unavailable";
    document.querySelector("#identity-role").textContent = "—";
    adminControls.hidden = true;
    hiddenNote.hidden = false;
    renderFunctions(roleSelect.value);
  }
}

async function sendSelectedAction() {
  const { base, actor } = selection();
  const request = ACTIONS[actionSelect.value](actor);
  const previewHeaders = { Authorization: `Bearer ${actor.token}`, ...request.headers };
  if (request.body !== null) previewHeaders["Content-Type"] = "application/json";
  document.querySelector("#request-output").textContent = JSON.stringify(
    {
      destination: base,
      method: request.method,
      path: request.path,
      headers: previewHeaders,
      body: request.body,
    },
    null,
    2,
  );
  const output = document.querySelector(
    base.endsWith(":8001") ? "#vulnerable-response-output" : "#secure-response-output",
  );
  output.textContent = "Sending…";
  try {
    const { response, text } = await callApi(request);
    output.textContent = `HTTP ${response.status}\n${text}`;
    await refreshIdentity();
  } catch (error) {
    output.textContent = `Network error\n${error.message}`;
  }
}

roleSelect.addEventListener("change", refreshIdentity);
applicationSelect.addEventListener("change", refreshIdentity);
document.querySelector("#send-button").addEventListener("click", sendSelectedAction);
document.querySelectorAll("[data-admin-action]").forEach((button) => {
  button.addEventListener("click", () => {
    actionSelect.value = button.dataset.adminAction;
    sendSelectedAction();
  });
});

refreshIdentity();
