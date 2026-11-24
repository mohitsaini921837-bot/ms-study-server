// MS Study API — Supabase Edge Function (Deno).
//
// Single-router replacement for the old Express server (server.mjs).
// Base URL: https://<project-ref>.supabase.co/functions/v1/ms-api
// JWT verification must be OFF for this function (the app authenticates
// with the password in the request body, exactly like the Express server).
//
// Routes (same paths, codes and JSON shapes as server.mjs):
//   GET  /health
//   POST /validate
//   POST /admin/create-password
//   POST /admin/passwords
//   POST /admin/deactivate
//   POST /drive/list
//   POST /drive/upload   (multipart, file field "file")
//
// Rules (same as server.mjs):
// - Passwords are SHA-256 hashes (unsalted).
// - No password expiry, ever.
// - One password = one device. Last login wins: a "login" rebinds the
//   password to the new device (old device becomes kicked); a
//   "revalidate" never rebinds. A kicked device can log back in by
//   re-entering the password, which kicks the other device.
// - Drive calls use a service-account JWT (RS256) + the Drive REST API
//   directly — no googleapis dependency. If the service-account JSON or
//   folder id is missing/invalid, Drive endpoints answer
//   { result: "drive-not-configured" } instead of crashing.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
if (!supabaseUrl || !supabaseServiceRoleKey) {
  throw new Error(
    "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured on the server.",
  );
}
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const driveFolderId = (Deno.env.get("MS_DRIVE_FOLDER_ID") ?? "").trim() || null;
const serviceAccountJson = (Deno.env.get("GOOGLE_SERVICE_ACCOUNT_JSON") ?? "").trim();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const nowIso = () => new Date().toISOString();

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const hashPassword = (password: string) => sha256Hex(password);

// Look up an ACTIVE password row by its SHA-256 hash. Returns the row or null.
async function findActivePasswordRow(password: string) {
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .select(
      "id, password_hash, role, active, device_id, device_label, created_at, last_used_at, kicked_device_id",
    )
    .eq("password_hash", await hashPassword(password))
    .eq("active", true)
    .maybeSingle();
  if (error) throw error;
  return data ?? null;
}

// Validate a password + device. mode is "login" (explicit password entry,
// may rebind — last login wins) or "revalidate" (background check, never
// rebinds). See server.mjs for the full rule table.
async function validateWithRebind(
  password: string,
  deviceId: string,
  deviceLabel: string | null | undefined,
  mode: string,
) {
  const row = await findActivePasswordRow(password);
  if (!row) return { result: "incorrect" };
  if (mode === "revalidate") {
    if (deviceId && row.device_id && row.device_id === deviceId) {
      const { error } = await supabaseAdmin
        .from("ms_passwords")
        .update({ last_used_at: nowIso() })
        .eq("id", row.id);
      if (error) throw error;
      return { result: "valid", role: row.role };
    }
    return { result: "kicked" };
  }
  if (deviceId && row.device_id && row.device_id !== deviceId) {
    const { error } = await supabaseAdmin
      .from("ms_passwords")
      .update({
        kicked_device_id: row.device_id,
        device_id: deviceId,
        device_label: deviceLabel ?? row.device_label ?? null,
        last_used_at: nowIso(),
      })
      .eq("id", row.id);
    if (error) throw error;
    return { result: "valid", role: row.role };
  }
  const { error } = await supabaseAdmin
    .from("ms_passwords")
    .update({
      device_id: deviceId ? deviceId : row.device_id,
      device_label: deviceLabel ?? row.device_label ?? null,
      last_used_at: nowIso(),
    })
    .eq("id", row.id);
  if (error) throw error;
  return { result: "valid", role: row.role };
}

// Validate a password + device WITHOUT rebinding (used by /drive/list and
// /drive/upload): a device bound to someone else is "kicked", not rebound.
async function validateNoRebind(
  password: string,
  deviceId: string,
  deviceLabel?: string | null,
) {
  const row = await findActivePasswordRow(password);
  if (!row) return { result: "incorrect" };
  if (deviceId && row.device_id && row.device_id !== deviceId) {
    return { result: "kicked" };
  }
  const { error } = await supabaseAdmin
    .from("ms_passwords")
    .update({
      device_id: deviceId ? deviceId : row.device_id,
      device_label: deviceLabel ?? row.device_label ?? null,
      last_used_at: nowIso(),
    })
    .eq("id", row.id);
  if (error) throw error;
  return { result: "valid", role: row.role };
}

// Verify an admin password. Returns { row } on success, or
// { result: "unauthorized" } on any failure.
async function verifyAdmin(adminPassword: unknown, deviceId?: unknown) {
  if (typeof adminPassword !== "string" || !adminPassword) {
    return { result: "unauthorized" };
  }
  let row;
  try {
    row = await findActivePasswordRow(adminPassword);
  } catch {
    return { result: "unauthorized" };
  }
  if (!row || row.role !== "admin") return { result: "unauthorized" };
  if (deviceId && row.device_id && row.device_id !== deviceId) {
    return { result: "unauthorized" };
  }
  try {
    await supabaseAdmin
      .from("ms_passwords")
      .update({
        device_id: deviceId ? deviceId : row.device_id,
        last_used_at: nowIso(),
      })
      .eq("id", row.id);
  } catch {
    // Binding bookkeeping must not block an otherwise valid admin check.
  }
  return { row };
}

// Readable user code: "MS-XXXXX", 5 chars from A-Z + 2-9 (no 0/O/1/I).
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function generateUserCode(): string {
  // 256 is divisible by 32, so byte % 32 is perfectly uniform here.
  const bytes = crypto.getRandomValues(new Uint8Array(5));
  let code = "MS-";
  for (let i = 0; i < 5; i += 1) {
    code += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return code;
}

const directLink = (fileId: string) =>
  `https://drive.google.com/uc?export=download&id=${fileId}`;
const viewerLink = (fileId: string) =>
  `https://drive.google.com/file/d/${fileId}/view`;

// ---------------------------------------------------------------------------
// Google Drive via REST (service-account JWT, RS256) — no googleapis dep.
// ---------------------------------------------------------------------------

type ServiceAccount = {
  client_email: string;
  private_key: string;
};

let driveCredentials: ServiceAccount | null = null;
let driveCredentialsBad = false;
if (!serviceAccountJson) {
  console.warn(
    "WARNING: GOOGLE_SERVICE_ACCOUNT_JSON is not set — Drive endpoints will return drive-not-configured.",
  );
} else {
  try {
    const parsed = JSON.parse(serviceAccountJson);
    if (
      typeof parsed.client_email === "string" &&
      typeof parsed.private_key === "string"
    ) {
      driveCredentials = parsed as ServiceAccount;
    } else {
      driveCredentialsBad = true;
    }
  } catch {
    driveCredentialsBad = true;
  }
  if (driveCredentialsBad) {
    console.warn(
      "WARNING: GOOGLE_SERVICE_ACCOUNT_JSON could not be parsed — Drive endpoints will return drive-not-configured.",
    );
  }
}

const driveConfigured = () => Boolean(driveCredentials) && Boolean(driveFolderId);

// In-memory access-token cache (best effort; a cold start just re-mints).
let cachedAccessToken: string | null = null;
let cachedAccessTokenExp = 0;

function base64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const derB64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(derB64), (c) => c.charCodeAt(0));
  return await crypto.subtle.importKey(
    "pkcs8",
    der.buffer as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function mintAccessToken(): Promise<string> {
  if (!driveCredentials) throw new Error("drive-not-configured");
  const nowSec = Math.floor(Date.now() / 1000);
  if (cachedAccessToken && cachedAccessTokenExp > nowSec + 60) {
    return cachedAccessToken;
  }
  const header = base64Url(
    new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const payload = base64Url(
    new TextEncoder().encode(JSON.stringify({
      iss: driveCredentials.client_email,
      scope: "https://www.googleapis.com/auth/drive",
      aud: "https://oauth2.googleapis.com/token",
      exp: nowSec + 3600,
      iat: nowSec,
    })),
  );
  const signingInput = `${header}.${payload}`;
  const key = await importPrivateKey(driveCredentials.private_key);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );
  const jwt = `${signingInput}.${base64Url(new Uint8Array(signature))}`;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) {
    throw new Error(`drive token exchange failed: ${res.status}`);
  }
  const data = await res.json();
  cachedAccessToken = data.access_token;
  cachedAccessTokenExp = nowSec + (data.expires_in ?? 3600);
  return cachedAccessToken as string;
}

async function driveFetch(path: string, init: RequestInit = {}) {
  const token = await mintAccessToken();
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return await fetch(`https://www.googleapis.com${path}`, { ...init, headers });
}

async function driveListFiles(parentId: string) {
  const q = `'${parentId.replace(/'/g, "")}' in parents and trashed = false`;
  const params = new URLSearchParams({
    q,
    fields: "files(id, name, mimeType, size, modifiedTime, webViewLink)",
    orderBy: "folder, name",
    pageSize: "100",
  });
  const res = await driveFetch(`/drive/v3/files?${params.toString()}`);
  if (!res.ok) throw new Error(`drive list failed: ${res.status}`);
  const data = await res.json();
  return (data.files ?? []).map((file: Record<string, string>) => ({
    id: file.id,
    name: file.name,
    mimeType: file.mimeType,
    size: file.size ?? null,
    modifiedTime: file.modifiedTime,
    link: directLink(file.id),
    viewerLink: file.webViewLink ?? viewerLink(file.id),
    isFolder: file.mimeType === "application/vnd.google-apps.folder",
  }));
}

async function driveUploadFile(
  name: string,
  mimeType: string,
  bytes: Uint8Array,
  parentId: string,
) {
  const boundary = `ms-study-${crypto.randomUUID()}`;
  const meta = JSON.stringify({ name, parents: [parentId] });
  const enc = new TextEncoder();
  const head = enc.encode(
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n` +
      `--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`,
  );
  const tail = enc.encode(`\r\n--${boundary}--`);
  const body = new Uint8Array(head.length + bytes.length + tail.length);
  body.set(head, 0);
  body.set(bytes, head.length);
  body.set(tail, head.length + bytes.length);
  const res = await driveFetch(
    "/upload/drive/v3/files?uploadType=multipart&fields=id,name,size",
    {
      method: "POST",
      headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
      body,
    },
  );
  if (!res.ok) throw new Error(`drive upload failed: ${res.status}`);
  return await res.json();
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

// Parse a small JSON body (same 16kb limit as the Express server).
async function readJsonBody(req: Request): Promise<Record<string, unknown> | null> {
  const text = await req.text();
  if (text.length > 16 * 1024) return null;
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async function handleValidate(body: Record<string, unknown>) {
  const password = body.password;
  const deviceId = body.deviceId;
  const deviceLabel = body.deviceLabel;
  const mode = body.mode;
  if (
    typeof password !== "string" || !password ||
    typeof deviceId !== "string" || !deviceId
  ) {
    return jsonResponse({ result: "incorrect" }, 400);
  }
  const validateMode = mode === "revalidate" ? "revalidate" : "login";
  try {
    const outcome = await validateWithRebind(
      password,
      deviceId,
      typeof deviceLabel === "string" ? deviceLabel : null,
      validateMode,
    );
    return jsonResponse(outcome, 200);
  } catch (error) {
    console.error("Password validation failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
}

async function handleAdminCreatePassword(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  let code: string | null = null;
  for (let attempt = 0; attempt < 5 && !code; attempt += 1) {
    const candidate = generateUserCode();
    const { data } = await supabaseAdmin
      .from("ms_passwords")
      .select("id")
      .eq("password_hash", await hashPassword(candidate))
      .maybeSingle();
    if (!data) code = candidate;
  }
  if (!code) return jsonResponse({ result: "unavailable" }, 500);
  const { error } = await supabaseAdmin.from("ms_passwords").insert({
    password_hash: await hashPassword(code),
    role: "user",
    active: true,
    device_id: null,
    device_label: null,
  });
  if (error) {
    console.error("Password creation failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", password: code }, 201);
}

async function handleAdminPasswords(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .select("id, role, device_id, device_label, active, created_at, last_used_at")
    .order("created_at", { ascending: false });
  if (error) {
    console.error("Password list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", passwords: data ?? [] }, 200);
}

async function handleAdminDeactivate(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const id = body.id;
  if (typeof id !== "string" || !id) {
    return jsonResponse({ result: "not-found" }, 400);
  }
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .update({ active: false })
    .eq("id", id)
    .select("id")
    .maybeSingle();
  if (error) {
    console.error("Password deactivate failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  if (!data) return jsonResponse({ result: "not-found" }, 404);
  return jsonResponse({ result: "ok" }, 200);
}

async function handleDriveList(body: Record<string, unknown>) {
  const password = body.password;
  const deviceId = body.deviceId;
  const folderId = body.folderId;
  if (
    typeof password !== "string" || !password ||
    typeof deviceId !== "string" || !deviceId
  ) {
    return jsonResponse({ result: "incorrect" }, 400);
  }
  try {
    const outcome = await validateNoRebind(password, deviceId);
    if (outcome.result !== "valid") {
      return jsonResponse({ result: outcome.result }, 200);
    }
  } catch (error) {
    console.error("Drive list validation failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
  if (!driveConfigured()) {
    return jsonResponse({ result: "drive-not-configured" }, 200);
  }
  const parentId =
    (typeof folderId === "string" && folderId.trim()) || driveFolderId;
  if (!parentId) {
    return jsonResponse({ result: "drive-not-configured" }, 200);
  }
  try {
    const files = await driveListFiles(parentId);
    return jsonResponse({ result: "ok", files }, 200);
  } catch (error) {
    console.error("Drive list failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
}

async function handleDriveUpload(req: Request) {
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const getStr = (key: string) => {
    const v = form.get(key);
    return typeof v === "string" ? v : null;
  };
  const password = getStr("password");
  const deviceId = getStr("deviceId");
  const title = getStr("title");
  const kind = getStr("kind");
  const folderId = getStr("folderId");
  const sectionId = getStr("sectionId");
  if (typeof password !== "string" || !password) {
    return jsonResponse({ result: "incorrect" }, 400);
  }
  let role: string;
  try {
    const outcome = await validateNoRebind(password, deviceId ?? "");
    if (outcome.result === "incorrect") {
      return jsonResponse({ result: "incorrect" }, 200);
    }
    if (outcome.result === "kicked") {
      return jsonResponse({ result: "kicked" }, 200);
    }
    role = outcome.role;
  } catch (error) {
    console.error("Drive upload validation failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
  if (role !== "admin") {
    return jsonResponse({ result: "unauthorized" }, 401);
  }
  if (!driveConfigured()) {
    return jsonResponse({ result: "drive-not-configured" }, 200);
  }
  const fileValue = form.get("file");
  if (!(fileValue instanceof File)) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const parentId = (folderId && folderId.trim()) || driveFolderId;
  if (!parentId) {
    return jsonResponse({ result: "drive-not-configured" }, 200);
  }
  try {
    const bytes = new Uint8Array(await fileValue.arrayBuffer());
    const data = await driveUploadFile(
      title ? title : fileValue.name,
      fileValue.type || "application/octet-stream",
      bytes,
      parentId,
    );
    const fileId = data.id;
    const response: Record<string, unknown> = {
      result: "ok",
      fileId,
      link: directLink(fileId),
      viewerLink: viewerLink(fileId),
      name: data.name,
      size: data.size ?? String(fileValue.size),
    };
    if (typeof title === "string" && title.trim()) {
      const { data: item, error } = await supabaseAdmin
        .from("ms_items")
        .insert({
          kind: typeof kind === "string" && kind.trim() ? kind.trim() : null,
          title: title.trim(),
          folder_id: folderId && folderId.trim() ? folderId.trim() : null,
          section_id: sectionId && sectionId.trim() ? sectionId.trim() : null,
          drive_file_id: fileId,
          drive_link: directLink(fileId),
        })
        .select("id")
        .single();
      if (error) {
        console.error("ms_items insert failed (file is in Drive)", {
          message: error.message,
        });
      } else if (item) {
        response.itemId = item.id;
      }
    }
    return jsonResponse(response, 200);
  } catch (error) {
    console.error("Drive upload failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  const url = new URL(req.url);
  // Supabase may pass the path with the /functions/v1/<name> prefix, with
  // just the /<name> prefix, or with no prefix at all — strip whichever
  // form is present so routing works in every case.
  let path = url.pathname;
  path = path.replace(/^\/functions\/v1\/ms-api/, "");
  path = path.replace(/^\/ms-api/, "");
  if (!path.startsWith("/")) path = `/${path}`;
  if (path === "") path = "/";
  try {
    if (req.method === "GET" && path === "/health") {
      return jsonResponse({ ok: true }, 200);
    }
    if (req.method === "POST" && path === "/validate") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "incorrect" }, 400);
      return await handleValidate(body);
    }
    if (req.method === "POST" && path === "/admin/create-password") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleAdminCreatePassword(body);
    }
    if (req.method === "POST" && path === "/admin/passwords") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleAdminPasswords(body);
    }
    if (req.method === "POST" && path === "/admin/deactivate") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleAdminDeactivate(body);
    }
    if (req.method === "POST" && path === "/drive/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 503);
      return await handleDriveList(body);
    }
    if (req.method === "POST" && path === "/drive/upload") {
      return await handleDriveUpload(req);
    }
    return jsonResponse({ message: "Route not found." }, 404);
  } catch (error) {
    console.error("Unhandled server error", { message: (error as Error).message });
    return jsonResponse(
      { message: "MS Study service failed unexpectedly." },
      500,
    );
  }
});
