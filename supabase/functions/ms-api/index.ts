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
  // Files always go to the single Drive root folder. folderId/sectionId
  // are database tags (ms_folders/ms_sections) only — they are NOT Drive
  // folder IDs, so they must never be used as the Drive parent.
  const parentId = driveFolderId;
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
// Folders / sections / items (Phase 2)
// ---------------------------------------------------------------------------

type Authed = { ok: true; role: string } | { ok: false; result: string };

async function requireValidUser(
  body: Record<string, unknown>,
): Promise<Authed> {
  const password = body.password;
  const deviceId = body.deviceId;
  if (
    typeof password !== "string" || !password ||
    typeof deviceId !== "string" || !deviceId
  ) {
    return { ok: false, result: "incorrect" };
  }
  try {
    const outcome = await validateNoRebind(password, deviceId);
    if (outcome.result !== "valid") {
      return { ok: false, result: outcome.result };
    }
    return { ok: true, role: outcome.role };
  } catch (error) {
    console.error("Auth check failed", { message: (error as Error).message });
    return { ok: false, result: "unavailable" };
  }
}

function cleanId(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

async function handleFoldersList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const parentId = cleanId(body.parentId);
  let q = supabaseAdmin
    .from("ms_folders")
    .select("id, name, parent_id, created_at")
    .order("name", { ascending: true });
  q = parentId ? q.eq("parent_id", parentId) : q.is("parent_id", null);
  const { data, error } = await q;
  if (error) {
    console.error("Folders list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", folders: data ?? [] }, 200);
}

async function handleFoldersCreate(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword ?? body.password, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!name) return jsonResponse({ result: "unavailable" }, 400);
  const parentId = cleanId(body.parentId);
  const { data, error } = await supabaseAdmin
    .from("ms_folders")
    .insert({ name, parent_id: parentId })
    .select("id, name, parent_id, created_at")
    .single();
  if (error) {
    console.error("Folder create failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", folder: data }, 201);
}

async function handleSectionsList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const folderId = cleanId(body.folderId);
  if (!folderId) return jsonResponse({ result: "unavailable" }, 400);
  const { data, error } = await supabaseAdmin
    .from("ms_sections")
    .select("id, name, folder_id, created_at")
    .eq("folder_id", folderId)
    .order("name", { ascending: true });
  if (error) {
    console.error("Sections list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", sections: data ?? [] }, 200);
}

async function handleSectionsCreate(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword ?? body.password, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const folderId = cleanId(body.folderId);
  if (!name || !folderId) return jsonResponse({ result: "unavailable" }, 400);
  const { data, error } = await supabaseAdmin
    .from("ms_sections")
    .insert({ name, folder_id: folderId })
    .select("id, name, folder_id, created_at")
    .single();
  if (error) {
    console.error("Section create failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", section: data }, 201);
}

async function handleItemsList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const folderId = cleanId(body.folderId);
  const sectionId = cleanId(body.sectionId);
  let q = supabaseAdmin
    .from("ms_items")
    .select("id, kind, title, drive_file_id, drive_link, created_at")
    .order("created_at", { ascending: false });
  if (sectionId) {
    q = q.eq("section_id", sectionId);
  } else if (folderId) {
    q = q.eq("folder_id", folderId).is("section_id", null);
  } else {
    q = q.is("folder_id", null).is("section_id", null);
  }
  const { data, error } = await q;
  if (error) {
    console.error("Items list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", items: data ?? [] }, 200);
}

async function handleTestsList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const { data, error } = await supabaseAdmin
    .from("ms_tests")
    .select("id, title, kind, language, question_count, duration_min, created_at")
    .order("created_at", { ascending: false });
  if (error) {
    console.error("Tests list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", tests: data ?? [] }, 200);
}

async function handleTestsQuestions(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const testId = cleanId(body.testId);
  if (!testId) return jsonResponse({ result: "unavailable" }, 400);
  const { data: test, error: testErr } = await supabaseAdmin
    .from("ms_tests")
    .select("id, title, kind, language, question_count, duration_min, created_at")
    .eq("id", testId)
    .maybeSingle();
  if (testErr || !test) {
    return jsonResponse({ result: "unavailable" }, 500);
  }
  const { data: questions, error: qErr } = await supabaseAdmin
    .from("ms_questions")
    .select("id, question, options, answer_index, explanation")
    .eq("test_id", testId);
  // No ORDER BY: ms_questions has no created_at/position column, and the
  // rows are inserted once in order, so a plain select returns them in
  // insertion order. Ordering by a missing column failed the whole call.
  if (qErr) {
    console.error("Tests questions failed", { message: qErr.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", test, questions: questions ?? [] }, 200);
}

async function handleTestsSubmit(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const testId = cleanId(body.testId);
  const score = typeof body.score === "number" ? body.score : 0;
  const total = typeof body.total === "number" ? body.total : 0;
  if (!testId) return jsonResponse({ result: "unavailable" }, 400);
  const { error } = await supabaseAdmin.from("ms_attempts").insert({
    test_id: testId,
    device_id: typeof body.deviceId === "string" ? body.deviceId : null,
    score,
    total,
    answers: Array.isArray(body.answers) ? body.answers : [],
    finished_at: new Date().toISOString(),
  });
  if (error) {
    console.error("Tests submit failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
}

// ---------------------------------------------------------------------------
// AI tests (Phase 3) — Gemini
// ---------------------------------------------------------------------------

const GEMINI_API_KEY = Deno.env.get("GEMINI_API_KEY") ?? "";
const GEMINI_MODEL = "gemini-3.5-flash";

type GenQuestion = {
  question: string;
  options: string[];
  answer: number;
  explanation?: string;
};

function extractJson(text: string): unknown | null {
  // Gemini may wrap JSON in ```json fences — strip them, then parse.
  let t = text.trim();
  t = t.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = t.indexOf("{");
  const end = t.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(t.slice(start, end + 1));
  } catch {
    return null;
  }
}

function validQuestions(raw: unknown): GenQuestion[] {
  if (!raw || typeof raw !== "object") return [];
  const arr = (raw as { questions?: unknown }).questions;
  if (!Array.isArray(arr)) return [];
  const out: GenQuestion[] = [];
  for (const q of arr) {
    if (!q || typeof q !== "object") continue;
    const item = q as Record<string, unknown>;
    const question = typeof item.question === "string" ? item.question.trim() : "";
    const options = Array.isArray(item.options)
      ? item.options.map((o) => (typeof o === "string" ? o.trim() : "")).filter(Boolean)
      : [];
    const answer = typeof item.answer === "number" ? item.answer : -1;
    if (!question || options.length !== 4 || answer < 0 || answer > 3) continue;
    if (new Set(options).size !== 4) continue;
    out.push({
      question,
      options,
      answer,
      explanation: typeof item.explanation === "string" ? item.explanation.trim() : "",
    });
  }
  return out;
}

async function geminiGenerate(prompt: string): Promise<string> {
  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, responseMimeType: "application/json" },
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Gemini ${res.status}: ${t.slice(0, 200)}`);
  }
  const data = await res.json() as {
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  };
  const text = data?.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ?? "";
  if (!text.trim()) throw new Error("Gemini returned no text");
  return text;
}

async function handleTestsGenerate(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword ?? body.password, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  if (!GEMINI_API_KEY) {
    console.error("Tests generate: GEMINI_API_KEY not set");
    return jsonResponse({ result: "unavailable" }, 503);
  }
  const type = typeof body.type === "string" ? body.type : "";
  const topic = typeof body.topic === "string" ? body.topic.trim() : "";
  const subject = typeof body.subject === "string" ? body.subject.trim() : "";
  const language = body.language === "en" ? "en" : "hi";
  const numQuestions = Math.min(50, Math.max(10, Math.round(Number(body.numQuestions) || 10)));
  const minutes = Math.min(50, Math.max(10, Math.round(Number(body.minutes) || numQuestions)));
  const sheetText = typeof body.sheetText === "string" ? body.sheetText.trim() : "";
  if (!["notes", "pyq", "mixed", "sheet"].includes(type) || !topic) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  if (type === "sheet" && !sheetText) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const langName = language === "hi" ? "Hindi" : "English";
  const source = type === "sheet"
    ? `Use ONLY the practice sheet text below as the source. Do not add questions from outside it.\n\nSHEET:\n${sheetText.slice(0, 12000)}`
    : type === "pyq"
    ? `Use real previous-year questions (PYQs) for ${subject || topic} as the source. Use the actual PYQ questions and their correct answers, with the values kept the same.`
    : type === "mixed"
    ? `Mix two sources: the study notes on ${topic} and the target exam ${subject || topic}. Take the same questions from the notes with values changed, plus exam-style questions for ${subject || topic}.`
    : `Use the study notes on ${topic}${subject ? ` for the subject ${subject}` : ""} as the source. Take the same questions with values changed.`;
  const prompt =
    `You are an expert exam question setter. ${source}\n\n` +
    `Write exactly ${numQuestions} multiple-choice questions in ${langName}. ` +
    `Every question must have exactly 4 options and exactly one correct answer. ` +
    `Only include a question if you are certain the answer is correct — accuracy matters more than anything. ` +
    `Double-check every answer before writing it. Do not repeat a question. ` +
    `Reply with ONLY this JSON object, no other text:\n` +
    `{"questions":[{"question":"...","options":["...","...","...","..."],"answer":0,"explanation":"one short line"}]}\n` +
    `The "answer" field is the index (0-3) of the correct option.`;
  try {
    const rawText = await geminiGenerate(prompt);
    let questions = validQuestions(extractJson(rawText));
    if (questions.length < Math.min(numQuestions, 10)) {
      console.error("Tests generate: too few valid questions", { got: questions.length });
      return jsonResponse({ result: "unavailable" }, 503);
    }
    // Verification pass: ask Gemini to check every answer and correct any
    // wrong one, so a wrong answer does not get saved.
    const verifyPrompt =
      `Check every question below. For each one, verify the marked answer is truly correct. ` +
      `If any answer is wrong, fix it to the correct option index. If a question is ambiguous or has no clearly correct option, remove it. ` +
      `Reply with ONLY the corrected JSON object in the same format, no other text:\n` +
      JSON.stringify({ questions: questions.slice(0, numQuestions) });
    try {
      const verifiedText = await geminiGenerate(verifyPrompt);
      const verified = validQuestions(extractJson(verifiedText));
      if (verified.length >= Math.min(questions.length, 5)) {
        questions = verified;
      }
    } catch (e) {
      console.error("Tests verify pass failed, keeping generated set", { message: (e as Error).message });
    }
    questions = questions.slice(0, numQuestions);
    const title = `${topic} — ${numQuestions} questions`;
    const { data: test, error: testErr } = await supabaseAdmin
      .from("ms_tests")
      .insert({
        title,
        kind: type,
        source_ref: subject || topic,
        language,
        question_count: questions.length,
        duration_min: minutes,
      })
      .select("id, title, kind, language, question_count, duration_min, created_at")
      .single();
    if (testErr || !test) {
      console.error("Test insert failed", { message: testErr?.message });
      return jsonResponse({ result: "unavailable" }, 500);
    }
    const rows = questions.map((q) => ({
      test_id: test.id,
      question: q.question,
      options: q.options,
      answer_index: q.answer,
      explanation: q.explanation ?? "",
    }));
    const { error: qErr } = await supabaseAdmin.from("ms_questions").insert(rows);
    if (qErr) {
      console.error("Questions insert failed", { message: qErr.message });
      await supabaseAdmin.from("ms_tests").delete().eq("id", test.id);
      return jsonResponse({ result: "unavailable" }, 500);
    }
    return jsonResponse({ result: "ok", test }, 201);
  } catch (error) {
    console.error("Tests generate failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
}

// ---------------------------------------------------------------------------
// Hidden chat (Phase 5) — 1:1 chat, pairing by code, max 2 per code.
// Room id = "ms_hidden_" + SHA-256(code). Members are deviceIds.
// Auth: the study password (any valid user) + deviceId, same as folders.
// ---------------------------------------------------------------------------

const CHAT_MAX_MEMBERS = 2;
const CHAT_ONLINE_MS = 45_000;

async function chatRoomId(code: string): Promise<string> {
  return `ms_hidden_${await sha256Hex(code)}`;
}

async function chatGetRoom(roomId: string) {
  const { data, error } = await supabaseAdmin
    .from("ms_chat_rooms")
    .select("id, code_hash, members, updated_at")
    .eq("id", roomId)
    .maybeSingle();
  if (error) throw error;
  return data as { id: string; code_hash: string; members: string[]; updated_at: string } | null;
}

async function chatTouchPresence(roomId: string, deviceId: string) {
  await supabaseAdmin.from("ms_chat_presence").upsert(
    { room_id: roomId, device_id: deviceId, last_seen: new Date().toISOString() },
    { onConflict: "room_id,device_id" },
  );
}

async function chatPresenceList(roomId: string) {
  const { data } = await supabaseAdmin
    .from("ms_chat_presence")
    .select("device_id, last_seen")
    .eq("room_id", roomId);
  const now = Date.now();
  return (data ?? []).map((p: { device_id: string; last_seen: string }) => ({
    deviceId: p.device_id,
    lastSeen: p.last_seen,
    online: now - new Date(p.last_seen).getTime() < CHAT_ONLINE_MS,
  }));
}

async function handleChatJoin(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  if (!code) return jsonResponse({ result: "unavailable" }, 400);
  const roomId = await chatRoomId(code);
  const codeHash = await sha256Hex(code);
  let room = await chatGetRoom(roomId);
  if (!room) {
    const { data, error } = await supabaseAdmin
      .from("ms_chat_rooms")
      .insert({ id: roomId, code_hash: codeHash, members: [deviceId] })
      .select("id, code_hash, members, updated_at")
      .single();
    if (error) {
      console.error("Chat room create failed", { message: error.message });
      return jsonResponse({ result: "unavailable" }, 500);
    }
    room = data as { id: string; code_hash: string; members: string[]; updated_at: string };
    await chatTouchPresence(roomId, deviceId);
    return jsonResponse({ result: "ok", roomId, members: room.members, isNew: true, presence: await chatPresenceList(roomId) }, 200);
  }
  const members: string[] = Array.isArray(room.members) ? room.members : [];
  if (!members.includes(deviceId)) {
    if (members.length >= CHAT_MAX_MEMBERS) {
      return jsonResponse({ result: "full" }, 200);
    }
    const next = [...members, deviceId];
    const { error } = await supabaseAdmin
      .from("ms_chat_rooms")
      .update({ members: next, updated_at: new Date().toISOString() })
      .eq("id", roomId);
    if (error) {
      console.error("Chat room join failed", { message: error.message });
      return jsonResponse({ result: "unavailable" }, 500);
    }
    room.members = next;
  }
  await chatTouchPresence(roomId, deviceId);
  return jsonResponse({ result: "ok", roomId, members: room.members, isNew: false, presence: await chatPresenceList(roomId) }, 200);
}

async function handleChatSend(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  const text = typeof body.text === "string" ? body.text.trim() : "";
  const replyTo = cleanId(body.replyTo);
  if (!code || !text || text.length > 2000) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const roomId = await chatRoomId(code);
  const room = await chatGetRoom(roomId);
  if (!room || !(Array.isArray(room.members) && room.members.includes(deviceId))) {
    return jsonResponse({ result: "not-joined" }, 403);
  }
  const { data, error } = await supabaseAdmin
    .from("ms_chat_messages")
    .insert({ room_id: roomId, sender_device: deviceId, body: text, reply_to: replyTo })
    .select("id, room_id, sender_device, body, reply_to, created_at")
    .single();
  if (error) {
    console.error("Chat send failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  await chatTouchPresence(roomId, deviceId);
  return jsonResponse({ result: "ok", message: data }, 201);
}

async function handleChatMessages(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  if (!code) return jsonResponse({ result: "unavailable" }, 400);
  const roomId = await chatRoomId(code);
  const room = await chatGetRoom(roomId);
  if (!room || !(Array.isArray(room.members) && room.members.includes(deviceId))) {
    return jsonResponse({ result: "not-joined" }, 403);
  }
  const since = typeof body.since === "string" ? body.since : null;
  let q = supabaseAdmin
    .from("ms_chat_messages")
    .select("id, room_id, sender_device, body, reply_to, created_at")
    .eq("room_id", roomId)
    .order("created_at", { ascending: true })
    .limit(500);
  if (since) q = q.gt("created_at", since);
  const { data, error } = await q;
  if (error) {
    console.error("Chat messages failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  await chatTouchPresence(roomId, deviceId);
  return jsonResponse({
    result: "ok",
    messages: data ?? [],
    members: room.members,
    presence: await chatPresenceList(roomId),
  }, 200);
}

async function handleChatDelete(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  const messageId = cleanId(body.messageId);
  if (!code || !messageId) return jsonResponse({ result: "unavailable" }, 400);
  const roomId = await chatRoomId(code);
  const room = await chatGetRoom(roomId);
  if (!room || !(Array.isArray(room.members) && room.members.includes(deviceId))) {
    return jsonResponse({ result: "not-joined" }, 403);
  }
  // Anyone in the room can delete any message; it deletes for both sides.
  const { error } = await supabaseAdmin
    .from("ms_chat_messages")
    .delete()
    .eq("id", messageId)
    .eq("room_id", roomId);
  if (error) {
    console.error("Chat delete failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
}

async function handleChatChangeCode(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  if (!code) return jsonResponse({ result: "unavailable" }, 400);
  const roomId = await chatRoomId(code);
  const room = await chatGetRoom(roomId);
  if (!room || !(Array.isArray(room.members) && room.members.includes(deviceId))) {
    return jsonResponse({ result: "not-joined" }, 403);
  }
  // Changing the code deletes the whole chat for BOTH and unlinks both.
  const { error } = await supabaseAdmin
    .from("ms_chat_rooms")
    .delete()
    .eq("id", roomId);
  if (error) {
    console.error("Chat change-code failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
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
    if (req.method === "POST" && path === "/folders/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleFoldersList(body);
    }
    if (req.method === "POST" && path === "/folders/create") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleFoldersCreate(body);
    }
    if (req.method === "POST" && path === "/sections/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleSectionsList(body);
    }
    if (req.method === "POST" && path === "/sections/create") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleSectionsCreate(body);
    }
    if (req.method === "POST" && path === "/items/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleItemsList(body);
    }
    if (req.method === "POST" && path === "/tests/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsList(body);
    }
    if (req.method === "POST" && path === "/tests/generate") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsGenerate(body);
    }
    if (req.method === "POST" && path === "/tests/questions") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsQuestions(body);
    }
    if (req.method === "POST" && path === "/tests/submit") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsSubmit(body);
    }
    if (req.method === "POST" && path === "/chat/join") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatJoin(body);
    }
    if (req.method === "POST" && path === "/chat/send") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatSend(body);
    }
    if (req.method === "POST" && path === "/chat/messages") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatMessages(body);
    }
    if (req.method === "POST" && path === "/chat/delete") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatDelete(body);
    }
    if (req.method === "POST" && path === "/chat/change-code") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatChangeCode(body);
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
