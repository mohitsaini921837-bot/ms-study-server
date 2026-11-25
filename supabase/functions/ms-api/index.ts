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
//   POST /chat/join      (accepts optional pushToken: FCM device token)
//   POST /chat/send      (sends a generic FCM push to the other member)
//   POST /chat/messages
//   POST /chat/delete
//   POST /chat/change-code
//   POST /chat/push-token (register / refresh this device's FCM token)
//
// Rules (same as server.mjs):
// - Passwords are SHA-256 hashes (unsalted).
// - No password expiry, ever.
// - One password = one device. Last login wins: a "login" rebinds the
//   password to the new device (old device becomes kicked); a
//   "revalidate" never rebinds. A kicked device can log back in by
//   re-entering the password, which kicks the other device.
// - Drive calls use OAuth user credentials (refresh token for the owner's
//   Google account) + the Drive REST API directly — no googleapis dep.
//   A service account CANNOT upload (it has no storage quota), so the
//   server mints access tokens from the refresh token. If the OAuth
//   credentials or folder id are missing/invalid, Drive endpoints answer
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
const googleOAuthClientId = (Deno.env.get("GOOGLE_OAUTH_CLIENT_ID") ?? "").trim();
const googleOAuthClientSecret = (Deno.env.get("GOOGLE_OAUTH_CLIENT_SECRET") ?? "").trim();
const googleOAuthRefreshToken = (Deno.env.get("GOOGLE_OAUTH_REFRESH_TOKEN") ?? "").trim();

// FCM push for the hidden chat (Firebase project weather-c0a4e, app
// com.kiara.msstudy). Credentials come from Edge Function secrets —
// NEVER commit the service-account JSON. Two forms are accepted:
//   a) split fields: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL,
//      FIREBASE_PRIVATE_KEY (PEM; literal "\n" is converted below), or
//   b) the whole JSON: FIREBASE_SERVICE_ACCOUNT_JSON.
// If none are set, push is silently skipped and the chat keeps working
// by polling. See setup-ms-chat-push-tokens.sql for the token table.
const fcmProjectId = (Deno.env.get("FIREBASE_PROJECT_ID") ?? "").trim();
const fcmClientEmail = (Deno.env.get("FIREBASE_CLIENT_EMAIL") ?? "").trim();
const fcmPrivateKeyRaw = (Deno.env.get("FIREBASE_PRIVATE_KEY") ?? "").trim();
const fcmServiceAccountJson = (Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON") ?? "").trim();

function resolveFcmCredentials(): { projectId: string; clientEmail: string; privateKey: string } | null {
  if (fcmServiceAccountJson) {
    try {
      const parsed = JSON.parse(fcmServiceAccountJson) as Record<string, unknown>;
      const projectId = typeof parsed.project_id === "string" ? parsed.project_id : "";
      const clientEmail = typeof parsed.client_email === "string" ? parsed.client_email : "";
      const privateKey = typeof parsed.private_key === "string" ? parsed.private_key : "";
      if (projectId && clientEmail && privateKey) return { projectId, clientEmail, privateKey };
    } catch {
      console.error("FCM service-account JSON is not valid JSON");
      return null;
    }
  }
  if (fcmProjectId && fcmClientEmail && fcmPrivateKeyRaw) {
    // Secrets set via `supabase secrets set` usually carry the PEM with
    // literal \n sequences; restore real newlines for the key import.
    return { projectId: fcmProjectId, clientEmail: fcmClientEmail, privateKey: fcmPrivateKeyRaw.replace(/\\n/g, "\n") };
  }
  return null;
}

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
// Google Drive via REST (OAuth user credentials) — no googleapis dep.
// ---------------------------------------------------------------------------

const driveConfigured = () =>
  Boolean(googleOAuthClientId) &&
  Boolean(googleOAuthClientSecret) &&
  Boolean(googleOAuthRefreshToken) &&
  Boolean(driveFolderId);
if (!driveConfigured()) {
  console.warn(
    "WARNING: Google OAuth Drive credentials or folder id not set — Drive endpoints will return drive-not-configured.",
  );
}

// In-memory access-token cache (best effort; a cold start just re-mints).
let cachedAccessToken: string | null = null;
let cachedAccessTokenExp = 0;

function base64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function mintAccessToken(): Promise<string> {
  if (!driveConfigured()) throw new Error("drive-not-configured");
  const nowSec = Math.floor(Date.now() / 1000);
  if (cachedAccessToken && cachedAccessTokenExp > nowSec + 60) {
    return cachedAccessToken;
  }
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: googleOAuthClientId,
      client_secret: googleOAuthClientSecret,
      refresh_token: googleOAuthRefreshToken,
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
  // FIX 9 (v1.0.12): the admin may TYPE her own password for a new user.
  // Custom passwords must be 4-32 chars of letters/digits/hyphen/underscore
  // and must not already be in use. Empty/missing keeps the random code.
  const custom = typeof body.password === "string" ? body.password.trim() : "";
  let code: string | null = null;
  if (custom) {
    if (custom.length < 4 || custom.length > 32 || !/^[A-Za-z0-9_-]+$/.test(custom)) {
      return jsonResponse({ result: "unavailable" }, 400);
    }
    const { data: existing } = await supabaseAdmin
      .from("ms_passwords")
      .select("id")
      .eq("password_hash", await hashPassword(custom))
      .maybeSingle();
    if (existing) return jsonResponse({ result: "unavailable" }, 409);
    code = custom;
  } else {
    for (let attempt = 0; attempt < 5 && !code; attempt += 1) {
      const candidate = generateUserCode();
      const { data } = await supabaseAdmin
        .from("ms_passwords")
        .select("id")
        .eq("password_hash", await hashPassword(candidate))
        .maybeSingle();
      if (!data) code = candidate;
    }
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

// FIX 9 (v1.0.12): real delete of a user password (not just deactivation).
// The user can no longer log in, and their next revalidation logs them out.
async function handleAdminDeletePassword(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const id = body.id;
  if (typeof id !== "string" || !id) {
    return jsonResponse({ result: "not-found" }, 400);
  }
  // The admin password can never be deleted from the app — deleting it
  // locks everyone out (2026-11-24: Kiara deleted it by mistake).
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .delete()
    .eq("id", id)
    .neq("role", "admin")
    .select("id")
    .maybeSingle();
  if (error) {
    console.error("Password delete failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  if (!data) return jsonResponse({ result: "not-found" }, 404);
  return jsonResponse({ result: "ok" }, 200);
}

async function handleAdminPasswords(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .select("id, role, device_id, device_label, active, created_at, last_used_at")
    .eq("role", "user")
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
  // The admin password can never be deactivated from the app either —
  // deactivating it locks everyone out just like deleting it.
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .update({ active: false })
    .eq("id", id)
    .neq("role", "admin")
    .select("id")
    .maybeSingle();
  if (error) {
    console.error("Password deactivate failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  if (!data) return jsonResponse({ result: "not-found" }, 404);
  return jsonResponse({ result: "ok" }, 200);
}

// FIX 7 (v1.0.12): in-app PDF viewer proxy. The app's PDF.js fetches the
// file through this endpoint (never directly from Drive — Drive links do
// not send CORS headers, so an XHR to Drive would fail). The server uses
// its OAuth token to fetch the bytes and streams them back with
// Access-Control-Allow-Origin: *, so PDF.js can render them in-app.
async function handleDriveFile(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const fileId = cleanId(body.fileId);
  if (!fileId) return jsonResponse({ result: "unavailable" }, 400);
  if (!driveConfigured()) {
    return jsonResponse({ result: "drive-not-configured" }, 200);
  }
  try {
    const metaRes = await driveFetch(`/drive/v3/files/${encodeURIComponent(fileId)}?fields=mimeType,name,size`);
    if (!metaRes.ok) {
      return jsonResponse({ result: "unavailable" }, metaRes.status === 404 ? 404 : 500);
    }
    const meta = await metaRes.json() as { mimeType?: string; name?: string; size?: string };
    const mimeType = typeof meta.mimeType === "string" && meta.mimeType ? meta.mimeType : "application/octet-stream";
    const fileRes = await driveFetch(`/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`);
    if (!fileRes.ok) {
      return jsonResponse({ result: "unavailable" }, fileRes.status === 404 ? 404 : 500);
    }
    const bytes = new Uint8Array(await fileRes.arrayBuffer());
    return new Response(bytes, {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        "Content-Type": mimeType,
        "Content-Length": String(bytes.length),
        "Cache-Control": "private, max-age=60",
      },
    });
  } catch (error) {
    console.error("Drive file failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 503);
  }
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
  // Scope: each browser screen (notes/practice/classes/tests) only sees
  // its own folders. No scope sent -> only unscoped (pre-migration) rows,
  // so old clients keep their previous behaviour.
  const scope = typeof body.scope === "string" && body.scope.trim() ? body.scope.trim() : null;
  let q = supabaseAdmin
    .from("ms_folders")
    .select("id, name, parent_id, scope, created_at")
    .order("name", { ascending: true });
  q = parentId ? q.eq("parent_id", parentId) : q.is("parent_id", null);
  q = scope ? q.eq("scope", scope) : q.is("scope", null);
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
  const scope = typeof body.scope === "string" && body.scope.trim() ? body.scope.trim() : null;
  const { data, error } = await supabaseAdmin
    .from("ms_folders")
    .insert({ name, parent_id: parentId, scope })
    .select("id, name, parent_id, scope, created_at")
    .single();
  if (error) {
    console.error("Folder create failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", folder: data }, 201);
}

async function handleFoldersDelete(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword ?? body.password, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const folderId = cleanId(body.folderId);
  if (!folderId) return jsonResponse({ result: "unavailable" }, 400);
  try {
    // Collect the folder and all descendant subfolders (BFS on parent_id).
    const folderIds: string[] = [folderId];
    let frontier: string[] = [folderId];
    while (frontier.length > 0) {
      const { data, error } = await supabaseAdmin
        .from("ms_folders")
        .select("id")
        .in("parent_id", frontier);
      if (error) throw error;
      const next = (data ?? []).map((r) => r.id as string).filter((id) => !folderIds.includes(id));
      folderIds.push(...next);
      frontier = next;
    }
    // Sections inside any of those folders.
    const { data: sections, error: secErr } = await supabaseAdmin
      .from("ms_sections")
      .select("id")
      .in("folder_id", folderIds);
    if (secErr) throw secErr;
    const sectionIds = (sections ?? []).map((r) => r.id as string);
    // Items first: ms_items folder_id/section_id are set-null on delete,
    // not cascade, so deleting folders/sections alone would orphan them.
    if (sectionIds.length > 0) {
      const { error } = await supabaseAdmin.from("ms_items").delete().in("section_id", sectionIds);
      if (error) throw error;
    }
    const { error: itemsErr } = await supabaseAdmin.from("ms_items").delete().in("folder_id", folderIds);
    if (itemsErr) throw itemsErr;
    if (sectionIds.length > 0) {
      const { error } = await supabaseAdmin.from("ms_sections").delete().in("id", sectionIds);
      if (error) throw error;
    }
    const { error: foldersErr } = await supabaseAdmin.from("ms_folders").delete().in("id", folderIds);
    if (foldersErr) throw foldersErr;
    return jsonResponse({ result: "ok" }, 200);
  } catch (error) {
    console.error("Folder delete failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
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
  const sections = data ?? [];
  // FIX 8 (v1.0.12): tell the app how many items each section has, and
  // when a section has exactly ONE item, include that item so the app can
  // open it directly on a section tap (no item row, no extra round-trip).
  const sectionIds = sections.map((x: { id: string }) => x.id);
  let itemsBySection: Record<string, Array<Record<string, unknown>>> = {};
  if (sectionIds.length) {
    const { data: items } = await supabaseAdmin
      .from("ms_items")
      .select("id, kind, title, drive_file_id, drive_link, section_id")
      .in("section_id", sectionIds);
    (items ?? []).forEach((it: Record<string, unknown>) => {
      const sid = String(it.section_id ?? "");
      if (!itemsBySection[sid]) itemsBySection[sid] = [];
      itemsBySection[sid].push(it);
    });
  }
  const out = sections.map((sec: { id: string }) => {
    const items = itemsBySection[sec.id] ?? [];
    const single = items.length === 1 ? items[0] : null;
    return {
      ...sec,
      item_count: items.length,
      single_item: single
        ? { id: single.id, kind: single.kind, title: single.title, drive_file_id: single.drive_file_id, drive_link: single.drive_link }
        : null,
    };
  });
  return jsonResponse({ result: "ok", sections: out }, 200);
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

async function handleSectionsDelete(body: Record<string, unknown>) {
  const admin = await verifyAdmin(body.adminPassword ?? body.password, body.deviceId);
  if (!admin.row) return jsonResponse({ result: "unauthorized" }, 401);
  const sectionId = cleanId(body.sectionId);
  if (!sectionId) return jsonResponse({ result: "unavailable" }, 400);
  try {
    const { error: itemsErr } = await supabaseAdmin.from("ms_items").delete().eq("section_id", sectionId);
    if (itemsErr) throw itemsErr;
    const { error } = await supabaseAdmin.from("ms_sections").delete().eq("id", sectionId);
    if (error) throw error;
    return jsonResponse({ result: "ok" }, 200);
  } catch (error) {
    console.error("Section delete failed", { message: (error as Error).message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
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

// ---------------------------------------------------------------------------
// Mark as Complete (v1.0.14, user order 2026-11-25)
// Every folder / section / note / practice sheet can be marked complete
// (green tick). The completion is keyed by the PASSWORD HASH — not the
// device — so it survives logout/login AND logging in on another phone
// with the same password. (One password = one user; the hash is the
// per-password identity. The app always sends the password, so the
// server can derive the hash without storing anything new.)
async function handleCompleteList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const password = body.password;
  if (typeof password !== "string" || !password) return jsonResponse({ result: "incorrect" }, 200);
  const ph = await hashPassword(password);
  const { data, error } = await supabaseAdmin
    .from("ms_completions")
    .select("item_type, item_id")
    .eq("password_hash", ph);
  if (error) {
    console.error("Complete list failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", completions: data ?? [] }, 200);
}

async function handleCompleteMark(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const password = body.password;
  const itemType = cleanId(body.itemType);
  const itemId = cleanId(body.itemId);
  if (
    typeof password !== "string" || !password || !itemType || !itemId ||
    (itemType !== "folder" && itemType !== "section" && itemType !== "item")
  ) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const ph = await hashPassword(password);
  const { error } = await supabaseAdmin
    .from("ms_completions")
    .upsert(
      { password_hash: ph, item_type: itemType, item_id: itemId },
      { onConflict: "password_hash,item_type,item_id" },
    );
  if (error) {
    console.error("Complete mark failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
}

async function handleCompleteUnmark(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const password = body.password;
  const itemType = cleanId(body.itemType);
  const itemId = cleanId(body.itemId);
  if (
    typeof password !== "string" || !password || !itemType || !itemId ||
    (itemType !== "folder" && itemType !== "section" && itemType !== "item")
  ) {
    return jsonResponse({ result: "unavailable" }, 400);
  }
  const ph = await hashPassword(password);
  const { error } = await supabaseAdmin
    .from("ms_completions")
    .delete()
    .eq("password_hash", ph)
    .eq("item_type", itemType)
    .eq("item_id", itemId);
  if (error) {
    console.error("Complete unmark failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
}

async function handleTestsList(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  // v1.0.14 (user order 2026-11-25): tests are visible to EVERYONE now.
  // The per-user filter (created_by = caller device) is REMOVED — every
  // logged-in user sees every test. Attempts/results stay per-user
  // (keyed by device_id in ms_attempts); only the tests themselves are
  // shared. created_by is still stored (who uploaded it) but no longer
  // filters anything.
  const { data, error } = await supabaseAdmin
    .from("ms_tests")
    .select("id, title, kind, language, question_count, duration_min, exam, category, chapter, total_marks, created_at, created_by")
    .eq("kind", typeof body.kind === "string" && body.kind ? body.kind : "notes")
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
    .select("id, title, kind, language, question_count, duration_min, exam, category, chapter, total_marks, created_at, created_by")
    .eq("id", testId)
    .maybeSingle();
  if (testErr || !test) {
    return jsonResponse({ result: "unavailable" }, 500);
  }
  // v1.0.14 (user order 2026-11-25): tests are visible to EVERYONE —
  // the per-user ownership check is REMOVED. Any logged-in user can
  // open any test. Attempts/results stay per-user.
  const { data: questions, error: qErr } = await supabaseAdmin
    .from("ms_questions")
    .select("id, question, options, answer_index, explanation")
    .eq("test_id", testId)
    .order("seq", { ascending: true, nullsFirst: false });
  // ORDER BY seq: questions display in their original Q1-Q20 order.
  // Rows inserted before the seq column existed have seq NULL and sort
  // last — they are backfilled from the JSON files (see vidyagram-tests/).
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
  const numOrNull = (v: unknown) =>
    typeof v === "number" && isFinite(v) ? Math.max(0, Math.round(v)) : null;
  const baseRow = {
    test_id: testId,
    device_id: typeof body.deviceId === "string" ? body.deviceId : null,
    score,
    total,
    answers: Array.isArray(body.answers) ? body.answers : [],
    finished_at: new Date().toISOString(),
  };
  // Full result detail (added 2026-11-24): time taken + correct/wrong/
  // unattempted counts. If the migration that adds these columns has not
  // landed yet, the insert fails on the unknown column — fall back to the
  // base row so the result still saves instead of being lost.
  const fullRow = {
    ...baseRow,
    time_taken_sec: numOrNull(body.time_taken_sec),
    correct_count: numOrNull(body.correct_count),
    wrong_count: numOrNull(body.wrong_count),
    unattempted_count: numOrNull(body.unattempted_count),
  };
  let { error } = await supabaseAdmin.from("ms_attempts").insert(fullRow);
  if (error) {
    const retry = await supabaseAdmin.from("ms_attempts").insert(baseRow);
    if (retry.error) {
      console.error("Tests submit failed", { message: retry.error.message });
      return jsonResponse({ result: "unavailable" }, 500);
    }
  }
  return jsonResponse({ result: "ok" }, 200);
}

// Latest attempt of one test for the CALLER only. The caller's deviceId
// comes from the authenticated body (requireValidUser already checked it),
// so a user can never see another user's attempt: one password = one
// device, and device_id is the per-user key. Returns attempt: null when
// the user has never taken this test.
async function handleTestsLastAttempt(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const testId = cleanId(body.testId);
  if (!testId) return jsonResponse({ result: "unavailable" }, 400);
  const deviceId = typeof body.deviceId === "string" ? body.deviceId : null;
  if (!deviceId) return jsonResponse({ result: "unavailable" }, 400);
  // select("*") on purpose: the detail columns may not exist yet if the
  // migration has not landed — the row still comes back without them and
  // the app computes the counts from the saved answers instead.
  const { data, error } = await supabaseAdmin
    .from("ms_attempts")
    .select("*")
    .eq("test_id", testId)
    .eq("device_id", deviceId)
    .order("finished_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) {
    console.error("Tests last-attempt failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok", attempt: data ?? null }, 200);
}

// ---------------------------------------------------------------------------
// RAS KNOWLEDGE BASE (v1.0.13, user order 2026-11-24 22:37 IST — "koi
// aisa AI jo sab kaam ekdam perfect kare"). The AI kept hallucinating Ras
// facts from its own knowledge (e.g. it named Banabhatta as Ras pravartak
// instead of Bharata Muni). So for Ras topics the prompt now carries the
// FACTS from Kiara's own Ras notes (transcribed merged.txt, her UPSI
// Daroga Ji Batch notes) and the model must use ONLY these facts.
// Condensed to the facts questions are asked about. If a fact is NOT in
// this list, the model must NOT invent a question about it.
const RAS_KNOWLEDGE = `RAS — FACTS FROM THE STUDENT'S OWN NOTES (use ONLY these, never your own knowledge):
- रस = आनन्द प्राप्त करना. Definition: काव्य की पंक्ति को पढ़ने में आनन्द प्राप्त होता है, उसे रस कहा जाता है।
- उद्भव: ऋग्वेद, संस्कृत भाषा. धातु: सृ (बहते जाना). उल्लेख: नाट्यशास्त्र.
- रस के प्रवर्तक: भरत मुनि. नाट्यशास्त्र के 6 और 7 अध्याय में रस का उल्लेख.
- काव्य के तीन भाग: रस = काव्य का आन्तरिक पक्ष; छंद = काव्य को नियमों में बाँधता है; अलंकार = काव्य का बाह्य पक्ष.
- आचार्य विश्वनाथ: वाक्यं रसात्मकं काव्यं (जिस वाक्य में रस होता है, उसे काव्य कहते हैं).
- भरतमुनि का सूत्र: विभावानुभावव्यभिचारिसंयोगाद्रसनिष्पत्तिः. सूत्र के भाग: विभाव, अनुभाव, संचारी भाव. सूत्र में उल्लेख नहीं है: स्थायी भाव (परिपक्व अवस्था = रस).
- भरतमुनि के अनुसार कुल भावों की संख्या: 49. काव्य की आत्मा: रस. रस की आत्मा: स्थायी भाव.
- रस के 4 अंग: 1 विभाव, 2 अनुभाव, 3 संचारी भाव, 4 स्थायी भाव.
- विभाव: चल रहे भाव को समाप्त कर नया भाव उत्पन्न होना. 2 भेद: आलम्बन विभाव, उद्दीपन विभाव. आलम्बन के 2 भेद: आश्रयगत आलम्बन (जिसके हृदय में भाव जागृत होता है), विषयगत आलम्बन (जिसकी वजह से भाव जागृत होता है). उद्दीपन के उदाहरण: कोयल का कूकना, मनोरम दृश्य, प्रेम पात्र की मधुर वाणी, वसंत ऋतु.
- अनुभाव: विभाव के बाद जागृत होने वाला भाव / शारीरिक चेष्टाएँ. संख्या: 4 — कायिक, सात्त्विक, वाचिक, आहार्य.
- सात्त्विक अनुभाव: शारीरिक चेष्टाएँ अपने आप उत्पन्न होती हैं. संख्या: 8 — स्वेद (पसीना), अश्रु (आँसू), प्रलय (मन की इन्द्रियों का शून्य होना), स्तम्भ (शरीर का काम न करना), स्वरभंग (स्वरों का बदल जाना), वैवर्ण्य (शरीर का रंग बदलना), कम्पन (शरीर का काँपना), रोमान्च (रोंगटों का खड़ा होना).
- संचारी भाव: व्यभिचारी भी कहते हैं. अल्पकाल तक रहने वाला भाव, समुद्र के बुलबुले के समान. संख्या: 33 (भरतमुनि), 34 (छल — देव), 35 (चपलता — आचार्य रामचन्द्र शुक्ल).
- स्थायी भाव: दीर्घ काल तक रहने वाला भाव. संख्या: भरतमुनि 8, हिंदी में 9 (मम्मट / अभिनवगुप्त), 10 (आचार्य विश्वनाथ), 11 (रूप गोस्वामी).
- 11 रस और उनके स्थायी भाव: 1 शृंगार — रति; 2 करुण — शोक; 3 हास्य — हास; 4 वीर — उत्साह; 5 रौद्र — क्रोध; 6 भयानक — भय; 7 अद्भुत — आश्चर्य; 8 वीभत्स — जुगुप्सा; 9 शान्त — निर्वेद; 10 वात्सल्य — वात्सल्यता; 11 भक्ति — अनुराग.
- शृंगार रस: नायक-नायिका / प्रेमी-प्रेमिका का मिलना और बिछड़ना. स्थायी भाव रति. रंग हरा / लाल. देवता विष्णु / श्री कृष्ण. गुण माधुर्य. 2 भेद: संयोग शृंगार (मिलन, आलिंगन), वियोग शृंगार / विप्रलम्भ (बिछड़ना, मिलने की सम्भावना बनी रहती है).
- करुण रस: धनिष्ठ मित्र की दयनीय स्थिति देखकर शोक का जन्म, उसकी परिपक्व अवस्था. स्थायी भाव शोक. देवता यम. रंग गोरा (कबूतर जैसा). जहाँ अपने से हमेशा के लिए बिछड़ जाना, मिलने की सम्भावना खत्म.
- वीर रस: स्थायी भाव उत्साह. देवता इन्द्र. रंग सुनहरा पीला. देश प्रेम, युद्ध, वीरता; नीचा दिखाए जाने पर उत्साह का जन्म.
- रौद्र रस: धर्म/जाति/मजहब द्वारा दूसरे को नीचा दिखाने पर क्रोध का जन्म. स्थायी भाव क्रोध. देवता रुद्र (शिव). रंग लाल. पहचान: शरीर काँपना, आँखें लाल-पीली, हाथ मलना, दाँत किटकिटाना.
- हास्य रस: स्थायी भाव हास. देवता शिवगण / गंधर्व. रंग सफेद. बेढंगी बात-चीत या पहनावा.
- भयानक रस: डरावने दृश्य देखकर भय का जन्म. स्थायी भाव भय. देवता कालदेव. रंग काला. जैसे प्राकृतिक आपदाएँ.
- अद्भुत रस: जिसकी कल्पना न की जाए वह कार्य हो जाए तो आश्चर्य का जन्म. स्थायी भाव आश्चर्य / विस्मय. देवता ब्रह्मा / गंधर्व. रंग पीला.
- वीभत्स रस: घिनौने दृश्य (खून, मवाद, मृत शरीर) देखकर जुगुप्सा का जन्म. स्थायी भाव जुगुप्सा. देवता महाकाल (शिव). रंग नीला.
- शान्त रस (9वाँ रस): ज्ञान / उपदेश से निर्वेद का जन्म. स्थायी भाव निर्वेद. देवता श्री नारायण (विष्णु). रंग कुन्द (सफेद चमेली). कवि: मम्मट / अभिनवगुप्त.
- तैत्तरीय उपनिषद: रस शब्द भौतिक स्वाद के लिए नहीं, परम आनन्द ईश्वर (ब्रह्म) के लिए — "रसो वै सः" (ब्रह्म ही रस है).
- आचार्य भट्ट लोल्लट: मत उत्पत्तिवाद. आचार्य शंकुक: मत अनुमितिवाद.
- भवभूति: करुण रस के लिए प्रसिद्ध (उत्तररामचरित में करुण रस प्रधान).
- Revision: रस धातु सृ; प्रवर्तक भरत मुनि; नाट्यशास्त्र अध्याय 6 और 7; कुल भाव 49; संचारी 33; सात्त्विक 8; अनुभाव 4; स्थायी भाव (भरत) 8; 9वाँ रस मम्मट ने दिया.`;

const GROQ_API_KEY = Deno.env.get("GROQ_API_KEY") ?? "";
// Single model — no fallback chain (user wants it FAST, one call path).
const GROQ_MODEL = "openai/gpt-oss-120b";

type GenQuestion = {
  question: string;
  options: string[];
  answer: number;
  explanation?: string;
};

function extractJson(text: string): unknown | null {
  // The model may wrap JSON in ```json fences — strip them, then parse.
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

async function callGroqOnce(prompt: string): Promise<string> {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
      response_format: { type: "json_object" },
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Groq ${res.status}: ${t.slice(0, 200)}`);
  }
  const data = await res.json() as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const text = data?.choices?.[0]?.message?.content ?? "";
  if (!text.trim()) throw new Error("Groq returned no text");
  return text;
}

async function groqGenerate(prompt: string): Promise<string> {
  // Single model, ONE retry for 503/429 (overload/quota) only, after a 3s
  // wait. A 400 (bad key/prompt) fails the same way on retry, so it throws
  // immediately. A hard deadline caps one generation at ~60s total —
  // Groq is far faster than Gemini, so 60s is generous.
  const deadline = Date.now() + 60000;
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (Date.now() >= deadline) {
      throw lastErr ?? new Error("Groq failed");
    }
    try {
      return await callGroqOnce(prompt);
    } catch (e) {
      lastErr = e as Error;
      const msg = (e as Error).message;
      if (!msg.includes("503") && !msg.includes("429")) throw e;
      if (attempt === 0) {
        console.error("Groq overloaded, retrying once", { message: msg.slice(0, 120) });
        await new Promise((r) => setTimeout(r, 3000));
        continue;
      }
      break;
    }
  }
  throw lastErr ?? new Error("Groq failed");
}

async function handleTestsGenerate(body: Record<string, unknown>) {
  // AI test creation is open to EVERY logged-in user (v1.0.12), not admin-only.
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const callerDevice = typeof body.deviceId === "string" ? body.deviceId : null;
  if (!GROQ_API_KEY) {
    console.error("Tests generate: GROQ_API_KEY not set");
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
  // SUBJECT LOCK (v1.0.12): the user is angry that the AI mixes in questions
  // from other subjects. Every question must be ONLY about the requested
  // topic/subject. Mixing is allowed ONLY when type is "mixed", and even
  // then only the two named sources below.
  const subjectName = subject || topic;
  const subjectLock = type === "mixed"
    ? `SUBJECT LOCK: you may mix ONLY the two named sources above (the notes on ${topic} and the exam ${subjectName}). Do not bring in questions from any other subject, chapter, or topic.`
    : `STRICT RULE: Every single question must be about ${subjectName} and nothing else. Do not include questions from any other subject, chapter, or topic. If you are unsure a question belongs to this subject, leave it out. Mixing subjects is NOT allowed for this test.`;
  // DESI LANGUAGE (v1.0.13): the topic/subject may be written in Hindi or
  // in Hinglish (Hindi written in Roman letters, e.g. "Ras", "UPSI
  // reasoning"). Understand it exactly as a Hindi-speaking student means
  // it. When the test language is Hindi, write natural, fluent, correct
  // Hindi — the way a real Hindi exam paper is written — not awkward
  // word-for-word translated Hindi. When the language is English, write
  // clear simple English.
  // RAS GROUNDING (v1.0.13): if the topic/subject is Ras, the prompt
  // carries the student's own Ras notes as the ONLY source of facts.
  // The model must NOT use its own knowledge for Ras — every fact must
  // come from RAS_KNOWLEDGE, and anything not in it must not be asked.
  const haystack = `${topic} ${subject}`.toLowerCase();
  const isRas = haystack.includes("रस") || haystack.includes("ras");
  const grounding = isRas
    ? `${RAS_KNOWLEDGE}\n\nGROUNDING RULE: Use ONLY the facts above for every question and every answer. Do NOT use your own knowledge about Ras. Do NOT invent a Rasa, a text, an author, or a number that is not in the facts above. If you cannot make a question purely from the facts above, skip it — never guess. `
    : ``;
  const prompt =
    `You are an expert exam question setter. ${source}\n\n` +
    `${subjectLock}\n\n` +
    `${grounding}` +
    `The topic or subject may be in Hindi or Hinglish (Hindi in Roman letters). Understand it exactly as a Hindi-speaking student means it. ` +
    `Write exactly ${numQuestions} multiple-choice questions in ${langName}. ` +
    (language === "hi"
      ? `Write natural, fluent, correct Hindi, like a real Hindi exam paper — not awkward translated Hindi. `
      : ``) +
    `Every question must have exactly 4 options and exactly one correct answer. ` +
    `Only include a question if you are certain the answer is correct — accuracy matters more than anything. ` +
    `Double-check every answer before writing it. Do not repeat a question. ` +
    `Reply with ONLY this JSON object, no other text:\n` +
    `{"questions":[{"question":"...","options":["...","...","...","..."],"answer":0,"explanation":"one short line"}]}\n` +
    `The "answer" field is the index (0-3) of the correct option.`;
  try {
    const rawText = await groqGenerate(prompt);
    let questions = validQuestions(extractJson(rawText));
    if (questions.length < Math.min(numQuestions, 10)) {
      console.error("Tests generate: too few valid questions", { got: questions.length });
      return jsonResponse({ result: "unavailable" }, 503);
    }
    // NO DAILY LIMIT (v1.0.12, user order 2026-11-24 20:31 IST): she must
    // be able to generate 50, 100 or more tests a day. There is NO per-day
    // count/quota/limit check anywhere in this handler (or in the app) —
    // the only hard limit is the AI provider's own free-tier quota, which
    // we spend as little of as possible. So the verification pass below is
    // now OPTIONAL: it runs ONLY when the first pass came back short. When
    // the first pass already returns the full requested set of valid
    // questions, one test costs ONE Groq call instead of two, so far more
    // tests fit in the free tier. The local validQuestions checks (4
    // distinct non-empty options, answer 0-3) always run and are NOT API
    // calls.
    const verifyPrompt =
      (isRas ? `${RAS_KNOWLEDGE}\n\nGROUNDING RULE: Verify every answer ONLY against the facts above. ` : ``) +
      `Check every question below. For each one, verify the marked answer is truly correct. ` +
      `If any answer is wrong, fix it to the correct option index. If a question is ambiguous or has no clearly correct option, remove it. ` +
      `SUBJECT CHECK: remove any question that is NOT about ${subjectName}` +
      (type === "mixed" ? ` (for this mixed test, keep only questions from the two named sources: the notes on ${topic} and the exam ${subjectName})` : ``) +
      `. Do not keep questions from any other subject or topic. ` +
      `Reply with ONLY the corrected JSON object in the same format, no other text:\n` +
      JSON.stringify({ questions: questions.slice(0, numQuestions) });
    // FIX 13 (v1.0.12): the verify pass runs ONLY when the first pass is
    // short — below 80% of the requested questions. At 80% or more the
    // first pass is already good enough, so one test costs ONE Groq call
    // instead of two, doubling how many tests fit in the free quota (her
    // NO-DAILY-LIMIT order: 50, 100 or more tests a day, no limit in code).
    // The local validQuestions checks always run and are NOT API calls.
    // RAS EXCEPTION (v1.0.13): for Ras topics the verify pass ALWAYS runs
    // — accuracy is the top priority and the verifier has the same
    // grounding facts, so it can actually catch a wrong answer.
    if (isRas || questions.length < Math.ceil(numQuestions * 0.8)) {
      try {
        const verifiedText = await groqGenerate(verifyPrompt);
        const verified = validQuestions(extractJson(verifiedText));
        if (verified.length >= Math.min(questions.length, 5)) {
          questions = verified;
        }
      } catch (e) {
        console.error("Tests verify pass failed, keeping generated set", { message: (e as Error).message });
      }
    }
    questions = questions.slice(0, numQuestions);
    const title = `${topic} — ${numQuestions} questions`;
    // Per-user: the test belongs to the user who created it.
    const testRow: Record<string, unknown> = {
      title,
      kind: type,
      source_ref: subject || topic,
      language,
      question_count: questions.length,
      duration_min: minutes,
      created_by: callerDevice,
    };
    let { data: test, error: testErr } = await supabaseAdmin
      .from("ms_tests")
      .insert(testRow)
      .select("id, title, kind, language, question_count, duration_min, created_at, created_by")
      .single();
    if (testErr) {
      // Fallback if the created_by migration has not landed yet: retry
      // without it so the test still gets created instead of being lost.
      const { created_by: _cb, ...baseRow } = testRow;
      const retry = await supabaseAdmin
        .from("ms_tests")
        .insert(baseRow)
        .select("id, title, kind, language, question_count, duration_min, created_at, created_by")
        .single();
      test = retry.data;
      testErr = retry.error;
    }
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
    .select("device_id, last_seen, last_read_at")
    .eq("room_id", roomId);
  const now = Date.now();
  return (data ?? []).map((p: { device_id: string; last_seen: string; last_read_at: string | null }) => ({
    deviceId: p.device_id,
    lastSeen: p.last_seen,
    // FIX 6 (v1.0.12): read receipts — when this member last read the chat.
    lastReadAt: p.last_read_at ?? null,
    online: now - new Date(p.last_seen).getTime() < CHAT_ONLINE_MS,
  }));
}

// ---------------------------------------------------------------------------
// Hidden-chat push notifications (FCM HTTP v1, Firebase project
// weather-c0a4e). Tokens live in ms_chat_push_tokens (room_id, device_id)
// — see setup-ms-chat-push-tokens.sql. The notification is GENERIC on
// purpose: title "MS Study", body "New message". NO message content is
// ever put in a push. Tapping it opens the app: FCM notification
// messages with no click_action open the launcher activity by default,
// so no click_action is set (a wrong custom action would break the tap).
// Push failures NEVER fail a message send — they are logged only.
// ---------------------------------------------------------------------------

// One FCM token per (room, device). Called from /chat/join (pushToken
// field) and /chat/push-token (token refresh / late registration).
async function chatSavePushToken(roomId: string, deviceId: string, token: string) {
  if (!token) return;
  const { error } = await supabaseAdmin.from("ms_chat_push_tokens").upsert(
    { room_id: roomId, device_id: deviceId, token, updated_at: new Date().toISOString() },
    { onConflict: "room_id,device_id" },
  );
  if (error) console.error("Chat push token save failed", { message: error.message });
}

function base64UrlEncode(data: Uint8Array): string {
  let s = "";
  data.forEach((b) => {
    s += String.fromCharCode(b);
  });
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Mint a Google OAuth2 access token from the Firebase service account
// (signed JWT, RS256, scope firebase.messaging) — no googleapis dep,
// WebCrypto only. Cached in memory until shortly before expiry.
let fcmAccessToken: { token: string; expiresAt: number } | null = null;

async function getFcmAccessToken(): Promise<string | null> {
  const creds = resolveFcmCredentials();
  if (!creds) return null;
  if (fcmAccessToken && Date.now() < fcmAccessToken.expiresAt - 60_000) {
    return fcmAccessToken.token;
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: creds.clientEmail,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    exp: nowSec + 3600,
    iat: nowSec,
  };
  const enc = new TextEncoder();
  const unsigned = `${base64UrlEncode(enc.encode(JSON.stringify(header)))}.${base64UrlEncode(enc.encode(JSON.stringify(payload)))}`;
  let key: CryptoKey;
  try {
    const b64 = creds.privateKey
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    key = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch (e) {
    console.error("FCM private key import failed", { message: (e as Error).message });
    return null;
  }
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(unsigned));
  const jwt = `${unsigned}.${base64UrlEncode(new Uint8Array(sig))}`;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) {
    console.error("FCM access token mint failed", { status: res.status });
    return null;
  }
  const data = await res.json() as { access_token?: string; expires_in?: number };
  if (!data.access_token) return null;
  fcmAccessToken = {
    token: data.access_token,
    expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
  return fcmAccessToken.token;
}

// Send the generic "New message" push to every OTHER member's stored
// token(s) in this room. Returns silently on any failure.
async function sendChatPush(roomId: string, senderDeviceId: string): Promise<void> {
  const creds = resolveFcmCredentials();
  if (!creds) return; // Push not configured — chat still works by polling.
  const { data: rows, error } = await supabaseAdmin
    .from("ms_chat_push_tokens")
    .select("device_id, token")
    .eq("room_id", roomId)
    .neq("device_id", senderDeviceId);
  if (error) {
    console.error("Chat push token lookup failed", { message: error.message });
    return;
  }
  if (!rows || rows.length === 0) return;
  const accessToken = await getFcmAccessToken();
  if (!accessToken) return;
  for (const row of rows as { device_id: string; token: string }[]) {
    try {
      const res = await fetch(
        `https://fcm.googleapis.com/v1/projects/${creds.projectId}/messages:send`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            message: {
              token: row.token,
              notification: { title: "MS Study", body: "New message" },
              android: { priority: "HIGH", notification: { sound: "default" } },
              data: { type: "chat" },
            },
          }),
        },
      );
      if (!res.ok) {
        // Dead token (app uninstalled / token rotated): stop sending
        // to it instead of retrying forever.
        const bodyText = await res.text().catch(() => "");
        if (res.status === 404 && bodyText.includes("UNREGISTERED")) {
          await supabaseAdmin
            .from("ms_chat_push_tokens")
            .delete()
            .eq("room_id", roomId)
            .eq("device_id", row.device_id);
        } else {
          console.error("FCM send failed", { status: res.status });
        }
      }
    } catch (e) {
      console.error("FCM send error", { message: (e as Error).message });
    }
  }
}

async function handleChatJoin(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  const pushToken = typeof body.pushToken === "string" ? body.pushToken.trim() : "";
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
    await chatSavePushToken(roomId, deviceId, pushToken);
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
  await chatSavePushToken(roomId, deviceId, pushToken);
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
  // Generic push to the other member (best-effort: a push failure must
  // never fail the message send — the message is already stored).
  try {
    await sendChatPush(roomId, deviceId);
  } catch (e) {
    console.error("Chat push failed", { message: (e as Error).message });
  }
  return jsonResponse({ result: "ok", message: data }, 201);
}

// Register / refresh this device's FCM token for the room. The app
// calls this whenever its token arrives or rotates, and /chat/join
// also accepts the token directly — either path stores the same row.
async function handleChatPushToken(body: Record<string, unknown>) {
  const auth = await requireValidUser(body);
  if (!auth.ok) {
    return jsonResponse({ result: auth.result }, auth.result === "unavailable" ? 503 : 200);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceId = body.deviceId as string;
  const pushToken = typeof body.pushToken === "string" ? body.pushToken.trim() : "";
  if (!code || !pushToken) return jsonResponse({ result: "unavailable" }, 400);
  const roomId = await chatRoomId(code);
  const room = await chatGetRoom(roomId);
  if (!room || !(Array.isArray(room.members) && room.members.includes(deviceId))) {
    return jsonResponse({ result: "not-joined" }, 403);
  }
  await chatSavePushToken(roomId, deviceId, pushToken);
  return jsonResponse({ result: "ok" }, 200);
}

// FIX 6 (v1.0.12): mark the chat as read — updates the caller's
// ms_chat_presence.last_read_at so the other side sees double ticks.
async function handleChatMarkRead(body: Record<string, unknown>) {
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
  const { error } = await supabaseAdmin
    .from("ms_chat_presence")
    .update({ last_read_at: new Date().toISOString() })
    .eq("room_id", roomId)
    .eq("device_id", deviceId);
  if (error) {
    console.error("Chat mark-read failed", { message: error.message });
    return jsonResponse({ result: "unavailable" }, 500);
  }
  return jsonResponse({ result: "ok" }, 200);
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
    if (req.method === "POST" && path === "/admin/delete-password") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleAdminDeletePassword(body);
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
    if (req.method === "POST" && path === "/folders/delete") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleFoldersDelete(body);
    }
    if (req.method === "POST" && path === "/sections/delete") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleSectionsDelete(body);
    }
    if (req.method === "POST" && path === "/items/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleItemsList(body);
    }
    if (req.method === "POST" && path === "/complete/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleCompleteList(body);
    }
    if (req.method === "POST" && path === "/complete/mark") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleCompleteMark(body);
    }
    if (req.method === "POST" && path === "/complete/unmark") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleCompleteUnmark(body);
    }
    if (req.method === "POST" && path === "/tests/list") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsList(body);
    }
    if (req.method === "POST" && path === "/tests/generate") {
      // v1.0.14 (user order 2026-11-25): AI test generation REMOVED.
      // The app no longer has the form and this endpoint is disabled —
      // tests are uploaded manually now. The handler code stays dormant.
      return jsonResponse({ result: "unavailable" }, 503);
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
    if (req.method === "POST" && path === "/tests/last-attempt") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleTestsLastAttempt(body);
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
    if (req.method === "POST" && path === "/chat/mark-read") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatMarkRead(body);
    }
    if (req.method === "POST" && path === "/chat/push-token") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleChatPushToken(body);
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
    if (req.method === "POST" && path === "/drive/file") {
      const body = await readJsonBody(req);
      if (body === null) return jsonResponse({ result: "unavailable" }, 500);
      return await handleDriveFile(body);
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
