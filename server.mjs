// MS Study server — password gate + Google Drive file server.
//
// SEPARATE from the PW password server and from Kiara Chat. This server
// talks to its OWN Supabase project (ms_passwords / ms_items tables) and
// its OWN Google Drive service account. Passwords must never mix with
// the PW app or Kiara Chat.
//
// Rules:
// - Passwords are SHA-256 hashes (unsalted) — same approach as the PW
//   server. See README.md "Security notes" for the caveat.
// - No password expiry, ever.
// - One password = one device. Last login wins: a new device that logs in
//   with a password REBINDS it to itself; the old device gets "kicked" on
//   its next validation (tracked via kicked_device_id). Background
//   revalidation never rebinds — only an explicit password entry (login)
//   moves the binding, so a kicked device can log back in by re-entering
//   the password, which kicks the other device.
// - All secrets come from environment variables. Nothing secret is
//   hard-coded in this file.

import { createHash, randomInt } from "node:crypto";
import cors from "cors";
import express from "express";
import multer from "multer";
import { google } from "googleapis";
import { createClient } from "@supabase/supabase-js";

const hashPassword = (password) =>
  createHash("sha256").update(password, "utf8").digest("hex");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!supabaseUrl || !supabaseServiceRoleKey) {
  throw new Error(
    "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured on the server."
  );
}
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const driveFolderId = (process.env.MS_DRIVE_FOLDER_ID ?? "").trim() || null;

// Drive client: built once at startup. If the service-account JSON is
// missing or invalid, the server keeps running and every Drive endpoint
// answers { result: "drive-not-configured" } instead of crashing.
let drive = null;
const serviceAccountJson = (process.env.GOOGLE_SERVICE_ACCOUNT_JSON ?? "").trim();
if (!serviceAccountJson) {
  console.warn(
    "WARNING: GOOGLE_SERVICE_ACCOUNT_JSON is not set — Drive endpoints will return drive-not-configured."
  );
} else {
  try {
    const credentials = JSON.parse(serviceAccountJson);
    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ["https://www.googleapis.com/auth/drive"],
    });
    drive = google.drive({ version: "v3", auth });
    console.log("Google Drive client initialised.");
  } catch (error) {
    console.warn(
      "WARNING: GOOGLE_SERVICE_ACCOUNT_JSON could not be parsed — Drive endpoints will return drive-not-configured.",
      { message: error.message }
    );
    drive = null;
  }
}

const app = express();
const port = Number(process.env.PORT ?? 3000);
app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: "16kb" }));

// Multer (memory storage) is used ONLY on POST /drive/upload.
const upload = multer({
  storage: multer.memoryStorage(),
  // Whole file is held in RAM during upload; keep under Render's memory.
  limits: { fileSize: 512 * 1024 * 1024 },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const nowIso = () => new Date().toISOString();

// Look up an ACTIVE password row by its SHA-256 hash. Returns the row or null.
async function findActivePasswordRow(password) {
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .select("id, password_hash, role, active, device_id, device_label, created_at, last_used_at, kicked_device_id")
    .eq("password_hash", hashPassword(password))
    .eq("active", true)
    .maybeSingle();
  if (error) throw error;
  return data ?? null;
}

// Validate a password + device. mode is "login" (explicit password entry,
// may rebind — last login wins) or "revalidate" (background check, never
// rebinds):
// - unknown/inactive password            -> { result: "incorrect" }
// - revalidate, device is not the bound one -> { result: "kicked" }
// - login, row bound to a different device (incl. a previously kicked
//   device logging back in)              -> rebind to this device,
//                                          { result: "valid", role }
// - row unbound, or bound to this device -> { result: "valid", role }
// Always refreshes last_used_at on success.
async function validateWithRebind(password, deviceId, deviceLabel, mode) {
  const row = await findActivePasswordRow(password);
  if (!row) return { result: "incorrect" };
  if (mode === "revalidate") {
    // Background check: only the currently bound device is valid.
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
    // New device takes over: remember the old device as kicked, then rebind.
    // A previously kicked device logging in again takes over the same way.
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
async function validateNoRebind(password, deviceId, deviceLabel) {
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
// { result: "unauthorized" } on any failure (unknown password, inactive,
// non-admin role, or admin device bound to a different device).
// If the admin row is unbound and a deviceId is given, it binds to it.
async function verifyAdmin(adminPassword, deviceId) {
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
function generateUserCode() {
  let code = "MS-";
  for (let i = 0; i < 5; i += 1) {
    code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

const directLink = (fileId) =>
  `https://drive.google.com/uc?export=download&id=${fileId}`;
const viewerLink = (fileId) =>
  `https://drive.google.com/file/d/${fileId}/view`;

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

app.post("/validate", async (req, res) => {
  const { password, deviceId, deviceLabel, mode } = req.body ?? {};
  if (typeof password !== "string" || !password || typeof deviceId !== "string" || !deviceId) {
    res.status(400).json({ result: "incorrect" });
    return;
  }
  // "login" (explicit password entry, may rebind) or "revalidate"
  // (background check, never rebinds). Anything else defaults to login.
  const validateMode = mode === "revalidate" ? "revalidate" : "login";
  try {
    const outcome = await validateWithRebind(password, deviceId, deviceLabel, validateMode);
    res.status(200).json(outcome);
  } catch (error) {
    console.error("Password validation failed", { message: error.message });
    res.status(503).json({ result: "unavailable" });
  }
});

app.post("/admin/create-password", async (req, res) => {
  const { adminPassword, deviceId } = req.body ?? {};
  const admin = await verifyAdmin(adminPassword, deviceId);
  if (!admin.row) {
    res.status(401).json({ result: "unauthorized" });
    return;
  }
  // Generate a code whose hash is not already in use (collision is
  // near-impossible with 32^5 codes, but check anyway).
  let code = null;
  for (let attempt = 0; attempt < 5 && !code; attempt += 1) {
    const candidate = generateUserCode();
    const { data } = await supabaseAdmin
      .from("ms_passwords")
      .select("id")
      .eq("password_hash", hashPassword(candidate))
      .maybeSingle();
    if (!data) code = candidate;
  }
  if (!code) {
    res.status(500).json({ result: "unavailable" });
    return;
  }
  const { error } = await supabaseAdmin.from("ms_passwords").insert({
    password_hash: hashPassword(code),
    role: "user",
    active: true,
    device_id: null,
    device_label: null,
  });
  if (error) {
    console.error("Password creation failed", { message: error.message });
    res.status(500).json({ result: "unavailable" });
    return;
  }
  // Plain code is returned ONCE, here. It is never stored or logged.
  res.status(201).json({ result: "ok", password: code });
});

app.post("/admin/passwords", async (req, res) => {
  const { adminPassword } = req.body ?? {};
  const admin = await verifyAdmin(adminPassword);
  if (!admin.row) {
    res.status(401).json({ result: "unauthorized" });
    return;
  }
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .select("id, role, device_id, device_label, active, created_at, last_used_at")
    .order("created_at", { ascending: false });
  if (error) {
    console.error("Password list failed", { message: error.message });
    res.status(500).json({ result: "unavailable" });
    return;
  }
  // No hashes and no plain passwords are ever returned.
  res.status(200).json({ result: "ok", passwords: data ?? [] });
});

app.post("/admin/deactivate", async (req, res) => {
  const { adminPassword, id } = req.body ?? {};
  const admin = await verifyAdmin(adminPassword);
  if (!admin.row) {
    res.status(401).json({ result: "unauthorized" });
    return;
  }
  if (typeof id !== "string" || !id) {
    res.status(400).json({ result: "not-found" });
    return;
  }
  const { data, error } = await supabaseAdmin
    .from("ms_passwords")
    .update({ active: false })
    .eq("id", id)
    .select("id")
    .maybeSingle();
  if (error) {
    console.error("Password deactivate failed", { message: error.message });
    res.status(500).json({ result: "unavailable" });
    return;
  }
  if (!data) {
    res.status(404).json({ result: "not-found" });
    return;
  }
  res.status(200).json({ result: "ok" });
});

app.post("/drive/list", async (req, res) => {
  const { password, deviceId, folderId } = req.body ?? {};
  if (typeof password !== "string" || !password || typeof deviceId !== "string" || !deviceId) {
    res.status(400).json({ result: "incorrect" });
    return;
  }
  try {
    const outcome = await validateNoRebind(password, deviceId);
    if (outcome.result !== "valid") {
      res.status(200).json({ result: outcome.result });
      return;
    }
  } catch (error) {
    console.error("Drive list validation failed", { message: error.message });
    res.status(503).json({ result: "unavailable" });
    return;
  }
  if (!drive) {
    res.status(200).json({ result: "drive-not-configured" });
    return;
  }
  const parentId = (typeof folderId === "string" && folderId.trim()) || driveFolderId;
  if (!parentId) {
    res.status(200).json({ result: "drive-not-configured" });
    return;
  }
  try {
    const { data } = await drive.files.list({
      q: `'${parentId.replace(/'/g, "")}' in parents and trashed = false`,
      fields: "files(id, name, mimeType, size, modifiedTime, webViewLink)",
      orderBy: "folder, name",
      pageSize: 100,
    });
    const files = (data.files ?? []).map((file) => ({
      id: file.id,
      name: file.name,
      mimeType: file.mimeType,
      size: file.size ?? null,
      modifiedTime: file.modifiedTime,
      link: directLink(file.id),
      viewerLink: file.webViewLink ?? viewerLink(file.id),
      isFolder: file.mimeType === "application/vnd.google-apps.folder",
    }));
    res.status(200).json({ result: "ok", files });
  } catch (error) {
    console.error("Drive list failed", { message: error.message });
    res.status(503).json({ result: "unavailable" });
  }
});

app.post("/drive/upload", upload.single("file"), async (req, res) => {
  const { password, deviceId, title, kind, folderId, sectionId } = req.body ?? {};
  if (typeof password !== "string" || !password) {
    res.status(400).json({ result: "incorrect" });
    return;
  }
  let role;
  try {
    const outcome = await validateNoRebind(password, deviceId);
    if (outcome.result === "incorrect") {
      res.status(200).json({ result: "incorrect" });
      return;
    }
    if (outcome.result === "kicked") {
      res.status(200).json({ result: "kicked" });
      return;
    }
    role = outcome.role;
  } catch (error) {
    console.error("Drive upload validation failed", { message: error.message });
    res.status(503).json({ result: "unavailable" });
    return;
  }
  if (role !== "admin") {
    res.status(401).json({ result: "unauthorized" });
    return;
  }
  if (!drive) {
    res.status(200).json({ result: "drive-not-configured" });
    return;
  }
  if (!req.file) {
    res.status(400).json({ result: "unavailable" });
    return;
  }
  const parentId = (typeof folderId === "string" && folderId.trim()) || driveFolderId;
  if (!parentId) {
    res.status(200).json({ result: "drive-not-configured" });
    return;
  }
  try {
    const { data } = await drive.files.create({
      requestBody: {
        name: title ? String(title) : req.file.originalname,
        parents: [parentId],
      },
      media: { mimeType: req.file.mimetype, body: req.file.buffer },
      fields: "id, name, size",
    });
    const fileId = data.id;
    const response = {
      result: "ok",
      fileId,
      link: directLink(fileId),
      viewerLink: viewerLink(fileId),
      name: data.name,
      size: data.size ?? String(req.file.size),
    };
    // Optional catalogue row: only when a title is supplied.
    if (typeof title === "string" && title.trim()) {
      const { data: item, error } = await supabaseAdmin
        .from("ms_items")
        .insert({
          kind: typeof kind === "string" && kind.trim() ? kind.trim() : null,
          title: title.trim(),
          folder_id: typeof folderId === "string" && folderId.trim() ? folderId.trim() : null,
          section_id: typeof sectionId === "string" && sectionId.trim() ? sectionId.trim() : null,
          drive_file_id: fileId,
          drive_link: directLink(fileId),
        })
        .select("id")
        .single();
      if (error) {
        // The file is already in Drive; a failed catalogue row must not
        // fail the upload — log it and return without itemId.
        console.error("ms_items insert failed (file is in Drive)", { message: error.message });
      } else if (item) {
        response.itemId = item.id;
      }
    }
    res.status(200).json(response);
  } catch (error) {
    console.error("Drive upload failed", { message: error.message });
    res.status(503).json({ result: "unavailable" });
  }
});

app.use((_req, res) => res.status(404).json({ message: "Route not found." }));
app.use((error, _req, res, _next) => {
  console.error("Unhandled server error", { message: error.message });
  res.status(500).json({ message: "MS Study service failed unexpectedly." });
});

app.listen(port, () => console.log(`MS Study server started on port ${port}`));
