// Seed the MS Study admin password — run ONCE after the Supabase project
// and the ms_passwords table exist (see README.md).
//
// Usage (from the server directory, or in Render Shell):
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... MS_ADMIN_PASSWORD=... node seed-admin.mjs
//
// The password is read from the environment, SHA-256 hashed, and upserted
// as the single admin row (role='admin', active=true, device unbound).
// The password is NEVER printed or logged — only success/failure is shown.

import { createHash } from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const adminPassword = process.env.MS_ADMIN_PASSWORD;

if (!supabaseUrl || !supabaseServiceRoleKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.");
  process.exit(1);
}
if (!adminPassword || adminPassword.length < 8) {
  console.error("Missing MS_ADMIN_PASSWORD (must be at least 8 characters).");
  process.exit(1);
}

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const passwordHash = createHash("sha256").update(adminPassword, "utf8").digest("hex");

const { error } = await supabaseAdmin.from("ms_passwords").upsert(
  {
    password_hash: passwordHash,
    role: "admin",
    active: true,
    device_id: null,
    device_label: null,
    kicked_device_id: null,
  },
  { onConflict: "password_hash" }
);

if (error) {
  console.error("Failed to seed admin password.", { message: error.message });
  process.exit(1);
}

console.log("Admin password seeded (role=admin, active=true, device unbound).");
