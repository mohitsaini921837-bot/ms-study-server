# MS Study Server

Password gate + Google Drive file server for the MS Study app (personal
study APK, no Play Store). **Separate** from the PW password server and
from Kiara Chat: this server talks to its **own new Supabase project**
(`ms_passwords` / `ms_items` tables) and its **own Google Drive service
account**. Passwords must never mix with the PW app or Kiara Chat.

Rules:

- No password expiry, ever.
- One password = one device. A new device that validates with a password
  **rebinds** it to itself and gets `valid`; the old device gets `kicked`
  on its next validation (tracked via `kicked_device_id`, so the old
  device cannot silently rebind itself back).
- Admin password is used to create user passwords (`MS-XXXXX`) and to
  upload files to Drive. Only the admin can upload.
- Files live in Google Drive (service account). The app plays PDFs /
  videos from the direct `uc` link in its own viewer/player; there is no
  download button in the app.

## Deploy steps (manual — nothing here is automated)

### (a) Create the GitHub repo and push these files

1. On GitHub, signed in as **mohitsaini921837-bot**, create a new
   **public or private** repo named **`ms-study-server`**.
2. From this directory, push:
   ```bash
   cd ~/workspace/ms-study/server
   git init
   git add server.mjs package.json seed-admin.mjs README.md DRIVE_SETUP.md
   git commit -m "MS Study server: password gate + Drive"
   git branch -M main
   git remote add origin https://github.com/mohitsaini921837-bot/ms-study-server.git
   git push -u origin main
   ```
   **Never** commit a service-account JSON key, a `.env` file, or any
   password. The repo must contain only the five files above.

### (b) Create the Render Web Service

1. In [Render](https://dashboard.render.com) → **New → Web Service** →
   **Build and deploy from a Git repository** → pick
   `mohitsaini921837-bot/ms-study-server`.
2. Settings:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `node server.mjs`
   - **Plan:** Free is fine to start (uploads hold the file in RAM —
     see "Upload size" under Security notes).
3. Deploy. The service URL will be like
   `https://ms-study-server.onrender.com` — that is the base URL the
   app client uses. Check `GET <url>/health` returns `{"ok":true}`.

### (c) Set the environment variables (Render → service → Environment)

| Variable | Value |
|---|---|
| `SUPABASE_URL` | New MS Study Supabase project URL, e.g. `https://xyzcompany.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | The project's **service_role** key (NOT the anon key) |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Entire service-account JSON file contents, pasted as **one line** (see DRIVE_SETUP.md) |
| `MS_DRIVE_FOLDER_ID` | ID of the "MS Study" Drive folder (see DRIVE_SETUP.md) |

`PORT` is set by Render automatically; do not set it yourself.

### (d) Create the Supabase tables, then seed the admin password

1. Create the **new** Supabase project for MS Study (do NOT reuse the
   PW project's or Kiara Chat's project).
2. In the Supabase SQL Editor, run the canonical schema file
   `supabase/setup-ms-study.sql` (in the ms-study project — it creates
   all 8 `ms_*` tables with RLS + policies + indexes, including
   `ms_passwords` and `ms_items`). Do NOT use a subset: the full file
   is the single source of truth.

   Note: `kicked_device_id` on `ms_passwords` is what makes the kick
   rule work — it remembers the device a password was taken away from,
   so that device gets `kicked` instead of silently stealing the
   password back. `password_hash` is UNIQUE (required by the seed
   script's upsert).
3. Seed the admin password **once** (Render Shell, or locally with the
   env vars set — the password is never printed):
   ```bash
   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... MS_ADMIN_PASSWORD=<choose-a-strong-admin-password> node seed-admin.mjs
   ```
   Or `npm run seed-admin` with the same env vars set. Keep the admin
   password somewhere safe (password manager) — it cannot be recovered
   from the server, only reset by re-running this script with a new one
   (that replaces the admin row's hash; the old admin password stops
   working). To let a kicked device back in, an admin creates it a new
   user password — a kicked device can never re-validate with the old one.

## Endpoint table

Base URL: the Render service URL. All requests/responses are JSON,
except `POST /drive/upload` which is `multipart/form-data`.

| Method & path | Body | Returns |
|---|---|---|
| `GET /health` | — | `{ok:true}` |
| `POST /validate` | `{password, deviceId, deviceLabel}` | `{result:"valid", role:"admin"\|"user"}` \| `{result:"incorrect"}` \| `{result:"kicked"}`. New device rebinds the password to itself; old device gets `kicked` next time. `last_used_at` is refreshed on success. |
| `POST /admin/create-password` | `{adminPassword, deviceId}` | `{result:"ok", password:"MS-XXXXX"}` (plain code returned **once**) \| `{result:"unauthorized"}`. Code is 5 chars, A–Z + 2–9 (no 0/O/1/I). |
| `POST /admin/passwords` | `{adminPassword}` | `{result:"ok", passwords:[{id, role, device_id, device_label, active, created_at, last_used_at}]}` \| `{result:"unauthorized"}`. No hashes, no plain passwords. |
| `POST /admin/deactivate` | `{adminPassword, id}` | `{result:"ok"}` \| `{result:"unauthorized"}` \| `{result:"not-found"}` |
| `POST /drive/list` | `{password, deviceId, folderId?}` | `{result:"ok", files:[{id, name, mimeType, size, modifiedTime, link, viewerLink, isFolder}]}` \| `{result:"incorrect"}` \| `{result:"kicked"}` (no rebind here) \| `{result:"drive-not-configured"}`. `link` is `https://drive.google.com/uc?export=download&id=<id>`; `viewerLink` is the Drive view URL. Default folder is `MS_DRIVE_FOLDER_ID`. |
| `POST /drive/upload` | multipart: `password`, `deviceId`, `file`, `title?`, `kind?`, `folderId?`, `sectionId?` | `{result:"ok", fileId, link, viewerLink, name, size, itemId?}` \| `{result:"unauthorized"}` (valid password but not admin) \| `{result:"incorrect"}` \| `{result:"kicked"}` (admin device bound elsewhere) \| `{result:"drive-not-configured"}`. `itemId` is returned only when `title` is given (a row is inserted into `ms_items`). Admin only. |

Other failures (e.g. Supabase/Drive temporarily down) return
`{result:"unavailable"}` with HTTP 503. Unknown routes return 404.

## Security notes

- **SHA-256 unsalted hashes — same as the PW server, with the same
  caveat:** an unsalted fast hash means anyone who ever obtains a
  database dump could brute-force weak passwords offline. Mitigations
  in place: passwords are random codes (`MS-XXXXX`, ~25 bits of
  entropy) or a strong admin password; only the hash is stored; the
  service-role key never leaves the server. If stronger hashing
  (bcrypt/argon2) is ever wanted, it must be changed in both
  `server.mjs` and `seed-admin.mjs` together — do not change one side
  only.
- **Service-account JSON lives ONLY as a Render env var**
  (`GOOGLE_SERVICE_ACCOUNT_JSON`). Never commit it to git, never put
  it in the APK, never paste it into chat. Anyone with it can read and
  write the "MS Study" Drive folder.
- **Service-role key** likewise lives only in Render env vars. It
  bypasses Row Level Security — keep it off the client and out of the
  APK. The app talks to this server, never directly to Supabase.
- **Upload size:** uploads are held in server RAM (multer memory
  storage, 512 MB limit). On Render Free (512 MB RAM) a very large
  video upload can run the server out of memory — upload big videos
  from the Drive web UI into the folder instead, or raise the plan.
- **CORS is allow-all** (same as the PW server), because the APK calls
  this server directly. There is no per-origin allow-list.
- **No password expiry** by design — there is no expiry column and no
  expiry check anywhere in the code.
- **The PW server is untouched.** This service is a separate repo,
  separate Render service, separate Supabase project, separate Drive
  account. Do not point it at the PW project's Supabase URL or the PW
  Drive folder.
