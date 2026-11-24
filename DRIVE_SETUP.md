# MS Study — Google Drive setup

Do this with the **user's Google login** (the parent agent handles this
with him). Every step uses the **NEW MS Study Google account** — the one
being created now — **not** his personal account and **not** any account
used by the PW app or Kiara Chat. The Drive holds all study notes,
sheets and videos (15 GB free on that account).

## Steps

### 1. Use the new MS Study Google account

Sign in to Google with the new MS Study account (the one created just
for this app). All steps below happen in that account.

### 2. Create a Google Cloud project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
   (signed in as the new MS Study account).
2. Top bar → project picker → **New Project**.
3. Project name: **`MS Study`** → **Create**. Wait for it to be created
   and selected.

### 3. Enable the Google Drive API

1. Left menu → **APIs & Services → Library**.
2. Search **`Google Drive API`** → open it → **Enable**.

### 4. Create the service account and download its JSON key

1. Left menu → **IAM & Admin → Service Accounts** → **Create Service
   Account**.
2. Service account name: **`ms-study-drive`** (ID fills in
   automatically). Click **Create and Continue**.
3. Role: **no role needed** — click **Continue**, then **Done**.
   (Access to the folder is granted by sharing the folder with the
   service account in step 5, not by a Cloud role.)
4. Click the new `ms-study-drive` account → **Keys** tab → **Add Key →
   Create new key** → **JSON** → **Create**.
5. A `.json` file downloads. **Keep this file safe.** It is the only
   copy of the private key — Google will not show it again.

### 5. Create the Drive folder and share it with the service account

1. Open [Google Drive](https://drive.google.com) (same new MS Study
   account) → **New → New folder** → name it **`MS Study`** → Create.
2. Find the service-account email inside the downloaded JSON file: it
   is the `client_email` value and looks like
   `ms-study-drive@<project-id>.iam.gserviceaccount.com`.
3. In Drive, right-click the **MS Study** folder → **Share** → paste
   that service-account email → set role to **Editor** → **Share**
   (uncheck "Notify people" — a service account has no inbox).
   Without this share, the server gets "not found" errors for the folder.

### 6. Copy the folder ID

Open the **MS Study** folder in Drive. The URL looks like:

```
https://drive.google.com/drive/folders/1AbC2dEfGhIjKlMnOpQrStUvWxYz
```

The part after `/folders/` is the folder ID. Copy it — this is
`MS_DRIVE_FOLDER_ID`.

### 7. Put both values into Render

Render → `ms-study-server` service → **Environment** → add:

| Variable | Value |
|---|---|
| `GOOGLE_SERVICE_ACCOUNT_JSON` | The **entire contents** of the downloaded JSON file, pasted as **one line** (remove line breaks, or paste it and let Render keep it as one value) |
| `MS_DRIVE_FOLDER_ID` | The folder ID from step 6 |

Save, then **redeploy** (or "Manual Deploy → Deploy latest commit") so
the new env vars take effect. Then check `GET <service-url>/health`
and a `POST /drive/list` call — it should return `{"result":"ok",
"files":[...]}` instead of `{"result":"drive-not-configured"}`.

## Warnings

- **NEVER commit the JSON key file to git** (not to
  `ms-study-server`, not anywhere). If it ever lands in a repo, delete
  that key in Cloud Console → Service Accounts → Keys and create a new
  one.
- **NEVER put the JSON key in the app / APK.** The app never talks to
  Google directly — only this server does, using the key from its Render
  env vars.
- **NEVER share the "MS Study" folder publicly** ("Anyone with the
  link"). Only the service account gets Editor access; the app reads
  files through this server's password check.
- If the JSON key is lost or leaked, delete it in Cloud Console and
  repeat step 4, then update `GOOGLE_SERVICE_ACCOUNT_JSON` in Render.
