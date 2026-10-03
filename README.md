# uploader

A small self-hosted drop box. Send someone a link: they pick files and press Upload. That's all they can do. You sign in to see what arrived, download it, delete it, or copy a share link to send a file the other way.

Built for the "my parents need to send me 40 GB of home videos" problem.

- **Any size, resumable.** Uploads are chunked ([tus](https://tus.io)). If the connection drops, adding the same file again continues where it stopped.
- **Upload-only for visitors.** Anonymous users can create and resume uploads. They can't list, read or delete anything.
- **Admin page** at `/admin`: upload, list, download, delete, and copy share links.
- **Share links** go to a small landing page with a Download button, so chat-app previews don't pull the whole file. A link is tied to the exact file: deleting, replacing or editing the file revokes it.
- **Email notifications** (optional). Uploads that arrive close together are sent as one email.
- **Disk safety.** New uploads are refused if they would cut into a free-space reserve, counting space already promised to unfinished uploads. Writes also stop if the local disk runs low.
- **Network-share friendly.** In-progress uploads stay on local disk. Finished files are then copied to `/data`, which can be an NFS or SMB share.
- One static Go binary in a distroless image, with no database.

## Quick start

```sh
curl -O https://raw.githubusercontent.com/MattJackson/uploader/main/docker-compose.example.yml
# set UPLOAD_SECRET (openssl rand -hex 32) and PUBLIC_URL, then:
docker compose -f docker-compose.example.yml up -d
```

Put it behind a reverse proxy that terminates TLS. The admin session cookie is `Secure`-only. For example, with Caddy:

```caddy
upload.example.com {
	reverse_proxy uploader:8080
}
```

Then open `https://upload.example.com/admin` and sign in with **`password`**. You'll be made to choose a new password before anything else works. After that, fill in **Settings** (your name, site URL, mail server) and send the main page's URL to whoever needs to send you files.

## Configuration

| Variable | Default | |
|---|---|---|
| `UPLOAD_SECRET` | — (required) | Signs sessions and share links. Long and random; changing it ends all sessions and links. |
| `DATA_DIR` | `/data` | Finished files. Can be a network share. |
| `SPOOL_DIR` | `/spool` | In-progress uploads, outbox, `admin.json`, `settings.json`. Keep it on local disk. |
| `RESERVE_GB` | `200` | Free space to always leave on each disk. |

Seed values for **Settings**. They're used only when `settings.json` doesn't exist yet. After that, edit them in the UI.

| Variable | Default | |
|---|---|---|
| `OWNER_NAME` | empty | "Send files to …" / "shared by …". Empty gives neutral wording. |
| `PUBLIC_URL` | empty | Used for links in emails. |
| `NOTIFY_TO` | empty | Address to notify. Empty means notifications are off. |
| `MAIL_FROM` | empty | Sender address. It must be one your mail server accepts. |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | Mail server. |
| `SMTP_SECURITY` | `starttls` | `starttls`, `tls` (implicit, usually port 465) or `none` (only for a relay on a private network). |
| `SMTP_USER` / `SMTP_PASS` | empty | Leave empty for no authentication. |

`settings.json` holds the SMTP password, which has to be recoverable to log in to the mail server. The file is mode 0600 and lives in the spool, so protect that volume.

## How it works

```
browser ──tus──▶ /spool/tus/<id>          (partial; idle 7 days → swept)
                     │ complete
                     ▼
               /spool/outbox/<id>/<name>   (copied, size-checked, then removed)
                     │
                     ▼
               /data/<name>                (never overwrites: "name (2).ext")
```

- If the share behind `/data` returns a stale handle (`ESTALE`), the process exits so your container runtime restarts it with a fresh mount. Uploads in progress resume.
- Visitors' filenames are cleaned. Path separators and control characters are replaced, and leading dots and bidi/invisible characters are removed.
- Admin sign-in is limited to about one password guess per second for the whole site.

## Admin password reset

Delete `SPOOL_DIR/admin.json` and restart. The password goes back to `password`, and you must change it at the next sign-in. If `admin.json` is ever corrupted, uploads keep working but admin stays locked, and the log says `ADMIN LOCKED`, until you delete the file.

## Development

```sh
go test ./...
UPLOAD_SECRET=dev DATA_DIR=./data SPOOL_DIR=./spool RESERVE_GB=1 go run .
```

Releases are built by GitHub Actions on `v*` tags and published as `ghcr.io/mattjackson/uploader:{version,latest}` for amd64 and arm64.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md) for bundled third-party code.
