# URL Shortener

A small personal URL shortener (Express + MongoDB). Following a short link is public;
everything else needs a login or an API token.

## Routes

| Route | Who | What |
| --- | --- | --- |
| `GET /<slug>` | public | 302 redirect to the target; 404 for unknown slugs |
| `GET /public/*` | public | stylesheet and script of the pages |
| `GET /login`, `POST /login` | public | sign-in form |
| `GET /setup?token=…`, `POST /setup` | setup token, only while no login exists | creates the one login, then answers 404 for good |
| `GET /` | login | the admin page: list, filter, add, edit, delete, change password |
| `POST /logout` | login + CSRF token | signs out every browser |
| `POST /account/password` | login + CSRF token | change the password (needs the current one) |
| `GET /api/session` | login or token | who is signed in, and the CSRF token for the page |
| `GET /api/links` | login or token | all links |
| `POST /api/links` | login or token | create: `{"url": "...", "slug": "..."}`; without `slug` the next free number is used |
| `PUT /api/links/<slug>` | login or token | change the target: `{"url": "..."}` |
| `DELETE /api/links/<slug>` | login or token | delete |

The old open routes `POST /add`, `GET /redirects` and `GET /success` are gone (404).

## Login

There is one user. The password is stored only as a scrypt hash (N=32768, r=8, p=3, random
salt) in the database, next to the links. A sign-in sets the cookie `__Host-urlsession`
(`Secure`, `HttpOnly`, `SameSite=Lax`, 30 days), signed with `SESSION_SECRET`. Requests from
the browser that change something must come from the app's own origin and carry the session's
CSRF token (`X-CSRF-Token` header, or `_csrf` in a form).

Wrong tries (password, API token, setup token) are slowed down: per address the first 4 are
free, the 5th locks that address for 30 seconds, and every further one doubles the lock up to
15 minutes. Across all addresses at most 20 wrong tries per 10 minutes are accepted. During a
lock the answer is `429` with `Retry-After`, also for the right password. Redirects are never
locked.

### First-time setup

1. Put `SESSION_SECRET` and `SETUP_TOKEN` (each `openssl rand -hex 32`) into the service's
   environment and restart it. The log says "the one-time setup page is open".
2. Open `https://<host>/setup?token=<SETUP_TOKEN>`, choose a user name and a password
   (12 to 128 characters; let the password manager generate it).
3. The page closes as soon as the login exists. Empty `SETUP_TOKEN` again and restart.

## API token (for scripts and agents)

`API_TOKEN` in the service's environment is a bearer token for the `/api` routes. It needs no
cookie and no CSRF token. It cannot change the password.

```sh
# the token is kept as the line url-felkru-token=... in ~/.env
TOKEN=$(grep '^url-felkru-token=' ~/.env | cut -d= -f2-)
curl -sS -X POST https://url.felkru.com/api/links \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug": "my-talk", "url": "https://example.org/slides"}'
# → 201 {"slug":"my-talk","url":"https://example.org/slides","short_url":"https://url.felkru.com/my-talk"}

curl -sS https://url.felkru.com/api/links -H "Authorization: Bearer $TOKEN"                 # list
curl -sS -X PUT https://url.felkru.com/api/links/my-talk -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"url": "https://example.org/new"}'               # change
curl -sS -X DELETE https://url.felkru.com/api/links/my-talk -H "Authorization: Bearer $TOKEN" # delete
```

Answers: `400` invalid input (the `error` field says why), `401` no or wrong token, `409` slug
exists already, `429` too many requests or wrong tries.

## Rules for links

- Targets: `http` and `https` only, at most 2048 characters, a full host name, no user name or
  password in the URL, no spaces or control characters, not the shortener itself. Input without
  a scheme gets `https://`. `javascript:`, `data:`, `file:` and every other scheme are refused.
- Slugs: 1 to 64 characters from `A-Z a-z 0-9 - _`, case-sensitive, and not a name the app
  uses itself (`login`, `logout`, `setup`, `api`, `public`, `account`, `add`, …). Older links
  with other characters keep working and can be edited or deleted.
- At most 5000 links; request bodies up to 8 kB.

## Rotating secrets

| What | How |
| --- | --- |
| Password | Admin page → "Change password" (needs the current one). Every other session ends. |
| Lost password | `node scripts/reset-login.js --yes` inside the container removes the login (links stay). Then do the first-time setup again with a new `SETUP_TOKEN`. |
| API token | Put a new `openssl rand -hex 32` into the environment as `API_TOKEN`, restart the service, update the copies (`url-felkru-token` in `~/.env`). The old token stops working at once. |
| Session secret | New `SESSION_SECRET`, restart: every browser is signed out. |
| Database password | Change it at the database host, update `db_uri`, restart. |

## Configuration

| Variable | Meaning |
| --- | --- |
| `db_uri` | MongoDB connection string. Links: database `felkrucom`, collection `short_urls`, one document `{ function: "sync urls", <slug>: <target>, … }`. Login: collection `shortener_auth`. |
| `PORT` | default 3000 |
| `PUBLIC_ORIGIN` | default `https://url.felkru.com`; used for the origin check and in `short_url` |
| `SESSION_SECRET` | at least 32 characters; without it browser login is switched off |
| `API_TOKEN` | at least 32 characters; without it the token API is switched off |
| `SETUP_TOKEN` | at least 32 characters; only needed for the first-time setup |

Redirects work without any of the three secrets; the admin side then stays closed.
No secret belongs in this repository: they live in the environment of the server.

## Behind a proxy

The app expects a reverse proxy in front that terminates TLS and sets `X-Forwarded-For` to the
address that connected to it (Traefik does). If that address is Cloudflare's, the visitor's
address is taken from `CF-Connecting-IP`; from anywhere else that header is ignored. The address
is only used for the rate limits (240 redirects and 120 admin or API requests per minute and
address) and in the log lines about sign-ins.

Every page sends a strict `Content-Security-Policy` (no inline script, `frame-ancestors 'none'`),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and
`Cache-Control: no-store`. Errors never include a stack trace.

## Run and test locally

```sh
npm ci
cp sample.env .env   # fill in db_uri and the secrets
npm run dev
npm test             # end-to-end tests with an in-memory store, no database needed
```

## Deploy

The image builds from this repository's `main` branch (see `Dockerfile`: Node 22, locked
dependencies, runs as the unprivileged `node` user). On the server:

```sh
docker compose up -d --build url-shortener
```
