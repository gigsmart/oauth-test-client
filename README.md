# GigSmart OAuth test client

Minimal confidential-client integration (authorization code + PKCE S256) to verify GigSmart's OAuth server end to end. Express backend, React frontend, Postgres for state and AES-256-GCM-encrypted tokens.

## Register the app

Register it manually in the developer portal of the target environment (beta: `https://api.gigsmart.soy`):

- Redirect URI: `https://localhost:8443/oauth/callback`. Deployed envs reject `http://localhost`; `https://localhost` passes.
- Grant type: `authorization_code` (add `refresh_token` if you want refresh later)
- Token auth method: `client_secret_basic`
- Scopes: `read:requester_profile`

Copy the client id and secret into `.env`.

## Run

```sh
cp .env.example .env    # fill in client id/secret and TOKEN_ENCRYPTION_KEY (openssl rand -base64 32)
npm install
npm run cert            # self-signed cert for https://localhost
npm run db              # postgres on 127.0.0.1:54329, schema applied on first start
npm start               # builds web, serves https://localhost:8443
npm test                # crypto + PKCE self-checks
```

Open `https://localhost:8443`, accept the self-signed cert, click **Connect GigSmart**, sign in as a requester. Success: the page shows `connected: true` and `graphql.data.viewer`.

## Local API

`.env.local` targets a local GigSmart API instead of beta. It holds its own client id and secret, registered straight into the local database:

```sh
npm run register:local   # upserts the app from .env.local; rerun after changing the secret, port, or scopes
npm run start:local      # same as start, but with .env.local
```

`GIGSMART_BASE_URL` and `GIGSMART_API_DIR` point at one monorepo worktree; every worktree has its own `$API_PORT` (`mise run ports:status`). Start that worktree's API (`iex -S mix phx.server`) first.

## Errors

The callback surfaces failures as `?error=...` on the page. `authorization_not_started` on GigSmart's own sign-in page means its `_gigsmart_oauth` session cookie was lost between `/oauth/authorize` and `/oauth/login`; restart from **Connect GigSmart**.
