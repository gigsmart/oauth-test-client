import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import express from "express";
import pg from "pg";
import { decrypt, encrypt, loadKey, pkceChallenge, randomToken } from "./crypto.js";

const env = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required (see .env.example)`);
  return value;
};

const GIGSMART = env("GIGSMART_BASE_URL").replace(/\/$/, "");
const CLIENT_ID = env("GIGSMART_CLIENT_ID");
const CLIENT_SECRET = env("GIGSMART_CLIENT_SECRET");
const SCOPES = process.env.GIGSMART_SCOPES ?? "read:requester_profile";
const PORT = Number(process.env.PORT ?? 8443);
const REDIRECT_URI = `https://localhost:${PORT}/oauth/callback`;
const KEY = loadKey(process.env.TOKEN_ENCRYPTION_KEY);
const STATE_TTL = "10 minutes";

const db = new pg.Pool({ connectionString: env("DATABASE_URL") });
const app = express();

// Opaque browser session id; everything else lives server-side.
app.use((req, res, next) => {
  const match = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie ?? "");
  req.sid = match?.[1];
  if (!req.sid) {
    req.sid = randomToken();
    res.cookie("sid", req.sid, { httpOnly: true, secure: true, sameSite: "lax" });
  }
  next();
});

app.get("/auth/login", async (req, res) => {
  const state = randomToken();
  const verifier = randomToken();
  await db.query("INSERT INTO oauth_states (state, session_id, code_verifier) VALUES ($1, $2, $3)", [
    state,
    req.sid,
    verifier,
  ]);
  const url = new URL(`${GIGSMART}/oauth/authorize`);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
  });
  res.redirect(url.href);
});

app.get("/oauth/callback", async (req, res) => {
  const fail = (error) => res.redirect(`/?error=${encodeURIComponent(error)}`);
  const { code, state, error, error_description } = req.query;
  if (error) return fail(`${error}: ${error_description ?? ""}`);

  // Single-use and bound to this browser: a replayed or foreign state finds no row.
  const { rows } = await db.query(
    `DELETE FROM oauth_states
     WHERE state = $1 AND session_id = $2 AND created_at > now() - $3::interval
     RETURNING code_verifier`,
    [String(state ?? ""), req.sid, STATE_TTL]
  );
  if (!rows[0]) return fail("invalid_state: unknown, expired, or started in another browser");

  const tokenRes = await fetch(`${GIGSMART}/oauth/token`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: REDIRECT_URI,
      code_verifier: rows[0].code_verifier,
    }),
  });
  const token = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok) return fail(`token_exchange_${tokenRes.status}: ${token.error ?? ""} ${token.error_description ?? ""}`);

  await db.query(
    `INSERT INTO credentials (session_id, access_token_enc, refresh_token_enc, scope, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
     ON CONFLICT (session_id) DO UPDATE SET
       access_token_enc = EXCLUDED.access_token_enc, refresh_token_enc = EXCLUDED.refresh_token_enc,
       scope = EXCLUDED.scope, expires_at = EXCLUDED.expires_at, created_at = now()`,
    [
      req.sid,
      encrypt(token.access_token, KEY),
      token.refresh_token ? encrypt(token.refresh_token, KEY) : null,
      token.scope ?? null,
      token.expires_in ?? null,
    ]
  );
  res.redirect("/");
});

app.get("/api/me", async (req, res) => {
  const { rows } = await db.query("SELECT access_token_enc, scope, expires_at FROM credentials WHERE session_id = $1", [
    req.sid,
  ]);
  if (!rows[0]) return res.json({ connected: false });

  const gql = await fetch(`${GIGSMART}/graphql`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${decrypt(rows[0].access_token_enc, KEY)}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ query: "{ viewer { __typename id displayName } }" }),
  });
  res.json({
    connected: true,
    scope: rows[0].scope,
    expiresAt: rows[0].expires_at,
    graphqlStatus: gql.status,
    graphql: await gql.json().catch(() => null),
  });
});

app.post("/auth/logout", async (req, res) => {
  await db.query("DELETE FROM credentials WHERE session_id = $1", [req.sid]);
  res.sendStatus(204);
});

app.use(express.static(new URL("../web/dist", import.meta.url).pathname));

const cert = new URL("../.cert/", import.meta.url);
createServer({ key: readFileSync(new URL("key.pem", cert)), cert: readFileSync(new URL("cert.pem", cert)) }, app).listen(
  PORT,
  () => console.log(`https://localhost:${PORT}  →  ${GIGSMART}  (redirect_uri ${REDIRECT_URI})`)
);
