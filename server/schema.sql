-- One row per in-flight authorization request; consumed by the callback.
CREATE TABLE oauth_states (
  state         text PRIMARY KEY,
  session_id    text NOT NULL,
  code_verifier text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Tokens are AES-256-GCM ciphertext; the key never touches the database.
CREATE TABLE credentials (
  session_id        text PRIMARY KEY,
  access_token_enc  text NOT NULL,
  refresh_token_enc text,
  scope             text,
  expires_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
