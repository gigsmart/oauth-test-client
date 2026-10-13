import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { decrypt, encrypt, pkceChallenge } from "./crypto.js";

const key = randomBytes(32);

test("round-trips a token", () => {
  assert.equal(decrypt(encrypt("secret-token", key), key), "secret-token");
});

test("rejects tampered ciphertext", () => {
  const buf = Buffer.from(encrypt("secret-token", key), "base64url");
  buf[buf.length - 1] ^= 1;
  assert.throws(() => decrypt(buf.toString("base64url"), key));
});

test("rejects the wrong key", () => {
  assert.throws(() => decrypt(encrypt("secret-token", key), randomBytes(32)));
});

test("PKCE S256 matches the RFC 7636 appendix B vector", () => {
  assert.equal(
    pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  );
});
