import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export const randomToken = () => randomBytes(32).toString("base64url");

export const pkceChallenge = (verifier) => createHash("sha256").update(verifier).digest("base64url");

// Output: base64url(iv | tag | ciphertext). GCM's tag makes tampering fail decryption.
export function encrypt(plaintext, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64url");
}

export function decrypt(encoded, key) {
  const buf = Buffer.from(encoded, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
}

export function loadKey(base64) {
  const key = Buffer.from(base64 ?? "", "base64");
  if (key.length !== 32) throw new Error("TOKEN_ENCRYPTION_KEY must be 32 bytes, base64-encoded");
  return key;
}
