import { describe, it, expect, beforeAll } from "vitest";
import crypto from "crypto";

// Generate a fresh test key BEFORE importing the module
const TEST_KEY = crypto.randomBytes(32).toString("hex");
process.env.ENCRYPTION_KEY = TEST_KEY;
process.env.LOG_LEVEL = "silent";

let encrypt, decrypt, blindIndex, isEncryptionEnabled, decryptFields;
beforeAll(async () => {
  ({ encrypt, decrypt, blindIndex, isEncryptionEnabled, decryptFields } =
    await import("../src/utils/crypto.js"));
});

describe("crypto utils", () => {
  describe("encrypt/decrypt round-trip", () => {
    it("encrypts and decrypts ASCII", () => {
      const ct = encrypt("hello world");
      expect(ct).toMatch(/^enc:/);
      expect(decrypt(ct)).toBe("hello world");
    });

    it("encrypts and decrypts Arabic UTF-8", () => {
      const plain = "مصطفى عبد الله — 0797973766";
      const ct = encrypt(plain);
      expect(ct).toMatch(/^enc:/);
      expect(decrypt(ct)).toBe(plain);
    });

    it("produces different ciphertext each call (random IV)", () => {
      const a = encrypt("same input");
      const b = encrypt("same input");
      expect(a).not.toBe(b);
      expect(decrypt(a)).toBe("same input");
      expect(decrypt(b)).toBe("same input");
    });

    it("does not double-encrypt", () => {
      const once = encrypt("x");
      const twice = encrypt(once);
      expect(twice).toBe(once);
    });

    it("passes through null/undefined unchanged", () => {
      expect(encrypt(null)).toBeNull();
      expect(encrypt(undefined)).toBeUndefined();
      expect(decrypt(null)).toBeNull();
      expect(decrypt(undefined)).toBeUndefined();
    });

    it("returns plaintext unchanged when not enc: prefixed (gradual migration)", () => {
      expect(decrypt("plain text")).toBe("plain text");
    });

    it("rejects tampered ciphertext (GCM auth tag check)", () => {
      const ct = encrypt("secret");
      // Flip a byte inside the base64 payload
      const broken = "enc:" + ct.slice(4, -2) + (ct.slice(-2) === "==" ? "AA" : "==");
      expect(decrypt(broken)).toBe("[decrypt-error]");
    });
  });

  describe("blindIndex", () => {
    it("is deterministic for the same input", () => {
      expect(blindIndex("user@example.com")).toBe(blindIndex("user@example.com"));
    });

    it("normalizes case and whitespace", () => {
      expect(blindIndex("  USER@Example.COM  ")).toBe(blindIndex("user@example.com"));
    });

    it("differs for different inputs", () => {
      expect(blindIndex("a@b.com")).not.toBe(blindIndex("a@c.com"));
    });

    it("returns null for empty/null", () => {
      expect(blindIndex(null)).toBeNull();
      expect(blindIndex("")).toBeNull();
    });

    it("hex-encoded SHA-256 → 64 chars", () => {
      expect(blindIndex("test")).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe("decryptFields", () => {
    it("decrypts only listed fields", () => {
      const row = {
        id: 1,
        name: encrypt("Alice"),
        email: encrypt("a@b.com"),
        notes: "plain",
      };
      const out = decryptFields(row, ["name", "email"]);
      expect(out.name).toBe("Alice");
      expect(out.email).toBe("a@b.com");
      expect(out.notes).toBe("plain");
      expect(out.id).toBe(1);
    });

    it("handles null row", () => {
      expect(decryptFields(null, ["x"])).toBeNull();
    });
  });

  it("isEncryptionEnabled() reflects key presence", () => {
    expect(isEncryptionEnabled()).toBe(true);
  });
});
