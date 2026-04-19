/**
 * Validate required environment variables at startup.
 * Fails fast with a clear error instead of mysterious runtime crashes.
 */
import logger from "./logger.js";

const REQUIRED = [
  "DATABASE_URL",
  "JWT_SECRET",
];

const RECOMMENDED = [
  "ENCRYPTION_KEY",
  "NODE_ENV",
];

const PRODUCTION_REQUIRED = [
  "ENCRYPTION_KEY",
];

export function validateEnv() {
  const missing = [];
  const warnings = [];

  for (const key of REQUIRED) {
    if (!process.env[key] || !String(process.env[key]).trim()) {
      missing.push(key);
    }
  }

  for (const key of RECOMMENDED) {
    if (!process.env[key]) warnings.push(key);
  }

  if (process.env.NODE_ENV === "production") {
    for (const key of PRODUCTION_REQUIRED) {
      if (!process.env[key]) {
        missing.push(`${key} (required in production)`);
      }
    }
  }

  // JWT secret strength check
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    missing.push("JWT_SECRET (must be >= 32 chars)");
  }

  // Encryption key format check
  if (process.env.ENCRYPTION_KEY && !/^[0-9a-f]{64}$/i.test(process.env.ENCRYPTION_KEY)) {
    missing.push("ENCRYPTION_KEY (must be 64 hex chars = 32 bytes)");
  }

  if (warnings.length) {
    logger.warn({ missing: warnings }, "Recommended env vars are not set");
  }

  if (missing.length) {
    logger.fatal({ missing }, "Missing required environment variables â€” refusing to start");
    process.exit(1);
  }

  logger.info("Environment validation passed");
}
