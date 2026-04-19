/**
 * Lightweight runtime input validators.
 * Intentionally tiny — no Joi/Zod dependency.
 *
 * Each helper returns a string (the trimmed/normalized value) or throws
 * a ValidationError carrying a 400-friendly message.
 */

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
    this.status = 400;
  }
}

/**
 * Express middleware: converts ValidationError to 400 JSON.
 */
export function handleValidationError(err, req, res, next) {
  if (err && err.name === "ValidationError") {
    return res.status(400).json({ error: err.message });
  }
  return next(err);
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Allow international digits, +, spaces, dashes, parentheses
const PHONE_RE = /^[+0-9 ()\-]{4,32}$/;

export function requireString(value, field, { min = 1, max = 500 } = {}) {
  if (value == null) throw new ValidationError(`${field} is required`);
  const s = String(value).trim();
  if (s.length < min) throw new ValidationError(`${field} too short`);
  if (s.length > max) throw new ValidationError(`${field} too long (max ${max})`);
  return s;
}

export function optionalString(value, field, { max = 2000 } = {}) {
  if (value == null) return null;
  const s = String(value).trim();
  if (!s) return null;
  if (s.length > max) throw new ValidationError(`${field} too long (max ${max})`);
  return s;
}

export function optionalEmail(value, field = "email") {
  const s = optionalString(value, field, { max: 254 });
  if (!s) return null;
  if (!EMAIL_RE.test(s)) throw new ValidationError(`${field} is not a valid email`);
  return s.toLowerCase();
}

export function optionalPhone(value, field = "phone") {
  const s = optionalString(value, field, { max: 32 });
  if (!s) return null;
  if (!PHONE_RE.test(s)) throw new ValidationError(`${field} is not a valid phone`);
  return s;
}

export function optionalEnum(value, field, allowed) {
  if (value == null || value === "") return null;
  const s = String(value);
  if (!allowed.includes(s)) {
    throw new ValidationError(`${field} must be one of: ${allowed.join(", ")}`);
  }
  return s;
}

export function optionalDate(value, field) {
  if (value == null || value === "") return null;
  const s = String(value).trim();
  // Accept ISO date or datetime
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new ValidationError(`${field} is not a valid date`);
  return s;
}

export function optionalInt(value, field, { min = -2147483648, max = 2147483647 } = {}) {
  if (value == null || value === "") return null;
  const n = Number(value);
  if (!Number.isInteger(n)) throw new ValidationError(`${field} must be an integer`);
  if (n < min || n > max) throw new ValidationError(`${field} out of range`);
  return n;
}

/**
 * Bound a JSON object's stringified size to prevent multi-MB blobs in jsonb columns.
 * Returns the original object (validated) or null.
 */
export function boundedJson(value, field, { maxBytes = 64 * 1024 } = {}) {
  if (value == null) return null;
  if (typeof value !== "object") {
    throw new ValidationError(`${field} must be a JSON object`);
  }
  const size = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (size > maxBytes) {
    throw new ValidationError(`${field} too large (${size} bytes, max ${maxBytes})`);
  }
  return value;
}
