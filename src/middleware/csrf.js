/**
 * Lightweight CSRF mitigation for browser-origin requests.
 *
 * Strategy: This API uses Authorization: Bearer JWT (not cookie sessions),
 * which is already not auto-sent by browsers and therefore not exploitable
 * via classic CSRF. As an additional defense-in-depth control, we require a
 * custom header on all state-changing requests from browsers. Because
 * cross-origin requests cannot set custom headers without a successful CORS
 * preflight (which our server only grants to allowedOrigins), this blocks
 * cross-site form submissions.
 */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function csrfGuard(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  // Skip server-to-server callers (no Origin/Referer + non-browser UA).
  // Bridge agent uses X-Bridge-Key on /bridge/* and is mounted before this.
  const origin = req.headers.origin || req.headers.referer || "";
  if (!origin) return next();

  // Require a custom header on all browser-origin mutating requests.
  const header = req.headers["x-requested-with"] || req.headers["x-csrf-token"];
  if (!header) {
    return res.status(403).json({ error: "CSRF token missing" });
  }
  next();
}

export default csrfGuard;
