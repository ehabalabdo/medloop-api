/**
 * Zod-based request validation middleware.
 *
 * Usage:
 *   import { z } from "zod";
 *   import { validateBody } from "../utils/zod-validate.js";
 *
 *   const LoginSchema = z.object({
 *     username: z.string().min(1).max(255),
 *     password: z.string().min(1).max(500),
 *     client_id: z.string().min(1),
 *   });
 *
 *   router.post("/login", validateBody(LoginSchema), async (req, res) => {
 *     const { username, password, client_id } = req.validBody;
 *     ...
 *   });
 *
 * Validated, parsed and coerced data lands on `req.validBody` /
 * `req.validQuery` / `req.validParams`. The original `req.body` is left
 * untouched so existing handlers keep working during migration.
 */
import { z } from "zod";

function formatIssues(issues) {
  return issues.map((i) => {
    const path = i.path.length ? i.path.join(".") : "(root)";
    return `${path}: ${i.message}`;
  });
}

function makeMiddleware(source, target) {
  return (schema) => (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return res.status(400).json({
        error: "Invalid request",
        details: formatIssues(result.error.issues),
      });
    }
    req[target] = result.data;
    next();
  };
}

export const validateBody = makeMiddleware("body", "validBody");
export const validateQuery = makeMiddleware("query", "validQuery");
export const validateParams = makeMiddleware("params", "validParams");

// Re-export so callers don't need a separate `import { z } from "zod"`.
export { z };
