import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import pinoHttp from "pino-http";
import logger from "./utils/logger.js";
import { validateEnv } from "./utils/env.js";
import authRoutes from "./routes/auth.js";
import appointmentsRouter from "./routes/appointments.js";
import reportsRouter from "./routes/reports.js";
import patientsRouter from "./routes/patients.js";
import usersRouter from "./routes/users.js";
import clinicsRouter from "./routes/clinics.js";
import clientsRouter from "./routes/clients.js";
import invoicesRouter from "./routes/invoices.js";
import devicesRouter from "./routes/devices.js";
import deviceResultsRouter from "./routes/device-results.js";
import hrRouter from "./routes/hr.js";
import catalogRouter from "./routes/catalog.js";
import bridgeRouter from "./routes/bridge.js";
import healthRouter from "./routes/health.js";
import { auditLog } from "./middleware/auditLog.js";
import { csrfGuard } from "./middleware/csrf.js";

dotenv.config();
validateEnv();

const app = express();

// Structured request logging (correlates with logger output)
app.use(pinoHttp({
  logger,
  customLogLevel: (req, res, err) => {
    if (err || res.statusCode >= 500) return "error";
    if (res.statusCode >= 400) return "warn";
    return "info";
  },
  serializers: {
    req: (req) => ({ method: req.method, url: req.url, id: req.id }),
    res: (res) => ({ statusCode: res.statusCode }),
  },
}));

// Behind Render's reverse proxy â€” needed for correct client IPs (rate limiting)
app.set("trust proxy", 1);

// Security headers (strict â€” API does not serve HTML so we lock CSP fully).
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'none'"],
      baseUri: ["'none'"],
    },
  },
  referrerPolicy: { policy: "no-referrer" },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// CORS: Allow frontend origins explicitly with credentials support
const allowedOrigins = [
  "https://med.loopjo.com",
  "http://localhost:5173",
  "http://localhost:3000",
];
const corsOptions = {
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-CSRF-Token",
    "Accept",
  ],
};
app.use(cors(corsOptions));

// Handle preflight explicitly for ALL routes
app.options("*", cors(corsOptions));

// Body size limit â€” defends against memory-exhaustion attacks
app.use(express.json({ limit: "200kb" }));

// Rate limit auth endpoints to slow down brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                  // 20 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
});
app.use("/auth/login", authLimiter);
app.use("/auth/super-admin/login", authLimiter);
app.use("/auth/hr-login", authLimiter);

// Global rate limit â€” broad DoS defense for authenticated endpoints.
// Tuned generously so normal use never hits it; abusive clients do.
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Slow down." },
});
app.use(globalLimiter);

// Audit log middleware (best-effort, runs after routes set req.user)
app.use(auditLog);

// Health endpoints (no auth required) — used by Render and uptime monitors.
app.use("/", healthRouter);

// Public routes (no auth)
app.use("/auth", authRoutes);

// Bridge Agent routes (auth via X-Bridge-Key, NOT JWT)
app.use("/bridge", bridgeRouter);

// CSRF guard for browser-origin mutating requests (defense in depth on top
// of Bearer JWT). Mounted AFTER /bridge (server-to-server) and /auth (login
// happens before any token exists, so frontend sends X-Requested-With).
app.use(csrfGuard);

// Protected routes (require JWT via router-level middleware)
app.use("/appointments", appointmentsRouter);
app.use("/reports", reportsRouter);
app.use("/patients", patientsRouter);
app.use("/users", usersRouter);
app.use("/clinics", clinicsRouter);
app.use("/clients", clientsRouter);
app.use("/invoices", invoicesRouter);
app.use("/devices", devicesRouter);
app.use("/device-results", deviceResultsRouter);
app.use("/hr", hrRouter);
app.use("/catalog", catalogRouter);

app.get("/", (_, res) => res.send("MedLoop API running"));

// 404 handler â€” return JSON instead of Express HTML
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Final error handler — never leak stack traces or err.message to clients.
// Errors thrown by route handlers without explicit try/catch land here.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error({ err, method: req.method, url: req.originalUrl }, "unhandled error");
  if (res.headersSent) return;
  res.status(err.status || 500).json({ error: "Server error" });
});

export default app;
