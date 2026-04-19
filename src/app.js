import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
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

dotenv.config();

if (!process.env.JWT_SECRET || !process.env.DATABASE_URL) {
  console.error("[FATAL] JWT_SECRET and DATABASE_URL env vars are required");
  process.exit(1);
}

const app = express();

// Behind Render's reverse proxy — needed for correct client IPs (rate limiting)
app.set("trust proxy", 1);

// Security headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

// CORS: Allow frontend origins explicitly with credentials support
const allowedOrigins = [
  "https://med.loopjo.com",
  "http://localhost:5173",
  "http://localhost:3000",
];
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Handle preflight explicitly for ALL routes
app.options("*", cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Body size limit — defends against memory-exhaustion attacks
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

// Public routes (no auth)
app.use("/auth", authRoutes);

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`API running on port ${PORT}`)
);
