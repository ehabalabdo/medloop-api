import express from "express";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();
import authRoutes from "./routes/auth.js";
import appointmentsRouter from "./routes/appointments.js";
import reportsRouter from "./routes/reports.js";
import patientsRouter from "./routes/patients.js";
import usersRouter from "./routes/users.js";
import authGuard from "./middleware/authGuard.js";

const app = express();

const PORT = process.env.PORT || 4000;
app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true
}));
app.use(express.json());

// Public routes
app.use("/auth", authRoutes);

// JWT protection for all other routes
app.use((req, res, next) => {
  if (req.path.startsWith("/auth")) return next();
  return authGuard(req, res, next);
});

app.use("/appointments", appointmentsRouter);
app.use("/reports", reportsRouter);
app.use("/patients", patientsRouter);
app.use("/users", usersRouter);

app.get("/", (_, res) => res.send("MedLoop API running"));

// Global error handler
app.use((err, req, res, next) => {
  console.error("API Error:", err);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT, () =>
  console.log(`API running on port ${PORT}`)
);
