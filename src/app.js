const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const authRoutes = require("./routes/auth.js");
const appointmentsRouter = require("./routes/appointments.js");
const reportsRouter = require("./routes/reports.js");
const patientsRouter = require("./routes/patients.js");
const usersRouter = require("./routes/users.js");
const authGuard = require("./middleware/authGuard.js");
const clinicsRouter = require("./routes/clinics.js");

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
app.use("/clinics", clinicsRouter);

app.get("/", (_, res) => res.send("MedLoop API running"));

// Global error handler
app.use((err, req, res, next) => {
  console.error("API Error:", err);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT, () =>
  console.log(`API running on port ${PORT}`)
);
