import express from "express";
import cors from "cors";
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

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

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

app.get("/", (_, res) => res.send("MedLoop API running"));

app.listen(process.env.PORT, () =>
  console.log(`API running on port ${process.env.PORT}`)
);
