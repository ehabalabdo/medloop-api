import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import appointmentsRouter from "./routes/appointments.js";
import reportsRouter from "./routes/reports.js";
import patientsRouter from "./routes/patients.js";
import usersRouter from "./routes/users.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/auth", authRoutes);
app.use("/appointments", appointmentsRouter);
app.use("/reports", reportsRouter);
app.use("/patients", patientsRouter);
app.use("/users", usersRouter);

app.get("/", (_, res) => res.send("MedLoop API running"));

app.listen(process.env.PORT, () =>
  console.log(`API running on port ${process.env.PORT}`)
);
