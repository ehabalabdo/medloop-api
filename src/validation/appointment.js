const { z } = require("zod");

const createAppointmentSchema = z.object({
  patient_id: z.number(),
  doctor_id: z.number(),
  start_time: z.string().datetime(),
  end_time: z.string().datetime()
});

module.exports = { createAppointmentSchema };
