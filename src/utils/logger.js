import pino from "pino";

const isDev = process.env.NODE_ENV !== "production";

const logger = pino({
  level: process.env.LOG_LEVEL || (isDev ? "debug" : "info"),
  redact: {
    // Never log secrets, tokens, passwords, or PII
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "req.headers['x-csrf-token']",
      "*.password",
      "*.token",
      "*.secret",
      "*.api_key",
      "*.bridge_key",
    ],
    censor: "[REDACTED]",
  },
  transport: isDev
    ? {
        target: "pino-pretty",
        options: { colorize: true, translateTime: "HH:MM:ss", ignore: "pid,hostname" },
      }
    : undefined,
});

export default logger;
