/**
 * Process entry point — starts the HTTP listener.
 * Kept separate from app.js so tests can import the express app
 * without spinning up a server or binding to a port.
 */
import app from "./app.js";
import logger from "./utils/logger.js";

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  logger.info({ port: PORT }, "API listening");
});

// Graceful shutdown for Render/Docker SIGTERM
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    logger.info({ sig }, "Received shutdown signal — exiting");
    server.close(() => process.exit(0));
    // Hard kill if connections don't drain
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}

process.on("unhandledRejection", (reason) => {
  logger.error({ reason }, "Unhandled promise rejection");
});

process.on("uncaughtException", (err) => {
  logger.fatal({ err }, "Uncaught exception — exiting");
  process.exit(1);
});
