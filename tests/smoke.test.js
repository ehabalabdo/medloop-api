/**
 * Smoke tests for the public API surface.
 * Uses supertest against the exported Express app — no real listener,
 * no real database (pool is mocked).
 */
import { describe, it, expect, vi, beforeAll } from "vitest";

// Mock env BEFORE importing app
process.env.JWT_SECRET = "x".repeat(40);
process.env.DATABASE_URL = "postgres://x:x@127.0.0.1:9999/x";
process.env.NODE_ENV = "test";
process.env.LOG_LEVEL = "silent";

// Mock the db pool — never actually hits Postgres
vi.mock("../src/db.js", () => ({
  default: {
    query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    connect: vi.fn(),
    end: vi.fn(),
  },
}));

let request;
beforeAll(async () => {
  const supertest = (await import("supertest")).default;
  const { default: app } = await import("../src/app.js");
  request = supertest(app);
});

describe("API smoke", () => {
  it("returns root health string", async () => {
    const res = await request.get("/");
    expect(res.status).toBe(200);
    expect(res.text).toBe("MedLoop API running");
  });

  it("returns 404 JSON for unknown routes", async () => {
    const res = await request.get("/this-route-does-not-exist");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "Not found" });
  });

  it("rejects unauthenticated requests to protected routes", async () => {
    const res = await request.get("/clients");
    expect([401, 403]).toContain(res.status);
  });

  it("accepts CORS preflight from allowed origin with new headers", async () => {
    const res = await request
      .options("/clients")
      .set("Origin", "https://med.loopjo.com")
      .set("Access-Control-Request-Method", "GET")
      .set("Access-Control-Request-Headers", "X-Requested-With,Authorization,X-CSRF-Token");
    expect(res.status).toBe(204);
    const allowed = (res.headers["access-control-allow-headers"] || "").toLowerCase();
    expect(allowed).toContain("x-requested-with");
    expect(allowed).toContain("authorization");
    expect(allowed).toContain("x-csrf-token");
  });

  it("blocks CORS from unknown origin", async () => {
    const res = await request
      .options("/clients")
      .set("Origin", "https://evil.example.com")
      .set("Access-Control-Request-Method", "GET");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("sets security headers (helmet)", async () => {
    const res = await request.get("/");
    expect(res.headers["strict-transport-security"]).toBeDefined();
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
  });

  it("rejects oversized JSON body (>200kb)", async () => {
    const huge = { data: "x".repeat(220 * 1024) };
    const res = await request
      .post("/auth/login")
      .send(huge)
      .set("Content-Type", "application/json");
    expect([413, 400]).toContain(res.status);
  });

  it("rejects login with missing credentials", async () => {
    const res = await request
      .post("/auth/super-admin/login")
      .send({})
      .set("Content-Type", "application/json");
    expect([400, 401]).toContain(res.status);
  });
});
