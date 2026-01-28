import React, { useState } from "react";

export default function LoginView() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: email, password }),
      });
      if (!res.ok) {
        if (res.status === 401) setError("Invalid email or password.");
        else setError("Server error. Please try again.");
        setLoading(false);
        return;
      }
      // handle success (redirect, etc.)
    } catch {
      setError("Network error. Please try again.");
    }
    setLoading(false);
  };

  return (
    <div className="flex min-h-screen">
      {/* Left Side */}
      <div className="hidden md:flex w-1/2 relative items-center justify-center bg-gradient-to-br from-blue-600 to-cyan-400">
        <img
          src="/medical-bg.jpg"
          alt="Medical abstract"
          className="absolute inset-0 w-full h-full object-cover opacity-60"
        />
        <div className="relative z-10 bg-white/20 backdrop-blur-md rounded-xl p-10 flex flex-col items-center shadow-lg">
          <img src="/logo.svg" alt="MedLoop Logo" className="w-20 mb-6" />
          <h1 className="text-3xl font-bold text-white mb-2 drop-shadow-lg">Welcome to MedLoop</h1>
          <p className="text-white/80 text-lg">Your Medical Dashboard</p>
        </div>
      </div>
      {/* Right Side */}
      <div className="flex w-full md:w-1/2 items-center justify-center bg-white">
        <form
          className="w-full max-w-md space-y-6 p-8 rounded-xl shadow-xl bg-white"
          onSubmit={handleSubmit}
        >
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Sign in to your account</h2>
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
              {error}
            </div>
          )}
          <div>
            <label className="block text-gray-700 mb-1" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-gray-700 mb-1" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="flex items-center justify-between">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={remember}
                onChange={e => setRemember(e.target.checked)}
                className="mr-2"
              />
              <span className="text-gray-700">Remember me</span>
            </label>
            <a href="/forgot-password" className="text-blue-500 hover:underline text-sm">
              Forgot Password?
            </a>
          </div>
          <button
            type="submit"
            className="w-full flex justify-center items-center bg-blue-600 text-white font-semibold py-2 rounded-lg hover:bg-blue-700 transition"
            disabled={loading}
          >
            {loading ? (
              <svg className="animate-spin h-5 w-5 mr-2 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
              </svg>
            ) : null}
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}
