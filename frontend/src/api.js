const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return data;
}

export function getFixtures() {
  return request("/api/fixtures");
}

export function runScan(payload) {
  return request("/api/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function runDebate(payload) {
  return request("/api/debate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function runVerifyMatrix() {
  return request("/api/verify", {
    method: "POST",
  });
}