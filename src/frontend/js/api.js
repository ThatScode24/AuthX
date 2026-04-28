const TOKEN_KEY = "token";

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

export function decodeJwt(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(b64));
  } catch {
    return null;
  }
}

export async function request(path, { method = "GET", body, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined && !h["Content-Type"]) h["Content-Type"] = "application/json";

  const tok = getToken();
  if (tok && !h["Authorization"]) h["Authorization"] = `Bearer ${tok}`;

  const res = await fetch(path, {
    method,
    headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try { data = await res.json(); } catch { /* response without body */ }

  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

export const get = (p) => request(p);
export const post = (p, body) => request(p, { method: "POST", body });
