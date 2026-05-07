import { useMemo, useState } from "react";

type Tab = "users" | "logs" | "apps" | "sessions";

const API_URL = "http://localhost:4000";

export const App = () => {
  const [token, setToken] = useState(localStorage.getItem("identityos_access_token") ?? "");
  const [csrf, setCsrf] = useState(localStorage.getItem("identityos_csrf_token") ?? "");
  const [output, setOutput] = useState<string>("Use Login/OAuth, then load data.");
  const [tab, setTab] = useState<Tab>("users");
  const headers = useMemo(
    () => ({
      "content-type": "application/json",
      authorization: token ? `Bearer ${token}` : "",
      "x-csrf-token": csrf,
    }),
    [token, csrf],
  );

  const call = async (path: string, method = "GET", body?: unknown) => {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      credentials: "include",
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({ status: res.status }));
    setOutput(JSON.stringify(json, null, 2));
  };

  const handleOauthFinalize = () => {
    const url = new URL(window.location.href);
    const accessToken = url.searchParams.get("accessToken");
    const csrfToken = url.searchParams.get("csrfToken");
    if (accessToken) {
      setToken(accessToken);
      localStorage.setItem("identityos_access_token", accessToken);
    }
    if (csrfToken) {
      setCsrf(csrfToken);
      localStorage.setItem("identityos_csrf_token", csrfToken);
    }
  };

  return (
    <div style={{ fontFamily: "sans-serif", margin: "20px auto", maxWidth: 1100, lineHeight: 1.4 }}>
      <h1>IdentityOS Admin</h1>
      <p>Basic admin console for users, logs, app clients, and session controls.</p>
      <button onClick={handleOauthFinalize}>Load OAuth tokens from URL</button>
      <div style={{ display: "grid", gap: 8, marginTop: 16 }}>
        <input
          placeholder="Access token"
          value={token}
          onChange={(e) => {
            setToken(e.target.value);
            localStorage.setItem("identityos_access_token", e.target.value);
          }}
        />
        <input
          placeholder="CSRF token"
          value={csrf}
          onChange={(e) => {
            setCsrf(e.target.value);
            localStorage.setItem("identityos_csrf_token", e.target.value);
          }}
        />
      </div>
      <div style={{ display: "flex", gap: 10, marginTop: 16, flexWrap: "wrap" }}>
        <button onClick={() => window.open(`${API_URL}/auth/google`, "_blank")}>Login with Google</button>
        <button onClick={() => window.open(`${API_URL}/auth/github`, "_blank")}>Login with GitHub</button>
        <button onClick={() => call("/auth/logout", "POST")}>Logout</button>
      </div>
      <hr />
      <div style={{ display: "flex", gap: 10 }}>
        <button onClick={() => setTab("users")}>Users</button>
        <button onClick={() => setTab("logs")}>Audit Logs</button>
        <button onClick={() => setTab("apps")}>Apps</button>
        <button onClick={() => setTab("sessions")}>Sessions</button>
      </div>
      <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
        {tab === "users" && <button onClick={() => call("/admin/users")}>Load Users</button>}
        {tab === "logs" && <button onClick={() => call("/admin/logs")}>Load Logs</button>}
        {tab === "apps" && (
          <>
            <button onClick={() => call("/apps")}>Load Apps</button>
            <button
              onClick={() =>
                call("/apps/register", "POST", {
                  name: "SampleClient",
                  callbackUrls: ["http://localhost:3000/callback"],
                })
              }
            >
              Register Demo App
            </button>
          </>
        )}
        {tab === "sessions" && <button onClick={() => call("/sessions")}>Load Sessions</button>}
      </div>
      <pre
        style={{
          marginTop: 16,
          background: "#111",
          color: "#e8e8e8",
          borderRadius: 8,
          padding: 12,
          minHeight: 260,
          overflowX: "auto",
        }}
      >
        {output}
      </pre>
    </div>
  );
};
