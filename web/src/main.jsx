import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

function App() {
  const [me, setMe] = useState(null);
  const error = new URLSearchParams(location.search).get("error");

  const load = () => fetch("/api/me").then((r) => r.json()).then(setMe, (e) => setMe({ error: String(e) }));
  useEffect(() => void load(), []);

  const logout = async () => {
    await fetch("/auth/logout", { method: "POST" });
    history.replaceState(null, "", "/");
    load();
  };

  return (
    <>
      <h1>GigSmart OAuth Test Client</h1>
      {error && <p style={{ color: "crimson" }}>Callback error: {error}</p>}
      {me === null ? (
        <p>Loading…</p>
      ) : me.connected ? (
        <button onClick={logout}>Disconnect</button>
      ) : (
        <a href="/auth/login">Connect GigSmart</a>
      )}
      {me && <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>{JSON.stringify(me, null, 2)}</pre>}
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
