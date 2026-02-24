import { Hono } from "hono";
import type { EnvBindings } from "../types";
import { getAppUrl } from "../lib/config";

const sdkScript = `(() => {
  class PajamaAuthClient {
    constructor(options = {}) {
      this.baseUrl = (options.baseUrl || window.location.origin).replace(/\\/$/, "");
      this.storageKey = options.storageKey || "pj_auth_access_token";
      this.accessToken = localStorage.getItem(this.storageKey) || null;
    }

    _saveToken(token) {
      this.accessToken = token || null;
      if (this.accessToken) {
        localStorage.setItem(this.storageKey, this.accessToken);
      } else {
        localStorage.removeItem(this.storageKey);
      }
    }

    _headers(extra = {}) {
      const headers = { "content-type": "application/json", ...extra };
      if (this.accessToken) {
        headers.authorization = \`Bearer \${this.accessToken}\`;
      }
      return headers;
    }

    async _request(path, options = {}) {
      const response = await fetch(this.baseUrl + path, options);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const err = new Error(payload?.error?.message || "Request failed");
        err.payload = payload;
        err.status = response.status;
        throw err;
      }
      if (payload?.session?.accessToken) {
        this._saveToken(payload.session.accessToken);
      }
      return payload;
    }

    signUp(data) {
      return this._request("/v1/auth/sign-up", {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify(data)
      });
    }

    signIn(data) {
      return this._request("/v1/auth/sign-in", {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify(data)
      });
    }

    refresh(refreshToken) {
      return this._request("/v1/auth/token/refresh", {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify(refreshToken ? { refreshToken } : {})
      });
    }

    me() {
      return this._request("/v1/auth/me", {
        method: "GET",
        headers: this._headers({ "content-type": "application/json" })
      });
    }

    async signOut() {
      try {
        await this._request("/v1/auth/sign-out", {
          method: "POST",
          headers: this._headers()
        });
      } finally {
        this._saveToken(null);
      }
    }

    startGoogleAuth(redirectTo) {
      const url = new URL("/v1/oauth/google/start", this.baseUrl);
      if (redirectTo) {
        url.searchParams.set("redirect_to", redirectTo);
      }
      window.location.href = url.toString();
    }
  }

  window.PajamaAuthClient = PajamaAuthClient;
})();`;

const demoHtml = (origin: string) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PajamaDot Auth Demo</title>
    <style>
      :root {
        --bg: #f7f8fb;
        --card: #ffffff;
        --text: #1f2937;
        --muted: #6b7280;
        --primary: #0f766e;
        --danger: #dc2626;
      }
      body {
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        background: radial-gradient(circle at 20% 20%, #e4f2ff, var(--bg) 40%);
        color: var(--text);
      }
      main {
        max-width: 980px;
        margin: 40px auto;
        padding: 0 16px 48px;
      }
      h1 { margin: 0 0 8px; }
      p  { margin: 0 0 24px; color: var(--muted); }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
      }
      .card {
        background: var(--card);
        border-radius: 14px;
        padding: 16px;
        box-shadow: 0 12px 24px rgba(0,0,0,.06);
      }
      label {
        display: block;
        font-size: 13px;
        margin-top: 10px;
      }
      input {
        width: 100%;
        box-sizing: border-box;
        margin-top: 6px;
        padding: 10px 12px;
        border: 1px solid #cbd5e1;
        border-radius: 10px;
        font-size: 14px;
      }
      button {
        margin-top: 12px;
        background: var(--primary);
        color: white;
        border: 0;
        border-radius: 10px;
        padding: 10px 14px;
        cursor: pointer;
        font-weight: 600;
      }
      button.secondary {
        background: #334155;
      }
      button.danger {
        background: var(--danger);
      }
      pre {
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 10px;
        padding: 14px;
        overflow-x: auto;
        min-height: 220px;
      }
      .row {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>PajamaDot Auth E2E Demo</h1>
      <p>Base URL: ${origin}</p>
      <div class="grid">
        <section class="card">
          <h3>Password Sign Up</h3>
          <label>Email <input id="su-email" type="email" placeholder="user@example.com"/></label>
          <label>Password <input id="su-password" type="password" placeholder="min 8 chars"/></label>
          <label>Full name <input id="su-name" type="text" placeholder="Pajama User"/></label>
          <button id="btn-signup">Create account</button>
        </section>
        <section class="card">
          <h3>Password Sign In</h3>
          <label>Email <input id="si-email" type="email" placeholder="user@example.com"/></label>
          <label>Password <input id="si-password" type="password" placeholder="min 8 chars"/></label>
          <button id="btn-signin">Sign in</button>
          <button id="btn-google" class="secondary">Continue with Google</button>
        </section>
        <section class="card">
          <h3>Session</h3>
          <div class="row">
            <button id="btn-me" class="secondary">Get current user</button>
            <button id="btn-refresh" class="secondary">Refresh session</button>
            <button id="btn-signout" class="danger">Sign out</button>
          </div>
        </section>
      </div>
      <section class="card" style="margin-top: 16px;">
        <h3>API Output</h3>
        <pre id="output"></pre>
      </section>
    </main>
    <script src="/sdk/pj-auth-client.js"></script>
    <script>
      const out = document.getElementById("output");
      const client = new window.PajamaAuthClient({ baseUrl: "${origin}" });

      const print = (value) => {
        out.textContent = JSON.stringify(value, null, 2);
      };

      if (window.location.hash.includes("access_token=")) {
        const token = window.location.hash.replace("#", "").split("access_token=")[1];
        if (token) {
          client._saveToken(decodeURIComponent(token));
          print({ info: "Access token restored from OAuth callback hash" });
        }
      }

      document.getElementById("btn-signup").onclick = async () => {
        try {
          const payload = await client.signUp({
            email: document.getElementById("su-email").value,
            password: document.getElementById("su-password").value,
            fullName: document.getElementById("su-name").value
          });
          print(payload);
        } catch (error) {
          print({ error: error.message, detail: error.payload });
        }
      };

      document.getElementById("btn-signin").onclick = async () => {
        try {
          const payload = await client.signIn({
            email: document.getElementById("si-email").value,
            password: document.getElementById("si-password").value
          });
          print(payload);
        } catch (error) {
          print({ error: error.message, detail: error.payload });
        }
      };

      document.getElementById("btn-google").onclick = () => {
        client.startGoogleAuth("${origin}/demo");
      };

      document.getElementById("btn-me").onclick = async () => {
        try {
          print(await client.me());
        } catch (error) {
          print({ error: error.message, detail: error.payload });
        }
      };

      document.getElementById("btn-refresh").onclick = async () => {
        try {
          print(await client.refresh());
        } catch (error) {
          print({ error: error.message, detail: error.payload });
        }
      };

      document.getElementById("btn-signout").onclick = async () => {
        try {
          await client.signOut();
          print({ ok: true, signedOut: true });
        } catch (error) {
          print({ error: error.message, detail: error.payload });
        }
      };
    </script>
  </body>
</html>`;

export const demoRoutes = new Hono<{ Bindings: EnvBindings }>();

demoRoutes.get("/sdk/pj-auth-client.js", (context) => {
  context.header("content-type", "application/javascript; charset=utf-8");
  return context.body(sdkScript);
});

demoRoutes.get("/demo", (context) => {
  context.header("content-type", "text/html; charset=utf-8");
  return context.body(demoHtml(getAppUrl(context.env, context.req.raw)));
});
