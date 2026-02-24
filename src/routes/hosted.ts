import { Hono } from "hono";
import type { EnvBindings } from "../types";
import { getAppUrl } from "../lib/config";

const widgetScript = `(() => {
  const toBase64Url = (bytes) => {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
  };
  const fromBase64Url = (value) => {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const pad = normalized.length % 4;
    const padded = pad ? normalized + "=".repeat(4 - pad) : normalized;
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  class PJAuthWidget extends HTMLElement {
    connectedCallback() {
      this.mode = (this.getAttribute("mode") || "sign-in").toLowerCase();
      this.baseUrl = (this.getAttribute("base-url") || window.location.origin).replace(/\\/$/, "");
      this.storageKey = this.getAttribute("token-storage-key") || "pj_auth_access_token";
      this.attachShadow({ mode: "open" });
      this.render();
    }

    setOutput(text, isError = false) {
      const out = this.shadowRoot.getElementById("out");
      out.textContent = text;
      out.style.color = isError ? "#b91c1c" : "#0f172a";
    }

    token() {
      return window.localStorage.getItem(this.storageKey);
    }

    saveToken(token) {
      if (token) {
        window.localStorage.setItem(this.storageKey, token);
      }
    }

    async request(path, method, body, withAuth = false) {
      const headers = { "content-type": "application/json" };
      if (withAuth && this.token()) {
        headers.authorization = "Bearer " + this.token();
      }
      const response = await fetch(this.baseUrl + path, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = payload?.error?.message || "Request failed";
        const err = new Error(message);
        err.payload = payload;
        throw err;
      }
      if (payload?.session?.accessToken) {
        this.saveToken(payload.session.accessToken);
      }
      return payload;
    }

    async handleSignUp() {
      const email = this.shadowRoot.getElementById("email").value;
      const password = this.shadowRoot.getElementById("password").value;
      const fullName = this.shadowRoot.getElementById("fullName").value;
      const payload = await this.request("/v1/auth/sign-up", "POST", { email, password, fullName });
      this.setOutput(JSON.stringify(payload, null, 2));
      this.dispatchEvent(new CustomEvent("pj-auth-success", { detail: payload }));
    }

    async handleSignIn() {
      const email = this.shadowRoot.getElementById("email").value;
      const password = this.shadowRoot.getElementById("password").value;
      const payload = await this.request("/v1/auth/sign-in", "POST", { email, password });
      this.setOutput(JSON.stringify(payload, null, 2));
      this.dispatchEvent(new CustomEvent("pj-auth-success", { detail: payload }));
    }

    async handleGoogle() {
      const url = new URL("/v1/oauth/google/start", this.baseUrl);
      url.searchParams.set("redirect_to", window.location.href);
      window.location.href = url.toString();
    }

    async handlePasskey() {
      const email = this.shadowRoot.getElementById("email").value;
      if (!email) {
        throw new Error("Email is required for passkey sign-in");
      }
      const start = await this.request("/v1/auth/passkeys/authenticate/start", "POST", { email });
      const publicKey = start.publicKey || {};
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: fromBase64Url(publicKey.challenge),
          rpId: publicKey.rpId,
          userVerification: publicKey.userVerification || "preferred",
          timeout: publicKey.timeout || 60000,
          allowCredentials: (publicKey.allowCredentials || []).map((item) => ({
            id: fromBase64Url(item.id),
            type: item.type || "public-key"
          }))
        }
      });
      if (!assertion) {
        throw new Error("Passkey authentication cancelled");
      }
      const response = assertion.response;
      const finish = await this.request("/v1/auth/passkeys/authenticate/finish", "POST", {
        challengeId: start.challengeId,
        credentialId: toBase64Url(new Uint8Array(assertion.rawId)),
        clientDataJSON: toBase64Url(new Uint8Array(response.clientDataJSON)),
        authenticatorData: toBase64Url(new Uint8Array(response.authenticatorData)),
        signature: toBase64Url(new Uint8Array(response.signature))
      });
      this.setOutput(JSON.stringify(finish, null, 2));
      this.dispatchEvent(new CustomEvent("pj-auth-success", { detail: finish }));
    }

    async handlePasskeyRegister() {
      const start = await this.request("/v1/auth/passkeys/register/start", "POST", {}, true);
      const publicKey = start.publicKey || {};
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: fromBase64Url(publicKey.challenge),
          rp: publicKey.rp,
          user: {
            id: fromBase64Url(publicKey.user.id),
            name: publicKey.user.name,
            displayName: publicKey.user.displayName
          },
          pubKeyCredParams: publicKey.pubKeyCredParams || [{ type: "public-key", alg: -7 }],
          timeout: publicKey.timeout || 60000,
          authenticatorSelection: publicKey.authenticatorSelection || undefined,
          attestation: publicKey.attestation || "none",
          excludeCredentials: (publicKey.excludeCredentials || []).map((item) => ({
            id: fromBase64Url(item.id),
            type: item.type || "public-key"
          }))
        }
      });
      if (!credential) {
        throw new Error("Passkey registration cancelled");
      }
      const response = credential.response;
      if (!response.getPublicKey) {
        throw new Error("Browser does not expose getPublicKey for passkey registration");
      }
      const spki = response.getPublicKey();
      if (!spki) {
        throw new Error("Passkey public key is missing");
      }
      const finish = await this.request("/v1/auth/passkeys/register/finish", "POST", {
        challengeId: start.challengeId,
        credentialId: toBase64Url(new Uint8Array(credential.rawId)),
        clientDataJSON: toBase64Url(new Uint8Array(response.clientDataJSON)),
        publicKeySpki: btoa(String.fromCharCode(...new Uint8Array(spki))),
        transports: response.getTransports ? response.getTransports() : []
      }, true);
      this.setOutput(JSON.stringify(finish, null, 2));
      this.dispatchEvent(new CustomEvent("pj-auth-success", { detail: finish }));
    }

    render() {
      const signUpMode = this.mode === "sign-up";
      this.shadowRoot.innerHTML = \`
        <style>
          :host {
            display: block;
            font-family: "Segoe UI", sans-serif;
            color: #0f172a;
          }
          .card {
            border: 1px solid #dbe2ef;
            border-radius: 12px;
            background: #ffffff;
            padding: 16px;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
          }
          .title {
            margin: 0 0 10px;
            font-size: 20px;
            font-weight: 700;
          }
          label {
            display: block;
            margin-top: 10px;
            font-size: 13px;
            color: #334155;
          }
          input {
            width: 100%;
            box-sizing: border-box;
            margin-top: 6px;
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            padding: 10px;
            font-size: 14px;
          }
          .row {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 12px;
          }
          button {
            border: 0;
            border-radius: 10px;
            padding: 10px 14px;
            cursor: pointer;
            font-weight: 600;
            color: #ffffff;
            background: #0f766e;
          }
          button.alt { background: #334155; }
          button.light { background: #475569; }
          pre {
            white-space: pre-wrap;
            margin-top: 12px;
            padding: 10px;
            border-radius: 10px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            min-height: 80px;
          }
        </style>
        <div class="card">
          <h3 class="title">\${signUpMode ? "Create account" : "Sign in"}</h3>
          <label>Email<input id="email" type="email" autocomplete="username" /></label>
          <label>Password<input id="password" type="password" autocomplete="\${signUpMode ? "new-password" : "current-password"}" /></label>
          \${signUpMode ? '<label>Full name<input id="fullName" type="text" autocomplete="name" /></label>' : ""}
          <div class="row">
            <button id="submitBtn">\${signUpMode ? "Sign up" : "Sign in"}</button>
            <button id="googleBtn" class="alt" type="button">Google</button>
            \${!signUpMode ? '<button id="passkeyBtn" class="light" type="button">Passkey</button>' : ""}
            <button id="registerPasskeyBtn" class="light" type="button">Register Passkey</button>
          </div>
          <pre id="out"></pre>
        </div>
      \`;

      this.shadowRoot.getElementById("submitBtn").addEventListener("click", async () => {
        try {
          if (signUpMode) {
            await this.handleSignUp();
          } else {
            await this.handleSignIn();
          }
        } catch (error) {
          this.setOutput(error.message || String(error), true);
          this.dispatchEvent(new CustomEvent("pj-auth-error", { detail: error }));
        }
      });

      this.shadowRoot.getElementById("googleBtn").addEventListener("click", async () => {
        try {
          await this.handleGoogle();
        } catch (error) {
          this.setOutput(error.message || String(error), true);
          this.dispatchEvent(new CustomEvent("pj-auth-error", { detail: error }));
        }
      });

      const passkeyBtn = this.shadowRoot.getElementById("passkeyBtn");
      if (passkeyBtn) {
        passkeyBtn.addEventListener("click", async () => {
          try {
            await this.handlePasskey();
          } catch (error) {
            this.setOutput(error.message || String(error), true);
            this.dispatchEvent(new CustomEvent("pj-auth-error", { detail: error }));
          }
        });
      }

      this.shadowRoot.getElementById("registerPasskeyBtn").addEventListener("click", async () => {
        try {
          await this.handlePasskeyRegister();
        } catch (error) {
          this.setOutput(error.message || String(error), true);
          this.dispatchEvent(new CustomEvent("pj-auth-error", { detail: error }));
        }
      });
    }
  }

  if (!window.customElements.get("pj-auth-widget")) {
    window.customElements.define("pj-auth-widget", PJAuthWidget);
  }
})();`;

const hostedPage = (params: { title: string; mode: "sign-in" | "sign-up"; origin: string }): string => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${params.title}</title>
    <style>
      body {
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        min-height: 100vh;
        background: linear-gradient(135deg, #dbeafe 0%, #f8fafc 45%, #ecfeff 100%);
        display: grid;
        place-items: center;
        color: #0f172a;
      }
      main {
        width: min(96vw, 480px);
      }
      .note {
        margin-top: 12px;
        text-align: center;
        color: #334155;
        font-size: 13px;
      }
      a {
        color: #0f766e;
      }
    </style>
  </head>
  <body>
    <main>
      <pj-auth-widget mode="${params.mode}" base-url="${params.origin}"></pj-auth-widget>
      <p class="note">
        ${params.mode === "sign-in" ? "No account?" : "Already have an account?"}
        <a href="${params.mode === "sign-in" ? "/hosted/sign-up" : "/hosted/sign-in"}">
          ${params.mode === "sign-in" ? "Create one" : "Sign in"}
        </a>
      </p>
    </main>
    <script src="/sdk/pj-auth-widgets.js"></script>
  </body>
</html>`;

export const hostedRoutes = new Hono<{ Bindings: EnvBindings }>();

hostedRoutes.get("/sdk/pj-auth-widgets.js", (context) => {
  context.header("content-type", "application/javascript; charset=utf-8");
  return context.body(widgetScript);
});

hostedRoutes.get("/hosted/sign-in", (context) => {
  context.header("content-type", "text/html; charset=utf-8");
  return context.body(
    hostedPage({
      title: "PajamaDot Sign In",
      mode: "sign-in",
      origin: getAppUrl(context.env, context.req.raw)
    })
  );
});

hostedRoutes.get("/hosted/sign-up", (context) => {
  context.header("content-type", "text/html; charset=utf-8");
  return context.body(
    hostedPage({
      title: "PajamaDot Sign Up",
      mode: "sign-up",
      origin: getAppUrl(context.env, context.req.raw)
    })
  );
});
