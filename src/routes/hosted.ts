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
      const inviteId = new URL(window.location.href).searchParams.get("invite_id");
      let invitation = null;
      let invitationError = null;
      if (inviteId && this.token()) {
        try {
          invitation = await this.request(
            "/v1/orgs/invitations/" + encodeURIComponent(inviteId) + "/accept",
            "POST",
            {},
            true
          );
        } catch (error) {
          invitationError = error?.message || String(error);
        }
      }
      const result = {
        signIn: payload,
        invitation,
        invitationError
      };
      this.setOutput(JSON.stringify(result, null, 2));
      this.dispatchEvent(new CustomEvent("pj-auth-success", { detail: result }));
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

const enterpriseHostedPage = (params: { origin: string }): string => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PajamaDot Enterprise Console</title>
    <style>
      :root {
        --bg: #f6f8fa;
        --card: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --accent: #0f766e;
        --accent-dark: #115e59;
        --danger: #b91c1c;
        --line: #d9e2ec;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        background:
          radial-gradient(900px 400px at 0% 0%, #dbeafe 0%, transparent 60%),
          radial-gradient(700px 420px at 100% 0%, #ecfeff 0%, transparent 58%),
          var(--bg);
        color: var(--text);
        font-family: "Segoe UI", sans-serif;
      }
      main {
        max-width: 1200px;
        margin: 22px auto 30px;
        padding: 0 14px;
      }
      h1 {
        margin: 0;
        font-size: 28px;
      }
      .sub {
        margin-top: 6px;
        color: var(--muted);
        font-size: 14px;
      }
      .top {
        margin-top: 14px;
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .chip-link {
        text-decoration: none;
        color: #0f172a;
        background: #e2e8f0;
        border-radius: 999px;
        padding: 7px 12px;
        font-size: 13px;
      }
      .grid {
        margin-top: 16px;
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      }
      .card {
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 14px;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
      }
      h3 {
        margin: 0 0 10px;
        font-size: 16px;
      }
      label {
        display: block;
        margin-top: 8px;
        font-size: 12px;
        color: #334155;
      }
      input, select, textarea {
        width: 100%;
        margin-top: 5px;
        border: 1px solid #cbd5e1;
        border-radius: 10px;
        padding: 9px 11px;
        font-size: 14px;
        font-family: inherit;
        background: #ffffff;
      }
      textarea {
        min-height: 110px;
        resize: vertical;
      }
      .row {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 10px;
      }
      button {
        border: 0;
        border-radius: 10px;
        padding: 9px 12px;
        font-weight: 600;
        cursor: pointer;
        color: #ffffff;
        background: var(--accent);
      }
      button:hover {
        background: var(--accent-dark);
      }
      button.alt {
        background: #334155;
      }
      button.danger {
        background: var(--danger);
      }
      .output-card {
        margin-top: 12px;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 14px;
        border: 1px solid #1e293b;
        overflow: hidden;
      }
      .output-head {
        padding: 9px 12px;
        font-size: 12px;
        color: #93c5fd;
        border-bottom: 1px solid #1e293b;
      }
      pre {
        margin: 0;
        padding: 12px;
        max-height: 360px;
        overflow: auto;
        white-space: pre-wrap;
      }
      .help {
        margin-top: 6px;
        font-size: 12px;
        color: var(--muted);
      }
      @media (max-width: 720px) {
        h1 { font-size: 24px; }
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Enterprise Console</h1>
      <div class="sub">Host: ${params.origin}</div>
      <div class="top">
        <a class="chip-link" href="/hosted/sign-in">Hosted Sign In</a>
        <a class="chip-link" href="/hosted/sign-up">Hosted Sign Up</a>
      </div>
      <section class="grid">
        <article class="card">
          <h3>Credentials & Org</h3>
          <label>Bearer Access Token
            <input id="token" type="text" placeholder="Paste access token or use localStorage" />
          </label>
          <label>Admin API Key (for /v1/admin endpoints)
            <input id="adminKey" type="text" placeholder="Admin API key" />
          </label>
          <div class="row">
            <button id="btnSaveToken">Save Token</button>
            <button id="btnClearToken" class="alt">Clear Token</button>
            <button id="btnLoadOrgs" class="alt">Load Orgs</button>
          </div>
          <label>Organization
            <select id="orgId">
              <option value="">-- choose org --</option>
            </select>
          </label>
          <div class="row">
            <button id="btnDiagnostics">Diagnostics</button>
            <button id="btnAdminStatus" class="alt">Admin Status</button>
            <button id="btnSamlSigHealth" class="alt">SAML Sig Health</button>
          </div>
        </article>

        <article class="card">
          <h3>SAML Connections</h3>
          <div class="row">
            <button id="btnListSaml" class="alt">List</button>
          </div>
          <label>Name <input id="samlName" type="text" placeholder="Example SAML" /></label>
          <label>Slug <input id="samlSlug" type="text" placeholder="example-saml" /></label>
          <label>IdP Entity ID <input id="samlEntityId" type="text" placeholder="https://idp.example.com/metadata" /></label>
          <label>SSO URL <input id="samlSsoUrl" type="text" placeholder="https://idp.example.com/sso" /></label>
          <label>X509 Certificate PEM
            <textarea id="samlCertPem" placeholder="-----BEGIN CERTIFICATE----- ..."></textarea>
          </label>
          <div class="row">
            <button id="btnCreateSaml">Create SAML Connection</button>
          </div>
        </article>

        <article class="card">
          <h3>Domain Routes</h3>
          <div class="row">
            <button id="btnListRoutes" class="alt">List</button>
          </div>
          <label>Domain <input id="routeDomain" type="text" placeholder="corp.example.com" /></label>
          <label>Connection Type
            <select id="routeType">
              <option value="password">password</option>
              <option value="google">google</option>
              <option value="saml">saml</option>
            </select>
          </label>
          <label>Connection ID (required for saml)
            <input id="routeConnectionId" type="text" placeholder="uuid for SAML connection" />
          </label>
          <div class="row">
            <button id="btnCreateRoute">Create Domain Route</button>
          </div>
        </article>

        <article class="card">
          <h3>Invitations</h3>
          <div class="row">
            <button id="btnListInvitations" class="alt">List</button>
          </div>
          <label>Email <input id="inviteEmail" type="email" placeholder="member@example.com" /></label>
          <label>Role
            <select id="inviteRole">
              <option value="member">member</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
            </select>
          </label>
          <label>Expires (hours)
            <input id="inviteExpiresHours" type="number" min="1" max="720" value="168" />
          </label>
          <div class="row">
            <button id="btnCreateInvitation">Create Invitation</button>
          </div>
          <label>Invitation ID
            <input id="inviteActionId" type="text" placeholder="invitation uuid" />
          </label>
          <label>Resend/Extend Hours (optional)
            <input id="inviteResendExpiresHours" type="number" min="1" max="720" placeholder="e.g. 168" />
          </label>
          <div class="row">
            <button id="btnResendInvitation" class="alt">Resend</button>
            <button id="btnExtendInvitation" class="alt">Extend</button>
            <button id="btnRevokeInvitation" class="danger">Revoke</button>
          </div>
        </article>

        <article class="card">
          <h3>Compliance Retention</h3>
          <div class="row">
            <button id="btnGetRetention" class="alt">Get Policies</button>
          </div>
          <label>Policies JSON Array
            <textarea id="retentionPolicies">[
  { "targetType": "audit_logs", "retentionDays": 30 },
  { "targetType": "export_jobs", "retentionDays": 14 }
]</textarea>
          </label>
          <div class="row">
            <button id="btnPutRetention">Set Policies</button>
            <button id="btnPrune" class="danger">Prune (Dry Run)</button>
          </div>
        </article>

        <article class="card">
          <h3>KMS Keys</h3>
          <div class="row">
            <button id="btnListKms" class="alt">List Keys</button>
          </div>
          <label>New Key Alias <input id="kmsAlias" type="text" placeholder="enterprise-key-1" /></label>
          <div class="row">
            <button id="btnCreateKms">Create Key</button>
          </div>
          <label>Rotate Key ID <input id="kmsRotateKeyId" type="text" placeholder="key uuid" /></label>
          <div class="row">
            <button id="btnRotateKms" class="alt">Rotate Key</button>
          </div>
        </article>

        <article class="card">
          <h3>Export Jobs</h3>
          <div class="row">
            <button id="btnListExports" class="alt">List Jobs</button>
          </div>
          <label>Target
            <select id="exportTarget">
              <option value="all">all</option>
              <option value="audit_logs">audit_logs</option>
              <option value="members">members</option>
              <option value="policies">policies</option>
              <option value="service_accounts">service_accounts</option>
              <option value="webhooks">webhooks</option>
              <option value="scim_tokens">scim_tokens</option>
            </select>
          </label>
          <label>KMS Key ID (optional)
            <input id="exportKmsKeyId" type="text" placeholder="kms key uuid" />
          </label>
          <label>Filters JSON (optional)
            <textarea id="exportFilters">{ "auditLogLimit": 200 }</textarea>
          </label>
          <div class="row">
            <button id="btnCreateExport">Create Export Job</button>
          </div>
          <div class="help">Use encrypted exports by passing a valid KMS key id.</div>
        </article>
      </section>

      <section class="output-card">
        <div class="output-head" id="outHead">Output</div>
        <pre id="output">Ready.</pre>
      </section>
    </main>
    <script>
      (() => {
        const baseUrl = "${params.origin}";
        const tokenStorageKey = "pj_auth_access_token";

        const tokenInput = document.getElementById("token");
        const adminKeyInput = document.getElementById("adminKey");
        const orgSelect = document.getElementById("orgId");
        const out = document.getElementById("output");
        const outHead = document.getElementById("outHead");

        tokenInput.value = window.localStorage.getItem(tokenStorageKey) || "";

        const print = (label, payload, isError = false) => {
          outHead.textContent = label + (isError ? " (error)" : "");
          out.style.color = isError ? "#fecaca" : "#e2e8f0";
          out.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
        };

        const token = () => tokenInput.value.trim();
        const selectedOrgId = () => orgSelect.value.trim();
        const parseOptionalInt = (value) => {
          const parsed = Number.parseInt((value || "").trim(), 10);
          return Number.isFinite(parsed) ? parsed : undefined;
        };

        const request = async (path, options = {}) => {
          const {
            method = "GET",
            body = undefined,
            auth = true,
            admin = false
          } = options;

          const headers = { "content-type": "application/json" };
          if (auth) {
            const accessToken = token();
            if (!accessToken) {
              throw new Error("Access token is required");
            }
            headers.authorization = "Bearer " + accessToken;
          }
          if (admin) {
            const adminKey = adminKeyInput.value.trim();
            if (!adminKey) {
              throw new Error("Admin API key is required");
            }
            headers["x-admin-api-key"] = adminKey;
          }

          const response = await fetch(baseUrl + path, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body)
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) {
            const message = payload?.error?.message || ("Request failed: " + response.status);
            const error = new Error(message);
            error.payload = payload;
            throw error;
          }
          return payload;
        };

        const withOrg = (suffix) => {
          const orgId = selectedOrgId();
          if (!orgId) {
            throw new Error("Select an organization first");
          }
          return "/v1/orgs/" + encodeURIComponent(orgId) + suffix;
        };

        const bind = (id, handler) => {
          const element = document.getElementById(id);
          element.addEventListener("click", async () => {
            try {
              await handler();
            } catch (error) {
              print(id, { error: error.message || String(error), detail: error.payload || null }, true);
            }
          });
        };

        bind("btnSaveToken", async () => {
          const value = token();
          if (!value) {
            throw new Error("Token is empty");
          }
          window.localStorage.setItem(tokenStorageKey, value);
          print("token", { saved: true });
        });

        bind("btnClearToken", async () => {
          tokenInput.value = "";
          window.localStorage.removeItem(tokenStorageKey);
          print("token", { cleared: true });
        });

        bind("btnLoadOrgs", async () => {
          const payload = await request("/v1/orgs", { method: "GET", auth: true });
          const organizations = payload.organizations || [];
          orgSelect.innerHTML = '<option value="">-- choose org --</option>';
          organizations.forEach((org) => {
            const opt = document.createElement("option");
            opt.value = org.id;
            opt.textContent = org.name + " (" + org.role + ")";
            orgSelect.appendChild(opt);
          });
          print("organizations", payload);
        });

        bind("btnDiagnostics", async () => {
          print("diagnostics", await request(withOrg("/enterprise/diagnostics"), { auth: true }));
        });

        bind("btnAdminStatus", async () => {
          print("admin-status", await request("/v1/admin/system/status", { auth: false, admin: true }));
        });

        bind("btnSamlSigHealth", async () => {
          print(
            "admin-saml-signature-health",
            await request("/v1/admin/saml/signature-health?hours=24", { auth: false, admin: true })
          );
        });

        bind("btnListSaml", async () => {
          print("saml-connections", await request(withOrg("/saml/connections"), { auth: true }));
        });

        bind("btnCreateSaml", async () => {
          const payload = {
            name: document.getElementById("samlName").value.trim(),
            slug: document.getElementById("samlSlug").value.trim() || undefined,
            idpEntityId: document.getElementById("samlEntityId").value.trim(),
            ssoUrl: document.getElementById("samlSsoUrl").value.trim(),
            x509CertPem: document.getElementById("samlCertPem").value.trim(),
            requireSignedAssertions: true,
            allowIdpInitiated: true
          };
          print(
            "create-saml",
            await request(withOrg("/saml/connections"), { method: "POST", auth: true, body: payload })
          );
        });

        bind("btnListRoutes", async () => {
          print("domain-routes", await request(withOrg("/domain-routes"), { auth: true }));
        });

        bind("btnCreateRoute", async () => {
          const connectionType = document.getElementById("routeType").value;
          const rawConnectionId = document.getElementById("routeConnectionId").value.trim();
          const payload = {
            domain: document.getElementById("routeDomain").value.trim(),
            connectionType,
            connectionId: connectionType === "saml" ? rawConnectionId || undefined : undefined
          };
          print(
            "create-domain-route",
            await request(withOrg("/domain-routes"), { method: "POST", auth: true, body: payload })
          );
        });

        bind("btnListInvitations", async () => {
          print("invitations", await request(withOrg("/invitations"), { auth: true }));
        });

        bind("btnCreateInvitation", async () => {
          const expiresInHours = parseOptionalInt(document.getElementById("inviteExpiresHours").value);
          const payload = {
            email: document.getElementById("inviteEmail").value.trim(),
            role: document.getElementById("inviteRole").value,
            expiresInHours: expiresInHours || undefined
          };
          print(
            "create-invitation",
            await request(withOrg("/invitations"), { method: "POST", auth: true, body: payload })
          );
        });

        bind("btnResendInvitation", async () => {
          const invitationId = document.getElementById("inviteActionId").value.trim();
          if (!invitationId) {
            throw new Error("Invitation ID is required");
          }
          const expiresInHours = parseOptionalInt(document.getElementById("inviteResendExpiresHours").value);
          const body = expiresInHours ? { expiresInHours } : {};
          print(
            "resend-invitation",
            await request(withOrg("/invitations/" + encodeURIComponent(invitationId) + "/resend"), {
              method: "POST",
              auth: true,
              body
            })
          );
        });

        bind("btnExtendInvitation", async () => {
          const invitationId = document.getElementById("inviteActionId").value.trim();
          if (!invitationId) {
            throw new Error("Invitation ID is required");
          }
          const expiresInHours = parseOptionalInt(document.getElementById("inviteResendExpiresHours").value);
          if (!expiresInHours) {
            throw new Error("Resend/Extend Hours is required for extension");
          }
          print(
            "extend-invitation",
            await request(withOrg("/invitations/" + encodeURIComponent(invitationId) + "/extend"), {
              method: "POST",
              auth: true,
              body: { expiresInHours }
            })
          );
        });

        bind("btnRevokeInvitation", async () => {
          const invitationId = document.getElementById("inviteActionId").value.trim();
          if (!invitationId) {
            throw new Error("Invitation ID is required");
          }
          print(
            "revoke-invitation",
            await request(withOrg("/invitations/" + encodeURIComponent(invitationId) + "/revoke"), {
              method: "POST",
              auth: true,
              body: {}
            })
          );
        });

        bind("btnGetRetention", async () => {
          print("retention", await request(withOrg("/compliance/retention"), { auth: true }));
        });

        bind("btnPutRetention", async () => {
          const raw = document.getElementById("retentionPolicies").value.trim();
          const policies = JSON.parse(raw);
          print(
            "set-retention",
            await request(withOrg("/compliance/retention"), {
              method: "PUT",
              auth: true,
              body: { policies }
            })
          );
        });

        bind("btnPrune", async () => {
          print(
            "prune",
            await request(withOrg("/compliance/prune"), {
              method: "POST",
              auth: true,
              body: { dryRun: true }
            })
          );
        });

        bind("btnListKms", async () => {
          print("kms-keys", await request(withOrg("/kms/keys"), { auth: true }));
        });

        bind("btnCreateKms", async () => {
          print(
            "create-kms",
            await request(withOrg("/kms/keys"), {
              method: "POST",
              auth: true,
              body: { alias: document.getElementById("kmsAlias").value.trim() }
            })
          );
        });

        bind("btnRotateKms", async () => {
          const keyId = document.getElementById("kmsRotateKeyId").value.trim();
          if (!keyId) {
            throw new Error("Rotate key id is required");
          }
          print(
            "rotate-kms",
            await request(withOrg("/kms/keys/" + encodeURIComponent(keyId) + "/rotate"), {
              method: "POST",
              auth: true,
              body: {}
            })
          );
        });

        bind("btnListExports", async () => {
          print("export-jobs", await request(withOrg("/compliance/exports"), { auth: true }));
        });

        bind("btnCreateExport", async () => {
          const targetType = document.getElementById("exportTarget").value;
          const kmsKeyId = document.getElementById("exportKmsKeyId").value.trim();
          const filtersRaw = document.getElementById("exportFilters").value.trim();
          const body = {
            targetType,
            filters: filtersRaw ? JSON.parse(filtersRaw) : undefined,
            kmsKeyId: kmsKeyId || undefined
          };
          print(
            "create-export",
            await request(withOrg("/compliance/exports"), { method: "POST", auth: true, body })
          );
        });
      })();
    </script>
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

hostedRoutes.get("/hosted/enterprise", (context) => {
  context.header("content-type", "text/html; charset=utf-8");
  return context.body(
    enterpriseHostedPage({
      origin: getAppUrl(context.env, context.req.raw)
    })
  );
});
