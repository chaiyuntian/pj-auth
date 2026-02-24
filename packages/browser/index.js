export class PajamaAuthBrowserClient {
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || "").replace(/\/$/, "");
    if (!this.baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.storage = options.storage || (typeof window !== "undefined" ? window.localStorage : null);
    this.storageKey = options.storageKey || "pj_auth_access_token";
    this.accessToken = this.storage ? this.storage.getItem(this.storageKey) : null;
  }

  setAccessToken(token) {
    this.accessToken = token || null;
    if (!this.storage) {
      return;
    }
    if (this.accessToken) {
      this.storage.setItem(this.storageKey, this.accessToken);
    } else {
      this.storage.removeItem(this.storageKey);
    }
  }

  getAccessToken() {
    return this.accessToken;
  }

  async request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has("content-type") && options.body) {
      headers.set("content-type", "application/json");
    }
    if (this.accessToken) {
      headers.set("authorization", `Bearer ${this.accessToken}`);
    }
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload?.error?.message || "Request failed");
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    if (payload?.session?.accessToken) {
      this.setAccessToken(payload.session.accessToken);
    }
    return payload;
  }

  signUp(input) {
    return this.request("/v1/auth/sign-up", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  signIn(input) {
    return this.request("/v1/auth/sign-in", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  signInWithPasskeyStart(input) {
    return this.request("/v1/auth/passkeys/authenticate/start", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  signInWithPasskeyFinish(input) {
    return this.request("/v1/auth/passkeys/authenticate/finish", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  me() {
    return this.request("/v1/auth/me", {
      method: "GET"
    });
  }

  signOut() {
    return this.request("/v1/auth/sign-out", {
      method: "POST"
    }).finally(() => this.setAccessToken(null));
  }

  startGoogleAuth(redirectTo) {
    const url = new URL("/v1/oauth/google/start", this.baseUrl);
    if (redirectTo) {
      url.searchParams.set("redirect_to", redirectTo);
    }
    if (typeof window !== "undefined") {
      window.location.href = url.toString();
      return;
    }
    return url.toString();
  }
}
