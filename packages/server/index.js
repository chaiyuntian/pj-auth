export class PajamaAuthServerClient {
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || "").replace(/\/$/, "");
    if (!this.baseUrl) {
      throw new Error("baseUrl is required");
    }
  }

  async getUserFromAccessToken(accessToken) {
    if (!accessToken) {
      throw new Error("accessToken is required");
    }
    const response = await fetch(`${this.baseUrl}/v1/auth/me`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload?.error?.message || "Auth verification failed");
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async introspectApiKey(apiKey) {
    if (!apiKey) {
      throw new Error("apiKey is required");
    }
    const response = await fetch(`${this.baseUrl}/v1/m2m/me`, {
      method: "GET",
      headers: {
        "x-api-key": apiKey
      }
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload?.error?.message || "API key introspection failed");
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }
}
