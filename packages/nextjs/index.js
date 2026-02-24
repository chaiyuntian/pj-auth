import { PajamaAuthServerClient } from "@pajamadot/auth-server";

export const createPajamaAuth = ({ baseUrl }) => {
  const client = new PajamaAuthServerClient({ baseUrl });

  const getAccessTokenFromRequest = (request, cookieName = "pj_auth_access_token") => {
    const authorization = request?.headers?.get?.("authorization");
    if (authorization && authorization.toLowerCase().startsWith("bearer ")) {
      return authorization.slice("bearer ".length).trim();
    }
    const cookieHeader = request?.headers?.get?.("cookie") || "";
    const cookies = Object.fromEntries(
      cookieHeader
        .split(";")
        .map((segment) => segment.trim())
        .filter(Boolean)
        .map((segment) => {
          const [key, ...rest] = segment.split("=");
          return [key, decodeURIComponent(rest.join("="))];
        })
    );
    return cookies[cookieName] || null;
  };

  const requireUser = async (request, options = {}) => {
    const accessToken = getAccessTokenFromRequest(request, options.cookieName);
    if (!accessToken) {
      const error = new Error("Missing access token");
      error.status = 401;
      throw error;
    }
    return client.getUserFromAccessToken(accessToken);
  };

  return {
    client,
    getAccessTokenFromRequest,
    requireUser
  };
};
