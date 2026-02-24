import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { EnvBindings } from "../types";
import { getCookieDomain, getCookieName } from "./config";

const isSecureRequest = <T extends { Bindings: EnvBindings }>(context: Context<T>): boolean =>
  new URL(context.req.url).protocol === "https:";

export const setRefreshTokenCookie = <T extends { Bindings: EnvBindings }>(
  context: Context<T>,
  refreshToken: string,
  maxAgeSeconds: number
): void => {
  const domain = getCookieDomain(context.env);
  setCookie(context, getCookieName(context.env), refreshToken, {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    secure: isSecureRequest(context),
    maxAge: maxAgeSeconds,
    domain: domain ?? undefined
  });
};

export const clearRefreshTokenCookie = <T extends { Bindings: EnvBindings }>(context: Context<T>): void => {
  const domain = getCookieDomain(context.env);
  deleteCookie(context, getCookieName(context.env), {
    path: "/",
    domain: domain ?? undefined
  });
};

export const readRefreshTokenCookie = <T extends { Bindings: EnvBindings }>(
  context: Context<T>
): string | undefined =>
  getCookie(context, getCookieName(context.env));
