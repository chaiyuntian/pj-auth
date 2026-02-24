import React from "react";
import { PajamaAuthBrowserClient } from "@pajamadot/auth-browser";

const PajamaAuthContext = React.createContext(null);

export const PajamaAuthProvider = ({ baseUrl, children, storageKey }) => {
  const client = React.useMemo(
    () =>
      new PajamaAuthBrowserClient({
        baseUrl,
        storageKey
      }),
    [baseUrl, storageKey]
  );
  return React.createElement(PajamaAuthContext.Provider, { value: client }, children);
};

export const usePajamaAuth = () => {
  const client = React.useContext(PajamaAuthContext);
  if (!client) {
    throw new Error("usePajamaAuth must be used inside PajamaAuthProvider");
  }
  return client;
};
