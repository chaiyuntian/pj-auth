import type { EnvBindings } from "../types";
import { getEmailFromAddress, getResendApiBaseUrl } from "./config";

export type EmailSendResult = {
  delivered: boolean;
  provider: "resend" | "log";
  messageId?: string;
  reason?: string;
};

const htmlEscape = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

export const sendTransactionalEmail = async (params: {
  env: EnvBindings;
  to: string;
  subject: string;
  text: string;
  html?: string;
}): Promise<EmailSendResult> => {
  const resendApiKey = params.env.RESEND_API_KEY?.trim();
  const fromAddress = getEmailFromAddress(params.env);

  if (!resendApiKey || !fromAddress) {
    console.log(
      `[email.log_only] to=${params.to} subject=${params.subject} text=${params.text.replaceAll("\n", " | ")}`
    );
    return {
      delivered: false,
      provider: "log",
      reason: "RESEND_API_KEY or EMAIL_FROM not configured"
    };
  }

  const response = await fetch(`${getResendApiBaseUrl(params.env)}/emails`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${resendApiKey}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      from: fromAddress,
      to: [params.to],
      subject: params.subject,
      text: params.text,
      html:
        params.html ??
        `<p>${htmlEscape(params.text)}</p>`
    })
  });

  if (!response.ok) {
    const detail = await response.text();
    console.error(`[email.resend_error] status=${response.status} detail=${detail}`);
    return {
      delivered: false,
      provider: "resend",
      reason: `Resend API error (${response.status})`
    };
  }

  const payload = (await response.json()) as { id?: string };
  return {
    delivered: true,
    provider: "resend",
    messageId: payload.id
  };
};
