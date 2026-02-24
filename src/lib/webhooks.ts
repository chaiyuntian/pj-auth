import type { EnvBindings } from "../types";
import { addSecondsToIso } from "./time";
import {
  createWebhookDelivery,
  findWebhookEndpointById,
  listActiveWebhookEndpointsForOrganization,
  listDueWebhookDeliveries,
  markWebhookDeliveryFailure,
  markWebhookDeliverySuccess,
  updateWebhookEndpointLastDelivery,
  type WebhookDeliveryRow,
  type WebhookEndpointRow
} from "./db";

const MAX_WEBHOOK_ATTEMPTS = 5;

const parseEventTypes = (raw: string | null): string[] => {
  if (!raw) {
    return ["*"];
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return ["*"];
    }
    const cleaned = parsed.filter((value): value is string => typeof value === "string");
    return cleaned.length > 0 ? cleaned : ["*"];
  } catch {
    return ["*"];
  }
};

const shouldDeliver = (endpoint: WebhookEndpointRow, eventType: string): boolean => {
  const allowed = parseEventTypes(endpoint.event_types_json);
  return allowed.includes("*") || allowed.includes(eventType);
};

const signPayload = async (secret: string, timestamp: string, payloadJson: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const message = new TextEncoder().encode(`${timestamp}.${payloadJson}`);
  const signature = await crypto.subtle.sign("HMAC", key, message);
  const bytes = new Uint8Array(signature);
  return Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
};

const retryBackoffSeconds = (attemptCount: number): number => {
  const exponential = Math.pow(2, Math.max(0, attemptCount - 1));
  return Math.min(30 * exponential, 3600);
};

const deliverWebhook = async (params: {
  env: EnvBindings;
  endpoint: WebhookEndpointRow;
  eventType: string;
  payloadJson: string;
  delivery: WebhookDeliveryRow;
}): Promise<void> => {
  const attemptCount = params.delivery.attempt_count + 1;
  const timestamp = new Date().toISOString();
  const signature = await signPayload(params.endpoint.signing_secret, timestamp, params.payloadJson);
  let statusCode: number | null = null;
  try {
    const response = await fetch(params.endpoint.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "pj-auth-webhooks/1.0",
        "x-pj-event": params.eventType,
        "x-pj-delivery-id": params.delivery.id,
        "x-pj-timestamp": timestamp,
        "x-pj-signature": signature
      },
      body: params.payloadJson
    });
    statusCode = response.status;
    if (response.ok) {
      await markWebhookDeliverySuccess(params.env.DB, {
        deliveryId: params.delivery.id,
        statusCode,
        attemptCount
      });
      await updateWebhookEndpointLastDelivery(params.env.DB, params.endpoint.id);
      return;
    }
    const detail = await response.text().catch(() => "");
    const nextAttemptAt = attemptCount >= MAX_WEBHOOK_ATTEMPTS ? null : addSecondsToIso(retryBackoffSeconds(attemptCount));
    await markWebhookDeliveryFailure(params.env.DB, {
      deliveryId: params.delivery.id,
      statusCode,
      attemptCount,
      nextAttemptAt,
      lastError: `HTTP ${statusCode}${detail ? ` ${detail.slice(0, 500)}` : ""}`
    });
  } catch (error) {
    const nextAttemptAt = attemptCount >= MAX_WEBHOOK_ATTEMPTS ? null : addSecondsToIso(retryBackoffSeconds(attemptCount));
    await markWebhookDeliveryFailure(params.env.DB, {
      deliveryId: params.delivery.id,
      statusCode,
      attemptCount,
      nextAttemptAt,
      lastError: error instanceof Error ? error.message : "Webhook delivery request failed"
    });
  }
};

export const emitOrganizationWebhookEvent = async (params: {
  env: EnvBindings;
  organizationId: string;
  eventType: string;
  payload: Record<string, unknown>;
}): Promise<void> => {
  const endpoints = await listActiveWebhookEndpointsForOrganization(params.env.DB, params.organizationId);
  if (endpoints.length === 0) {
    return;
  }
  const payloadJson = JSON.stringify({
    eventType: params.eventType,
    organizationId: params.organizationId,
    timestamp: new Date().toISOString(),
    data: params.payload
  });

  for (const endpoint of endpoints) {
    if (!shouldDeliver(endpoint, params.eventType)) {
      continue;
    }
    const delivery: WebhookDeliveryRow = {
      id: crypto.randomUUID(),
      endpoint_id: endpoint.id,
      event_type: params.eventType,
      payload_json: payloadJson,
      status: "pending",
      status_code: null,
      attempt_count: 0,
      next_attempt_at: new Date().toISOString(),
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    await createWebhookDelivery(params.env.DB, {
      id: delivery.id,
      endpointId: endpoint.id,
      eventType: params.eventType,
      payloadJson
    });
    await deliverWebhook({
      env: params.env,
      endpoint,
      eventType: params.eventType,
      payloadJson,
      delivery
    });
  }
};

export const retryDueWebhookDeliveries = async (params: {
  env: EnvBindings;
  limit?: number;
}): Promise<{ processed: number }> => {
  const due = await listDueWebhookDeliveries(params.env.DB, params.limit ?? 50);
  let processed = 0;
  for (const delivery of due) {
    const endpoint = await findWebhookEndpointById(params.env.DB, delivery.endpoint_id);
    if (!endpoint || !endpoint.is_active) {
      await markWebhookDeliveryFailure(params.env.DB, {
        deliveryId: delivery.id,
        statusCode: delivery.status_code,
        attemptCount: delivery.attempt_count + 1,
        nextAttemptAt: null,
        lastError: "Webhook endpoint missing or inactive"
      });
      processed += 1;
      continue;
    }
    await deliverWebhook({
      env: params.env,
      endpoint,
      eventType: delivery.event_type,
      payloadJson: delivery.payload_json,
      delivery
    });
    processed += 1;
  }
  return { processed };
};
