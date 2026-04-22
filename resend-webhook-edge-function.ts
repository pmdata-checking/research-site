// Supabase Edge Function: resend-webhook
// Receives Resend email event webhooks (Svix-signed) and handles bounce events:
//   1. Verifies the Svix signature (RESEND_WEBHOOK_SECRET)
//   2. On email.bounced, searches the records table Private Notes for the
//      recipient's email, appends a [BOUNCED] stamp to that record's
//      Private Notes, and emails rob@prospectmanager.co.uk a notification.
//
// Deploy:
//   supabase functions deploy resend-webhook --no-verify-jwt
//
// Required Supabase secrets:
//   RESEND_WEBHOOK_SECRET     — from Resend webhook endpoint (whsec_...)
//   RESEND_API_KEY            — existing, used to send notification email
//   SUPABASE_URL              — auto-set by Supabase
//   SUPABASE_SERVICE_ROLE_KEY — for service-role DB access (bypass RLS)

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, svix-id, svix-timestamp, svix-signature",
};

const NOTIFY_TO = "rob@prospectmanager.co.uk";
const NOTIFY_FROM = "Prospect Manager <noreply@prospectmanager.co.uk>";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { ...corsHeaders, "Content-Type": "text/plain" },
  });
}

// ---- Svix signature verification ----
// Svix signatures are formatted "v1,<base64_hmac_sha256>" and multiple can be
// present space-separated. The signed payload is "{id}.{timestamp}.{body}".
async function verifySvixSignature(
  payload: string,
  headerSig: string | null,
  headerId: string | null,
  headerTimestamp: string | null,
  secret: string,
): Promise<boolean> {
  if (!headerSig || !headerId || !headerTimestamp) return false;

  // Reject timestamps more than 5 minutes old (replay protection)
  const tsSec = parseInt(headerTimestamp, 10);
  if (!Number.isFinite(tsSec)) return false;
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - tsSec) > 60 * 5) return false;

  // Strip the "whsec_" prefix if present, then base64-decode the secret
  const rawSecret = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  let keyBytes: Uint8Array;
  try {
    keyBytes = Uint8Array.from(atob(rawSecret), (c) => c.charCodeAt(0));
  } catch {
    return false;
  }

  const toSign = `${headerId}.${headerTimestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(toSign),
  );
  const expected = btoa(
    String.fromCharCode(...new Uint8Array(sigBytes)),
  );

  // Header format: "v1,sig1 v1,sig2 ..." — match any v1 entry
  for (const part of headerSig.split(/\s+/)) {
    const [version, sig] = part.split(",");
    if (version === "v1" && sig === expected) return true;
  }
  return false;
}

// ---- Find the record that was emailed to this recipient ----
// The frontend stamps Private Notes on send with a line like:
//   "Name — YYYYMMDD HH:MM — Email sent to recipient@example.com"
// We search the records table for that stamp (case-insensitively) on either
// a direct Private_Notes column or anywhere in the data JSONB blob, and
// pick the most recently updated match.
interface FoundRecord {
  id: string;
  privateNotesColumn: "Private_Notes" | "data";
  privateNotesKey: string | null;
  existingNotes: string;
}

async function findRecordByRecipient(
  supabase: ReturnType<typeof createClient>,
  recipient: string,
): Promise<FoundRecord | null> {
  const stampSnippet = `Email sent to ${recipient}`;
  // Try direct Private_Notes column first.
  // The column name on the records table is unknown (varies by schema),
  // but if it exists we try common variants.
  for (const col of ["Private_Notes", "private_notes", "PRIVATE_NOTES"]) {
    try {
      const { data, error } = await supabase
        .from("records")
        .select("id," + col + ",updated_at")
        .ilike(col, `%${stampSnippet}%`)
        .order("updated_at", { ascending: false })
        .limit(1);
      if (!error && data && data.length > 0) {
        const row = data[0] as Record<string, unknown>;
        return {
          id: String(row.id),
          privateNotesColumn: "Private_Notes",
          privateNotesKey: col,
          existingNotes: String(row[col] || ""),
        };
      }
    } catch {
      // Column likely doesn't exist — try the next variant.
    }
  }

  // Fall back to searching the data JSONB blob.
  // Postgres: data::text ILIKE '%...%'. Supabase JS doesn't expose raw SQL,
  // so we use a wildcard filter on the text cast via rpc or PostgREST.
  // PostgREST supports: ?data=cs.%22...%22 (contains) but not ILIKE on JSONB.
  // Workaround: use .textSearch on data if available, otherwise use rpc.
  const { data, error } = await supabase
    .from("records")
    .select("id,data,updated_at")
    .filter("data::text", "ilike", `%${stampSnippet}%`)
    .order("updated_at", { ascending: false })
    .limit(1);
  if (!error && data && data.length > 0) {
    const row = data[0] as { id: string; data: Record<string, unknown> };
    // Locate the Private Notes key case-insensitively within the JSONB
    const pnKey =
      Object.keys(row.data || {}).find(
        (k) => k.toLowerCase().replace(/[_\s]/g, "") === "privatenotes",
      ) || "Private_Notes";
    return {
      id: row.id,
      privateNotesColumn: "data",
      privateNotesKey: pnKey,
      existingNotes: String((row.data || {})[pnKey] || ""),
    };
  }

  return null;
}

async function appendBounceStamp(
  supabase: ReturnType<typeof createClient>,
  found: FoundRecord,
  recipient: string,
  bouncedAt: Date,
): Promise<boolean> {
  const stampDate =
    bouncedAt.getFullYear().toString() +
    String(bouncedAt.getMonth() + 1).padStart(2, "0") +
    String(bouncedAt.getDate()).padStart(2, "0");
  const stamp = `[BOUNCED] Email to ${recipient} bounced on ${stampDate}`;
  const newNotes = found.existingNotes
    ? `${found.existingNotes}\n${stamp}`
    : stamp;

  if (found.privateNotesColumn === "Private_Notes" && found.privateNotesKey) {
    const patch: Record<string, string> = {};
    patch[found.privateNotesKey] = newNotes;
    const { error } = await supabase
      .from("records")
      .update(patch)
      .eq("id", found.id);
    if (error) {
      console.error("appendBounceStamp (direct column) error:", error);
      return false;
    }
    return true;
  }

  // data JSONB path — read-modify-write
  const { data: row, error: readErr } = await supabase
    .from("records")
    .select("data")
    .eq("id", found.id)
    .single();
  if (readErr || !row) {
    console.error("appendBounceStamp (jsonb read) error:", readErr);
    return false;
  }
  const currentData = (row as { data: Record<string, unknown> }).data || {};
  const key = found.privateNotesKey || "Private_Notes";
  currentData[key] = newNotes;
  const { error: writeErr } = await supabase
    .from("records")
    .update({ data: currentData })
    .eq("id", found.id);
  if (writeErr) {
    console.error("appendBounceStamp (jsonb write) error:", writeErr);
    return false;
  }
  return true;
}

async function sendNotificationEmail(
  subject: string,
  to: string,
  recipient: string,
  bouncedAt: Date,
  recordFound: boolean,
): Promise<void> {
  const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY");
  if (!RESEND_API_KEY) {
    console.error("RESEND_API_KEY not set — skipping notification email");
    return;
  }
  const dateStr = bouncedAt.toISOString().slice(0, 19).replace("T", " ") + " UTC";
  const body = `
    <p>An email sent via Prospect Manager has bounced.</p>
    <ul>
      <li><strong>Subject:</strong> ${subject || "(none)"}</li>
      <li><strong>To:</strong> ${recipient}</li>
      <li><strong>Date:</strong> ${dateStr}</li>
      <li><strong>Record updated:</strong> ${recordFound ? "Yes — [BOUNCED] stamp added to Private Notes" : "No match found in records"}</li>
    </ul>
    <p style="color:#666;font-size:12px;">Sent automatically by the resend-webhook Edge Function.</p>
  `;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: NOTIFY_FROM,
      to: [NOTIFY_TO],
      subject: `Email bounced — ${recipient}`,
      html: body,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    console.error("Notification email send failed:", res.status, errText);
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return textResponse("Method not allowed", 405);
  }

  const WEBHOOK_SECRET = Deno.env.get("RESEND_WEBHOOK_SECRET");
  if (!WEBHOOK_SECRET) {
    console.error("RESEND_WEBHOOK_SECRET not configured");
    return jsonResponse({ error: "Webhook secret not configured" }, 500);
  }

  // Read the raw body BEFORE JSON-parsing — signature is over the raw bytes
  const rawBody = await req.text();

  const svixId = req.headers.get("svix-id");
  const svixTimestamp = req.headers.get("svix-timestamp");
  const svixSignature = req.headers.get("svix-signature");

  const sigOk = await verifySvixSignature(
    rawBody,
    svixSignature,
    svixId,
    svixTimestamp,
    WEBHOOK_SECRET,
  );
  if (!sigOk) {
    console.warn("Signature verification failed");
    return jsonResponse({ error: "Invalid signature" }, 401);
  }

  let event: Record<string, unknown>;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return jsonResponse({ error: "Invalid JSON" }, 400);
  }

  const eventType = String(event.type || "");
  console.log("Resend webhook event:", eventType);

  if (eventType !== "email.bounced") {
    // Recognised event types from Resend we explicitly ignore (200)
    const ignored = [
      "email.sent", "email.delivered", "email.delivery_delayed",
      "email.complained", "email.opened", "email.clicked",
    ];
    if (ignored.includes(eventType)) {
      return jsonResponse({ status: "ignored", type: eventType }, 200);
    }
    return jsonResponse({ error: `Unrecognised event: ${eventType}` }, 400);
  }

  // Extract bounce data
  const data = (event.data || {}) as Record<string, unknown>;
  const toField = data.to;
  const recipient = Array.isArray(toField)
    ? String(toField[0] || "")
    : String(toField || "");
  const subject = String(data.subject || "");
  const createdAt = String(data.created_at || event.created_at || "");
  const bouncedAt = createdAt ? new Date(createdAt) : new Date();

  if (!recipient) {
    return jsonResponse({ error: "Missing recipient (to) in bounce event" }, 400);
  }

  console.log(`Bounce: to=${recipient} subject=${subject} at=${bouncedAt.toISOString()}`);

  // Supabase service-role client (bypasses RLS)
  const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
  const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  let recordFound = false;

  if (SUPABASE_URL && SERVICE_KEY) {
    const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    try {
      const found = await findRecordByRecipient(supabase, recipient);
      if (found) {
        const ok = await appendBounceStamp(supabase, found, recipient, bouncedAt);
        recordFound = ok;
        if (ok) console.log(`Record ${found.id} updated with bounce stamp`);
      } else {
        console.log(`No record found with "Email sent to ${recipient}" in Private Notes`);
      }
    } catch (e) {
      console.error("Record update failed:", e);
    }
  } else {
    console.warn("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set — skipping record update");
  }

  // Always send the notification email to rob@
  try {
    await sendNotificationEmail(subject, recipient, recipient, bouncedAt, recordFound);
  } catch (e) {
    console.error("Notification email failed:", e);
  }

  return jsonResponse({ status: "ok", recipient, record_updated: recordFound }, 200);
});
