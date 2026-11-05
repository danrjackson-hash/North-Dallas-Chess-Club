import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://danrjackson-hash.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function response(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "Method not allowed." }, 405);

  const origin = req.headers.get("origin");
  if (origin !== allowedOrigin) return response({ error: "Request not allowed." }, 403);

  let body: { full_name?: unknown; email?: unknown; website?: unknown };
  try {
    body = await req.json();
  } catch {
    return response({ error: "Invalid request." }, 400);
  }

  // Keep the existing honeypot. Quietly discard likely bot submissions.
  if (typeof body.website === "string" && body.website.trim()) {
    return response({ ok: true });
  }

  const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (!fullName || fullName.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return response({ error: "Please enter a valid name and email address." }, 400);
  }

  // Supabase's hosted edge ingress supplies this client address header.
  // Fail closed rather than falling back to spoofable forwarding headers.
  const clientIp = req.headers.get("cf-connecting-ip")?.trim();
  if (!clientIp) return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) {
    console.error("Registration function is missing its Supabase environment configuration.");
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }

  const admin = createClient(supabaseUrl, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // Hash the address with a server-held secret; raw IP addresses are never stored.
  const ipHash = await sha256(clientIp + ":" + serviceKey);
  const { data: allowed, error: limitError } = await admin.rpc("consume_registration_rate_limit", {
    p_ip_hash: ipHash,
  });
  if (limitError) {
    console.error("Registration rate-limit check failed:", limitError.message);
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }
  if (allowed !== true) {
    return new Response(JSON.stringify({ error: "Too many registration requests from this network. Please try again in about an hour." }), {
      status: 429,
      headers: { ...corsHeaders, "Content-Type": "application/json", "Retry-After": "3600" },
    });
  }

  const { error: insertError } = await admin.from("registration_requests").insert({
    full_name: fullName,
    email,
  });

  if (insertError?.code === "23505") {
    return response({ error: "A registration request for this email is already awaiting review." }, 409);
  }
  if (insertError) {
    console.error("Registration insert failed:", insertError.message);
    return response({ error: "We could not submit your request. Please try again." }, 500);
  }

  return response({ ok: true });
});
