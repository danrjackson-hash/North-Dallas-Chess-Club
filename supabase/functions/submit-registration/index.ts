import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://danrjackson-hash.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function response(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}
async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "Method not allowed." }, 405);
  if (req.headers.get("origin") !== allowedOrigin) return response({ error: "Request not allowed." }, 403);

  let body: { full_name?: unknown; email?: unknown; skill_level?: unknown; access_code?: unknown; website?: unknown };
  try { body = await req.json(); } catch { return response({ error: "Invalid request." }, 400); }
  if (!body || typeof body !== "object") return response({ error: "Invalid request." }, 400);
  if (typeof body.website === "string" && body.website.trim()) return response({ ok: true });

  const fullName = typeof body.full_name === "string" ? body.full_name.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const skillLevel = typeof body.skill_level === "string" ? body.skill_level : "";
  const accessCode = typeof body.access_code === "string" ? body.access_code.trim().toUpperCase().replace(/[^A-Z0-9]/g, "") : "";
  const allowedSkillLevels = ["Beginner", "Intermediate", "Advanced", "Expert"];
  if (!fullName || fullName.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return response({ error: "Please enter a valid name and email address." }, 400);
  }
  if (!allowedSkillLevels.includes(skillLevel)) return response({ error: "Please choose a valid starting skill level." }, 400);
  if (accessCode.length !== 20) return response({ error: "Enter the club access code provided by a member." }, 400);

  const clientIp = req.headers.get("cf-connecting-ip")?.trim();
  if (!clientIp) return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) {
    console.error("Registration function is missing its Supabase environment configuration.");
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }

  const admin = createClient(supabaseUrl, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const ipHash = await sha256(clientIp + ":" + serviceKey);
  const { data: allowed, error: limitError } = await admin.rpc("consume_registration_rate_limit", { p_ip_hash: ipHash });
  if (limitError) {
    console.error("Registration rate-limit check failed:", limitError.message);
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }
  if (allowed !== true) {
    return new Response(JSON.stringify({ error: "Too many registration attempts from this network. Please try again in about an hour." }), {
      status: 429, headers: { ...corsHeaders, "Content-Type": "application/json", "Retry-After": "3600" },
    });
  }

  const { data: secret, error: secretError } = await admin.from("club_registration_secrets")
    .select("code_hash").eq("id", true).maybeSingle();
  if (secretError || !secret?.code_hash) {
    console.error("Registration access-code lookup failed:", secretError?.message || "No code configured");
    return response({ error: "Club registration is not currently available. Please contact a club member." }, 503);
  }
  const submittedHash = await sha256(accessCode);
  if (!constantTimeEqual(submittedHash, secret.code_hash)) {
    return response({ error: "That club access code is not valid. Please check it with the person who invited you." }, 403);
  }

  const { data: existingProfile, error: profileError } = await admin.from("profiles")
    .select("player_id").ilike("email", email).maybeSingle();
  if (profileError) {
    console.error("Registration duplicate check failed:", profileError.message);
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }
  if (existingProfile?.player_id) return response({ error: "This email is already linked to a club player account. Please sign in instead." }, 409);

  const { data: existingRequest, error: requestLookupError } = await admin.from("registration_requests")
    .select("id,status").ilike("email", email)
    .in("status", ["pending", "awaiting_verification", "approved"]).maybeSingle();
  if (requestLookupError) {
    console.error("Registration request lookup failed:", requestLookupError.message);
    return response({ error: "Registration is temporarily unavailable. Please try again later." }, 503);
  }
  if (existingRequest?.status === "approved") {
    return response({ error: "This email already has a club registration. Please sign in or contact the club administrator." }, 409);
  }
  if (existingRequest?.status === "pending") {
    return response({ error: "A previous registration request for this email is awaiting administrator review. Please contact the club administrator." }, 409);
  }

  if (existingRequest?.status === "awaiting_verification") {
    const { error: updateError } = await admin.from("registration_requests")
      .update({ full_name: fullName, skill_level: skillLevel, submitted_at: new Date().toISOString() })
      .eq("id", existingRequest.id);
    if (updateError) {
      console.error("Registration retry update failed:", updateError.message);
      return response({ error: "We could not prepare your verification email. Please try again." }, 500);
    }
  } else {
    const { error: insertError } = await admin.from("registration_requests").insert({
      full_name: fullName, email, skill_level: skillLevel, status: "awaiting_verification",
    });
    if (insertError?.code === "23505") {
      return response({ error: "A registration for this email is already in progress. Please try again in a moment." }, 409);
    }
    if (insertError) {
      console.error("Registration insert failed:", insertError.message);
      return response({ error: "We could not submit your registration. Please try again." }, 500);
    }
  }
  return response({ ok: true });
});
