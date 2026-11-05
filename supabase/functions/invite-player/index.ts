import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://danrjackson-hash.github.io";
const appRedirect = "https://danrjackson-hash.github.io/North-Dallas-Chess-Club/";
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

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "Method not allowed." }, 405);
  if (req.headers.get("origin") !== allowedOrigin) {
    return response({ error: "Request not allowed." }, 403);
  }

  const authorization = req.headers.get("authorization") || "";
  const accessToken = authorization.replace(/^Bearer\s+/i, "").trim();
  if (!accessToken) {
    console.error("Invitation auth check failed: Authorization bearer token was missing.");
    return response({ error: "Please sign in as a club administrator." }, 401);
  }

  let body: { request_id?: unknown };
  try {
    body = await req.json();
  } catch {
    return response({ error: "Invalid request." }, 400);
  }
  if (!body || typeof body !== "object" ||
      typeof body.request_id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.request_id)) {
    return response({ error: "A valid registration request is required." }, 400);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceKey) {
    console.error("Invitation function is missing Supabase environment configuration.");
    return response({ error: "Invitations are temporarily unavailable." }, 503);
  }

  // Verify the caller's access token directly against Supabase Auth.
  // This avoids relying on an SDK client's in-memory session state in an Edge Function.
  let verifiedUser: { id: string } | null = null;
  try {
    const verifyResponse = await fetch(`${supabaseUrl}/auth/v1/user`, {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (verifyResponse.ok) {
      const authUser = await verifyResponse.json();
      if (typeof authUser?.id === "string") verifiedUser = { id: authUser.id };
    } else {
      const detail = await verifyResponse.text();
      console.error("Invitation auth check failed: Supabase Auth returned", verifyResponse.status, detail.slice(0, 500));
    }
  } catch (error) {
    console.error("Invitation auth check failed during token verification:", error instanceof Error ? error.message : "Unknown error");
  }
  if (!verifiedUser) {
    return response({ error: "Your sign-in session is invalid. Please sign in again." }, 401);
  }

  const admin = createClient(supabaseUrl, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data: profile, error: profileError } = await admin
    .from("profiles")
    .select("role")
    .eq("id", verifiedUser.id)
    .maybeSingle();
  if (profileError) {
    console.error("Could not verify invitation administrator:", profileError.message);
    return response({ error: "Could not verify administrator permissions." }, 500);
  }
  if (profile?.role !== "admin") {
    return response({ error: "Only a club administrator can send player invitations." }, 403);
  }

  const { data: registration, error: requestError } = await admin
    .from("registration_requests")
    .select("id, full_name, email, status, player_id, invitation_sent_at")
    .eq("id", body.request_id)
    .maybeSingle();
  if (requestError) {
    console.error("Could not load approved registration:", requestError.message);
    return response({ error: "Could not load the registration request." }, 500);
  }
  if (!registration || registration.status !== "approved" || !registration.player_id) {
    return response({ error: "This registration must be approved before an invitation can be sent." }, 409);
  }
  if (registration.invitation_sent_at) {
    return response({ error: "An invitation has already been sent for this registration." }, 409);
  }

  const { error: inviteError } = await admin.auth.admin.inviteUserByEmail(
    registration.email,
    {
      redirectTo: appRedirect,
      data: { display_name: registration.full_name },
    },
  );
  if (inviteError) {
    console.error("Supabase invitation failed:", inviteError.message);
    return response({ error: inviteError.message }, 502);
  }

  const { error: updateError } = await admin
    .from("registration_requests")
    .update({ invitation_sent_at: new Date().toISOString() })
    .eq("id", registration.id)
    .is("invitation_sent_at", null);
  if (updateError) {
    console.error("Invitation sent but status update failed:", updateError.message);
    return response({
      error: "The invitation may have been sent, but its status could not be saved. Check the Supabase Auth user list before retrying.",
    }, 500);
  }

  return response({ ok: true, email: registration.email, full_name: registration.full_name });
});
