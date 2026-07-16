const crypto = require("crypto");

const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60; // 8 hours

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sign(payloadB64, secret) {
  return crypto.createHmac("sha256", secret).update(payloadB64).digest("hex");
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const adminPassword = process.env.ADMIN_PASSWORD;
  const secret = process.env.SESSION_SECRET;

  if (!adminPassword || !secret) {
    res.status(500).json({
      error:
        "Server not configured. Set ADMIN_PASSWORD and SESSION_SECRET environment variables in Vercel.",
    });
    return;
  }

  const { password } = req.body || {};

  await new Promise((resolve) => setTimeout(resolve, 400));

  if (!password || !timingSafeEqualStr(password, adminPassword)) {
    res.status(401).json({ error: "Incorrect password" });
    return;
  }

  const exp = Date.now() + SESSION_MAX_AGE_SECONDS * 1000;
  const payloadB64 = base64url(JSON.stringify({ exp }));
  const signature = sign(payloadB64, secret);
  const token = `${payloadB64}.${signature}`;

  res.setHeader(
    "Set-Cookie",
    `gh_admin_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}`
  );
  res.status(200).json({ success: true });
};
