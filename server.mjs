import http from "node:http";
import { execFile } from "node:child_process";

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

let running = false;

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        reject(new Error("Body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    return res.end("POST only");
  }

  if (running) {
    res.writeHead(429, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "login already running" }));
  }

  let body = {};
  try {
    body = await readJson(req);
  } catch (e) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: e.message }));
  }

  const email = body.email;
  const password = body.password;

  if (!email || !password) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "email and password required" }));
  }

running = true;

  const childEnv = {
    ...process.env,
    ARYEO_EMAIL: email,
    ARYEO_PASSWORD: password,
    ARYEO_OTP: body.otp || process.env.ARYEO_OTP || "",
    ARYEO_TOTP_SECRET: body.totpSecret || process.env.ARYEO_TOTP_SECRET || "",
    ARYEO_LOGIN_URL: body.loginUrl || process.env.ARYEO_LOGIN_URL || "",
    ARYEO_POST_LOGIN_URL: body.postLoginUrl || process.env.ARYEO_POST_LOGIN_URL || "",
    ARYEO_PROFILE_DIR: process.env.ARYEO_PROFILE_DIR || "/home/pw/profile",
    ARYEO_TIMEOUT: String(body.timeoutMs || process.env.ARYEO_TIMEOUT || "60000"),
    ARYEO_SELECTOR_TIMEOUT: String(body.selectorTimeoutMs || process.env.ARYEO_SELECTOR_TIMEOUT || "15000"),
    ARYEO_DEBUG: body.debug ? "1" : (process.env.ARYEO_DEBUG || "0"),
    ARYEO_CAPTURE_NETWORK: body.captureNetwork ? "1" : "0",
    ARYEO_CAPTURE_URL: body.captureUrl || "",
  };

  execFile(
    "node",
    ["/app/login_and_cookies.mjs"],
    {
      env: childEnv,
      timeout: 180000,
      maxBuffer: 25 * 1024 * 1024,
    },
    (err, stdout, stderr) => {
      running = false;

      if (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          error: err.message,
          code: err.code,
          signal: err.signal,
          stderr: stderr?.slice?.(-8000) || stderr,
          stdout: stdout?.slice?.(-8000) || stdout,
        }));
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(stdout);
    }
  );
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Aryeo login service listening on ${PORT}`);
});
