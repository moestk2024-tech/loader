const CONFIG = {
  // === EDIT REDIRECT DI SINI ===
  redirects: {
    "gacorr1": "https://vpn.8naga.space/1slowin79",
    "gacorr2": "https://vpn.8naga.space/2slowin79",
    "gacorr3": "https://vpn.8naga.space/3slowin79",
    "gacorr4": "https://vpn.8naga.space/4slowin79"
  },

  // PoW difficulty. 14 = ringan. Naikkan jika perlu.
  difficulty: 14,

  // Challenge berlaku 2 menit.
  challengeTtlSeconds: 120,

  // Cookie valid 1 jam.
  passTtlSeconds: 3600,

  // Secret acak dibuat saat ZIP ini dibuat.
  // Jika repo PUBLIC, sebaiknya pindahkan ke Cloudflare Secret env AMAROK_SECRET.
  embeddedSecret: "ac64aeadd32ba707c39b5fb2a8fd53dc55521a01ccb6eaf60929961d408a97b0"
};

const COOKIE = "__Host-amrk_pass_v1";
const enc = new TextEncoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    {name:"HMAC", hash:"SHA-256"}, false, ["sign"]
  );
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}

async function sha256Text(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

function zeroBits(bytes) {
  let bits = 0;
  for (const b of bytes) {
    if (b === 0) { bits += 8; continue; }
    for (let i=7;i>=0;i--) {
      if ((b & (1<<i)) === 0) bits++;
      else return bits;
    }
  }
  return bits;
}

function getCookie(req, name) {
  const h = req.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const p = part.trim();
    if (p.startsWith(name + "=")) return p.slice(name.length + 1);
  }
  return "";
}

function safeCode(pathname) {
  const p = pathname.replace(/^\/+|\/+$/g, "");
  if (!p || p.includes("/")) return "";
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(p)) return "";
  return p;
}

function json(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type":"application/json; charset=utf-8",
      "cache-control":"no-store",
      ...headers
    }
  });
}

async function getSecret(env) {
  return env.AMAROK_SECRET || CONFIG.embeddedSecret;
}

async function validPass(request, code, env) {
  const raw = getCookie(request, COOKIE);
  if (!raw) return false;

  const parts = raw.split(".");
  if (parts.length !== 4) return false;

  const [cookieCode, expStr, uaHash, sig] = parts;
  if (cookieCode !== code) return false;

  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;

  const currentUaHash = b64url(await sha256Text(request.headers.get("user-agent") || ""));
  if (uaHash !== currentUaHash) return false;

  const secret = await getSecret(env);
  const expected = await hmac(secret, cookieCode+"."+expStr+"."+uaHash);
  return sig === expected;
}

async function challenge(request, env) {
  if (request.method !== "GET") return new Response("Method Not Allowed", {status:405});

  const url = new URL(request.url);
  const code = url.searchParams.get("code") || "";
  if (!Object.prototype.hasOwnProperty.call(CONFIG.redirects, code)) {
    return json({error:"unknown code"},404,{"x-amrk-reason":"unknown-code"});
  }

  const ts = Date.now();
  const rand = randomHex(16);
  const secret = await getSecret(env);
  const body = code+"."+ts+"."+rand;
  const sig = await hmac(secret, body);
  return json({
    challenge: body+"."+sig,
    difficulty: CONFIG.difficulty
  });
}

async function issue(request, env) {
  if (request.method !== "POST") return new Response("Method Not Allowed", {status:405});

  let data;
  try { data = await request.json(); }
  catch { return json({error:"bad json"},400,{"x-amrk-reason":"bad-json"}); }

  const code = String(data.code || "");
  const challengeStr = String(data.challenge || "");
  const nonce = Number(data.nonce);
  const ua = String(data.ua || "");

  if (!Object.prototype.hasOwnProperty.call(CONFIG.redirects, code))
    return json({error:"unknown code"},404,{"x-amrk-reason":"unknown-code"});

  const parts = challengeStr.split(".");
  if (parts.length !== 4)
    return json({error:"bad challenge"},400,{"x-amrk-reason":"bad-challenge"});

  const [cCode, tsStr, rand, sig] = parts;
  if (cCode !== code)
    return json({error:"code mismatch"},400,{"x-amrk-reason":"code-mismatch"});

  const ts = Number(tsStr);
  if (!Number.isFinite(ts) || Math.abs(Date.now()-ts) > CONFIG.challengeTtlSeconds*1000)
    return json({error:"challenge expired"},400,{"x-amrk-reason":"challenge-expired"});

  const secret = await getSecret(env);
  const expectedChallengeSig = await hmac(secret, cCode+"."+tsStr+"."+rand);
  if (sig !== expectedChallengeSig)
    return json({error:"challenge signature"},400,{"x-amrk-reason":"bad-signature"});

  if (!Number.isInteger(nonce) || nonce < 0)
    return json({error:"bad nonce"},400,{"x-amrk-reason":"bad-nonce"});

  const digest = await sha256Text(challengeStr+":"+nonce);
  if (zeroBits(digest) < CONFIG.difficulty)
    return json({error:"pow failed"},400,{"x-amrk-reason":"pow-failed"});

  const reqUa = request.headers.get("user-agent") || "";
  if (ua && ua !== reqUa)
    return json({error:"ua mismatch"},400,{"x-amrk-reason":"ua-mismatch"});

  const exp = Date.now() + CONFIG.passTtlSeconds*1000;
  const uaHash = b64url(await sha256Text(reqUa));
  const payload = code+"."+exp+"."+uaHash;
  const passSig = await hmac(secret, payload);
  const cookieVal = payload+"."+passSig;

  return new Response(null, {
    status:204,
    headers:{
      "set-cookie": `${COOKIE}=${cookieVal}; Path=/; Max-Age=${CONFIG.passTtlSeconds}; HttpOnly; Secure; SameSite=Lax`,
      "cache-control":"no-store"
    }
  });
}

async function gateHtml(request, env, code) {
  const assetUrl = new URL("/index.html", request.url);
  const res = await env.ASSETS.fetch(new Request(assetUrl, request));
  if (!res.ok) return res;
  let html = await res.text();
  html = html.replace(/__CODE__/g, code);
  return new Response(html, {
    status:200,
    headers:{
      "content-type":"text/html; charset=utf-8",
      "cache-control":"no-store",
      "x-robots-tag":"noindex, nofollow"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/amarok/gate/challenge") return challenge(request, env);
    if (url.pathname === "/amarok/gate/issue") return issue(request, env);

    // static assets tetap dilayani normal
    if (
      url.pathname === "/jembot.js" ||
      url.pathname === "/index.html" ||
      url.pathname === "/favicon.ico" ||
      url.pathname.startsWith("/assets/")
    ) {
      return env.ASSETS.fetch(request);
    }

    // Root sengaja 404
    if (url.pathname === "/") {
      return new Response("404 Not Found", {
        status:404,
        headers:{"content-type":"text/plain; charset=utf-8"}
      });
    }

    const code = safeCode(url.pathname);
    if (!code || !Object.prototype.hasOwnProperty.call(CONFIG.redirects, code)) {
      return new Response("404 Not Found", {
        status:404,
        headers:{"content-type":"text/plain; charset=utf-8"}
      });
    }

    // JSON probe untuk tombol/manual client
    if (url.searchParams.get("_amrk_json") === "1") {
      if (await validPass(request, code, env)) {
        return json({destination:CONFIG.redirects[code]});
      }
      return json({error:"not verified"},401,{"x-amrk-reason":"no-pass"});
    }

    if (await validPass(request, code, env)) {
      return Response.redirect(CONFIG.redirects[code], 302);
    }

    return gateHtml(request, env, code);
  }
};
