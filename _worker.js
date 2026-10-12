const CONFIG = {
  // Satu shortcode, banyak destination.
  redirects: {
    "gacor": [
      "https://vpn.8naga.space/1slowin79",
      "https://vpn.8naga.space/2slowin79",
      "https://vpn.8naga.space/3slowin79",
      "https://vpn.8naga.space/4slowin79"
    ]
  },

  difficulty: 14,
  challengeTtlSeconds: 30,
  passTtlSeconds: 3600
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

async function getSecret(env) {
  if (!env.AMAROK_SECRET) throw new Error("AMAROK_SECRET belum diset di Cloudflare");
  return env.AMAROK_SECRET;
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

function destinationsFor(code) {
  const v = CONFIG.redirects[code];
  if (!Array.isArray(v)) return [];
  return v.filter(x => typeof x === "string" && /^https?:\/\//i.test(x));
}

async function pickDestination(code, env) {
  const destinations = destinationsFor(code);
  if (!destinations.length) throw new Error("destination kosong");
  if (!env.ROTATOR) throw new Error("Binding ROTATOR belum diset di Cloudflare Pages");

  // Satu Durable Object per shortcode. Semua request /gacor menuju object
  // global yang sama, sehingga pembagian tidak bergantung pada instance Pages.
  const id = env.ROTATOR.idFromName("amarok:" + code);
  const stub = env.ROTATOR.get(id);

  const r = await stub.fetch("https://rotator.internal/pick", {
    method: "POST",
    headers: {"content-type":"application/json"},
    body: JSON.stringify({code, destinations})
  });

  if (!r.ok) throw new Error("rotator HTTP " + r.status);
  const data = await r.json();
  if (!data || typeof data.destination !== "string") throw new Error("bad rotator response");
  return data.destination;
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

  if (!destinationsFor(code).length)
    return json({error:"unknown code"},404,{"x-amrk-reason":"unknown-code"});

  try {
    const ts = Date.now();
    const rand = randomHex(16);
    const secret = await getSecret(env);
    const body = code+"."+ts+"."+rand;
    const sig = await hmac(secret, body);
    return json({challenge:body+"."+sig,difficulty:CONFIG.difficulty});
  } catch (e) {
    return json({error:String(e && e.message || e)},500,{"x-amrk-reason":"secret-error"});
  }
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

  if (!destinationsFor(code).length)
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

  let secret;
  try { secret = await getSecret(env); }
  catch(e) { return json({error:String(e.message||e)},500,{"x-amrk-reason":"secret-error"}); }

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
  const assetUrl = new URL("/gate-template.txt", request.url);
  const res = await env.ASSETS.fetch(new Request(assetUrl, {method:"GET",headers:request.headers}));
  if (!res.ok) return new Response("Gate template missing", {status:500});
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

    if (url.pathname === "/jembot.js" || url.pathname === "/gate-template.txt")
      return env.ASSETS.fetch(request);

    if (url.pathname === "/")
      return new Response("404 Not Found",{status:404,headers:{"content-type":"text/plain; charset=utf-8"}});

    const code = safeCode(url.pathname);
    if (!code || !destinationsFor(code).length)
      return new Response("404 Not Found",{status:404,headers:{"content-type":"text/plain; charset=utf-8"}});

    if (url.searchParams.get("_amrk_json") === "1") {
      if (!(await validPass(request, code, env)))
        return json({error:"not verified"},401,{"x-amrk-reason":"no-pass"});

      try { return json({destination:await pickDestination(code, env)}); }
      catch(e) { return json({error:String(e.message||e)},503,{"x-amrk-reason":"rotator-error"}); }
    }

    if (await validPass(request, code, env)) {
      try {
        return Response.redirect(await pickDestination(code, env), 302);
      } catch (e) {
        return new Response("Rotator unavailable: "+String(e.message||e), {
          status:503,
          headers:{"content-type":"text/plain; charset=utf-8","cache-control":"no-store"}
        });
      }
    }

    return gateHtml(request, env, code);
  }
};
