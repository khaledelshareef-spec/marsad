// مرصد العملات - Worker: يحفظ الاشتراكات والتنبيهات، ويفحص الأسعار بالجدولة، ويرسل Web Push.
const PRICE = "https://data-api.binance.vision/api/v3/ticker/price";
const te = new TextEncoder();

const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; a.forEach((x) => { o.set(x, i); i += x.length; }); return o; };
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json" } });

// مفاتيح VAPID تُولَّد تلقائياً أول مرة وتُحفظ في KV (لا أسرار داخل الكود)
async function vapid(env) {
  let v = await env.KV.get("vapid", "json");
  if (!v) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    v = { priv: await crypto.subtle.exportKey("jwk", kp.privateKey), pub: b64u(await crypto.subtle.exportKey("raw", kp.publicKey)) };
    await env.KV.put("vapid", JSON.stringify(v));
  }
  return v;
}

async function jwt(v, aud, env) {
  const enc = (o) => b64u(te.encode(JSON.stringify(o)));
  const h = enc({ typ: "JWT", alg: "ES256" }) + "." + enc({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: env.CONTACT || "mailto:admin@example.com" });
  const key = await crypto.subtle.importKey("jwk", v.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return h + "." + b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(h)));
}

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}

// تشفير الرسالة بصيغة aes128gcm (RFC 8291)
async function encrypt(sub, text) {
  const ua = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const e = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", e.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, e.privateKey, 256));
  const prk = await hkdf(auth, secret, concat(te.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, prk, te.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(te.encode(text), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct);
}

async function push(env, v, sub, payload) {
  const body = await encrypt(sub, JSON.stringify(payload));
  const aud = new URL(sub.endpoint).origin;
  return fetch(sub.endpoint, {
    method: "POST",
    headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "3600", Urgency: "high", Authorization: "vapid t=" + (await jwt(v, aud, env)) + ", k=" + v.pub },
    body,
  });
}

const akey = (a) => a.id || a.sym + a.c + a.p;
const clean = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 50).filter((a) => a && /^[A-Z0-9]{2,20}USDT$/.test(a.sym) && (a.c === "up" || a.c === "dn") && +a.p > 0)
  .map((a) => ({ id: String(a.id || "").slice(0, 24), sym: a.sym, c: a.c, p: +a.p, done: !!a.done }));

async function handle(req, env) {
  const u = new URL(req.url);
  if (u.pathname === "/api/check") return json(await run(env));
  if (u.pathname === "/api/vapid") return json({ key: (await vapid(env)).pub });
  if (u.pathname === "/api/sync" && req.method === "POST") {
    let b; try { b = await req.json(); } catch (e) { return json({ error: "bad json" }, 400); }
    const sub = b.sub;
    if (!sub || !/^https:\/\//.test(sub.endpoint || "") || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return json({ error: "bad subscription" }, 400);
    const subs = (await env.KV.get("subs", "json")) || {};
    const old = subs[sub.endpoint];
    const prev = {}; if (old) old.alerts.forEach((a) => { prev[akey(a)] = a; });
    const alerts = clean(b.alerts).map((a) => { const o = prev[akey(a)]; if (o && o.done) a.done = true; return a; });
    subs[sub.endpoint] = { sub: { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } }, alerts };
    await env.KV.put("subs", JSON.stringify(subs));
    if (b.test) {
      try { await push(env, await vapid(env), subs[sub.endpoint].sub, { title: "مرصد العملات", body: "الإشعارات في الخلفية تعمل بنجاح" }); } catch (e) {}
    }
    return json({ alerts });
  }
  if (env.ASSETS) return env.ASSETS.fetch(req);
  return new Response("not found", { status: 404 });
}

// الجدولة: إن فشل مصدر الأسعار لا نرسل أي تنبيه. تعيد الدالة تقريراً للتشخيص.
async function run(env) {
  const info = { subs: 0, pending: 0, price: null, symbols: 0, fired: [] };
  const subs = (await env.KV.get("subs", "json")) || {};
  const ids = Object.keys(subs);
  info.subs = ids.length;
  ids.forEach((id) => subs[id].alerts.forEach((a) => { if (!a.done) info.pending++; }));
  if (!ids.length) return info;
  const prices = {};
  try {
    const r = await fetch(PRICE);
    info.price = r.status;
    if (!r.ok) return info;
    (await r.json()).forEach((x) => { prices[x.symbol] = +x.price; });
    info.symbols = Object.keys(prices).length;
  } catch (e) { info.price = "error: " + e.message; return info; }
  const v = await vapid(env);
  let dirty = false;
  for (const id of ids) {
    const s = subs[id];
    for (const a of s.alerts) {
      const p = prices[a.sym];
      if (a.done || !p) continue;
      if ((a.c === "up" && p >= a.p) || (a.c === "dn" && p <= a.p)) {
        const r = await push(env, v, s.sub, { title: "مرصد العملات", body: a.sym.slice(0, -4) + " وصل إلى $" + p, tag: akey(a) }).catch((e) => ({ status: "error: " + e.message }));
        info.fired.push({ sym: a.sym, push: r.status });
        if (r.status === 404 || r.status === 410) { delete subs[id]; dirty = true; break; }
        if (r.ok) { a.done = true; dirty = true; }
      }
    }
  }
  if (dirty) await env.KV.put("subs", JSON.stringify(subs));
  return info;
}

export default {
  fetch: (req, env) => handle(req, env),
  scheduled: (ev, env, ctx) => ctx.waitUntil(run(env)),
};
