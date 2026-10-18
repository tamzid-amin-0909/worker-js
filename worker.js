// Cloudflare Worker port of proxy.js
//  • POST -> encrypted MP4 range endpoint (sw.js) + quality list ("a=q")
//  • GET  -> HLS proxy (m3u8 / key / ts)
//
// Secrets / vars (wrangler.toml [vars] or `wrangler secret put`), all optional:
//   AES_KEY, AES_IV          16 characters each (must match HardenedPlayer.js)
//   ALLOWED_ORIGINS          comma separated, e.g. https://everythingfree.iceiy.com
//   UPSTREAM_REFERER         defaults to https://iframe.mediadelivery.net

const MAX_CHUNK = 4 * 1024 * 1024;
const HOST_RE = /^vz-[a-z0-9-]+\.b-cdn\.net$/i;

const enc = new TextEncoder();
const dec = new TextDecoder();

function cfg(env) {
  const referer = env.UPSTREAM_REFERER || "https://iframe.mediadelivery.net";
  return {
    keyRaw: enc.encode(env.AES_KEY || "1234567890123456"),
    ivRaw: enc.encode(env.AES_IV || "1234567890123456"),
    allowed: (env.ALLOWED_ORIGINS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    upstream: {
      Referer: referer,
      Origin: referer,
      "User-Agent": "Mozilla/5.0",
    },
  };
}

// ── base64 helpers ───────────────────────────────────────────
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// ── AES helpers (CBC, URL-safe base64) ───────────────────────
async function cbcKey(c, usage) {
  return crypto.subtle.importKey("raw", c.keyRaw, { name: "AES-CBC" }, false, [usage]);
}

async function aesDecrypt(c, token) {
  try {
    let b64 = String(token).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const key = await cbcKey(c, "decrypt");
    const plain = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: c.ivRaw },
      key,
      b64ToBytes(b64),
    );
    return dec.decode(plain);
  } catch (e) {
    return null;
  }
}

async function aesEncrypt(c, text) {
  const key = await cbcKey(c, "encrypt");
  const buf = await crypto.subtle.encrypt({ name: "AES-CBC", iv: c.ivRaw }, key, enc.encode(text));
  return bytesToB64(new Uint8Array(buf))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function safeUrl(u) {
  try {
    const p = new URL(u);
    return HOST_RE.test(p.hostname) ? p : null;
  } catch (e) {
    return null;
  }
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "X-HP-Req, Content-Type, Range",
    "Access-Control-Expose-Headers": "X-Total-Size, Content-Range, Content-Length",
    "Access-Control-Max-Age": "7200",
  };
}

function text(body, status, extra) {
  return new Response(body, { status, headers: { "Content-Type": "text/plain", ...extra } });
}

// ═══════════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const c = cfg(env);
    const origin = request.headers.get("Origin") || "";
    if (c.allowed.length && origin && !c.allowed.includes(origin)) {
      return new Response("Forbidden origin", { status: 403 });
    }
    const cors = corsHeaders(origin);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    let res;
    try {
      res =
        request.method === "POST"
          ? await handlePost(request, c)
          : await handleHls(request, c);
    } catch (e) {
      res = new Response("Proxy error: " + e.message, { status: 502 });
    }

    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  },
};

// ═══════════════════════════════════════════════════════════════
// POST: MP4 ranges (encrypted with AES-128-CTR) and quality list
// ═══════════════════════════════════════════════════════════════
async function handlePost(request, c) {
  if (request.headers.get("X-HP-Req") !== "1") return new Response(null, { status: 404 });

  const body = Object.fromEntries(new URLSearchParams(await request.text()));

  const url = await aesDecrypt(c, body.u || "");
  if (!url) {
    return text("Forbidden: bad token (body fields: " + Object.keys(body).join(",") + ")", 403);
  }
  const p = safeUrl(url);
  if (!p) return text("Forbidden: host not allowed (" + url.slice(0, 60) + ")", 403);

  // ── quality list: read the master playlist server-side ──
  if (body.a === "q") {
    const dir = url.substring(0, url.lastIndexOf("/"));
    const r = await fetch(dir + "/playlist.m3u8", { headers: c.upstream });
    const txt = await r.text();

    let heights = [...txt.matchAll(/RESOLUTION=\d+x(\d+)/gi)].map((m) => +m[1]);
    if (!heights.length) heights = [...txt.matchAll(/^(\d{3,4})p\//gm)].map((m) => +m[1]);
    heights = [...new Set(heights)].sort((a, b) => b - a);

    return text(JSON.stringify({ q: heights }), 200, { "Cache-Control": "no-store" });
  }

  // ── MP4 range ──
  if (!/\.mp4$/i.test(p.pathname)) return text("Forbidden: not an mp4 (" + p.pathname + ")", 403);

  const start = Number.isFinite(+body.s) ? +body.s : -1;
  let end = Number.isFinite(+body.e) ? +body.e : -1;
  const nHex = String(body.n || "");

  if (start < 0 || end < start || start % 16 !== 0 || !/^[0-9a-f]{16}$/.test(nHex)) {
    return text("Bad request", 400);
  }
  end = Math.min(end, start + MAX_CHUNK - 1);

  const up = await fetch(url, { headers: { ...c.upstream, Range: `bytes=${start}-${end}` } });
  const cr = up.headers.get("content-range");
  if (up.status !== 206 || !cr) return text("Upstream HTTP " + up.status, 502);

  const total = parseInt(cr.split("/")[1], 10);
  const plain = new Uint8Array(await up.arrayBuffer());

  // AES-128-CTR, counter = nonce(8) || uint64be(blockIndex)
  const counter = new Uint8Array(16);
  counter.set(hexToBytes(nHex).slice(0, 8), 0);
  new DataView(counter.buffer).setBigUint64(8, BigInt(start / 16), false);

  const key = await crypto.subtle.importKey("raw", c.keyRaw, { name: "AES-CTR" }, false, [
    "encrypt",
  ]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CTR", counter, length: 64 },
    key,
    plain,
  );

  return new Response(encrypted, {
    status: 206,
    headers: {
      "Content-Type": "text/plain",
      "Cache-Control": "no-store",
      "X-Total-Size": String(total),
      "Content-Range": `bytes ${start}-${start + plain.length - 1}/${total}`,
    },
  });
}

// ═══════════════════════════════════════════════════════════════
// GET: HLS proxy (m3u8 / key / ts)
// ═══════════════════════════════════════════════════════════════
async function handleHls(request, c) {
  const raw = new URL(request.url).searchParams.get("url") || "";
  if (!raw) return text("Missing url", 400);

  const url = await aesDecrypt(c, raw);
  if (!url) return text("Invalid or corrupted encrypted URL", 400);

  const p = safeUrl(url);
  if (!p) return text("Forbidden host", 403);

  const ext = (p.pathname.split(".").pop() || "").toLowerCase();
  const isM3U8 = ext === "m3u8";
  const isKey = ext === "key";

  const headers = { ...c.upstream };
  const range = request.headers.get("Range");
  if (range) headers.Range = range;

  const up = await fetch(url, { headers });

  // ── TS segments: stream straight through ──
  if (!isM3U8 && !isKey) {
    const h = new Headers({
      "Content-Type": up.headers.get("content-type") || "video/mp2t",
      "Cache-Control": "no-store",
      "Accept-Ranges": "bytes",
    });
    const cl = up.headers.get("content-length");
    const cr = up.headers.get("content-range");
    if (cl) h.set("Content-Length", cl);
    if (cr) h.set("Content-Range", cr);
    return new Response(up.body, { status: up.status, headers: h });
  }

  // ── key: buffer ──
  if (isKey) {
    return new Response(await up.arrayBuffer(), {
      status: up.status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": up.headers.get("content-type") || "application/octet-stream",
      },
    });
  }

  // ── m3u8: rewrite URIs ──
  const txt = await up.text();
  const base = url.substring(0, url.lastIndexOf("/"));
  const lines = txt.split("\n");
  const out = [];

  for (const l of lines) {
    let line = l.trim();
    if (!line) {
      out.push(line);
      continue;
    }

    if (line.startsWith("#EXT-X-KEY")) {
      const m = line.match(/URI="([^"]+)"/);
      if (m) {
        const abs = m[1].startsWith("http") ? m[1] : base + "/" + m[1].replace(/^\/+/, "");
        const token = encodeURIComponent(await aesEncrypt(c, abs));
        line = line.replace(/URI="([^"]+)"/, `URI="detect?url=${token}"`);
      }
      out.push(line);
      continue;
    }
    if (line.startsWith("#")) {
      out.push(line);
      continue;
    }

    if (!line.startsWith("http")) line = base + "/" + line.replace(/^\/+/, "");
    out.push(`detect?url=${encodeURIComponent(await aesEncrypt(c, line))}`);
  }

  return new Response(out.join("\n"), {
    status: up.status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": up.headers.get("content-type") || "application/vnd.apple.mpegurl",
    },
  });
}
