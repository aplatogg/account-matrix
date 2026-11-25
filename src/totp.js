// src/totp.js — Zero-dependency RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s window) via WebCrypto

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function b32encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function b32decode(str) {
  const clean = String(str || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function parseTotpSecret(raw) {
  if (!raw) return null;
  let str = String(raw).trim();
  if (/^otpauth:\/\//i.test(str)) {
    try {
      const u = new URL(str);
      str = u.searchParams.get("secret") || "";
    } catch {
      const m = str.match(/[?&]secret=([A-Za-z2-7=\s-]+)/i);
      str = m ? m[1] : "";
    }
  }
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "").slice(0, 128);
  if (!clean || b32decode(clean).length === 0) return null;
  return clean;
}

async function hotp(secretBytes, counter, digits = 6) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter % 0x100000000);

  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));

  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return String(code % Math.pow(10, digits)).padStart(digits, "0");
}

export async function totpAt(secretB32, atMs = Date.now(), step = 30, digits = 6) {
  const bytes = b32decode(secretB32);
  if (!bytes.length) return null;
  const counter = Math.floor(atMs / 1000 / step);
  return hotp(bytes, counter, digits);
}
