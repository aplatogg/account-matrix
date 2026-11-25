// src/index.js — AccountMatrix Cloudflare Worker (Multi-Account Vault, Live TOTP, Trial Radar & InboxStealth Bridge)
import { parseTotpSecret, totpAt } from "./totp.js";

const now = () => Date.now();

const FIRST = [
  "roro","janeru","budi","siti","andi","dewi","rizky","putri","agus","maya",
  "dimas","intan","fajar","nadia","reza","sari","yoga","lia","hafiz","tari",
  "galih","wulan","arif","ratna","bayu","sinta","eko","mega","hendra","vina"
];
const LAST = [
  "pratama","saputra","wijaya","nugroho","rahmawati","setiawan","kusuma",
  "haryanto","permata","firdaus","anggraini","wibowo","lestari","sanjaya","maulida"
];
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const digits = (n) => String(Math.floor(Math.random() * Math.pow(10, n))).padStart(n, "0");

function randLocal() {
  return `${pick(FIRST)}.${pick(LAST)}${digits(2)}`;
}

function generateStrongPassword(len = 18) {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const nums  = "23456789";
  const syms  = "!@#$%^&*_-+=";
  const all   = upper + lower + nums + syms;
  const rnd   = new Uint32Array(len + 4);
  crypto.getRandomValues(rnd);
  const chars = [
    upper[rnd[0] % upper.length],
    lower[rnd[1] % lower.length],
    nums[rnd[2] % nums.length],
    syms[rnd[3] % syms.length],
  ];
  for (let i = 4; i < len; i++) chars.push(all[rnd[i] % all.length]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rnd[i] % (i + 1);
    const t = chars[i]; chars[i] = chars[j]; chars[j] = t;
  }
  return chars.join("");
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

function extractOtp(subject, textBody, htmlBody) {
  const subj = String(subject || "").trim();
  const plainHtml = htmlBody
    ? String(htmlBody)
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<head[\s\S]*?<\/head>/gi, " ")
        .replace(/<[^>]+>/g, " ")
    : "";
  const rawTxt = String(textBody || "");
  const cssPolluted = /@font-face|\bbox-sizing\s*:|mso-table-lspace|\bmargin\s*:\s*0/i.test(rawTxt);
  const body = ((cssPolluted && plainHtml) ? plainHtml : (rawTxt || plainHtml))
    .replace(/#[0-9a-fA-F]{3,8}\b/g, " ")
    .replace(/https?:\/\/\S+/gi, " ")
    .slice(0, 12000);
  const combined = `${subj}\n${body}`;
  const hasCtx = /\b(otp|kode|code|pin|verifikasi|verification|verify|passcode|token|authenticat|masuk|login|sign[\s-]?in|confirm|konfirmasi|sandi|password|security|aktivasi|activate)\b/i.test(combined);
  if (!hasCtx) return null;

  const ctxRe = /\b(?:otp|kode|code|verifikasi|verification|login\s*code|sign[-\s]?in\s*code|pin|passcode|token|sandi|confirm|security)\b[^0-9A-Za-z\n]{0,32}\b([0-9]{4,8})\b/gi;
  let m;
  while ((m = ctxRe.exec(combined)) !== null) {
    if (!/^(19\d\d|20[2-3]\d)$/.test(m[1])) return m[1];
  }
  const beforeRe = /\b(\d{4,8})\b[^0-9A-Za-z\n]{0,24}\b(?:adalah\s+kode|is\s+your\s+(?:verification|security|login|sign[-\s]?in|confirmation|one-time|temporary)?\s*(?:code|otp|pin))\b/i.exec(combined);
  if (beforeRe) return beforeRe[1];

  const sixRe = /\b([0-9]{6})\b/g;
  while ((m = sixRe.exec(combined)) !== null) {
    if (!/^(19\d\d|20[2-3]\d|000000)$/.test(m[1])) return m[1];
  }
  return null;
}

function extractMagicLink(textBody, htmlBody) {
  const src = `${htmlBody || ""}\n${textBody || ""}`.slice(0, 48000);
  const re = /https?:\/\/[^\s"'<>)\]]+/gi;
  const skipHostRe = /^(click|links?|trk|track|metrics|pixel|open|ablink|email\.mg|url\d+)\.|mandrillapp\.com|sendgrid\.net|list-manage\.com|aklamio\.com/i;
  const skipRe = /\.(png|jpe?g|gif|svg|webp|css|js|woff2?|ttf|eot|ico|pdf)(\?|$)|unsubscribe|privacy|terms|help\.|support\.|status\.|mailto:|w3\.org/i;
  const hitRe = /([?&](token|code|key|ticket|magic|verify|confirmation|access_token)=|\/verify\/|\/confirm\/|\/activate\/|\/magic[-_]?link|\/auth\/callback|\/reset[-_]?password)/i;
  let m;
  while ((m = re.exec(src)) !== null) {
    const u = m[0].replace(/[.,;:'")\]>]+$/, "").replace(/&amp;/g, "&");
    if (u.length < 24 || skipRe.test(u)) continue;
    try {
      const host = new URL(u).hostname.toLowerCase();
      if (skipHostRe.test(host) && !hitRe.test(u)) continue;
    } catch { continue; }
    if (hitRe.test(u)) return u;
  }
  return null;
}

function checkAuth(request, env) {
  const secret = (env.MATRIX_MASTER_KEY || "").trim();
  if (!secret) return true; // local/unconfigured dev mode
  const hdr = (request.headers.get("x-matrix-key") || "").trim();
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  return hdr === secret || bearer === secret;
}

async function pullRemoteInboxOtp(env, address) {
  const origin = (env.INBOXSTEALTH_ORIGIN || "").trim().replace(/\/+$/, "");
  const apiKey = (env.INBOXSTEALTH_API_KEY || "").trim();
  if (!origin || !apiKey || origin.includes("example.com")) return {};
  try {
    const res = await fetch(`${origin}/api/inbox/${encodeURIComponent(address)}`, {
      headers: { "x-api-key": apiKey, "accept": "application/json" },
    });
    if (!res.ok) return {};
    const data = await res.json();
    const msgs = data.messages || [];
    if (!msgs.length) return { message_count: 0 };
    const latest = msgs[0];
    let fullText = latest.snippet || "";
    let fullHtml = "";
    try {
      const mRes = await fetch(`${origin}/api/message/${encodeURIComponent(address)}/${encodeURIComponent(latest.id)}`, {
        headers: { "x-api-key": apiKey, "accept": "application/json" },
      });
      if (mRes.ok) {
        const mData = await mRes.json();
        fullText = mData.text_body || fullText;
        fullHtml = mData.html_body || "";
      }
    } catch {}
    return {
      message_count: msgs.length,
      email_otp: extractOtp(latest.subject, fullText, fullHtml),
      magic_link: extractMagicLink(fullText, fullHtml),
      latest_subject: latest.subject || null,
      latest_from: latest.from_name || latest.from_addr || null,
      latest_at: latest.received_at || null,
    };
  } catch {
    return {};
  }
}

async function provisionRemoteInbox(env, local, domain, note) {
  const origin = (env.INBOXSTEALTH_ORIGIN || "").trim().replace(/\/+$/, "");
  const apiKey = (env.INBOXSTEALTH_API_KEY || "").trim();
  if (!origin || !apiKey || origin.includes("example.com")) return null;
  try {
    const res = await fetch(`${origin}/api/inbox`, {
      method: "POST",
      headers: { "x-api-key": apiKey, "content-type": "application/json" },
      body: JSON.stringify({ local, domain, note }),
    });
    if (!res.ok) return null;
    const j = await res.json();
    if (j.address) {
      await fetch(`${origin}/api/inbox/${encodeURIComponent(j.address)}`, {
        method: "PATCH",
        headers: { "x-api-key": apiKey, "content-type": "application/json" },
        body: JSON.stringify({ pinned: true }),
      }).catch(() => {});
      return j.address;
    }
  } catch {}
  return null;
}

async function enrichAccount(row, nowMs = now(), remoteInfo = {}) {
  let totpCode = null, totpRem = null;
  if (row.totp_secret) {
    totpCode = await totpAt(row.totp_secret, nowMs);
    totpRem  = 30 - (Math.floor(nowMs / 1000) % 30);
  }
  return {
    ...row,
    totp_code: totpCode,
    totp_rem: totpRem,
    message_count: remoteInfo.message_count ?? 0,
    email_otp: remoteInfo.email_otp ?? null,
    magic_link: remoteInfo.magic_link ?? null,
    latest_subject: remoteInfo.latest_subject ?? null,
    latest_from: remoteInfo.latest_from ?? null,
    latest_at: remoteInfo.latest_at ?? null,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const method = request.method;

    if (p === "/api/health") {
      return json({ ok: true, app: env.APP_NAME || "AccountMatrix" });
    }

    if (p.startsWith("/api/")) {
      if (!checkAuth(request, env)) {
        return json({ error: "unauthorized", note: "Provide a valid X-Matrix-Key or Bearer token." }, 401);
      }
      const t = now();

      if (p === "/api/accounts" && method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT * FROM matrix_accounts ORDER BY created_at DESC LIMIT 300`
        ).all();
        const out = [];
        for (const r of results || []) {
          out.push(await enrichAccount(r, t));
        }
        return json({ accounts: out, default_domain: env.DEFAULT_MAIL_DOMAIN || "example.com" });
      }

      if (p === "/api/accounts" && method === "POST") {
        const b = await request.json().catch(() => ({}));
        const service = String(b.service || "").trim().slice(0, 60);
        if (!service) return json({ error: "service_required" }, 400);
        const tag = String(b.tag || "").trim().slice(0, 40) || null;
        const domain = String(b.domain || env.DEFAULT_MAIL_DOMAIN || "example.com").trim().toLowerCase();
        const local = String(b.local || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "") || randLocal();
        const boxNote = tag ? `${service} (${tag})` : service;

        const remoteAddr = await provisionRemoteInbox(env, local, domain, boxNote);
        const address = b.address && String(b.address).includes("@")
          ? String(b.address).trim().toLowerCase()
          : (remoteAddr || `${local}@${domain}`);

        const username = String(b.username || "").trim().slice(0, 80) || address.split("@")[0].replace(/[._-]/g, "");
        const password = (b.password && String(b.password).trim())
          ? String(b.password).trim().slice(0, 200)
          : generateStrongPassword(18);
        const totpSecret = parseTotpSecret(b.totp_secret);
        if (b.totp_secret && String(b.totp_secret).trim() && !totpSecret) {
          return json({ error: "invalid_totp_secret" }, 400);
        }
        const apiKey = String(b.api_key || "").trim().slice(0, 500) || null;
        const recCodes = String(b.recovery_codes || "").trim().slice(0, 1000) || null;
        const opsecNote = String(b.opsec_note || "").trim().slice(0, 300) || null;
        const trialDays = Number(b.trial_days || 0);
        const status = ["active", "trial", "cooldown", "burned"].includes(b.status)
          ? b.status
          : (trialDays > 0 ? "trial" : "active");
        const expiresAt = trialDays > 0 ? (t + Math.min(3650, trialDays) * 86400_000) : null;

        const id = crypto.randomUUID();
        await env.DB.prepare(
          `INSERT INTO matrix_accounts
             (id, service, tag, address, username, password, totp_secret,
              api_key, recovery_codes, opsec_note, status, expires_at, created_at, updated_at)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)`
        ).bind(
          id, service, tag, address, username, password, totpSecret,
          apiKey, recCodes, opsecNote, status, expiresAt, t
        ).run();

        const created = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
        return json({ ok: true, account: await enrichAccount(created, t) }, 201);
      }

      const mOtp = p.match(/^\/api\/accounts\/([^/]+)\/otp$/);
      if (mOtp && method === "GET") {
        const id = decodeURIComponent(mOtp[1]);
        const row = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
        if (!row) return json({ error: "not_found" }, 404);
        const remoteInfo = await pullRemoteInboxOtp(env, row.address);
        const enriched = await enrichAccount(row, t, remoteInfo);
        return json({
          ok: true,
          id: enriched.id,
          address: enriched.address,
          totp_code: enriched.totp_code,
          totp_rem: enriched.totp_rem,
          email_otp: enriched.email_otp,
          magic_link: enriched.magic_link,
          message_count: enriched.message_count,
          latest_subject: enriched.latest_subject,
          latest_from: enriched.latest_from,
          latest_at: enriched.latest_at,
        });
      }

      const mItem = p.match(/^\/api\/accounts\/([^/]+)$/);
      if (mItem) {
        const id = decodeURIComponent(mItem[1]);
        const row = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
        if (!row) return json({ error: "not_found" }, 404);

        if (method === "PATCH") {
          const b = await request.json().catch(() => ({}));
          const service = b.service !== undefined ? (String(b.service || "").trim().slice(0, 60) || row.service) : row.service;
          const tag = b.tag !== undefined ? (String(b.tag || "").trim().slice(0, 40) || null) : row.tag;
          const username = b.username !== undefined ? (String(b.username || "").trim().slice(0, 80) || null) : row.username;
          const password = b.password !== undefined ? (String(b.password || "").trim().slice(0, 200) || null) : row.password;
          let totpSecret = row.totp_secret;
          if (b.totp_secret !== undefined) {
            const rawT = String(b.totp_secret || "").trim();
            totpSecret = rawT ? parseTotpSecret(rawT) : null;
            if (rawT && !totpSecret) return json({ error: "invalid_totp_secret" }, 400);
          }
          const apiKey = b.api_key !== undefined ? (String(b.api_key || "").trim().slice(0, 500) || null) : row.api_key;
          const recCodes = b.recovery_codes !== undefined ? (String(b.recovery_codes || "").trim().slice(0, 1000) || null) : row.recovery_codes;
          const opsecNote = b.opsec_note !== undefined ? (String(b.opsec_note || "").trim().slice(0, 300) || null) : row.opsec_note;
          const status = ["active", "trial", "cooldown", "burned"].includes(b.status) ? b.status : row.status;

          await env.DB.prepare(
            `UPDATE matrix_accounts
                SET service = ?2, tag = ?3, username = ?4, password = ?5, totp_secret = ?6,
                    api_key = ?7, recovery_codes = ?8, opsec_note = ?9, status = ?10, updated_at = ?11
              WHERE id = ?1`
          ).bind(id, service, tag, username, password, totpSecret, apiKey, recCodes, opsecNote, status, t).run();

          const updated = await env.DB.prepare(`SELECT * FROM matrix_accounts WHERE id = ?1`).bind(id).first();
          return json({ ok: true, account: await enrichAccount(updated, t) });
        }

        if (method === "DELETE") {
          await env.DB.prepare(`DELETE FROM matrix_accounts WHERE id = ?1`).bind(id).run();
          return json({ ok: true, id });
        }
      }

      return json({ error: "not_found" }, 404);
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response("Not found", { status: 404 });
  },
};
