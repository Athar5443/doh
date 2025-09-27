// SPDX-License-Identifier: 0BSD

/**
 * Alamat server DNS-over-HTTPS (DoH) upstream.
 * @type {string}
 */
const DOH_UPSTREAM = 'https://security.cloudflare-dns.com/dns-query';

/**
 * @type {string}
 */
const BLOCKLIST_URL = 'https://raw.githubusercontent.com/Athar5443/Youtube_BlockAds_List/refs/heads/main/blocklist.txt'; // <-- GANTI DENGAN URL LIST ANDA

/**
 * Domain utama tempat worker ini berjalan.
 * Worker akan mengarahkan domain yang diblokir ke domain ini.
 * @type {string}
 */
const SELF_DOMAIN = 'dns.athars.me';

/**
 * Durasi (dalam detik) untuk menyimpan daftar blokir di cache.
 * @type {number}
 */
const CACHE_TTL_SECONDS = 1600;

const DOH_PATH = '/dns-query';
const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';

let blocklistCache = new Set();
let lastCacheUpdateTime = 0;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith(DOH_PATH)) {
      ctx.waitUntil(updateBlocklistCache());
      return handleDohRequest(request);
    } else {
      return serveBlockedPage(request);
    }
  },
};

async function handleDohRequest(request) {
  const { method, headers, url } = request;
  const { searchParams } = new URL(url);
  let domain = null, requestBuffer = null, isDohJsonRequest = false;

  try {
    if (method === 'GET' && searchParams.has('dns')) {
      const dnsParam = searchParams.get('dns').replace(/-/g, '+').replace(/_/g, '/');
      requestBuffer = Uint8Array.from(atob(dnsParam), c => c.charCodeAt(0)).buffer;
      domain = getDomainFromDnsMessage(requestBuffer);
    } else if (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) {
      requestBuffer = await request.clone().arrayBuffer();
      domain = getDomainFromDnsMessage(requestBuffer);
    } else if (method === 'GET' && headers.get('Accept') === CONTENT_TYPE_JSON) {
      domain = searchParams.get('name');
      isDohJsonRequest = true;
    }
  } catch (e) { console.error("Gagal mem-parsing permintaan:", e); }

  if (domain && isBlocked(domain)) {
    console.log(`Domain terblokir: ${domain}`);
    if (isDohJsonRequest) {
      return new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    if (requestBuffer) {
      return createBlockedResponseCname(requestBuffer, SELF_DOMAIN);
    }
  }

  const dohUrl = new URL(DOH_UPSTREAM);
  dohUrl.search = searchParams.toString();
  return fetch(dohUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body
  });
}


async function serveBlockedPage(request) {
  const blockedDomain = request.headers.get('X-Forwarded-Host') || "Situs ini";
  const html = `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Akses Dibatasi</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root { --background-color: #f8f9fa; --card-background: #ffffff; --text-color: #212529; --accent-color: #e63946; --muted-color: #6c757d; --code-background: #e9ecef; }
        @media (prefers-color-scheme: dark) { :root { --background-color: #121212; --card-background: #1e1e1e; --text-color: #e0e0e0; --accent-color: #f9a826; --muted-color: #9e9e9e; --code-background: #2c2c2c; } }
        body { font-family: 'Inter', sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 1rem; background-color: var(--background-color); color: var(--text-color); box-sizing: border-box; }
        .card { background-color: var(--card-background); border-radius: 16px; padding: 2.5rem 3rem; max-width: 500px; width: 100%; text-align: center; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1); border: 1px solid rgba(0, 0, 0, 0.05); }
        .icon { font-size: 3.5rem; line-height: 1; margin-bottom: 1rem; color: var(--accent-color); }
        h1 { font-size: 1.75rem; font-weight: 600; margin: 0 0 0.5rem 0; }
        p { font-size: 1.1rem; color: var(--muted-color); margin: 0; }
        code { display: inline-block; margin-top: 0.25rem; background-color: var(--code-background); padding: 0.25em 0.6em; border-radius: 8px; font-family: "SF Mono", monospace; font-size: 0.95em; color: var(--accent-color); }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️</div>
        <h1>Akses Dibatasi</h1>
        <p>Koneksi ke domain berikut telah diblokir oleh kebijakan jaringan Anda: <code>${blockedDomain}</code></p>
    </div>
</body>
</html>`;
  return new Response(html, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function updateBlocklistCache() {
  const now = Date.now() / 1000;
  if (now - lastCacheUpdateTime < CACHE_TTL_SECONDS && blocklistCache.size > 0) return;
  try {
    const response = await fetch(BLOCKLIST_URL); if (!response.ok) throw new Error(`Status: ${response.status}`);
    const text = await response.text();
    const domains = text.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#')).map(l => l.split(/\s+/).pop());
    blocklistCache = new Set(domains); lastCacheUpdateTime = now; console.log(`Cache diperbarui: ${blocklistCache.size} domain.`);
  } catch (error) { console.error('Gagal memperbarui cache:', error); }
}
function isBlocked(domain) {
  let currentDomain = domain.toLowerCase();
  while (currentDomain) {
    if (blocklistCache.has(currentDomain)) return true;
    const dotIndex = currentDomain.indexOf('.');
    if (dotIndex === -1) break;
    currentDomain = currentDomain.substring(dotIndex + 1);
  }
  return false;
}
function getDomainFromDnsMessage(reqBuffer) {
  const view = new DataView(reqBuffer); if (view.byteLength < 13) return null;
  let len = view.getUint8(12), offset = 13, parts = [];
  while (len !== 0 && offset < view.byteLength) {
    parts.push(new TextDecoder('ascii').decode(new Uint8Array(reqBuffer, offset, len)));
    offset += len; len = view.getUint8(offset); offset += 1;
  }
  return parts.join('.');
}
function createBlockedResponseCname(reqBuffer, targetDomain) {
  const reqView = new DataView(reqBuffer);
  let qnameEnd = 12; while (qnameEnd < reqBuffer.byteLength && reqView.getUint8(qnameEnd) !== 0) { qnameEnd += reqView.getUint8(qnameEnd) + 1; } qnameEnd++;
  const question = new Uint8Array(reqBuffer, 12, qnameEnd - 12 + 4);
  const targetBytes = new Uint8Array(targetDomain.split('.').reduce((acc, part) => acc.concat(part.length, [...part].map(c => c.charCodeAt(0))), []).concat(0));
  const resBuffer = new ArrayBuffer(12 + question.byteLength + 12 + targetBytes.byteLength);
  const resView = new DataView(resBuffer); const resBytes = new Uint8Array(resBuffer);
  resView.setUint16(0, reqView.getUint16(0)); resView.setUint16(2, 0x8180); resView.setUint16(4, 1); resView.setUint16(6, 1);
  resBytes.set(question, 12); const answerOffset = 12 + question.byteLength;
  resView.setUint16(answerOffset, 0xc00c); resView.setUint16(answerOffset + 2, 5); resView.setUint16(answerOffset + 4, 1);
  resView.setUint32(answerOffset + 6, 60); resView.setUint16(answerOffset + 10, targetBytes.byteLength);
  resBytes.set(targetBytes, answerOffset + 12);
  return new Response(resBuffer, { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
}
