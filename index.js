// SPDX-License-Identifier: 0BSD

// ====================================================================================
// KONFIGURASI UTAMA
// ====================================================================================

/**
 * Alamat server DNS-over-HTTPS (DoH) upstream.
 */
const DOH_UPSTREAM = 'https://security.cloudflare-dns.com/dns-query';

/**
 * URL ke file .txt mentah yang berisi daftar domain untuk diblokir.
 */
const BLOCKLIST_URL = 'https://raw.githubusercontent.com/Athar5443/Youtube_BlockAds_List/refs/heads/main/blocklist.txt';

/**
 * Domain utama tempat worker ini berjalan (yang diatur di Workers Routes).
 * Worker akan mengarahkan domain yang diblokir ke domain ini sendiri.
 */
const SELF_DOMAIN = 'dns.athars.me'; // <-- PASTIKAN INI SESUAI DENGAN RUTE ANDA

/**
 * Durasi (dalam detik) untuk menyimpan daftar blokir di cache.
 */
const CACHE_TTL_SECONDS = 3600; // 1 jam

// ====================================================================================
// KODE INTI WORKER (Tidak perlu diubah)
// ====================================================================================

const DOH_PATH = '/dns-query';
const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';

let blocklistCache = new Set();
let lastCacheUpdateTime = 0;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Logika routing berdasarkan jalur URL
    if (url.pathname.startsWith(DOH_PATH)) {
      ctx.waitUntil(updateBlocklistCache());
      return handleDohRequest(request);
    } else {
      return serveBlockedPage(request);
    }
  },
};

// --- Fungsi untuk DNS-over-HTTPS ---
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
    if (isDohJsonRequest) return new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } });
    if (requestBuffer) return createBlockedResponseCname(requestBuffer, SELF_DOMAIN);
  }
  
  const dohUrl = new URL(DOH_UPSTREAM);
  dohUrl.search = searchParams.toString();
  return fetch(dohUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body
  });
}

// --- Fungsi untuk Menampilkan Halaman Blokir ---
async function serveBlockedPage(request) {
  const blockedDomain = request.headers.get('X-Forwarded-Host') || "Situs ini";
  const html = `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Akses Dibatasi</title>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root { --b: #f8f9fa; --c: #fff; --t: #212529; --a: #e63946; --m: #6c757d; --d: #e9ecef; }
        @media (prefers-color-scheme: dark) { :root { --b: #121212; --c: #1e1e1e; --t: #e0e0e0; --a: #f9a826; --m: #9e9e9e; --d: #2c2c2c; } }
        body { font-family: 'Inter', sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 1rem; background-color: var(--b); color: var(--t); box-sizing: border-box; }
        .card { background-color: var(--c); border-radius: 16px; padding: 2.5rem 3rem; max-width: 500px; width: 100%; text-align: center; box-shadow: 0 8px 32px rgba(0,0,0,0.1); border: 1px solid rgba(0,0,0,0.05); }
        .icon { font-size: 3.5rem; line-height: 1; margin-bottom: 1rem; color: var(--a); }
        h1 { font-size: 1.75rem; font-weight: 600; margin: 0 0 0.5rem 0; }
        p { font-size: 1.1rem; color: var(--m); margin: 0; }
        code { display: inline-block; margin-top: 0.25rem; background-color: var(--d); padding: 0.25em 0.6em; border-radius: 8px; font-family: "SF Mono", monospace; font-size: 0.95em; color: var(--a); }
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

// --- Fungsi Bantuan ---
async function updateBlocklistCache() {
  const now = Date.now()/1000;
  if (now - lastCacheUpdateTime < CACHE_TTL_SECONDS && blocklistCache.size > 0) return;
  try {
    const res = await fetch(BLOCKLIST_URL); if (!res.ok) throw new Error(`Status: ${res.status}`);
    const text = await res.text();
    blocklistCache = new Set(text.split('\n').map(l=>l.trim()).filter(l=>l.length>0&&!l.startsWith('#')).map(l=>l.split(/\s+/).pop()));
    lastCacheUpdateTime = now; console.log(`Cache diperbarui: ${blocklistCache.size} domain.`);
  } catch (err) { console.error('Gagal memperbarui cache:', err); }
}
function isBlocked(domain) {
  let d = domain.toLowerCase();
  while (d) {
    if (blocklistCache.has(d)) return true;
    const i = d.indexOf('.');
    if (i === -1) break;
    d = d.substring(i + 1);
  }
  return false;
}
function getDomainFromDnsMessage(buf) {
  const view = new DataView(buf); if (view.byteLength < 13) return null;
  let len = view.getUint8(12), offset = 13, parts = [];
  while (len !== 0 && offset < view.byteLength) {
    parts.push(new TextDecoder('ascii').decode(new Uint8Array(buf, offset, len)));
    offset += len; len = view.getUint8(offset); offset += 1;
  }
  return parts.join('.');
}
function createBlockedResponseCname(reqBuf, target) {
  const reqView=new DataView(reqBuf);
  let qEnd=12; while(qEnd<reqBuf.byteLength&&reqView.getUint8(qEnd)!==0){qEnd+=reqView.getUint8(qEnd)+1;} qEnd++;
  const q=new Uint8Array(reqBuf,12,qEnd-12+4);
  const tBytes=new Uint8Array(target.split('.').reduce((a,p)=>a.concat(p.length,[...p].map(c=>c.charCodeAt(0))),[]).concat(0));
  const resBuf=new ArrayBuffer(12+q.byteLength+12+tBytes.byteLength);
  const resView=new DataView(resBuf), resBytes=new Uint8Array(resBuf);
  resView.setUint16(0,reqView.getUint16(0)); resView.setUint16(2,0x8180); resView.setUint16(4,1); resView.setUint16(6,1);
  resBytes.set(q,12); const aOff=12+q.byteLength;
  resView.setUint16(aOff,0xc00c); resView.setUint16(aOff+2,5); resView.setUint16(aOff+4,1);
  resView.setUint32(aOff+6,60); resView.setUint16(aOff+10,tBytes.byteLength);
  resBytes.set(tBytes,aOff+12);
  return new Response(resBuf, {headers: {'Content-Type': CONTENT_TYPE_DNS}});
}
