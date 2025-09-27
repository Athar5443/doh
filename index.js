// SPDX-License-Identifier: 0BSD

// ====================================================================================
// KONFIGURASI UTAMA
// ====================================================================================

const DOH_UPSTREAM = 'https://security.cloudflare-dns.com/dns-query';
const BLOCKLIST_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts';
const SELF_DOMAIN = 'dns.athars.me'; // Pastikan sesuai dengan Workers Route
const CACHE_TTL_SECONDS = 3600;

// ====================================================================================
// KODE INTI WORKER
// ====================================================================================

const DOH_PATH = '/dns-query';
const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';
const BLOCKED_IP = '127.0.0.1'; // IP untuk redirect domain terblokir

let blocklistCache = new Set();
let lastCacheUpdateTime = 0;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const hostname = url.hostname;

    // Update cache secara asinkron
    ctx.waitUntil(updateBlocklistCache());

    // Routing logic yang diperbaiki
    if (url.pathname === DOH_PATH || url.pathname.startsWith(DOH_PATH)) {
      return handleDohRequest(request);
    } else if (hostname === SELF_DOMAIN || isBlockedDomain(url.searchParams.get('blocked'))) {
      return serveBlockedPage(request, url.searchParams.get('blocked'));
    } else {
      // Default fallback untuk request lain
      return new Response('Not Found', { status: 404 });
    }
  },
};

// --- DNS-over-HTTPS Handler yang Diperbaiki ---
async function handleDohRequest(request) {
  const { method, headers, url } = request;
  const { searchParams } = new URL(url);
  let domain = null;
  let requestBuffer = null;
  let isDohJsonRequest = false;

  try {
    // Parse berbagai format DoH request
    if (method === 'GET' && searchParams.has('dns')) {
      const dnsParam = searchParams.get('dns').replace(/-/g, '+').replace(/_/g, '/');
      requestBuffer = Uint8Array.from(atob(dnsParam), c => c.charCodeAt(0)).buffer;
      domain = getDomainFromDnsMessage(requestBuffer);
    } else if (method === 'POST' && headers.get('content-type')?.includes(CONTENT_TYPE_DNS)) {
      requestBuffer = await request.clone().arrayBuffer();
      domain = getDomainFromDnsMessage(requestBuffer);
    } else if (method === 'GET' && (headers.get('Accept')?.includes(CONTENT_TYPE_JSON) || searchParams.has('name'))) {
      domain = searchParams.get('name');
      isDohJsonRequest = true;
    }
  } catch (e) {
    console.error("Error parsing DNS request:", e);
  }

  // Cek apakah domain terblokir
  if (domain && isBlocked(domain)) {
    console.log(`Blocked domain: ${domain}`);
    
    if (isDohJsonRequest) {
      // Return blocked response untuk JSON format
      return createJsonBlockedResponse(domain);
    } else if (requestBuffer) {
      // Return DNS response dengan redirect ke halaman blokir
      return createBlockedDnsResponse(requestBuffer, domain);
    }
  }

  // Forward request ke upstream DNS
  const dohUrl = new URL(DOH_UPSTREAM);
  dohUrl.search = searchParams.toString();
  
  return fetch(dohUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body
  });
}

// --- Halaman Blokir yang Diperbaiki ---
async function serveBlockedPage(request, blockedDomain) {
  const url = new URL(request.url);
  
  // Deteksi domain yang diblokir dari berbagai sumber
  const targetDomain = blockedDomain || 
                      request.headers.get('X-Forwarded-Host') || 
                      request.headers.get('Host') ||
                      url.searchParams.get('domain') ||
                      'Domain tidak diketahui';

  const html = `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Akses Dibatasi - DNS Filter</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg: #f8f9fa; --card: #fff; --text: #212529; 
            --accent: #dc3545; --muted: #6c757d; --border: #e9ecef; 
        }
        @media (prefers-color-scheme: dark) { 
            :root { 
                --bg: #0d1117; --card: #21262d; --text: #e6edf3; 
                --accent: #f85149; --muted: #7d8590; --border: #30363d; 
            } 
        }
        * { box-sizing: border-box; }
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            margin: 0; padding: 1rem; min-height: 100vh;
            background: var(--bg); color: var(--text);
            display: flex; align-items: center; justify-content: center;
        }
        .container { 
            background: var(--card); border-radius: 12px; 
            padding: 2.5rem; max-width: 520px; width: 100%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.12);
            border: 1px solid var(--border); text-align: center;
        }
        .icon { font-size: 4rem; margin-bottom: 1.5rem; }
        h1 { font-size: 1.75rem; font-weight: 600; margin: 0 0 1rem 0; }
        .domain { 
            background: var(--border); padding: 0.75rem 1rem;
            border-radius: 8px; font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.95rem; color: var(--accent); margin: 1rem 0;
            word-break: break-all;
        }
        .description { 
            color: var(--muted); font-size: 1rem; 
            line-height: 1.6; margin-bottom: 1.5rem; 
        }
        .footer { 
            color: var(--muted); font-size: 0.85rem; 
            margin-top: 2rem; padding-top: 1.5rem; 
            border-top: 1px solid var(--border); 
        }
        .status-badge {
            background: var(--accent); color: white;
            padding: 0.25rem 0.75rem; border-radius: 20px;
            font-size: 0.8rem; font-weight: 600;
            display: inline-block; margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <div class="status-badge">DIBLOKIR</div>
        <h1>Akses Dibatasi</h1>
        <div class="domain">${escapeHtml(targetDomain)}</div>
        <p class="description">
            Koneksi ke domain ini telah diblokir oleh filter DNS untuk melindungi 
            jaringan dari konten berbahaya, iklan, atau malware.
        </p>
        <div class="footer">
            DNS Filter • Powered by Cloudflare Workers<br>
            ${new Date().toLocaleString('id-ID')}
        </div>
    </div>
</body>
</html>`;

  return new Response(html, {
    status: 200, // Ubah ke 200 agar lebih kompatibel
    headers: { 
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=300' // Cache 5 menit
    }
  });
}

// --- Fungsi Bantuan yang Diperbaiki ---

async function updateBlocklistCache() {
  const now = Date.now() / 1000;
  if (now - lastCacheUpdateTime < CACHE_TTL_SECONDS && blocklistCache.size > 0) {
    return;
  }

  try {
    const response = await fetch(BLOCKLIST_URL, {
      cf: { cacheTtl: CACHE_TTL_SECONDS } // Gunakan Cloudflare cache
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    const domains = new Set();
    
    // Parse hosts file format dengan lebih robust
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        const domain = parts[1].toLowerCase();
        if (domain && domain !== 'localhost' && !domain.startsWith('127.') && !domain.startsWith('0.0.0.0')) {
          domains.add(domain);
        }
      }
    }
    
    blocklistCache = domains;
    lastCacheUpdateTime = now;
    console.log(`Blocklist updated: ${blocklistCache.size} domains cached`);
  } catch (err) {
    console.error('Failed to update blocklist:', err);
  }
}

function isBlocked(domain) {
  if (!domain) return false;
  const normalizedDomain = domain.toLowerCase().replace(/\.$/, ''); // Remove trailing dot
  return blocklistCache.has(normalizedDomain);
}

function isBlockedDomain(domain) {
  return domain && isBlocked(domain);
}

function escapeHtml(str) {
  const div = { innerHTML: '' };
  div.textContent = str;
  return div.innerHTML;
}

function getDomainFromDnsMessage(buffer) {
  try {
    const view = new DataView(buffer);
    if (view.byteLength < 13) return null;

    let offset = 12; // Skip DNS header
    const labels = [];
    
    while (offset < view.byteLength) {
      const length = view.getUint8(offset);
      if (length === 0) break; // End of domain name
      if (length > 63 || offset + length >= view.byteLength) break; // Invalid label
      
      offset++;
      const label = new TextDecoder('ascii').decode(
        new Uint8Array(buffer, offset, length)
      );
      labels.push(label);
      offset += length;
    }
    
    return labels.length > 0 ? labels.join('.') : null;
  } catch (e) {
    console.error('Error parsing DNS message:', e);
    return null;
  }
}

// Response untuk format JSON DoH
function createJsonBlockedResponse(domain) {
  const response = {
    Status: 0, // NOERROR
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name: domain, type: 1 }],
    Answer: [{
      name: domain,
      type: 1, // A record
      TTL: 60,
      data: BLOCKED_IP
    }]
  };
  
  return new Response(JSON.stringify(response), {
    headers: { 'Content-Type': CONTENT_TYPE_JSON }
  });
}

// Response DNS yang mengarahkan ke halaman blokir
function createBlockedDnsResponse(requestBuffer, domain) {
  try {
    const reqView = new DataView(requestBuffer);
    const transactionId = reqView.getUint16(0);
    
    // Build response dengan A record pointing ke halaman blokir
    const blockedUrl = `https://${SELF_DOMAIN}/?blocked=${encodeURIComponent(domain)}`;
    
    // Untuk simplifikasi, return A record dengan IP yang mengarah ke halaman blokir
    // Browser akan mengakses IP ini dan mendapat halaman blokir
    const responseBuffer = buildDnsResponse(transactionId, domain, BLOCKED_IP);
    
    return new Response(responseBuffer, {
      headers: { 'Content-Type': CONTENT_TYPE_DNS }
    });
  } catch (e) {
    console.error('Error creating blocked DNS response:', e);
    // Fallback: return NXDOMAIN
    return createNxdomainResponse(requestBuffer);
  }
}

function buildDnsResponse(transactionId, domain, ip) {
  // Simplified DNS response builder
  const domainBytes = encodeDomainName(domain);
  const responseSize = 12 + domainBytes.length + 4 + 12 + 4; // Header + Question + Answer
  const buffer = new ArrayBuffer(responseSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  
  // DNS Header
  view.setUint16(0, transactionId); // Transaction ID
  view.setUint16(2, 0x8180); // Flags: Response, Authoritative
  view.setUint16(4, 1); // Questions
  view.setUint16(6, 1); // Answers
  view.setUint16(8, 0); // Authority RRs
  view.setUint16(10, 0); // Additional RRs
  
  let offset = 12;
  
  // Question section
  bytes.set(domainBytes, offset);
  offset += domainBytes.length;
  view.setUint16(offset, 1); // Type A
  view.setUint16(offset + 2, 1); // Class IN
  offset += 4;
  
  // Answer section
  view.setUint16(offset, 0xc00c); // Compression pointer to question
  view.setUint16(offset + 2, 1); // Type A
  view.setUint16(offset + 4, 1); // Class IN
  view.setUint32(offset + 6, 60); // TTL
  view.setUint16(offset + 10, 4); // Data length
  
  // IP Address
  const ipParts = ip.split('.').map(part => parseInt(part));
  bytes[offset + 12] = ipParts[0];
  bytes[offset + 13] = ipParts[1];
  bytes[offset + 14] = ipParts[2];
  bytes[offset + 15] = ipParts[3];
  
  return buffer;
}

function encodeDomainName(domain) {
  const labels = domain.split('.');
  const bytes = [];
  
  for (const label of labels) {
    bytes.push(label.length);
    for (let i = 0; i < label.length; i++) {
      bytes.push(label.charCodeAt(i));
    }
  }
  bytes.push(0); // End of domain name
  
  return new Uint8Array(bytes);
}

function createNxdomainResponse(requestBuffer) {
  const view = new DataView(requestBuffer);
  const responseBuffer = new ArrayBuffer(requestBuffer.byteLength);
  const responseView = new DataView(responseBuffer);
  const responseBytes = new Uint8Array(responseBuffer);
  
  // Copy request
  responseBytes.set(new Uint8Array(requestBuffer));
  
  // Set response flags (NXDOMAIN)
  responseView.setUint16(2, 0x8183); // Response with NXDOMAIN
  
  return new Response(responseBuffer, {
    headers: { 'Content-Type': CONTENT_TYPE_DNS }
  });
}
