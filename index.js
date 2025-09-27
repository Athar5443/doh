// SPDX-License-Identifier: 0BSD

// ====================================================================================
// KONFIGURASI UTAMA
// ====================================================================================

const DOH_UPSTREAM = 'https://security.cloudflare-dns.com/dns-query';
const BLOCKLIST_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts';
const SELF_DOMAIN = 'dns.athars.me'; // PASTIKAN SESUAI WORKERS ROUTE
const CACHE_TTL_SECONDS = 3600;

// ====================================================================================
// KODE INTI WORKER - IMPROVED REDIRECT LOGIC
// ====================================================================================

const DOH_PATH = '/dns-query';
const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';

let blocklistCache = new Set();
let lastCacheUpdateTime = 0;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const hostname = url.hostname;

    ctx.waitUntil(updateBlocklistCache());

    // ROUTING LOGIC: Prioritas halaman blocked
    if (url.pathname === '/blocked' || url.searchParams.has('blocked') || url.searchParams.has('domain')) {
      return serveBlockedPage(request);
    } else if (url.pathname === DOH_PATH || url.pathname.startsWith(DOH_PATH)) {
      return handleDohRequest(request);
    } else if (hostname === SELF_DOMAIN && !url.pathname.startsWith(DOH_PATH)) {
      // Semua request ke SELF_DOMAIN (kecuali DoH) adalah halaman blocked
      return serveBlockedPage(request);
    } else {
      return new Response('DNS Filter Service', { 
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  },
};

// --- DNS-over-HTTPS Handler dengan FORCED REDIRECT ---
async function handleDohRequest(request) {
  const { method, headers, url } = request;
  const { searchParams } = new URL(url);
  let domain = null;
  let requestBuffer = null;
  let isDohJsonRequest = false;

  try {
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
    console.error("DNS parsing error:", e);
  }

  // CRITICAL: Jika domain blocked, PAKSA redirect ke halaman blocked
  if (domain && isBlocked(domain)) {
    console.log(`🚫 BLOCKING: ${domain} -> Redirecting to blocked page`);
    
    if (isDohJsonRequest) {
      // JSON Response mengarah ke blocked page
      return createJsonRedirectResponse(domain);
    } else if (requestBuffer) {
      // DNS Response mengarah ke SELF_DOMAIN untuk blocked page
      return createDnsRedirectResponse(requestBuffer, domain);
    }
  }

  // Forward request normal ke upstream
  const dohUrl = new URL(DOH_UPSTREAM);
  dohUrl.search = searchParams.toString();
  
  return fetch(dohUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body
  });
}

// --- FORCED BLOCKED PAGE dengan Multiple Domain Detection ---
async function serveBlockedPage(request) {
  const url = new URL(request.url);
  
  // MULTI-SOURCE domain detection untuk memastikan blocked domain terdeteksi
  const blockedDomain = 
    url.searchParams.get('blocked') || 
    url.searchParams.get('domain') || 
    url.pathname.replace('/blocked/', '').replace('/blocked', '') ||
    request.headers.get('X-Forwarded-Host') || 
    request.headers.get('X-Original-Domain') ||
    request.headers.get('Referer')?.match(/\/\/([^\/]+)/)?.[1] ||
    'Domain Terblokir';

  const isDirectBlocked = url.searchParams.has('blocked') || url.searchParams.has('domain') || url.pathname.includes('blocked');

  const html = `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚫 Akses Diblokir - DNS Security</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-bg: rgba(255, 255, 255, 0.95); 
            --text: #1a202c; --accent: #e53e3e; --muted: #4a5568; 
            --border: rgba(0,0,0,0.1); --success: #38a169;
        }
        @media (prefers-color-scheme: dark) { 
            :root { 
                --bg: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                --card-bg: rgba(26, 32, 44, 0.95); --text: #f7fafc; 
                --accent: #fc8181; --muted: #a0aec0; --border: rgba(255,255,255,0.1);
            } 
        }
        
        * { box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', -apple-system, sans-serif; margin: 0; padding: 0;
            min-height: 100vh; background: var(--bg); color: var(--text);
            display: flex; align-items: center; justify-content: center;
            position: relative; overflow-x: hidden;
        }
        
        .background-pattern {
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background-image: radial-gradient(circle at 25% 25%, rgba(255,255,255,0.1) 0%, transparent 50%),
                              radial-gradient(circle at 75% 75%, rgba(255,255,255,0.1) 0%, transparent 50%);
            pointer-events: none;
        }
        
        .container { 
            background: var(--card-bg); border-radius: 20px; backdrop-filter: blur(20px);
            padding: 3rem 2.5rem; max-width: 580px; width: 90%; margin: 2rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3), 0 0 0 1px var(--border);
            text-align: center; position: relative; z-index: 10;
            animation: slideIn 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        
        @keyframes slideIn {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .shield-icon { 
            font-size: 5rem; line-height: 1; margin-bottom: 1.5rem;
            animation: pulse 2s infinite ease-in-out;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .status-badge {
            background: var(--accent); color: white; padding: 0.5rem 1.25rem;
            border-radius: 50px; font-size: 0.9rem; font-weight: 600;
            display: inline-block; margin-bottom: 1.5rem; letter-spacing: 0.5px;
            text-transform: uppercase; box-shadow: 0 4px 15px rgba(229, 62, 62, 0.3);
        }
        
        h1 { 
            font-size: 2rem; font-weight: 600; margin: 0 0 1rem 0; 
            background: linear-gradient(135deg, var(--text), var(--accent));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .domain-box { 
            background: var(--border); padding: 1rem 1.5rem; border-radius: 12px;
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 1.1rem; color: var(--accent); margin: 1.5rem 0;
            word-break: break-all; border: 2px solid var(--accent);
            position: relative; overflow: hidden;
        }
        
        .domain-box::before {
            content: ''; position: absolute; top: 0; left: -100%;
            width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(229,62,62,0.1), transparent);
            animation: shimmer 3s infinite;
        }
        
        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        
        .description { 
            color: var(--muted); font-size: 1.1rem; line-height: 1.7;
            margin-bottom: 2rem; font-style: italic;
        }
        
        .info-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem; margin: 2rem 0; text-align: left;
        }
        
        .info-item {
            background: var(--border); padding: 1rem; border-radius: 10px;
            border-left: 4px solid var(--accent);
        }
        
        .info-item strong { color: var(--accent); display: block; margin-bottom: 0.25rem; }
        
        .footer { 
            color: var(--muted); font-size: 0.9rem; margin-top: 2.5rem;
            padding-top: 2rem; border-top: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            flex-wrap: wrap; gap: 1rem;
        }
        
        .timestamp { font-weight: 500; }
        
        @media (max-width: 600px) {
            .container { padding: 2rem 1.5rem; margin: 1rem; }
            h1 { font-size: 1.75rem; }
            .shield-icon { font-size: 4rem; }
            .footer { flex-direction: column; text-align: center; }
        }
        
        .redirect-info {
            background: var(--success); color: white; padding: 0.75rem;
            border-radius: 8px; margin-top: 1rem; font-size: 0.9rem;
            ${isDirectBlocked ? 'display: block;' : 'display: none;'}
        }
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    <div class="container">
        <div class="shield-icon">🛡️</div>
        <div class="status-badge">Akses Diblokir</div>
        <h1>Domain Tidak Dapat Diakses</h1>
        
        <div class="domain-box">${escapeHtml(blockedDomain)}</div>
        
        <p class="description">
            Domain ini telah diblokir oleh sistem keamanan DNS untuk melindungi 
            jaringan dari konten berbahaya, malware, phishing, atau iklan yang mengganggu.
        </p>
        
        <div class="info-grid">
            <div class="info-item">
                <strong>Status</strong>
                Diblokir oleh DNS Filter
            </div>
            <div class="info-item">
                <strong>Alasan</strong>
                Keamanan & Privasi
            </div>
            <div class="info-item">
                <strong>Waktu</strong>
                ${new Date().toLocaleTimeString('id-ID')}
            </div>
            <div class="info-item">
                <strong>Filter</strong>
                StevenBlack Hosts
            </div>
        </div>
        
        <div class="redirect-info">
            ✅ Redirect berhasil! Domain berbahaya dialihkan ke halaman ini.
        </div>
        
        <div class="footer">
            <div>🔒 DNS Security Filter</div>
            <div class="timestamp">${new Date().toLocaleDateString('id-ID', { 
              weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' 
            })}</div>
        </div>
    </div>
    
    <script>
        // Log blocked domain untuk debugging
        console.log('🚫 Blocked Domain:', '${escapeHtml(blockedDomain)}');
        console.log('🔗 Current URL:', window.location.href);
        
        // Auto refresh jika tidak ada domain info (fallback)
        if ('${blockedDomain}' === 'Domain Terblokir' && !window.location.search) {
            setTimeout(() => {
                if (document.referrer) {
                    const referrerDomain = new URL(document.referrer).hostname;
                    window.location.href = window.location.href + '?blocked=' + referrerDomain;
                }
            }, 1000);
        }
    </script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { 
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
      'X-Blocked-Domain': blockedDomain,
      'X-DNS-Filter': 'Active'
    }
  });
}

// --- HELPER FUNCTIONS yang DIPERBAIKI ---

async function updateBlocklistCache() {
  const now = Date.now() / 1000;
  if (now - lastCacheUpdateTime < CACHE_TTL_SECONDS && blocklistCache.size > 0) return;

  try {
    const response = await fetch(BLOCKLIST_URL, {
      cf: { cacheTtl: CACHE_TTL_SECONDS }
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const text = await response.text();
    const domains = new Set();
    
    // Robust hosts file parsing
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
      
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        const domain = parts[1].toLowerCase().replace(/\.$/, '');
        if (domain && domain !== 'localhost' && domain.includes('.') && 
            !domain.startsWith('127.') && !domain.startsWith('0.0.0.0') && 
            !domain.startsWith('::1') && domain.length > 3) {
          domains.add(domain);
        }
      }
    }
    
    blocklistCache = domains;
    lastCacheUpdateTime = now;
    console.log(`📋 Blocklist updated: ${blocklistCache.size} domains`);
  } catch (err) {
    console.error('❌ Blocklist update failed:', err);
  }
}

function isBlocked(domain) {
  if (!domain) return false;
  const clean = domain.toLowerCase().replace(/\.$/, '');
  return blocklistCache.has(clean);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getDomainFromDnsMessage(buffer) {
  try {
    const view = new DataView(buffer);
    if (view.byteLength < 13) return null;

    let offset = 12;
    const labels = [];
    
    while (offset < view.byteLength) {
      const length = view.getUint8(offset);
      if (length === 0) break;
      if (length > 63 || offset + length >= view.byteLength) break;
      
      offset++;
      const label = new TextDecoder('ascii').decode(
        new Uint8Array(buffer, offset, length)
      );
      labels.push(label);
      offset += length;
    }
    
    return labels.length > 0 ? labels.join('.') : null;
  } catch (e) {
    return null;
  }
}

// JSON DoH Response yang MENGARAH ke blocked page
function createJsonRedirectResponse(domain) {
  // Resolve SELF_DOMAIN ke IP yang akan menampilkan blocked page
  const response = {
    Status: 0,
    TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name: domain, type: 1 }],
    Answer: [{
      name: domain,
      type: 5, // CNAME record
      TTL: 60,
      data: `${SELF_DOMAIN}.` // CNAME ke SELF_DOMAIN
    }]
  };
  
  return new Response(JSON.stringify(response), {
    headers: { 'Content-Type': CONTENT_TYPE_JSON }
  });
}

// DNS Response yang PAKSA redirect ke blocked page
function createDnsRedirectResponse(requestBuffer, domain) {
  try {
    const reqView = new DataView(requestBuffer);
    const transactionId = reqView.getUint16(0);
    
    // Parse question untuk rebuild response
    let questionEnd = 12;
    while (questionEnd < requestBuffer.byteLength && reqView.getUint8(questionEnd) !== 0) {
      questionEnd += reqView.getUint8(questionEnd) + 1;
    }
    questionEnd += 5; // Skip null terminator + type + class
    
    const questionSection = new Uint8Array(requestBuffer, 12, questionEnd - 12);
    
    // Build CNAME response yang mengarah ke SELF_DOMAIN dengan parameter blocked
    const targetDomain = `${SELF_DOMAIN}`;
    const targetBytes = encodeDomainName(targetDomain);
    
    const responseSize = 12 + questionSection.length + 12 + targetBytes.length;
    const buffer = new ArrayBuffer(responseSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    
    // DNS Header - Response dengan CNAME
    view.setUint16(0, transactionId);
    view.setUint16(2, 0x8180); // Response, Authoritative
    view.setUint16(4, 1); // Questions
    view.setUint16(6, 1); // Answers
    view.setUint16(8, 0); // Authority
    view.setUint16(10, 0); // Additional
    
    let offset = 12;
    
    // Question section (copy dari request)
    bytes.set(questionSection, offset);
    offset += questionSection.length;
    
    // Answer section - CNAME record
    view.setUint16(offset, 0xc00c); // Compression pointer
    view.setUint16(offset + 2, 5); // CNAME type
    view.setUint16(offset + 4, 1); // Class IN
    view.setUint32(offset + 6, 300); // TTL 5 menit
    view.setUint16(offset + 10, targetBytes.length); // Data length
    
    // CNAME target domain
    bytes.set(targetBytes, offset + 12);
    
    console.log(`🔄 DNS CNAME: ${domain} -> ${targetDomain}`);
    
    return new Response(buffer, {
      headers: { 
        'Content-Type': CONTENT_TYPE_DNS,
        'X-Blocked-Domain': domain
      }
    });
    
  } catch (e) {
    console.error('❌ DNS redirect error:', e);
    return createNxdomainResponse(requestBuffer);
  }
}

function encodeDomainName(domain) {
  const labels = domain.split('.');
  const bytes = [];
  
  for (const label of labels) {
    if (label.length === 0) continue;
    bytes.push(label.length);
    for (let i = 0; i < label.length; i++) {
      bytes.push(label.charCodeAt(i));
    }
  }
  bytes.push(0);
  
  return new Uint8Array(bytes);
}

function createNxdomainResponse(requestBuffer) {
  const buffer = new ArrayBuffer(requestBuffer.byteLength);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  
  bytes.set(new Uint8Array(requestBuffer));
  view.setUint16(2, 0x8183); // NXDOMAIN response
  
  return new Response(buffer, {
    headers: { 'Content-Type': CONTENT_TYPE_DNS }
  });
}
