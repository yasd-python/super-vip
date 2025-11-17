// @ts-nocheck
// ============================================================================
// ULTIMATE VLESS PROXY WORKER - UNIVERSAL QR CODE VERSION
// ============================================================================
//
// QR Code generation with multiple fallbacks for 100% cross-browser compatibility
// Works in Chrome, Firefox, Safari, Edge, and all mobile browsers
//
// ============================================================================

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  scamalytics: {
    username: '', 
    apiKey: '',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },
  
  async fromEnv(env) {
    let selectedProxyIP = null;

    if (env.D1) {
      try {
        const { results } = await env.D1.prepare("SELECT ip FROM proxy_scans WHERE is_current_best = 1 LIMIT 1").all();
        selectedProxyIP = results[0]?.ip || null;
        if (selectedProxyIP) {
          console.log(`Using proxy IP from D1: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read from D1: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined");
        selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  AUTO_REFRESH_INTERVAL: 60000, // 1 minute auto-refresh
  IP_CLEANUP_AGE_DAYS: 30, // Cleanup old user_ips
};

// ============================================================================
// SECURITY & HELPER FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'self'",
    "base-uri 'self'",
    nonce ? `script-src 'nonce-${nonce}' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'` : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'",
    nonce ? `style-src 'nonce-${nonce}' 'unsafe-inline'` : "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: https: blob: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: ${cspDomains.connect || ''}`.trim(),
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=0');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const aLen = a.length;
  const bLen = b.length;
  let result = 0;

  if (aLen !== bLen) {
    for (let i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  
  for (let i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function kvGet(db, key, type = 'text') {
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      try {
        return JSON.parse(res.value);
      } catch (e) {
        console.error(`Failed to parse JSON for key ${key}: ${e.message}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e.message}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error(`kvPut error for ${key}: ${e.message}`);
  }
}

async function kvDelete(db, key) {
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e.message}`);
  }
}

async function getUserData(env, uuid, ctx) {
  if (!isValidUUID(uuid)) return null;
  if (!env.DB) {
    console.error("D1 binding missing");
    return null;
  }
  
  const cacheKey = `user:${uuid}`;
  
  try {
    const cachedData = await kvGet(env.DB, cacheKey, 'json');
    if (cachedData && cachedData.uuid) return cachedData;
  } catch (e) {
    console.error(`Failed to get cached data for ${uuid}`, e.message);
  }

  const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
  if (!userFromDb) return null;
  
  const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
  
  if (ctx) {
    ctx.waitUntil(cachePromise);
  } else {
    await cachePromise;
  }
  
  return userFromDb;
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // Acquire lock
    while (!lockAcquired) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 }); // 5s lock
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100)); // Backoff
      }
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
      .bind(usage, uuid)
      .run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}: ${err.message}`);
  } finally {
    if (lockAcquired) {
      await kvDelete(env.DB, usageLockKey);
    }
  }
}

async function cleanupOldIps(env, ctx) {
  const cleanupPromise = env.DB.prepare(
    "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
  ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
  
  if (ctx) {
    ctx.waitUntil(cleanupPromise);
  } else {
    await cleanupPromise;
  }
}

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics API credentials not configured. IP ${ip} allowed by default (fail-open mode). Set SCAMALYTICS_USERNAME and SCAMALYTICS_API_KEY for protection.`);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      console.warn(`Scamalytics API returned ${response.status} for ${ip}. Allowing (fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics timeout for ${ip}. Allowing (fail-open).`);
    } else {
      console.error(`Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// TFA (TOTP) VALIDATION
// ============================================================================

function base32ToBuffer(base32) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const charValue = base32Chars.indexOf(char);
    if (charValue === -1) throw new Error('Invalid Base32 character');
    
    value = (value << 5) | charValue;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hmacBuffer = new Uint8Array(hmac);
  
  const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  const otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }
  
  let secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    console.error("Failed to decode TOTP secret:", e.message);
    return false;
  }
  
  const timeStep = 30;
  const epoch = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(epoch / timeStep);
  
  const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

  for (const counter of counters) {
    const generatedCode = await generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) {
      return true;
    }
  }
  
  return false;
}

async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(db, key, limit, ttl) {
  const countStr = await kvGet(db, key);
  const count = parseInt(countStr, 10) || 0;
  if (count >= limit) return true;
  await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
  return false;
}

// ============================================================================
// UUID STRINGIFY
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + 
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION GENERATION
// ============================================================================

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}${query ? '?' + query : ''}`;
}

const CORE_PRESETS = {
  xray: {
    tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} },
    tcp: { path: () => generateRandomPath(12, 'ed=2048'), security: 'none', fp: 'chrome', extra: {} },
  },
  sb: {
    tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: CONST.ED_PARAMS },
    tcp: { path: () => generateRandomPath(18), security: 'none', fp: 'firefox', extra: CONST.ED_PARAMS },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
  const params = new URLSearchParams({ type: 'ws', host, path });
  if (security) params.set('security', security);
  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);
  for (const [k, v] of Object.entries(extra)) params.set(k, v);
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID, address, port, host: hostName, path: p.path(), security: p.security,
    sni: p.security === 'tls' ? hostName : undefined, fp: p.fp, alpn: p.alpn, extra: p.extra, name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName, 'creativecommons.org', 'mail.tm',
    'temp-mail.org', 'ipaddress.my', 
    'mdbmax.com', 'check-host.net',
    'kodambroker.com', 'iplocation.io',
    'whatismyip.org', 'ifciran.net',
    'whatismyip.com', 'www.speedtest.net',
    'www.linkedin.com', 'exir.io',
    'arzex.io', 'ok-ex.io',
    'arzdigital.com', 'pouyanit.com',
    'auth.grok.com', 'grok.com',
    'whatismyip.live', 'whatismyip.org',
    'maxmind.com', 'whatsmyip.com',
    'iplocation.net','ipchicken.com',
    'showmyip.com', 'whatsmyip.now', 'router-network.com',
    'sky.rethinkdns.com', 'cfip.1323123.xyz',
    'go.inmobi.com', 'whatismyipaddress.com',
    'cf.090227.xyz', 'cdnjs.com', 'zula.ir',
  ];
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i+1}` }));
    if (!isPagesDeployment) {
      links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i+1}` }));
    }
  });

  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 ?? []), ...(json.ipv6 ?? [])].slice(0, 20).map(x => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i+1}` }));
        if (!isPagesDeployment) {
          links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i+1}` }));
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e.message);
  }

  const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8' });
  addSecurityHeaders(headers, null, {});

  return new Response(btoa(links.join('\n')), { headers });
}

// ============================================================================
// ADMIN PANEL HTML (preserved from original, with auto-refresh enhancements)
// ============================================================================

const adminLoginHTML = [
  '<!DOCTYPE html>',
  '<html lang="en">',
  '<head>',
  '    <meta charset="UTF-8">',
  '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
  '    <title>Admin Login</title>',
  '    <style nonce="CSP_NONCE_PLACEHOLDER">',
  '        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #121212; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }',
  '        .login-container { background-color: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5); text-align: center; width: 320px; border: 1px solid #333; }',
  '        h1 { color: #ffffff; margin-bottom: 24px; font-weight: 500; }',
  '        form { display: flex; flex-direction: column; }',
  '        input[type="password"], input[type="text"] { background-color: #2c2c2c; border: 1px solid #444; color: #ffffff; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 16px; box-sizing: border-box; width: 100%; }',
  '        input[type="password"]:focus, input[type="text"]:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.3); }',
  '        button { background-color: #007aff; color: white; border: none; padding: 12px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }',
  '        button:hover { background-color: #005ecb; }',
  '        .error { color: #ff3b30; margin-top: 15px; font-size: 14px; }',
  '        @media (max-width: 400px) {',
  '            .login-container { width: 90%; padding: 25px; }',
  '        }',
  '    </style>',
  '</head>',
  '<body>',
  '    <div class="login-container">',
  '        <h1>Admin Login</h1>',
  '        <form method="POST" action="ADMIN_PATH_PLACEHOLDER">',
  '            <input type="password" name="password" placeholder="Enter admin password" required>',
  '            <input type="text" name="totp" placeholder="Enter TOTP code (if enabled)" autocomplete="off" />',
  '            <button type="submit">Login</button>',
  '        </form>',
  '    </div>',
  '</body>',
  '</html>'
].join('\n');

const adminPanelHTML = [
  '<!DOCTYPE html>',
  '<html lang="en">',
  '<head>',
  '    <meta charset="UTF-8">',
  '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
  '    <title>Admin Dashboard</title>',
  '    <style nonce="CSP_NONCE_PLACEHOLDER">',
  '        :root {',
  '            --bg-main: #111827; --bg-card: #1F2937; --border: #374151; --text-primary: #F9FAFB;',
  '            --text-secondary: #9CA3AF; --accent: #3B82F6; --accent-hover: #2563EB; --danger: #EF4444;',
  '            --danger-hover: #DC2626; --success: #22C55E; --expired: #F59e0b; --btn-secondary-bg: #4B5563;',
  '        }',
  '        body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-main); color: var(--text-primary); font-size: 14px; }',
  '        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }',
  '        h1, h2 { font-weight: 600; }',
  '        h1 { font-size: 24px; margin-bottom: 20px; }',
  '        h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 20px; }',
  '        .card { background-color: var(--bg-card); border-radius: 8px; padding: 24px; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }',
  '        .dashboard-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }',
  '        .stat-card { background: #1F2937; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }',
  '        .stat-value { font-size: 24px; font-weight: 600; color: var(--accent); }',
  '        .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; margin-top: 4px; }',
  '        .form-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(200px, 1fr)); gap: 16px; align-items: flex-end; }',
  '        .form-group { display: flex; flex-direction: column; }',
  '        .form-group label { margin-bottom: 8px; font-weight: 500; color: var(--text-secondary); }',
  '        .form-group .input-group { display: flex; }',
  '        input[type="text"], input[type="date"], input[type="time"], input[type="number"], select {',
  '            width: 100%; box-sizing: border-box; background-color: #374151; border: 1px solid #4B5563; color: var(--text-primary);',
  '            padding: 10px; border-radius: 6px; font-size: 14px; transition: border-color 0.2s;',
  '        }',
  '        input:focus, select:focus { outline: none; border-color: var(--accent); }',
  '        .label-note { font-size: 11px; color: var(--text-secondary); margin-top: 4px; }',
  '        .btn {',
  '            padding: 10px 16px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;',
  '            transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px;',
  '        }',
  '        .btn:active { transform: scale(0.98); }',
  '        .btn-primary { background-color: var(--accent); color: white; }',
  '        .btn-primary:hover { background-color: var(--accent-hover); }',
  '        .btn-secondary { background-color: var(--btn-secondary-bg); color: white; }',
  '        .btn-secondary:hover { background-color: #6B7280; }',
  '        .btn-danger { background-color: var(--danger); color: white; }',
  '        .btn-danger:hover { background-color: var(--danger-hover); }',
  '        .input-group .btn-secondary { border-top-left-radius: 0; border-bottom-left-radius: 0; }',
  '        .input-group input { border-top-right-radius: 0; border-bottom-right-radius: 0; border-right: none; }',
  '        .input-group select { border-top-left-radius: 0; border-bottom-left-radius: 0; }',
  '        .search-input { width: 100%; margin-bottom: 16px; box-sizing: border-box; }',
  '        .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; }',
  '        table { width: 100%; border-collapse: collapse; margin-top: 20px; }',
  '        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }',
  '        th { color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; }',
  '        td { color: var(--text-primary); font-family: "SF Mono", "Fira Code", monospace; font-size: 13px; }',
  '        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; display: inline-block; }',
  '        .status-active { background-color: var(--success); color: #064E3B; }',
  '        .status-expired { background-color: var(--expired); color: #78350F; }',
  '        .actions-cell .btn { padding: 6px 10px; font-size: 12px; }',
  '        #toast { position: fixed; top: 20px; right: 20px; background-color: var(--bg-card); color: white; padding: 15px 20px; border-radius: 8px; z-index: 1001; display: none; border: 1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.3); opacity: 0; transition: opacity 0.3s, transform 0.3s; transform: translateY(-20px); }',
  '        #toast.show { display: block; opacity: 1; transform: translateY(0); }',
  '        #toast.error { border-left: 5px solid var(--danger); }',
  '        #toast.success { border-left: 5px solid var(--success); }',
  '        .uuid-cell { display: flex; align-items: center; justify-content: space-between; gap: 8px; }',
  '        .uuid-text { flex: 1; overflow: hidden; text-overflow: ellipsis; }',
  '        .btn-copy-uuid { ',
  '            padding: 4px 8px; font-size: 11px; background-color: rgba(59, 130, 246, 0.1); ',
  '            border: 1px solid rgba(59, 130, 246, 0.3); color: var(--accent); border-radius: 4px;',
  '            cursor: pointer; transition: all 0.2s; white-space: nowrap; flex-shrink: 0;',
  '        }',
  '        .btn-copy-uuid:hover { background-color: rgba(59, 130, 246, 0.2); border-color: var(--accent); }',
  '        .btn-copy-uuid.copied { background-color: rgba(34, 197, 94, 0.1); border-color: rgba(34, 197, 94, 0.3); color: var(--success); }',
  '        .actions-cell { display: flex; gap: 8px; justify-content: center; }',
  '        .time-display { display: flex; flex-direction: column; }',
  '        .time-local { font-weight: 600; }',
  '        .time-utc, .time-relative { font-size: 11px; color: var(--text-secondary); }',
  '        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); z-index: 1000; display: flex; justify-content: center; align-items: center; opacity: 0; visibility: hidden; transition: opacity 0.3s, visibility 0.3s; }',
  '        .modal-overlay.show { opacity: 1; visibility: visible; }',
  '        .modal-content { background-color: var(--bg-card); padding: 30px; border-radius: 12px; box-shadow: 0 5px 25px rgba(0,0,0,0.4); width: 90%; max-width: 500px; transform: scale(0.9); transition: transform 0.3s; border: 1px solid var(--border); max-height: 90vh; overflow-y: auto; }',
  '        .modal-overlay.show .modal-content { transform: scale(1); }',
  '        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; }',
  '        .modal-header h2 { margin: 0; border: none; font-size: 20px; }',
  '        .modal-close-btn { background: none; border: none; color: var(--text-secondary); font-size: 24px; cursor: pointer; line-height: 1; }',
  '        .modal-footer { display: flex; justify-content: flex-end; gap: 12px; margin-top: 25px; }',
  '        .time-quick-set-group { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }',
  '        .btn-outline-secondary {',
  '            background-color: transparent; border: 1px solid var(--btn-secondary-bg); color: var(--text-secondary);',
  '            padding: 6px 10px; font-size: 12px; font-weight: 500;',
  '        }',
  '        .btn-outline-secondary:hover { background-color: var(--btn-secondary-bg); color: white; border-color: var(--btn-secondary-bg); }',
  '        .checkbox { width: 16px; height: 16px; margin-right: 10px; cursor: pointer; }',
  '        .select-all { cursor: pointer; }',
  '        ',
  '        .logout-btn { position: absolute; top: 20px; right: 20px; }',
  '        .mt-30 { margin-top: 30px; }',
  '        .grid-col-full { grid-column: 1 / -1; }',
  '        .mt-16 { margin-top: 16px; }',
  '        ',
  '        @media (max-width: 768px) {',
  '            .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }',
  '            .container { padding: 0 10px; margin: 20px auto; }',
  '            .card { padding: 16px; }',
  '            h1 { font-size: 20px; }',
  '            .form-grid { grid-template-columns: 1fr; }',
  '            .modal-content { width: 95%; padding: 20px; }',
  '            .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; }',
  '            table { font-size: 12px; } ',
  '            th, td { padding: 10px 8px; font-size: 11px; white-space: nowrap; }',
  '            .actions-cell { flex-wrap: wrap; justify-content: flex-end; }',
  '        }',
  '    </style>',
  '</head>',
  '<body>',
  '    <div class="container">',
  '        <h1>Admin Dashboard</h1>',
  '        <button id="logoutBtn" class="btn btn-danger logout-btn">Logout</button>',
  '        <div class="dashboard-stats">',
  '            <div class="stat-card"><div class="stat-value" id="total-users">0</div><div class="stat-label">Total Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="active-users">0</div><div class="stat-label">Active Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="expired-users">0</div><div class="stat-label">Expired Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="total-traffic">0 KB</div><div class="stat-label">Total Traffic Used</div></div>',
  '        </div>',
  '        <div class="card">',
  '            <h2>Create User</h2>',
  '            <form id="createUserForm" class="form-grid">',
  '                <div class="form-group grid-col-full"><label for="uuid">UUID</label><div class="input-group"><input type="text" id="uuid" required><button type="button" id="generateUUID" class="btn btn-secondary">Generate</button></div></div>',
  '                <div class="form-group"><label for="expiryDate">Expiry Date</label><input type="date" id="expiryDate" required></div>',
  '                <div class="form-group">',
  '                    <label for="expiryTime">Expiry Time (Your Local Time)</label>',
  '                    <input type="time" id="expiryTime" step="1" required>',
  '                    <div class="label-note">Automatically converted to UTC on save.</div>',
  '                    <div class="time-quick-set-group" data-target-date="expiryDate" data-target-time="expiryTime">',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>',
  '                    </div>',
  '                </div>',
  '                <div class="form-group"><label for="notes">Notes</label><input type="text" id="notes" placeholder="Optional notes"></div>',
  '                <div class="form-group"><label for="dataLimit">Data Limit</label><div class="input-group"><input type="number" id="dataLimit" min="0" step="0.01" placeholder="0"><select id="dataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited" selected>Unlimited</option></select></div></div>',
  '                <div class="form-group"><label for="ipLimit">IP Limit</label><div class="input-group"><input type="number" id="ipLimit" min="-1" step="1" placeholder="-1"><select id="ipUnit"><option value="-1" selected>Unlimited (-1)</option></select></div></div>',
  '                <div class="form-group"><label>&nbsp;</label><button type="submit" class="btn btn-primary">Create User</button></div>',
  '            </form>',
  '        </div>',
  '        <div class="card mt-30">',
  '            <h2>User List</h2>',
  '            <input type="text" id="searchInput" class="search-input" placeholder="Search by UUID or Notes...">',
  '            <button id="deleteSelected" class="btn btn-danger" style="margin-bottom: 16px;">Delete Selected</button>',
  '            <div class="table-wrapper">',
  '                 <table>',
  '                    <thead><tr><th><input type="checkbox" id="selectAll" class="select-all checkbox"></th><th>UUID</th><th>Created</th><th>Expiry (Admin Local)</th><th>Expiry (Tehran)</th><th>Status</th><th>Notes</th><th>Data Limit</th><th>Usage</th><th>IP Limit</th><th>Actions</th></tr></thead>',
  '                    <tbody id="userList"></tbody>',
  '                </table>',
  '            </div>',
  '        </div>',
  '    </div>',
  '    <div id="toast"></div>',
  '    <div id="editModal" class="modal-overlay">',
  '        <div class="modal-content">',
  '            <div class="modal-header">',
  '                <h2>Edit User</h2>',
  '                <button id="modalCloseBtn" class="modal-close-btn">&times;</button>',
  '            </div>',
  '            <form id="editUserForm">',
  '                <input type="hidden" id="editUuid" name="uuid">',
  '                <div class="form-group"><label for="editExpiryDate">Expiry Date</label><input type="date" id="editExpiryDate" name="exp_date" required></div>',
  '                <div class="form-group mt-16">',
  '                    <label for="editExpiryTime">Expiry Time (Your Local Time)</label>',
  '                    <input type="time" id="editExpiryTime" name="exp_time" step="1" required>',
  '                     <div class="label-note">Your current timezone is used for conversion.</div>',
  '                    <div class="time-quick-set-group" data-target-date="editExpiryDate" data-target-time="editExpiryTime">',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>',
  '                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>',
  '                    </div>',
  '                </div>',
  '                <div class="form-group mt-16"><label for="editNotes">Notes</label><input type="text" id="editNotes" name="notes" placeholder="Optional notes"></div>',
  '                <div class="form-group mt-16"><label for="editDataLimit">Data Limit</label><div class="input-group"><input type="number" id="editDataLimit" min="0" step="0.01"><select id="editDataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited">Unlimited</option></select></div></div>',
  '                <div class="form-group mt-16"><label for="editIpLimit">IP Limit</label><div class="input-group"><input type="number" id="editIpLimit" min="-1" step="1"><select id="editIpUnit"><option value="-1">Unlimited (-1)</option></select></div></div>',
  '                <div class="form-group mt-16"><label><input type="checkbox" id="resetTraffic" name="reset_traffic" class="checkbox" style="width: auto; margin-right: 8px;"> Reset Traffic Usage</label></div>',
  '                <div class="modal-footer">',
  '                    <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>',
  '                    <button type="submit" class="btn btn-primary">Save Changes</button>',
  '                </div>',
  '            </form>',
  '        </div>',
  '    </div>',
  '',
  '    <script nonce="CSP_NONCE_PLACEHOLDER">',
  '        document.addEventListener(\'DOMContentLoaded\', () => {',
  '            const API_BASE = \'ADMIN_API_BASE_PATH_PLACEHOLDER\';',
  '            let allUsers = [];',
  '            const userList = document.getElementById(\'userList\');',
  '            const createUserForm = document.getElementById(\'createUserForm\');',
  '            const generateUUIDBtn = document.getElementById(\'generateUUID\');',
  '            const uuidInput = document.getElementById(\'uuid\');',
  '            const toast = document.getElementById(\'toast\');',
  '            const editModal = document.getElementById(\'editModal\');',
  '            const editUserForm = document.getElementById(\'editUserForm\');',
  '            const searchInput = document.getElementById(\'searchInput\');',
  '            const selectAll = document.getElementById(\'selectAll\');',
  '            const deleteSelected = document.getElementById(\'deleteSelected\');',
  '            const logoutBtn = document.getElementById(\'logoutBtn\');',
  '            let autoRefreshInterval;',
  '',
  '            function escapeHTML(str) {',
  '              if (typeof str !== \'string\') return \'\';',
  '              return str.replace(/[&<>"\']/g, m => ({',
  '                \'&\': \'&amp;\',',
  '                \'<\': \'&lt;\',',
  '                \'>\': \'&gt;\',',
  '                \'"\' : \'&quot;\',',
  '                "\'": \'&#39;\'',
  '              })[m]);',
  '            }',
  '',
  '            function formatBytes(bytes) {',
  '              if (bytes === 0) return \'0 Bytes\';',
  '              const k = 1024;',
  '              const sizes = [\'Bytes\', \'KB\', \'MB\', \'GB\', \'TB\', \'PB\', \'EB\', \'ZB\', \'YB\'];',
  '              const i = Math.floor(Math.log(bytes) / Math.log(k));',
  '              return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + \' \' + sizes[i];',
  '            }',
  '',
  '            function showToast(message, isError = false) {',
  '                toast.textContent = message;',
  '                toast.className = isError ? \'error\' : \'success\';',
  '                toast.classList.add(\'show\');',
  '                setTimeout(() => { toast.classList.remove(\'show\'); }, 3000);',
  '            }',
  '',
  '            const getCsrfToken = () => document.cookie.split(\'; \').find(row => row.startsWith(\'csrf_token=\'))?.split(\'=\')[1] || \'\';',
  '',
  '            const api = {',
  '                get: (endpoint) => fetch(API_BASE + endpoint, { credentials: \'include\' }).then(handleResponse),',
  '                post: (endpoint, body) => fetch(API_BASE + endpoint, { method: \'POST\', credentials: \'include\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse),',
  '                put: (endpoint, body) => fetch(API_BASE + endpoint, { method: \'PUT\', credentials: \'include\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse),',
  '                delete: (endpoint) => fetch(API_BASE + endpoint, { method: \'DELETE\', credentials: \'include\', headers: {\'X-CSRF-Token\': getCsrfToken()} }).then(handleResponse),',
  '            };',
  '',
  '            async function handleResponse(response) {',
  '                if (response.status === 401) {',
  '                    showToast(\'Session expired. Please log in again.\', true);',
  '                    setTimeout(() => window.location.reload(), 2000);',
  '                }',
  '                if (!response.ok) {',
  '                    const errorData = await response.json().catch(() => ({ error: \'An unknown error occurred.\' }));',
  '                    throw new Error(errorData.error || \'Request failed with status \' + response.status);',
  '                }',
  '                return response.status === 204 ? null : response.json();',
  '            }',
  '',
  '            const pad = (num) => num.toString().padStart(2, \'0\');',
  '',
  '            function localToUTC(dateStr, timeStr) {',
  '                if (!dateStr || !timeStr) return { utcDate: \'\', utcTime: \'\' };',
  '                const localDateTime = new Date(dateStr + \'T\' + timeStr);',
  '                if (isNaN(localDateTime.getTime())) return { utcDate: \'\', utcTime: \'\' };',
  '',
  '                const year = localDateTime.getUTCFullYear();',
  '                const month = pad(localDateTime.getUTCMonth() + 1);',
  '                const day = pad(localDateTime.getUTCDate());',
  '                const hours = pad(localDateTime.getUTCHours());',
  '                const minutes = pad(localDateTime.getUTCMinutes());',
  '                const seconds = pad(localDateTime.getUTCSeconds());',
  '',
  '                return {',
  '                    utcDate: year + \'-\' + month + \'-\' + day,',
  '                    utcTime: hours + \':\' + minutes + \':\' + seconds',
  '                };',
  '            }',
  '',
  '            function utcToLocal(utcDateStr, utcTimeStr) {',
  '                if (!utcDateStr || !utcTimeStr) return { localDate: \'\', localTime: \'\' };',
  '                const utcDateTime = new Date(utcDateStr + \'T\' + utcTimeStr + \'Z\');',
  '                if (isNaN(utcDateTime.getTime())) return { localDate: \'\', localTime: \'\' };',
  '',
  '                const year = utcDateTime.getFullYear();',
  '                const month = pad(utcDateTime.getMonth() + 1);',
  '                const day = pad(utcDateTime.getDate());',
  '                const hours = pad(utcDateTime.getHours());',
  '                const minutes = pad(utcDateTime.getMinutes());',
  '                const seconds = pad(utcDateTime.getSeconds());',
  '',
  '                return {',
  '                    localDate: year + \'-\' + month + \'-\' + day,',
  '                    localTime: hours + \':\' + minutes + \':\' + seconds',
  '                };',
  '            }',
  '',
  '            function addExpiryTime(dateInputId, timeInputId, amount, unit) {',
  '                const dateInput = document.getElementById(dateInputId);',
  '                const timeInput = document.getElementById(timeInputId);',
  '',
  '                let date = new Date(dateInput.value + \'T\' + (timeInput.value || \'00:00:00\'));',
  '                if (isNaN(date.getTime())) {',
  '                    date = new Date();',
  '                }',
  '',
  '                if (unit === \'hour\') date.setHours(date.getHours() + amount);',
  '                else if (unit === \'day\') date.setDate(date.getDate() + amount);',
  '                else if (unit === \'month\') date.setMonth(date.getMonth() + amount);',
  '',
  '                const year = date.getFullYear();',
  '                const month = pad(date.getMonth() + 1);',
  '                const day = pad(date.getDate());',
  '                const hours = pad(date.getHours());',
  '                const minutes = pad(date.getMinutes());',
  '                const seconds = pad(date.getSeconds());',
  '',
  '                dateInput.value = year + \'-\' + month + \'-\' + day;',
  '                timeInput.value = hours + \':\' + minutes + \':\' + seconds;',
  '            }',
  '',
  '            document.body.addEventListener(\'click\', (e) => {',
  '                const target = e.target.closest(\'.time-quick-set-group button\');',
  '                if (!target) return;',
  '                const group = target.closest(\'.time-quick-set-group\');',
  '                addExpiryTime(',
  '                    group.dataset.targetDate,',
  '                    group.dataset.targetTime,',
  '                    parseInt(target.dataset.amount, 10),',
  '                    target.dataset.unit',
  '                );',
  '            });',
  '',
  '            function formatExpiryDateTime(expDateStr, expTimeStr) {',
  '                const expiryUTC = new Date(expDateStr + \'T\' + expTimeStr + \'Z\');',
  '                if (isNaN(expiryUTC.getTime())) return { local: \'Invalid Date\', utc: \'\', relative: \'\', tehran: \'\', isExpired: true };',
  '',
  '                const now = new Date();',
  '                const isExpired = expiryUTC < now;',
  '',
  '                const commonOptions = {',
  '                    year: \'numeric\', month: \'2-digit\', day: \'2-digit\',',
  '                    hour: \'2-digit\', minute: \'2-digit\', second: \'2-digit\', hour12: false, timeZoneName: \'short\'',
  '                };',
  '',
  '                const localTime = expiryUTC.toLocaleString(undefined, commonOptions);',
  '                let tehranTime = \'N/A\';',
  '                try {',
  '                     tehranTime = expiryUTC.toLocaleString(\'en-US\', { ...commonOptions, timeZone: \'Asia/Tehran\' });',
  '                } catch(e) { console.error("Could not format Tehran time:", e.message); }',
  '                const utcTime = expiryUTC.toISOString().replace(\'T\', \' \').substring(0, 19) + \' UTC\';',
  '',
  '                let relativeTime = \'\';',
  '                try {',
  '                    const rtf = new Intl.RelativeTimeFormat(\'en\', { numeric: \'auto\' });',
  '                    const diffSeconds = (expiryUTC.getTime() - now.getTime()) / 1000;',
  '                    let diffMinutes = Math.round(diffSeconds / 60);',
  '                    let diffHours = Math.round(diffSeconds / 3600);',
  '                    let diffDays = Math.round(diffSeconds / 86400);',
  '                    if (Math.abs(diffSeconds) < 60) relativeTime = rtf.format(Math.round(diffSeconds), \'second\');',
  '                    else if (Math.abs(diffSeconds) < 3600) relativeTime = rtf.format(diffMinutes, \'minute\');',
  '                    else if (Math.abs(diffSeconds) < 86400) relativeTime = rtf.format(diffHours, \'hour\');',
  '                    else relativeTime = rtf.format(diffDays, \'day\');',
  '                } catch(e) { console.error("Could not format relative time:", e.message); }',
  '',
  '                return { local: localTime, tehran: tehranTime, utc: utcTime, relative: relativeTime, isExpired };',
  '            }',
  '',
  '            async function copyUUID(uuid, button) {',
  '                try {',
  '                    await navigator.clipboard.writeText(uuid);',
  '                    const originalText = button.innerHTML;',
  '                    button.innerHTML = \'✓ Copied\';',
  '                    button.classList.add(\'copied\');',
  '                    setTimeout(() => {',
  '                        button.innerHTML = originalText;',
  '                        button.classList.remove(\'copied\');',
  '                    }, 2000);',
  '                    showToast(\'UUID copied to clipboard!\', false);',
  '                } catch (error) {',
  '                    try {',
  '                        const textArea = document.createElement("textarea");',
  '                        textArea.value = uuid;',
  '                        textArea.style.position = "fixed";',
  '                        textArea.style.top = "0";',
  '                        textArea.style.left = "0";',
  '                        document.body.appendChild(textArea);',
  '                        textArea.focus();',
  '                        textArea.select();',
  '                        document.execCommand(\'copy\');',
  '                        document.body.removeChild(textArea);',
  '                        ',
  '                        const originalText = button.innerHTML;',
  '                        button.innerHTML = \'✓ Copied\';',
  '                        button.classList.add(\'copied\');',
  '                        setTimeout(() => {',
  '                            button.innerHTML = originalText;',
  '                            button.classList.remove(\'copied\');',
  '                        }, 2000);',
  '                        showToast(\'UUID copied to clipboard!\', false);',
  '                    } catch(err) {',
  '                        showToast(\'Failed to copy UUID\', true);',
  '                        console.error(\'Copy error:\', error, err);',
  '                    }',
  '                }',
  '            }',
  '',
  '            async function fetchStats() {',
  '              try {',
  '                const stats = await api.get(\'/stats\');',
  '                document.getElementById(\'total-users\').textContent = stats.total_users;',
  '                document.getElementById(\'active-users\').textContent = stats.active_users;',
  '                document.getElementById(\'expired-users\').textContent = stats.expired_users;',
  '                document.getElementById(\'total-traffic\').textContent = formatBytes(stats.total_traffic);',
  '              } catch (error) { showToast(error.message, true); }',
  '            }',
  '',
  '            function renderUsers(usersToRender = allUsers) {',
  '                userList.innerHTML = \'\';',
  '                if (usersToRender.length === 0) {',
  '                    userList.innerHTML = \'<tr><td colspan="11" style="text-align:center;">No users found.</td></tr>\';',
  '                } else {',
  '                    usersToRender.forEach(user => {',
  '                        const expiry = formatExpiryDateTime(user.expiration_date, user.expiration_time);',
  '                        const row = document.createElement(\'tr\');',
  '                        row.innerHTML = \`',
  '                            <td><input type="checkbox" class="user-checkbox checkbox" data-uuid="\${user.uuid}"></td>',
  '                            <td>',
  '                                <div class="uuid-cell">',
  '                                    <span class="uuid-text" title="\${user.uuid}">\${user.uuid.substring(0, 8)}...</span>',
  '                                    <button class="btn-copy-uuid" data-uuid="\${user.uuid}">📋 Copy</button>',
  '                                </div>',
  '                            </td>',
  '                            <td>\${new Date(user.created_at).toLocaleString()}</td>',
  '                            <td>',
  '                                <div class="time-display">',
  '                                    <span class="time-local" title="Your Local Time">\${expiry.local}</span>',
  '                                    <span class="time-utc" title="Coordinated Universal Time">\${expiry.utc}</span>',
  '                                    <span class="time-relative">\${expiry.relative}</span>',
  '                                </div>',
  '                            </td>',
  '                             <td>',
  '                                <div class="time-display">',
  '                                    <span class="time-local" title="Tehran Time (GMT+03:30)">\${expiry.tehran}</span>',
  '                                    <span class="time-utc">Asia/Tehran</span>',
  '                                </div>',
  '                            </td>',
  '                            <td><span class="status-badge \${expiry.isExpired ? \'status-expired\' : \'status-active\'}">\${expiry.isExpired ? \'Expired\' : \'Active\'}</span></td>',
  '                            <td>\${escapeHTML(user.notes || \'-\')}</td>',
  '                            <td>\${user.traffic_limit ? formatBytes(user.traffic_limit) : \'Unlimited\'}</td>',
  '                            <td>\${formatBytes(user.traffic_used || 0)}</td>',
  '                            <td>\${user.ip_limit === -1 ? \'Unlimited\' : user.ip_limit}</td>',
  '                            <td>',
  '                                <div class="actions-cell">',
  '                                    <button class="btn btn-secondary btn-edit" data-uuid="\${user.uuid}">Edit</button>',
  '                                    <button class="btn btn-danger btn-delete" data-uuid="\${user.uuid}">Delete</button>',
  '                                </div>',
  '                            </td>',
  '                        \`;',
  '                        userList.appendChild(row);',
  '                    });',
  '                }',
  '            }',
  '',
  '            async function fetchAndRenderUsers() {',
  '                try {',
  '                    allUsers = await api.get(\'/users\');',
  '                    allUsers.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));',
  '                    renderUsers();',
  '                    fetchStats();',
  '                } catch (error) { showToast(error.message, true); }',
  '            }',
  '',
  '            function startAutoRefresh() {',
  '              if (autoRefreshInterval) clearInterval(autoRefreshInterval);',
  '              autoRefreshInterval = setInterval(async () => {',
  '                try {',
  '                  await fetchAndRenderUsers();',
  '                  showToast(\'Dashboard auto-refreshed\', false);',
  '                } catch (error) {',
  '                  showToast(\'Auto-refresh failed: \' + error.message, true);',
  '                }',
  '              }, ' + CONST.AUTO_REFRESH_INTERVAL + ');',
  '            }',
  '',
  '            async function handleCreateUser(e) {',
  '                e.preventDefault();',
  '                const localDate = document.getElementById(\'expiryDate\').value;',
  '                const localTime = document.getElementById(\'expiryTime\').value;',
  '',
  '                const { utcDate, utcTime } = localToUTC(localDate, localTime);',
  '                if (!utcDate|| !utcTime) return showToast(\'Invalid date or time entered.\', true);',
  '',
  '                const dataLimit = document.getElementById(\'dataLimit\').value;',
  '                const dataUnit = document.getElementById(\'dataUnit\').value;',
  '                let trafficLimit = null;',
  '                ',
  '                if (dataUnit !== \'unlimited\' && dataLimit) {',
  '                    const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };',
  '                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);',
  '                }',
  '',
  '                const ipLimit = parseInt(document.getElementById(\'ipLimit\').value) || -1;',
  '',
  '                const userData = {',
  '                    uuid: uuidInput.value,',
  '                    exp_date: utcDate,',
  '                    exp_time: utcTime,',
  '                    notes: document.getElementById(\'notes\').value,',
  '                    traffic_limit: trafficLimit,',
  '                    ip_limit: ipLimit',
  '                };',
  '',
  '                try {',
  '                    await api.post(\'/users\', userData);',
  '                    showToast(\'User created successfully!\');',
  '                    createUserForm.reset();',
  '                    uuidInput.value = crypto.randomUUID();',
  '                    setDefaultExpiry();',
  '                    await fetchAndRenderUsers();',
  '                } catch (error) { showToast(error.message, true); }',
  '            }',
  '',
  '            async function handleDeleteUser(uuid) {',
  '                if (confirm(\'Delete user \' + uuid + \'?\')) {',
  '                    try {',
  '                        await api.delete(\'/users/\' + uuid);',
  '                        showToast(\'User deleted successfully!\');',
  '                        await fetchAndRenderUsers();',
  '                    } catch (error) { showToast(error.message, true); }',
  '                }',
  '            }',
  '',
  '            async function handleBulkDelete() {',
  '                const selected = Array.from(document.querySelectorAll(\'.user-checkbox:checked\')).map(cb => cb.dataset.uuid);',
  '                if (selected.length === 0) return showToast(\'No users selected.\', true);',
  '                if (confirm(\'Delete \' + selected.length + \' selected users?\')) {',
  '                    try {',
  '                        await api.post(\'/users/bulk-delete\', { uuids: selected });',
  '                        showToast(\'Selected users deleted successfully!\');',
  '                        await fetchAndRenderUsers();',
  '                    } catch (error) { showToast(error.message, true); }',
  '                }',
  '            }',
  '',
  '            function openEditModal(uuid) {',
  '                const user = allUsers.find(u => u.uuid === uuid);',
  '                if (!user) return showToast(\'User not found.\', true);',
  '',
  '                const { localDate, localTime } = utcToLocal(user.expiration_date, user.expiration_time);',
  '',
  '                document.getElementById(\'editUuid\').value = user.uuid;',
  '                document.getElementById(\'editExpiryDate\').value = localDate;',
  '                document.getElementById(\'editExpiryTime\').value = localTime;',
  '                document.getElementById(\'editNotes\').value = user.notes || \'\';',
  '',
  '                const editDataLimit = document.getElementById(\'editDataLimit\');',
  '                const editDataUnit = document.getElementById(\'editDataUnit\');',
  '                if (user.traffic_limit === null || user.traffic_limit === 0) {',
  '                  editDataUnit.value = \'unlimited\';',
  '                  editDataLimit.value = \'\';',
  '                } else {',
  '                  let bytes = user.traffic_limit;',
  '                  let unit = \'KB\';',
  '                  let value = bytes / 1024;',
  '                  ',
  '                  if (value >= 1024) { value = value / 1024; unit = \'MB\'; }',
  '                  if (value >= 1024) { value = value / 1024; unit = \'GB\'; }',
  '                  if (value >= 1024) { value = value / 1024; unit = \'TB\'; }',
  '                  ',
  '                  editDataLimit.value = value.toFixed(2);',
  '                  editDataUnit.value = unit;',
  '                }',
  '                const editIpLimit = document.getElementById(\'editIpLimit\');',
  '                editIpLimit.value = user.ip_limit !== null ? user.ip_limit : -1;',
  '                document.getElementById(\'resetTraffic\').checked = false;',
  '',
  '                editModal.classList.add(\'show\');',
  '            }',
  '            ',
  '            function closeEditModal() { editModal.classList.remove(\'show\'); }',
  '',
  '            async function handleEditUser(e) {',
  '                e.preventDefault();',
  '                const localDate = document.getElementById(\'editExpiryDate\').value;',
  '                const localTime = document.getElementById(\'editExpiryTime\').value;',
  '',
  '                const { utcDate, utcTime } = localToUTC(localDate, localTime);',
  '                if (!utcDate || !utcTime) return showToast(\'Invalid date or time entered.\', true);',
  '',
  '                const dataLimit = document.getElementById(\'editDataLimit\').value;',
  '                const dataUnit = document.getElementById(\'editDataUnit\').value;',
  '                let trafficLimit = null;',
  '                ',
  '                if (dataUnit !== \'unlimited\' && dataLimit) {',
  '                    const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };',
  '                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);',
  '                }',
  '',
  '                const ipLimit = parseInt(document.getElementById(\'editIpLimit\').value) || -1;',
  '',
  '                const updatedData = {',
  '                    exp_date: utcDate,',
  '                    exp_time: utcTime,',
  '                    notes: document.getElementById(\'editNotes\').value,',
  '                    traffic_limit: trafficLimit,',
  '                    ip_limit: ipLimit,',
  '                    reset_traffic: document.getElementById(\'resetTraffic\').checked',
  '                };',
  '',
  '                try {',
  '                    await api.put(\'/users/\' + document.getElementById(\'editUuid\').value, updatedData);',
  '                    showToast(\'User updated successfully!\');',
  '                    closeEditModal();',
  '                    await fetchAndRenderUsers();',
  '                } catch (error) { showToast(error.message, true); }',
  '            }',
  '',
  '            async function handleLogout() {',
  '                try {',
  '                    await api.post(\'/logout\', {});',
  '                    showToast(\'Logged out successfully!\');',
  '                    setTimeout(() => window.location.reload(), 1000);',
  '                } catch (error) { showToast(error.message, true); }',
  '            }',
  '',
  '            function setDefaultExpiry() {',
  '                const now = new Date();',
  '                now.setDate(now.getDate() + 1);',
  '',
  '                const year = now.getFullYear();',
  '                const month = pad(now.getMonth() + 1);',
  '                const day = pad(now.getDate());',
  '                const hours = pad(now.getHours());',
  '                const minutes = pad(now.getMinutes());',
  '                const seconds = pad(now.getSeconds());',
  '',
  '                document.getElementById(\'expiryDate\').value = year + \'-\' + month + \'-\' + day;',
  '                document.getElementById(\'expiryTime\').value = hours + \':\' + minutes + \':\' + seconds;',
  '            }',
  '',
  '            function filterUsers() {',
  '              const searchTerm = searchInput.value.toLowerCase();',
  '              const filtered = allUsers.filter(user => ',
  '                user.uuid.toLowerCase().includes(searchTerm) || ',
  '                (user.notes && user.notes.toLowerCase().includes(searchTerm))',
  '              );',
  '              renderUsers(filtered);',
  '            }',
  '',
  '            generateUUIDBtn.addEventListener(\'click\', () => uuidInput.value = crypto.randomUUID());',
  '            createUserForm.addEventListener(\'submit\', handleCreateUser);',
  '            editUserForm.addEventListener(\'submit\', handleEditUser);',
  '            editModal.addEventListener(\'click\', (e) => { if (e.target === editModal) closeEditModal(); });',
  '            document.getElementById(\'modalCloseBtn\').addEventListener(\'click\', closeEditModal);',
  '            document.getElementById(\'modalCancelBtn\').addEventListener(\'click\', closeEditModal);',
  '            ',
  '            userList.addEventListener(\'click\', (e) => {',
  '                const copyBtn = e.target.closest(\'.btn-copy-uuid\');',
  '                if (copyBtn) {',
  '                    const uuid = copyBtn.dataset.uuid;',
  '                    copyUUID(uuid, copyBtn);',
  '                    return;',
  '                }',
  '',
  '                const actionBtn = e.target.closest(\'button\');',
  '                if (!actionBtn) return;',
  '                const uuid = actionBtn.dataset.uuid;',
  '                if (actionBtn.classList.contains(\'btn-edit\')) openEditModal(uuid);',
  '                else if (actionBtn.classList.contains(\'btn-delete\')) handleDeleteUser(uuid);',
  '            });',
  '            ',
  '            searchInput.addEventListener(\'input\', filterUsers);',
  '            selectAll.addEventListener(\'change\', (e) => {',
  '              document.querySelectorAll(\'.user-checkbox\').forEach(cb => cb.checked = e.target.checked);',
  '            });',
  '            deleteSelected.addEventListener(\'click\', handleBulkDelete);',
  '            logoutBtn.addEventListener(\'click\', handleLogout);',
  '',
  '            setDefaultExpiry();',
  '            uuidInput.value = crypto.randomUUID();',
  '            fetchAndRenderUsers();',
  '            startAutoRefresh(); // Start auto-refresh',
  '        });',
  '    </script>',
  '</body>',
  '</html>'
].join('\n');

// ============================================================================
// USER PANEL - UNIVERSAL QR CODE WITH MULTIPLE FALLBACK METHODS (with auto-refresh enhancements)
// ============================================================================

function handleUserPanel(userID, hostName, proxyAddress, userData) {
  const subXrayUrl = `https://${hostName}/xray/${userID}`;
  const subSbUrl = `https://${hostName}/sb/${userID}`;
  
  const singleXrayConfig = buildLink({ 
    core:'xray', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main'  });
  
  const singleSingboxConfig = buildLink({ 
    core: 'sb', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main'
  });

  const clientUrls = {
    universalAndroid: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    windows: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
    macos: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
    karing: `karing://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    shadowrocket: `shadowrocket://add/sub?url=${encodeURIComponent(subXrayUrl)}&name=${encodeURIComponent(hostName)}`,
    streisand: `streisand://install-config?url=${encodeURIComponent(subXrayUrl)}`
  };

  const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
  const expirationDateTime = userData.expiration_date && userData.expiration_time 
    ? `${userData.expiration_date}T${userData.expiration_time}Z` 
    : null;

  let usagePercentage = 0;
  if (userData.traffic_limit && userData.traffic_limit > 0) {
    usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
  }

  let usagePercentageDisplay;
  if (usagePercentage > 0 && usagePercentage < 0.01) {
    usagePercentageDisplay = '< 0.01%';
  } else if (usagePercentage === 0) {
    usagePercentageDisplay = '0%';
  } else if (usagePercentage === 100) {
    usagePercentageDisplay = '100%';
  } else {
    usagePercentageDisplay = `${usagePercentage.toFixed(2)}%`;
  }

  const nonce = generateNonce();
  const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
  addSecurityHeaders(headers, nonce, {
    img: 'data: https://api.qrserver.com',
    connect: 'https://*.ipapi.co https://*.ip-api.com https://ipwho.is https://*.ipify.org https://*.my-ip.io https://ifconfig.me https://icanhazip.com https://cloudflare-dns.com https://dns.google https://api.qrserver.com https://checkip.amazonaws.com https://wtfismyip.com https://freegeoip.app'
  });
  
  let finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
  return new Response(finalHtml, { headers });
}

// ============================================================================
// VLESS PROTOCOL HANDLERS (complete, unchanged from original)
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
    return new Response('Access denied', { status: 403 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  let sessionUsage = 0;
  let userUUID = '';
  let udpStreamWriter = null;

  const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

  const deferredUsageUpdate = () => {
    if (sessionUsage > 0 && userUUID) {
      const usageToUpdate = sessionUsage;
      const uuidToUpdate = userUUID;
      
      sessionUsage = 0;
      
      ctx.waitUntil(
        updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
          .catch(err => console.error(`Deferred usage update failed for ${uuidToUpdate}: ${err.message}`))
      );
    }
  };

  const updateInterval = setInterval(deferredUsageUpdate, 10000);

  const finalCleanup = () => {
    clearInterval(updateInterval);
    deferredUsageUpdate();
  };

  webSocket.addEventListener('close', finalCleanup, { once: true });
  webSocket.addEventListener('error', finalCleanup, { once: true });

  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWrapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          sessionUsage += chunk.byteLength;

          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            user,
            hasError,
            message,
            addressType,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            ProtocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await ProcessProtocolHeader(chunk, env, ctx);

          if (hasError) {
            controller.error(new Error('Authentication failed'));
            return;
          }
          
          if (!user) {
            controller.error(new Error('Authentication failed'));
            return;
          }

          userUUID = user.uuid;

          if (isExpired(user.expiration_date, user.expiration_time)) {
            controller.error(new Error('Authentication failed'));
            return;
          }

          if (user.traffic_limit && user.traffic_limit > 0) {
            const totalUsage = (user.traffic_used || 0) + sessionUsage;
            if (totalUsage >= user.traffic_limit) {
              controller.error(new Error('Authentication failed'));
              return;
            }
          }

          // IP Limit Check
          if (user.ip_limit && user.ip_limit > -1) {
            const ipCount = await env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?").bind(userUUID).first('count');
            if (ipCount >= user.ip_limit) {
              controller.error(new Error('IP limit exceeded'));
              return;
            }
            // Update current IP
            await env.DB.prepare("INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)").bind(userUUID, clientIp).run();
          }

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => {
                sessionUsage += bytes;
              });
              udpStreamWriter = dnsPipeline.write;
              await udpStreamWriter(rawClientData);
            } else {
              controller.error(new Error('Authentication failed'));
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWrapper,
            addressType,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
            (bytes) => { sessionUsage += bytes; }
          );
        },
        close() {
          log('readableWebSocketStream closed');
          finalCleanup();
        },
        abort(err) {
          log('readableWebSocketStream aborted', err);
          finalCleanup();
        },
      }),
    )
    .catch(err => {
      console.error('Pipeline failed:', err.stack || err);
      safeCloseWebSocket(webSocket);
      finalCleanup();
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }
  
  const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
  const version = dataView.getUint8(0);

  let uuid;
  try {
    uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  } catch (e) {
    return { hasError: true, message: 'invalid UUID format' };
  }

  const userData = await getUserData(env, uuid, ctx);
  if (!userData) {
    return { hasError: true, message: 'invalid user' };
  }

  const payloadStart = 17;
  if (protocolBuffer.byteLength < payloadStart + 1) {
    return { hasError: true, message: 'invalid data length' };
  }

  const optLength = dataView.getUint8(payloadStart);
  const commandIndex = payloadStart + 1 + optLength;
  
  if (protocolBuffer.byteLength < commandIndex + 1) {
    return { hasError: true, message: 'invalid data length (command)' };
  }
  
  const command = dataView.getUint8(commandIndex);
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported` };
  }

  const portIndex = commandIndex + 1;
  if (protocolBuffer.byteLength < portIndex + 2) {
    return { hasError: true, message: 'invalid data length (port)' };
  }
  
  const portRemote = dataView.getUint16(portIndex, false);

  const addressTypeIndex = portIndex + 2;
  if (protocolBuffer.byteLength < addressTypeIndex + 1) {
    return { hasError: true, message: 'invalid data length (address type)' };
  }
  
  const addressType = dataView.getUint8(addressTypeIndex);

  let addressValue, addressLength, addressValueIndex;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = addressTypeIndex + 1;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (ipv4)' };
      }
      addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
      
    case 2:
      if (protocolBuffer.byteLength < addressTypeIndex + 2) {
        return { hasError: true, message: 'invalid data length (domain length)' };
      }
      addressLength = dataView.getUint8(addressTypeIndex + 1);
      addressValueIndex = addressTypeIndex + 2;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (domain)' };
      }
      addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
      
    case 3:
      addressLength = 16;
      addressValueIndex = addressTypeIndex + 1;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (ipv6)' };
      }
      addressValue = Array.from({ length: 8 }, (_, i) => 
        dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
      ).join(':');
      break;
      
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  const rawDataIndex = addressValueIndex + addressLength;
  if (protocolBuffer.byteLength < rawDataIndex) {
    return { hasError: true, message: 'invalid data length (raw data)' };
  }

  return {
    user: userData,
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
}

async function HandleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
  trafficCallback
) {
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

    tcpSocket.closed
      .catch(error => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) { },
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error('WebSocket is not open');
          hasIncomingData = true;
          
          if (trafficCallback) {
            trafficCallback(chunk.byteLength);
          }
          
          const dataToSend = protocolResponseHeader
            ? await new Blob([protocolResponseHeader, chunk]).arrayBuffer()
            : chunk;
          webSocket.send(dataToSend);
          protocolResponseHeader = null;
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error('Remote connection readable aborted:', reason);
        },
      }),
    );
  } catch (error) {
    console.error('RemoteSocketToWS error:', error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying');
    try {
        await retry();
    } catch(e) {
        console.error('Retry failed:', e.message);
    }
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error.message);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) break;
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              let responseChunk;
              if (isHeaderSent) {
                responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) {
                trafficCallback(responseChunk.byteLength);
              }
              webSocket.send(responseChunk);
            }
          } catch (error) {
            log('DNS query error: ' + error.message);
          }
        },
      }),
    )
    .catch(e => {
      log('DNS stream error: ' + e.message);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (chunk) => writer.write(chunk),
  };
}

function parseIPv6(ipv6) {
    const buffer = new ArrayBuffer(16);
    const view = new DataView(buffer);
    
    const parts = ipv6.split('::');
    let left = parts[0] ? parts[0].split(':') : [];
    let right = parts[1] ? parts[1].split(':') : [];
    
    if (left.length === 1 && left[0] === '') left = [];
    if (right.length === 1 && right[0] === '') right = [];
    
    const missing = 8 - (left.length + right.length);
    const expansion = [];
    if (missing > 0) {
        for (let i = 0; i < missing; i++) {
            expansion.push('0000');
        }
    }
    
    const hextets = [...left, ...expansion, ...right];
    
    for (let i = 0; i < 8; i++) {
        const val = parseInt(hextets[i] || '0', 16);
        view.setUint16(i * 2, val, false);
    }
    
    return new Uint8Array(buffer);
}

// @ts-ignore
async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  
  let socket;
  let reader;
  let writer;
  let success = false;

  try {
    socket = connect({ hostname, port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    
    const encoder = new TextEncoder();

    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read()).value;
    if (!res || res[0] !== 0x05 || res[1] === 0xff) {
      throw new Error('SOCKS5 handshake failed. Server rejected methods.');
    }

    if (res[1] === 0x02) {
      if (!username || !password) {
        throw new Error('SOCKS5 server requires credentials, but none provided.');
      }
      const authRequest = new Uint8Array([
        1,
        username.length,
        ...encoder.encode(username),
        password.length,
        ...encoder.encode(password)
      ]);
      await writer.write(authRequest);
      res = (await reader.read()).value;
      if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
        throw new Error(`SOCKS5 authentication failed (Code: ${res[1]})`);
      }
    }

    let dstAddr;
    switch (addressType) {
      case 1:
        dstAddr = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
        break;
      case 2:
        dstAddr = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
        break;
      case 3:
        const ipv6Bytes = parseIPv6(addressRemote);
        if (ipv6Bytes.length !== 16) {
          throw new Error(`Failed to parse IPv6 address: ${addressRemote}`);
        }
        dstAddr = new Uint8Array(1 + 16);
        dstAddr[0] = 4;
        dstAddr.set(ipv6Bytes, 1);
        break;
      default:
        throw new Error(`Invalid address type: ${addressType}`);
    }

    const socksRequest = new Uint8Array([
      5,
      1,
      0,
      ...dstAddr,
      portRemote >> 8,
      portRemote & 0xff
    ]);
    await writer.write(socksRequest);
    
    res = (await reader.read()).value;
    if (!res || res[1] !== 0x00) {
      throw new Error(`SOCKS5 connection failed. Server responded with code: ${res[1]}`);
    }

    log(`SOCKS5 connection to ${addressRemote}:${portRemote} established.`);
    success = true;
    return socket;

  } catch (err) {
    log(`socks5Connect Error: ${err.message}`, err);
    throw err;
  } finally {
    if (writer) writer.releaseLock();
    if (reader) reader.releaseLock();
    
    if (!success && socket) {
      try {
        socket.abort();
      } catch (e) {
        log('Error aborting SOCKS5 socket during cleanup', e.message);
      }
    }
  }
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  let hostname;
  if (hostPart.startsWith('[')) {
      const closingBracketIndex = hostPart.lastIndexOf(']');
      if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
          throw new Error('Invalid IPv6 SOCKS5 address format');
      }
      hostname = hostPart.substring(1, closingBracketIndex);
  } else {
      hostname = hostPart.substring(0, lastColonIndex);
  }

  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  let username, password;
  if (authPart) {
    [username, password] = authPart.split(':');
  }
  
  return { username, password, hostname, port };
}

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    let cfg;
    
    try {
      cfg = await Config.fromEnv(env);
    } catch (err) {
      console.error(`Configuration Error: ${err.message}`);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response(`Configuration Error: ${err.message}`, { status: 503, headers });
    }

    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP');

    const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
    
    if (url.pathname.startsWith(`/${adminPrefix}/`)) {
      return await handleAdminRequest(request, env, ctx, adminPrefix);
    }

    if (url.pathname === '/health') {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('OK', { status: 200, headers });
    }

    if (url.pathname.startsWith('/api/user/')) {
      const uuid = url.pathname.substring('/api/user/'.length);
      const headers = new Headers({ 'Content-Type': 'application/json' });
      addSecurityHeaders(headers, null, {});
      if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers });
      }
      if (!isValidUUID(uuid)) {
        return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
      }
      const userData = await getUserData(env, uuid, ctx);
      if (!userData) {
        return new Response(JSON.stringify({ error: 'Authentication failed' }), { status: 403, headers });
      }
      return new Response(JSON.stringify({
        traffic_used: userData.traffic_used || 0,
        traffic_limit: userData.traffic_limit,
        expiration_date: userData.expiration_date,
        expiration_time: userData.expiration_time
      }), { status: 200, headers });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader?.toLowerCase() === 'websocket') {
      if (!env.DB) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service not configured properly', { status: 503, headers });
      }
      
      const requestConfig = {
        userID: cfg.userID,
        proxyIP: cfg.proxyIP,
        proxyPort: cfg.proxyPort,
        socks5Address: cfg.socks5.address,
        socks5Relay: cfg.socks5.relayMode,
        enableSocks: cfg.socks5.enabled,
        parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
        scamalytics: cfg.scamalytics,
      };
      
      const wsResponse = await ProtocolOverWSHandler(request, requestConfig, env, ctx);
      
      const headers = new Headers(wsResponse.headers);
      addSecurityHeaders(headers, null, {});
      
      return new Response(wsResponse.body, { status: wsResponse.status, webSocket: wsResponse.webSocket, headers });
    }

    const handleSubscription = async (core) => {
      const rateLimitKey = `user_path_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers });
      }

      const uuid = url.pathname.substring(`/${core}/`.length);
      if (!isValidUUID(uuid)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Invalid UUID', { status: 400, headers });
      }
      
      const userData = await getUserData(env, uuid, ctx);
      if (!userData) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers });
      }
      
      if (isExpired(userData.expiration_date, userData.expiration_time)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers });
      }
      
      if (userData.traffic_limit && userData.traffic_limit > 0 && 
          (userData.traffic_used || 0) >= userData.traffic_limit) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers });
      }
      
      return await handleIpSubscription(core, uuid, url.hostname);
    };

    if (url.pathname.startsWith('/xray/')) {
      return await handleSubscription('xray');
    }
    
    if (url.pathname.startsWith('/sb/')) {
      return await handleSubscription('sb');
    }

    const path = url.pathname.slice(1);
    if (isValidUUID(path)) {
      const rateLimitKey = `user_path_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers });
      }

      const userData = await getUserData(env, path, ctx);
      if (!userData) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers });
      }
      
      return handleUserPanel(path, url.hostname, cfg.proxyAddress, userData);
    }

    if (env.ROOT_PROXY_URL) {
      try {
        let proxyUrl;
        try {
          proxyUrl = new URL(env.ROOT_PROXY_URL);
        } catch (urlError) {
          console.error(`Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Proxy configuration error: Invalid URL format', { status: 500, headers });
        }

        const targetUrl = new URL(request.url);
        targetUrl.hostname = proxyUrl.hostname;
        targetUrl.protocol = proxyUrl.protocol;
        if (proxyUrl.port) {
          targetUrl.port = proxyUrl.port;
        }
        
        const newRequest = new Request(targetUrl.toString(), {
          method: request.method,
          headers: request.headers,
          body: request.body,
          redirect: 'manual'
        });
        
        newRequest.headers.set('Host', proxyUrl.hostname);
        newRequest.headers.set('X-Forwarded-For', clientIp);
        newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', ''));
        newRequest.headers.set('X-Real-IP', clientIp);
        
        const response = await fetch(newRequest);
        const mutableHeaders = new Headers(response.headers);
        
        mutableHeaders.delete('content-security-policy-report-only');
        mutableHeaders.delete('x-frame-options');
        
        if (!mutableHeaders.has('Content-Security-Policy')) {
          mutableHeaders.set('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
        }
        if (!mutableHeaders.has('X-Frame-Options')) {
          mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
        }
        if (!mutableHeaders.has('Strict-Transport-Security')) {
          mutableHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        if (!mutableHeaders.has('X-Content-Type-Options')) {
          mutableHeaders.set('X-Content-Type-Options', 'nosniff');
        }
        if (!mutableHeaders.has('Referrer-Policy')) {
          mutableHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        }
        
        mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
        
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: mutableHeaders
        });
      } catch (e) {
        console.error(`Reverse Proxy Error: ${e.message}`, e.stack);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response(`Proxy error: ${e.message}`, { status: 502, headers });
      }
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  },
}
