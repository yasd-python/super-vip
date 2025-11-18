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

var Config = {
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
  
  fromEnv: function(env) {
    var selectedProxyIP = null;

    if (env.D1) {
      try {
        var results = env.D1.prepare("SELECT ip FROM proxy_scans WHERE is_current_best = 1 LIMIT 1").all();
        selectedProxyIP = results[0] ? results[0].ip : null;
        if (selectedProxyIP) {
          console.log("Using proxy IP from D1: " + selectedProxyIP);
        }
      } catch (e) {
        console.error("Failed to read from D1: " + e.message);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log("Using proxy IP from env.PROXYIP: " + selectedProxyIP);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log("Using proxy IP from hardcoded list: " + selectedProxyIP);
      }
    }
    
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined");
        selectedProxyIP = this.proxyIPs[0]; 
    }
    
    var proxyParts = selectedProxyIP.split(':');
    var proxyHost = proxyParts[0];
    var proxyPort = proxyParts[1] || '443';
    
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
  }
};

var CONST = {
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
  var arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains) {
  cspDomains = cspDomains || {};
  var csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    nonce ? "script-src 'nonce-" + nonce + "' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'" : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'",
    nonce ? "style-src 'nonce-" + nonce + "' 'unsafe-inline' 'unsafe-hashes'" : "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    "img-src 'self' data: https: blob: " + (cspDomains.img || '').trim(),
    "connect-src 'self' https: " + (cspDomains.connect || '').trim(),
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

  var aLen = a.length;
  var bLen = b.length;
  var result = 0;

  if (aLen !== bLen) {
    for (var i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  
  for (var i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m];
  });
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  var uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  var expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? expTime + ':00' : expTime;
  var cleanTime = expTimeSeconds.split('.')[0];
  var expDatetimeUTC = new Date(expDate + 'T' + cleanTime + 'Z');
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  var k = 1024;
  var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  var i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function kvGet(db, key, type) {
  type = type || 'text';
  var stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
  var res = stmt.first();
  
  if (!res) return null;
  
  if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
    db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
    return null;
  }
  
  if (type === 'json') {
    try {
      return JSON.parse(res.value);
    } catch (e) {
      console.error("Failed to parse JSON for key " + key + ": " + e);
      return null;
    }
  }
  
  return res.value;
}

function kvPut(db, key, value, options) {
  options = options || {};
  if (typeof value === 'object') {
    value = JSON.stringify(value);
  }
  
  var exp = options.expirationTtl 
    ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
    : null;
  
  db.prepare(
    "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
  ).bind(key, value, exp).run();
}

function kvDelete(db, key) {
  db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
}

function getUserData(env, uuid, ctx) {
  if (!isValidUUID(uuid)) return null;
  if (!env.DB) {
    console.error("D1 binding missing");
    return null;
  }
  
  var cacheKey = "user:" + uuid;
  
  var cachedData = kvGet(env.DB, cacheKey, 'json');
  if (cachedData && cachedData.uuid) return cachedData;

  var userFromDb = env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
  if (!userFromDb) return null;
  
  var cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
  
  if (ctx) {
    ctx.waitUntil(cachePromise);
  } else {
    cachePromise;
  }
  
  return userFromDb;
}

function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  
  var usageLockKey = "usage_lock:" + uuid;
  var lockAcquired = false;
  
  while (!lockAcquired) {
    var existingLock = kvGet(env.DB, usageLockKey);
    if (!existingLock) {
      kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 }); // 5s lock
      lockAcquired = true;
    } else {
      new Promise(function(resolve) { setTimeout(resolve, 100); }); // Backoff
    }
  }
  
  var usage = Math.round(bytes);
  var updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
    .bind(usage, uuid)
    .run();
  
  var deleteCachePromise = kvDelete(env.DB, "user:" + uuid);
  
  if (ctx) {
    ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
  } else {
    Promise.all([updatePromise, deleteCachePromise]);
  }
  
  if (lockAcquired) {
    kvDelete(env.DB, usageLockKey);
  }
}

function cleanupOldIps(env, ctx) {
  var cleanupPromise = env.DB.prepare(
    "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
  ).bind("-" + CONST.IP_CLEANUP_AGE_DAYS + " days").run();
  
  if (ctx) {
    ctx.waitUntil(cleanupPromise);
  } else {
    cleanupPromise;
  }
}

function isSuspiciousIP(ip, scamalyticsConfig, threshold) {
  threshold = threshold || CONST.SCAMALYTICS_THRESHOLD;
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn("⚠️  Scamalytics API credentials not configured. IP " + ip + " allowed by default (fail-open mode). Set SCAMALYTICS_USERNAME and SCAMALYTICS_API_KEY for protection.");
    return false;
  }

  var controller = new AbortController();
  var timeoutId = setTimeout(function() { controller.abort(); }, 5000);

  try {
    var url = scamalyticsConfig.baseUrl + "score?username=" + scamalyticsConfig.username + "&ip=" + ip + "&key=" + scamalyticsConfig.apiKey;
    var response = fetch(url, { signal: controller.signal });
    if (!response.ok) {
      console.warn("Scamalytics API returned " + response.status + " for " + ip + ". Allowing (fail-open).");
      return false;
    }

    var data = response.json();
    return data.score >= threshold;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// TFA (TOTP) VALIDATION
// ============================================================================

function base32ToBuffer(base32) {
  var base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var str = base32.toUpperCase().replace(/=+$/, '');
  
  var bits = 0;
  var value = 0;
  var index = 0;
  var output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (var i = 0; i < str.length; i++) {
    var char = str[i];
    var charValue = base32Chars.indexOf(char);
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

function generateHOTP(secretBuffer, counter) {
  var counterBuffer = new ArrayBuffer(8);
  var counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
  var key = crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  var hmac = crypto.subtle.sign('HMAC', key, counterBuffer);
  var hmacBuffer = new Uint8Array(hmac);
  
  var offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  var binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  var otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }
  
  var secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    console.error("Failed to decode TOTP secret:", e.message);
    return false;
  }
  
  var timeStep = 30;
  var epoch = Math.floor(Date.now() / 1000);
  var currentCounter = Math.floor(epoch / timeStep);
  
  var counters = [currentCounter, currentCounter - 1, currentCounter + 1];

  for (var i = 0; i < counters.length; i++) {
    var counter = counters[i];
    var generatedCode = generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) {
      return true;
    }
  }
  
  return false;
}

function hashSHA256(str) {
  var encoder = new TextEncoder();
  var data = encoder.encode(str);
  var hashBuffer = crypto.subtle.digest('SHA-256', data);
  var hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function checkRateLimit(db, key, limit, ttl) {
  var countStr = kvGet(db, key);
  var count = parseInt(countStr, 10) || 0;
  if (count >= limit) return true;
  kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
  return false;
}

// ============================================================================
// UUID STRINGIFY
// ============================================================================

var byteToHex = Array.from({ length: 256 }, function(_, i) { return (i + 0x100).toString(16).slice(1); });

function unsafeStringify(arr, offset) {
  offset = offset || 0;
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + 
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset) {
  offset = offset || 0;
  var uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION GENERATION
// ============================================================================

function generateRandomPath(length, query) {
  length = length || 12;
  query = query || '';
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var result = '';
  for (var i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return '/' + result + (query ? '?' + query : '');
}

var CORE_PRESETS = {
  xray: {
    tls: { path: function() { return generateRandomPath(12, 'ed=2048'); }, security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} },
    tcp: { path: function() { return generateRandomPath(12, 'ed=2048'); }, security: 'none', fp: 'chrome', extra: {} },
  },
  sb: {
    tls: { path: function() { return generateRandomPath(18); }, security: 'tls', fp: 'firefox', alpn: 'h3', extra: CONST.ED_PARAMS },
    tcp: { path: function() { return generateRandomPath(18); }, security: 'none', fp: 'firefox', extra: CONST.ED_PARAMS },
  },
};

function makeName(tag, proto) {
  return tag + "-" + proto.toUpperCase();
}

function createVlessLink(options) {
  var userID = options.userID;
  var address = options.address;
  var port = options.port;
  var host = options.host;
  var path = options.path;
  var security = options.security;
  var sni = options.sni;
  var fp = options.fp;
  var alpn = options.alpn;
  var extra = options.extra || {};
  var name = options.name;

  var params = new URLSearchParams({ type: 'ws', host: host, path: path });
  if (security) params.set('security', security);
  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);
  for (var k in extra) {
    params.set(k, extra[k]);
  }
  return "vless://" + userID + "@" + address + ":" + port + "?" + params.toString() + "#" + encodeURIComponent(name);
}

function buildLink(options) {
  var core = options.core;
  var proto = options.proto;
  var userID = options.userID;
  var hostName = options.hostName;
  var address = options.address;
  var port = options.port;
  var tag = options.tag;

  var p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID: userID, address: address, port: port, host: hostName, path: p.path(), security: p.security,
    sni: p.security === 'tls' ? hostName : undefined, fp: p.fp, alpn: p.alpn, extra: p.extra, name: makeName(tag, proto),
  });
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

async function handleIpSubscription(core, userID, hostName) {
  var mainDomains = [
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
  var httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  var httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  var links = [];
  var isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach(function(domain, i) {
    links.push(buildLink({ core: core, proto: 'tls', userID: userID, hostName: hostName, address: domain, port: pick(httpsPorts), tag: "D" + (i+1) }));
    if (!isPagesDeployment) {
      links.push(buildLink({ core: core, proto: 'tcp', userID: userID, hostName: hostName, address: domain, port: pick(httpPorts), tag: "D" + (i+1) }));
    }
  });

  try {
    var r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      var json = await r.json();
      var ips = [].concat(json.ipv4 || [], json.ipv6 || []).slice(0, 20).map(function(x) { return x.ip; });
      ips.forEach(function(ip, i) {
        var formattedAddress = ip.includes(':') ? "[" + ip + "]" : ip;
        links.push(buildLink({ core: core, proto: 'tls', userID: userID, hostName: hostName, address: formattedAddress, port: pick(httpsPorts), tag: "IP" + (i+1) }));
        if (!isPagesDeployment) {
          links.push(buildLink({ core: core, proto: 'tcp', userID: userID, hostName: hostName, address: formattedAddress, port: pick(httpPorts), tag: "IP" + (i+1) }));
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  var headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8' });
  addSecurityHeaders(headers, null, {});

  return new Response(btoa(links.join('\n')), { headers: headers });
}

// ============================================================================
// ADMIN PANEL HTML (preserved from original, with auto-refresh enhancements)
// ============================================================================

var adminLoginHTML = [
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

var adminPanelHTML = [
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
  '        <button id="logoutBtn" class="btn btn-danger" style="position: absolute; top: 20px; right: 20px;">Logout</button>',
  '        <div class="dashboard-stats">',
  '            <div class="stat-card"><div class="stat-value" id="total-users">0</div><div class="stat-label">Total Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="active-users">0</div><div class="stat-label">Active Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="expired-users">0</div><div class="stat-label">Expired Users</div></div>',
  '            <div class="stat-card"><div class="stat-value" id="total-traffic">0 KB</div><div class="stat-label">Total Traffic Used</div></div>',
  '        </div>',
  '        <div class="card">',
  '            <h2>Create User</h2>',
  '            <form id="createUserForm" class="form-grid">',
  '                <div class="form-group" style="grid-column: 1 / -1;"><label for="uuid">UUID</label><div class="input-group"><input type="text" id="uuid" required><button type="button" id="generateUUID" class="btn btn-secondary">Generate</button></div></div>',
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
  '        <div class="card" style="margin-top: 30px;">',
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
  '                <div class="form-group" style="margin-top: 16px;">',
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
  '                <div class="form-group" style="margin-top: 16px;"><label for="editNotes">Notes</label><input type="text" id="editNotes" name="notes" placeholder="Optional notes"></div>',
  '                <div class="form-group" style="margin-top: 16px;"><label for="editDataLimit">Data Limit</label><div class="input-group"><input type="number" id="editDataLimit" min="0" step="0.01"><select id="editDataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited">Unlimited</option></select></div></div>',
  '                <div class="form-group" style="margin-top: 16px;"><label for="editIpLimit">IP Limit</label><div class="input-group"><input type="number" id="editIpLimit" min="-1" step="1"><select id="editIpUnit"><option value="-1">Unlimited (-1)</option></select></div></div>',
  '                <div class="form-group" style="margin-top: 16px;"><label><input type="checkbox" id="resetTraffic" name="reset_traffic" class="checkbox" style="width: auto; margin-right: 8px;"> Reset Traffic Usage</label></div>',
  '                <div class="modal-footer">',
  '                    <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>',
  '                    <button type="submit" class="btn btn-primary">Save Changes</button>',
  '                </div>',
  '            </form>',
  '        </div>',
  '    </div>',
  '',
  '    <script nonce="CSP_NONCE_PLACEHOLDER">',
  '        document.addEventListener(\'DOMContentLoaded\', function() {',
  '            var API_BASE = \'ADMIN_API_BASE_PATH_PLACEHOLDER\';',
  '            var allUsers = [];',
  '            var userList = document.getElementById(\'userList\');',
  '            var createUserForm = document.getElementById(\'createUserForm\');',
  '            var generateUUIDBtn = document.getElementById(\'generateUUID\');',
  '            var uuidInput = document.getElementById(\'uuid\');',
  '            var toast = document.getElementById(\'toast\');',
  '            var editModal = document.getElementById(\'editModal\');',
  '            var editUserForm = document.getElementById(\'editUserForm\');',
  '            var searchInput = document.getElementById(\'searchInput\');',
  '            var selectAll = document.getElementById(\'selectAll\');',
  '            var deleteSelected = document.getElementById(\'deleteSelected\');',
  '            var logoutBtn = document.getElementById(\'logoutBtn\');',
  '            var autoRefreshInterval;',
  '',
  '            function escapeHTML(str) {',
  '              if (typeof str !== \'string\') return \'\';',
  '              return str.replace(/[&<>"\']/g, function(m) {',
  '                return {',
  '                  \'&\': \'&amp;\',',
  '                  \'<\': \'&lt;\',',
  '                  \'>\': \'&gt;\',',
  '                  \'"\' : \'&quot;\',',
  '                  "\'": \'&#39;\'',
  '                }[m];',
  '              });',
  '            }',
  '',
  '            function formatBytes(bytes) {',
  '              if (bytes === 0) return \'0 Bytes\';',
  '              var k = 1024;',
  '              var sizes = [\'Bytes\', \'KB\', \'MB\', \'GB\', \'TB\', \'PB\', \'EB\', \'ZB\', \'YB\'];',
  '              var i = Math.floor(Math.log(bytes) / Math.log(k));',
  '              return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + \' \' + sizes[i];',
  '            }',
  '',
  '            function showToast(message, isError) {',
  '                isError = isError || false;',
  '                toast.textContent = message;',
  '                toast.className = isError ? \'error\' : \'success\';',
  '                toast.classList.add(\'show\');',
  '                setTimeout(function() { toast.classList.remove(\'show\'); }, 3000);',
  '            }',
  '',
  '            function getCsrfToken() {',
  '                var cookie = document.cookie.split(\'; \').find(function(row) { return row.startsWith(\'csrf_token=\'); });',
  '                return cookie ? cookie.split(\'=\')[1] : \'\';',
  '            }',
  '',
  '            var api = {',
  '                get: function(endpoint) { return fetch(API_BASE + endpoint, { credentials: \'include\' }).then(handleResponse); },',
  '                post: function(endpoint, body) { return fetch(API_BASE + endpoint, { method: \'POST\', credentials: \'include\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse); },',
  '                put: function(endpoint, body) { return fetch(API_BASE + endpoint, { method: \'PUT\', credentials: \'include\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse); },',
  '                \'delete\': function(endpoint) { return fetch(API_BASE + endpoint, { method: \'DELETE\', credentials: \'include\', headers: {\'X-CSRF-Token\': getCsrfToken()} }).then(handleResponse); },',
  '            };',
  '',
  '            function handleResponse(response) {',
  '                if (response.status === 401) {',
  '                    showToast(\'Session expired. Please log in again.\', true);',
  '                    setTimeout(function() { window.location.reload(); }, 2000);',
  '                }',
  '                if (!response.ok) {',
  '                    return response.json().then(function(errorData) {',
  '                        throw new Error(errorData.error || \'Request failed with status \' + response.status);',
  '                    }).catch(function() {',
  '                        throw new Error(\'An unknown error occurred.\');',
  '                    });',
  '                }',
  '                return response.status === 204 ? null : response.json();',
  '            }',
  '',
  '            function pad(num) {',
  '                return num.toString().padStart(2, \'0\');',
  '            }',
  '',
  '            function localToUTC(dateStr, timeStr) {',
  '                if (!dateStr || !timeStr) return { utcDate: \'\', utcTime: \'\' };',
  '                var localDateTime = new Date(dateStr + \'T\' + timeStr);',
  '                if (isNaN(localDateTime.getTime())) return { utcDate: \'\', utcTime: \'\' };',
  '',
  '                var year = localDateTime.getUTCFullYear();',
  '                var month = pad(localDateTime.getUTCMonth() + 1);',
  '                var day = pad(localDateTime.getUTCDate());',
  '                var hours = pad(localDateTime.getUTCHours());',
  '                var minutes = pad(localDateTime.getUTCMinutes());',
  '                var seconds = pad(localDateTime.getUTCSeconds());',
  '',
  '                return {',
  '                    utcDate: year + \'-\' + month + \'-\' + day,',
  '                    utcTime: hours + \':\' + minutes + \':\' + seconds',
  '                };',
  '            }',
  '',
  '            function utcToLocal(utcDateStr, utcTimeStr) {',
  '                if (!utcDateStr || !utcTimeStr) return { localDate: \'\', localTime: \'\' };',
  '                var utcDateTime = new Date(utcDateStr + \'T\' + utcTimeStr + \'Z\');',
  '                if (isNaN(utcDateTime.getTime())) return { localDate: \'\', localTime: \'\' };',
  '',
  '                var year = utcDateTime.getFullYear();',
  '                var month = pad(utcDateTime.getMonth() + 1);',
  '                var day = pad(utcDateTime.getDate());',
  '                var hours = pad(utcDateTime.getHours());',
  '                var minutes = pad(utcDateTime.getMinutes());',
  '                var seconds = pad(utcDateTime.getSeconds());',
  '',
  '                return {',
  '                    localDate: year + \'-\' + month + \'-\' + day,',
  '                    localTime: hours + \':\' + minutes + \':\' + seconds',
  '                };',
  '            }',
  '',
  '            function addExpiryTime(dateInputId, timeInputId, amount, unit) {',
  '                var dateInput = document.getElementById(dateInputId);',
  '                var timeInput = document.getElementById(timeInputId);',
  '',
  '                var date = new Date(dateInput.value + \'T\' + (timeInput.value || \'00:00:00\'));',
  '                if (isNaN(date.getTime())) {',
  '                    date = new Date();',
  '                }',
  '',
  '                if (unit === \'hour\') date.setHours(date.getHours() + amount);',
  '                else if (unit === \'day\') date.setDate(date.getDate() + amount);',
  '                else if (unit === \'month\') date.setMonth(date.getMonth() + amount);',
  '',
  '                var year = date.getFullYear();',
  '                var month = pad(date.getMonth() + 1);',
  '                var day = pad(date.getDate());',
  '                var hours = pad(date.getHours());',
  '                var minutes = pad(date.getMinutes());',
  '                var seconds = pad(date.getSeconds());',
  '',
  '                dateInput.value = year + \'-\' + month + \'-\' + day;',
  '                timeInput.value = hours + \':\' + minutes + \':\' + seconds;',
  '            }',
  '',
  '            document.body.addEventListener(\'click\', function(e) {',
  '                var target = e.target.closest(\'.time-quick-set-group button\');',
  '                if (!target) return;',
  '                var group = target.closest(\'.time-quick-set-group\');',
  '                addExpiryTime(',
  '                    group.dataset.targetDate,',
  '                    group.dataset.targetTime,',
  '                    parseInt(target.dataset.amount, 10),',
  '                    target.dataset.unit',
  '                );',
  '            });',
  '',
  '            function formatExpiryDateTime(expDateStr, expTimeStr) {',
  '                var expiryUTC = new Date(expDateStr + \'T\' + expTimeStr + \'Z\');',
  '                if (isNaN(expiryUTC.getTime())) return { local: \'Invalid Date\', utc: \'\', relative: \'\', tehran: \'\', isExpired: true };',
  '',
  '                var now = new Date();',
  '                var isExpired = expiryUTC < now;',
  '',
  '                var commonOptions = {',
  '                    year: \'numeric\', month: \'2-digit\', day: \'2-digit\',',
  '                    hour: \'2-digit\', minute: \'2-digit\', second: \'2-digit\', hour12: false, timeZoneName: \'short\'',
  '                };',
  '',
  '                var localTime = expiryUTC.toLocaleString(undefined, commonOptions);',
  '                var tehranTime = \'N/A\';',
  '                try {',
  '                     tehranTime = expiryUTC.toLocaleString(\'en-US\', Object.assign({}, commonOptions, { timeZone: \'Asia/Tehran\' }));',
  '                } catch(e) { console.error("Could not format Tehran time:", e); }',
  '                var utcTime = expiryUTC.toISOString().replace(\'T\', \' \').substring(0, 19) + \' UTC\';',
  '',
  '                var relativeTime = \'\';',
  '                try {',
  '                    var rtf = new Intl.RelativeTimeFormat(\'en\', { numeric: \'auto\' });',
  '                    var diffSeconds = (expiryUTC.getTime() - now.getTime()) / 1000;',
  '                    var diffMinutes = Math.round(diffSeconds / 60);',
  '                    var diffHours = Math.round(diffSeconds / 3600);',
  '                    var diffDays = Math.round(diffSeconds / 86400);',
  '                    if (Math.abs(diffSeconds) < 60) relativeTime = rtf.format(Math.round(diffSeconds), \'second\');',
  '                    else if (Math.abs(diffSeconds) < 3600) relativeTime = rtf.format(diffMinutes, \'minute\');',
  '                    else if (Math.abs(diffSeconds) < 86400) relativeTime = rtf.format(diffHours, \'hour\');',
  '                    else relativeTime = rtf.format(diffDays, \'day\');',
  '                } catch(e) { console.error("Could not format relative time:", e); }',
  '',
  '                return { local: localTime, tehran: tehranTime, utc: utcTime, relative: relativeTime, isExpired: isExpired };',
  '            }',
  '',
  '            function copyUUID(uuid, button) {',
  '                navigator.clipboard.writeText(uuid).then(function() {',
  '                    var originalText = button.innerHTML;',
  '                    button.innerHTML = \'✓ Copied\';',
  '                    button.classList.add(\'copied\');',
  '                    setTimeout(function() {',
  '                        button.innerHTML = originalText;',
  '                        button.classList.remove(\'copied\');',
  '                    }, 2000);',
  '                    showToast(\'UUID copied to clipboard!\', false);',
  '                }).catch(function(error) {',
  '                    var textArea = document.createElement("textarea");',
  '                    textArea.value = uuid;',
  '                    textArea.style.position = "fixed";',
  '                    textArea.style.top = "0";',
  '                    textArea.style.left = "0";',
  '                    document.body.appendChild(textArea);',
  '                    textArea.focus();',
  '                    textArea.select();',
  '                    try {',
  '                        document.execCommand(\'copy\');',
  '                        var originalText = button.innerHTML;',
  '                        button.innerHTML = \'✓ Copied\';',
  '                        button.classList.add(\'copied\');',
  '                        setTimeout(function() {',
  '                            button.innerHTML = originalText;',
  '                            button.classList.remove(\'copied\');',
  '                        }, 2000);',
  '                        showToast(\'UUID copied to clipboard!\', false);',
  '                    } catch(err) {',
  '                        showToast(\'Failed to copy UUID\', true);',
  '                        console.error(\'Copy error:\', error, err);',
  '                    }',
  '                    document.body.removeChild(textArea);',
  '                });',
  '            }',
  '',
  '            function fetchStats() {',
  '              api.get(\'/stats\').then(function(stats) {',
  '                document.getElementById(\'total-users\').textContent = stats.total_users;',
  '                document.getElementById(\'active-users\').textContent = stats.active_users;',
  '                document.getElementById(\'expired-users\').textContent = stats.expired_users;',
  '                document.getElementById(\'total-traffic\').textContent = formatBytes(stats.total_traffic);',
  '              }).catch(function(error) { showToast(error.message, true); });',
  '            }',
  '',
  '            function renderUsers(usersToRender) {',
  '                usersToRender = usersToRender || allUsers;',
  '                userList.innerHTML = \'\';',
  '                if (usersToRender.length === 0) {',
  '                    userList.innerHTML = \'<tr><td colspan="11" style="text-align:center;">No users found.</td></tr>\';',
  '                } else {',
  '                    usersToRender.forEach(function(user) {',
  '                        var expiry = formatExpiryDateTime(user.expiration_date, user.expiration_time);',
  '                        var row = document.createElement(\'tr\');',
  '                        row.innerHTML = \'',
  '                            <td><input type="checkbox" class="user-checkbox checkbox" data-uuid="\' + user.uuid + \'></td>',
  '                            <td>',
  '                                <div class="uuid-cell">',
  '                                    <span class="uuid-text" title="\' + user.uuid + \'">\' + user.uuid.substring(0, 8) + \'...</span>',
  '                                    <button class="btn-copy-uuid" data-uuid="\' + user.uuid + \'">📋 Copy</button>',
  '                                </div>',
  '                            </td>',
  '                            <td>\' + new Date(user.created_at).toLocaleString() + \'</td>',
  '                            <td>',
  '                                <div class="time-display">',
  '                                    <span class="time-local" title="Your Local Time">\' + expiry.local + \'</span>',
  '                                    <span class="time-utc" title="Coordinated Universal Time">\' + expiry.utc + \'</span>',
  '                                    <span class="time-relative">\' + expiry.relative + \'</span>',
  '                                </div>',
  '                            </td>',
  '                             <td>',
  '                                <div class="time-display">',
  '                                    <span class="time-local" title="Tehran Time (GMT+03:30)">\' + expiry.tehran + \'</span>',
  '                                    <span class="time-utc">Asia/Tehran</span>',
  '                                </div>',
  '                            </td>',
  '                            <td><span class="status-badge \' + (expiry.isExpired ? \'status-expired\' : \'status-active\') + \'">\' + (expiry.isExpired ? \'Expired\' : \'Active\') + \'</span></td>',
  '                            <td>\' + escapeHTML(user.notes || \'-\') + \'</td>',
  '                            <td>\' + (user.traffic_limit ? formatBytes(user.traffic_limit) : \'Unlimited\') + \'</td>',
  '                            <td>\' + formatBytes(user.traffic_used || 0) + \'</td>',
  '                            <td>\' + (user.ip_limit === -1 ? \'Unlimited\' : user.ip_limit) + \'</td>',
  '                            <td>',
  '                                <div class="actions-cell">',
  '                                    <button class="btn btn-secondary btn-edit" data-uuid="\' + user.uuid + \'">Edit</button>',
  '                                    <button class="btn btn-danger btn-delete" data-uuid="\' + user.uuid + \'">Delete</button>',
  '                                </div>',
  '                            </td>',
  '                        \';',
  '                        userList.appendChild(row);',
  '                    });',
  '                }',
  '            }',
  '',
  '            function fetchAndRenderUsers() {',
  '                api.get(\'/users\').then(function(users) {',
  '                    allUsers = users;',
  '                    allUsers.sort(function(a, b) { return new Date(b.created_at) - new Date(a.created_at); });',
  '                    renderUsers();',
  '                    fetchStats();',
  '                }).catch(function(error) { showToast(error.message, true); });',
  '            }',
  '',
  '            function startAutoRefresh() {',
  '              if (autoRefreshInterval) clearInterval(autoRefreshInterval);',
  '              autoRefreshInterval = setInterval(function() {',
  '                fetchAndRenderUsers().then(function() {',
  '                  showToast(\'Dashboard auto-refreshed\', false);',
  '                }).catch(function(error) {',
  '                  showToast(\'Auto-refresh failed: \' + error.message, true);',
  '                });',
  '              }, ' + CONST.AUTO_REFRESH_INTERVAL + ');',
  '            }',
  '',
  '            function handleCreateUser(e) {',
  '                e.preventDefault();',
  '                var localDate = document.getElementById(\'expiryDate\').value;',
  '                var localTime = document.getElementById(\'expiryTime\').value;',
  '',
  '                var utc = localToUTC(localDate, localTime);',
  '                var utcDate = utc.utcDate;',
  '                var utcTime = utc.utcTime;',
  '                if (!utcDate || !utcTime) return showToast(\'Invalid date or time entered.\', true);',
  '',
  '                var dataLimit = document.getElementById(\'dataLimit\').value;',
  '                var dataUnit = document.getElementById(\'dataUnit\').value;',
  '                var trafficLimit = null;',
  '                ',
  '                if (dataUnit !== \'unlimited\' && dataLimit) {',
  '                    var multipliers = { KB: 1024, MB: 1024*1024, GB: 1024*1024*1024, TB: 1024*1024*1024*1024 };',
  '                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);',
  '                }',
  '',
  '                var ipLimit = parseInt(document.getElementById(\'ipLimit\').value, 10) || -1;',
  '',
  '                var userData = {',
  '                    uuid: uuidInput.value,',
  '                    exp_date: utcDate,',
  '                    exp_time: utcTime,',
  '                    notes: document.getElementById(\'notes\').value,',
  '                    traffic_limit: trafficLimit,',
  '                    ip_limit: ipLimit',
  '                };',
  '',
  '                api.post(\'/users\', userData).then(function() {',
  '                    showToast(\'User created successfully!\');',
  '                    createUserForm.reset();',
  '                    uuidInput.value = crypto.randomUUID();',
  '                    setDefaultExpiry();',
  '                    fetchAndRenderUsers();',
  '                }).catch(function(error) { showToast(error.message, true); });',
  '            }',
  '',
  '            function handleDeleteUser(uuid) {',
  '                if (confirm(\'Delete user \' + uuid + \'?\')) {',
  '                    api[\'delete\'](\'/users/\' + uuid).then(function() {',
  '                        showToast(\'User deleted successfully!\');',
  '                        fetchAndRenderUsers();',
  '                    }).catch(function(error) { showToast(error.message, true); });',
  '                }',
  '            }',
  '',
  '            function handleBulkDelete() {',
  '                var selected = Array.from(document.querySelectorAll(\'.user-checkbox:checked\')).map(function(cb) { return cb.dataset.uuid; });',
  '                if (selected.length === 0) return showToast(\'No users selected.\', true);',
  '                if (confirm(\'Delete \' + selected.length + \' selected users?\')) {',
  '                    api.post(\'/users/bulk-delete\', { uuids: selected }).then(function() {',
  '                        showToast(\'Selected users deleted successfully!\');',
  '                        fetchAndRenderUsers();',
  '                    }).catch(function(error) { showToast(error.message, true); });',
  '                }',
  '            }',
  '',
  '            function openEditModal(uuid) {',
  '                var user = allUsers.find(function(u) { return u.uuid === uuid; });',
  '                if (!user) return showToast(\'User not found.\', true);',
  '',
  '                var local = utcToLocal(user.expiration_date, user.expiration_time);',
  '                var localDate = local.localDate;',
  '                var localTime = local.localTime;',
  '',
  '                document.getElementById(\'editUuid\').value = user.uuid;',
  '                document.getElementById(\'editExpiryDate\').value = localDate;',
  '                document.getElementById(\'editExpiryTime\').value = localTime;',
  '                document.getElementById(\'editNotes\').value = user.notes || \'\';',
  '',
  '                var editDataLimit = document.getElementById(\'editDataLimit\');',
  '                var editDataUnit = document.getElementById(\'editDataUnit\');',
  '                if (user.traffic_limit === null || user.traffic_limit === 0) {',
  '                  editDataUnit.value = \'unlimited\';',
  '                  editDataLimit.value = \'\';',
  '                } else {',
  '                  var bytes = user.traffic_limit;',
  '                  var unit = \'KB\';',
  '                  var value = bytes / 1024;',
  '                  ',
  '                  if (value >= 1024) { value = value / 1024; unit = \'MB\'; }',
  '                  if (value >= 1024) { value = value / 1024; unit = \'GB\'; }',
  '                  if (value >= 1024) { value = value / 1024; unit = \'TB\'; }',
  '                  ',
  '                  editDataLimit.value = value.toFixed(2);',
  '                  editDataUnit.value = unit;',
  '                }',
  '                var editIpLimit = document.getElementById(\'editIpLimit\');',
  '                editIpLimit.value = user.ip_limit !== null ? user.ip_limit : -1;',
  '                document.getElementById(\'resetTraffic\').checked = false;',
  '',
  '                editModal.classList.add(\'show\');',
  '            }',
  '',
  '            function closeEditModal() { editModal.classList.remove(\'show\'); }',
  '',
  '            function handleEditUser(e) {',
  '                e.preventDefault();',
  '                var localDate = document.getElementById(\'editExpiryDate\').value;',
  '                var localTime = document.getElementById(\'editExpiryTime\').value;',
  '',
  '                var utc = localToUTC(localDate, localTime);',
  '                var utcDate = utc.utcDate;',
  '                var utcTime = utc.utcTime;',
  '                if (!utcDate || !utcTime) return showToast(\'Invalid date or time entered.\', true);',
  '',
  '                var dataLimit = document.getElementById(\'editDataLimit\').value;',
  '                var dataUnit = document.getElementById(\'editDataUnit\').value;',
  '                var trafficLimit = null;',
  '                ',
  '                if (dataUnit !== \'unlimited\' && dataLimit) {',
  '                    var multipliers = { KB: 1024, MB: 1024*1024, GB: 1024*1024*1024, TB: 1024*1024*1024*1024 };',
  '                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);',
  '                }',
  '',
  '                var ipLimit = parseInt(document.getElementById(\'editIpLimit\').value, 10) || -1;',
  '',
  '                var updatedData = {',
  '                    exp_date: utcDate,',
  '                    exp_time: utcTime,',
  '                    notes: document.getElementById(\'editNotes\').value,',
  '                    traffic_limit: trafficLimit,',
  '                    ip_limit: ipLimit,',
  '                    reset_traffic: document.getElementById(\'resetTraffic\').checked',
  '                };',
  '',
  '                api.put(\'/users/\' + document.getElementById(\'editUuid\').value, updatedData).then(function() {',
  '                    showToast(\'User updated successfully!\');',
  '                    closeEditModal();',
  '                    fetchAndRenderUsers();',
  '                }).catch(function(error) { showToast(error.message, true); });',
  '            }',
  '',
  '            function handleLogout() {',
  '                api.post(\'/logout\', {}).then(function() {',
  '                    showToast(\'Logged out successfully!\');',
  '                    setTimeout(function() { window.location.reload(); }, 1000);',
  '                }).catch(function(error) { showToast(error.message, true); });',
  '            }',
  '',
  '            function setDefaultExpiry() {',
  '                var now = new Date();',
  '                now.setDate(now.getDate() + 1);',
  '',
  '                var year = now.getFullYear();',
  '                var month = pad(now.getMonth() + 1);',
  '                var day = pad(now.getDate());',
  '                var hours = pad(now.getHours());',
  '                var minutes = pad(now.getMinutes());',
  '                var seconds = pad(now.getSeconds());',
  '',
  '                document.getElementById(\'expiryDate\').value = year + \'-\' + month + \'-\' + day;',
  '                document.getElementById(\'expiryTime\').value = hours + \':\' + minutes + \':\' + seconds;',
  '            }',
  '',
  '            function filterUsers() {',
  '              var searchTerm = searchInput.value.toLowerCase();',
  '              var filtered = allUsers.filter(function(user) { ',
  '                return user.uuid.toLowerCase().includes(searchTerm) || ',
  '                       (user.notes && user.notes.toLowerCase().includes(searchTerm));',
  '              });',
  '              renderUsers(filtered);',
  '            }',
  '',
  '            generateUUIDBtn.addEventListener(\'click\', function() { uuidInput.value = crypto.randomUUID(); });',
  '            createUserForm.addEventListener(\'submit\', handleCreateUser);',
  '            editUserForm.addEventListener(\'submit\', handleEditUser);',
  '            editModal.addEventListener(\'click\', function(e) { if (e.target === editModal) closeEditModal(); });',
  '            document.getElementById(\'modalCloseBtn\').addEventListener(\'click\', closeEditModal);',
  '            document.getElementById(\'modalCancelBtn\').addEventListener(\'click\', closeEditModal);',
  '            ',
  '            userList.addEventListener(\'click\', function(e) {',
  '                var copyBtn = e.target.closest(\'.btn-copy-uuid\');',
  '                if (copyBtn) {',
  '                    var uuid = copyBtn.dataset.uuid;',
  '                    copyUUID(uuid, copyBtn);',
  '                    return;',
  '                }',
  '',
  '                var actionBtn = e.target.closest(\'button\');',
  '                if (!actionBtn) return;',
  '                var uuid = actionBtn.dataset.uuid;',
  '                if (actionBtn.classList.contains(\'btn-edit\')) openEditModal(uuid);',
  '                else if (actionBtn.classList.contains(\'btn-delete\')) handleDeleteUser(uuid);',
  '            });',
  '            ',
  '            searchInput.addEventListener(\'input\', filterUsers);',
  '            selectAll.addEventListener(\'change\', function(e) {',
  '              var checkboxes = document.querySelectorAll(\'.user-checkbox\');',
  '              for (var i = 0; i < checkboxes.length; i++) { checkboxes[i].checked = e.target.checked; }',
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
// ADMIN API HANDLERS
// ============================================================================

function isAdmin(request, env) {
  var cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  var tokenMatch = cookieHeader.match(/auth_token=([^;]+)/);
  var token = tokenMatch ? tokenMatch[1] : null;
  if (!token) return false;

  var hashedToken = hashSHA256(token);
  var storedHashedToken = kvGet(env.DB, 'admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  var url = new URL(request.url);
  var jsonHeader = { 'Content-Type': 'application/json' };
  var htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
  var clientIp = request.headers.get('CF-Connecting-IP');

  if (!env.ADMIN_KEY) {
    addSecurityHeaders(htmlHeaders, null, {});
    return new Response('Admin panel is not configured.', { status: 503, headers: htmlHeaders });
  }

  if (env.ADMIN_IP_WHITELIST) {
    var allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(function(ip) { return ip.trim(); });
    if (allowedIps.indexOf(clientIp) === -1) {
      console.warn("Admin access denied for IP: " + clientIp + " (Not in whitelist)");
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  } else {
    var scamalyticsConfig = {
      username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
      apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
      baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
    };
    if (isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      console.warn("Admin access denied for suspicious IP: " + clientIp);
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  }

  if (env.ADMIN_HEADER_KEY) {
    var headerValue = request.headers.get('X-Admin-Auth');
    if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  }

  var adminBasePath = "/" + adminPrefix + "/" + env.ADMIN_KEY;

  if (!url.pathname.startsWith(adminBasePath)) {
    var headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers: headers });
  }

  var adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

  if (adminSubPath.startsWith('/api/')) {
    if (!isAdmin(request, env)) {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: headers });
    }

    // Added rate limiting for API endpoints
    var apiRateKey = "admin_api_rate:" + clientIp;
    if (checkRateLimit(env.DB, apiRateKey, 100, 60)) { // 100 req/min
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'API rate limit exceeded' }), { status: 429, headers: headers });
    }

    if (request.method !== 'GET') {
      var origin = request.headers.get('Origin');
      var secFetch = request.headers.get('Sec-Fetch-Site');

      if (!origin || new URL(origin).hostname !== url.hostname || secFetch !== 'same-origin') {
        var headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Invalid Origin/Request' }), { status: 403, headers: headers });
      }

      var csrfToken = request.headers.get('X-CSRF-Token');
      var cookieCsrfMatch = request.headers.get('Cookie') ? request.headers.get('Cookie').match(/csrf_token=([^;]+)/) : null;
      var cookieCsrf = cookieCsrfMatch ? cookieCsrfMatch[1] : null;
      if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
        var headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers: headers });
      }
    }
    
    if (adminSubPath === '/api/stats' && request.method === 'GET') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var totalUsers = env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
      var expiredQuery = env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')").first();
      var expiredUsers = expiredQuery ? expiredQuery.count : 0;
      var activeUsers = totalUsers - expiredUsers;
      var totalTrafficQuery = env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
      var totalTraffic = totalTrafficQuery ? totalTraffic.sum : 0;
      return new Response(JSON.stringify({ 
        total_users: totalUsers, 
        active_users: activeUsers, 
        expired_users: expiredUsers, 
        total_traffic: totalTraffic 
      }), { status: 200, headers: headers });
    }

    if (adminSubPath === '/api/users' && request.method === 'GET') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var results = env.DB.prepare("SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC").all().results;
      return new Response(JSON.stringify(results || []), { status: 200, headers: headers });
    }

    if (adminSubPath === '/api/users' && request.method === 'POST') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var body = await request.json();
      var uuid = body.uuid;
      var expDate = body.exp_date;
      var expTime = body.exp_time;
      var notes = body.notes;
      var traffic_limit = body.traffic_limit;
      var ip_limit = body.ip_limit;

      if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
        throw new Error('Invalid or missing fields. Use UUID, YYYY-MM-DD, and HH:MM:SS.');
      }

      env.DB.prepare("INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)")
        .bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run();
      
      ctx.waitUntil(kvPut(env.DB, "user:" + uuid, { 
        uuid: uuid,
        expiration_date: expDate, 
        expiration_time: expTime, 
        notes: notes || null,
        traffic_limit: traffic_limit, 
        ip_limit: ip_limit || -1,
        traffic_used: 0 
      }, { expirationTtl: 3600 }));

      return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 201, headers: headers });
    }

    if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var body = await request.json();
      var uuids = body.uuids;
      if (!Array.isArray(uuids) || uuids.length === 0) {
        throw new Error('Invalid request body: Expected an array of UUIDs.');
      }

      var deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
      var stmts = uuids.map(function(uuid) { return deleteUserStmt.bind(uuid); });
      env.DB.batch(stmts);

      ctx.waitUntil(Promise.all(uuids.map(function(uuid) { return kvDelete(env.DB, "user:" + uuid); })));

      return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers: headers });
    }

    var userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);

    if (userRouteMatch && request.method === 'PUT') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var uuid = userRouteMatch[1];
      var body = await request.json();
      var expDate = body.exp_date;
      var expTime = body.exp_time;
      var notes = body.notes;
      var traffic_limit = body.traffic_limit;
      var ip_limit = body.ip_limit;
      var reset_traffic = body.reset_traffic;
      if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
        throw new Error('Invalid date/time fields. Use YYYY-MM-DD and HH:MM:SS.');
      }

      var query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?, ip_limit = ?";
      var binds = [expDate, expTime, notes || null, traffic_limit, ip_limit || -1];
      
      if (reset_traffic) {
        query += ", traffic_used = 0";
      }
      
      query += " WHERE uuid = ?";
      binds.push(uuid);

      env.DB.prepare(query).bind.apply(null, binds).run();
      
      ctx.waitUntil(kvDelete(env.DB, "user:" + uuid));

      return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 200, headers: headers });
    }

    if (userRouteMatch && request.method === 'DELETE') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      var uuid = userRouteMatch[1];
      env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
      ctx.waitUntil(kvDelete(env.DB, "user:" + uuid));
      return new Response(JSON.stringify({ success: true, uuid: uuid }), { status: 200, headers: headers });
    }

    if (adminSubPath === '/api/logout' && request.method === 'POST') {
      var headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      kvDelete(env.DB, 'admin_session_token_hash');
      var setCookie = [
        'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict',
        'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict'
      ];
      headers.append('Set-Cookie', setCookie[0]);
      headers.append('Set-Cookie', setCookie[1]);
      return new Response(JSON.stringify({ success: true }), { status: 200, headers: headers });
    }

    var headers = new Headers(jsonHeader);
    addSecurityHeaders(headers, null, {});
    return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers: headers });
  }

  if (adminSubPath === '/') {
    
    if (request.method === 'POST') {
      var rateLimitKey = "login_fail_ip:" + clientIp;
      
      var failCountStr = kvGet(env.DB, rateLimitKey);
      var failCount = parseInt(failCountStr, 10) || 0;
        
      if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Too many failed login attempts. Please try again later.', { status: 429, headers: htmlHeaders });
      }
        
      var formData = await request.formData();
        
      if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
        if (env.ADMIN_TOTP_SECRET) {
          var totpCode = formData.get('totp');
          if (!validateTOTP(env.ADMIN_TOTP_SECRET, totpCode)) {
            var nonce = generateNonce();
            addSecurityHeaders(htmlHeaders, nonce, {});
            var html = adminLoginHTML.replace('</form>', "</form><p class=\"error\">Invalid TOTP code. Attempt " + (failCount + 1) + " of " + CONST.ADMIN_LOGIN_FAIL_LIMIT + ".</p>");
            html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
            html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', "action=\"" + adminBasePath + "\"");
            return new Response(html, { status: 401, headers: htmlHeaders });
          }
        }
        var token = crypto.randomUUID();
        var csrfToken = crypto.randomUUID();
        var hashedToken = hashSHA256(token);
        ctx.waitUntil(Promise.all([
          kvPut(env.DB, 'admin_session_token_hash', hashedToken, { expirationTtl: 86400 }),
          kvDelete(env.DB, rateLimitKey)
        ]));
          
        var headers = new Headers({
          'Location': adminBasePath,
        });
        headers.append('Set-Cookie', "auth_token=" + token + "; HttpOnly; Secure; Path=" + adminBasePath + "; Max-Age=86400; SameSite=Strict");
        headers.append('Set-Cookie', "csrf_token=" + csrfToken + "; Secure; Path=" + adminBasePath + "; Max-Age=86400; SameSite=Strict");

        addSecurityHeaders(headers, null, {});
          
        return new Response(null, { status: 302, headers: headers });
        
      } else {
        ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
          
        var nonce = generateNonce();
        addSecurityHeaders(htmlHeaders, nonce, {});
        var html = adminLoginHTML.replace('</form>', "</form><p class=\"error\">Invalid password. Attempt " + (failCount + 1) + " of " + CONST.ADMIN_LOGIN_FAIL_LIMIT + ".</p>");
        html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
        html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', "action=\"" + adminBasePath + "\"");
        return new Response(html, { status: 401, headers: htmlHeaders });
      }
    }

    if (request.method === 'GET') {
      var nonce = generateNonce();
      addSecurityHeaders(htmlHeaders, nonce, {});
      
      var html;
      if (isAdmin(request, env)) {
        html = adminPanelHTML;
        html = html.replace("'ADMIN_API_BASE_PATH_PLACEHOLDER'", "'" + adminBasePath + "/api'");
      } else {
        html = adminLoginHTML;
        html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', "action=\"" + adminBasePath + "\"");
      }
      
      html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
      return new Response(html, { headers: htmlHeaders });
    }

    var headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Method Not Allowed', { status: 405, headers: headers });
  }

  var headers = new Headers();
  addSecurityHeaders(headers, null, {});
  return new Response('Not found', { status: 404, headers: headers });
}

// ============================================================================
// USER PANEL - UNIVERSAL QR CODE WITH MULTIPLE FALLBACK METHODS (with auto-refresh enhancements)
// ============================================================================

function resolveProxyIP(proxyHost) {
  var ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  var ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;

  if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
    return proxyHost;
  }

  var dnsAPIs = [
    { url: "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(proxyHost) + "&type=A", parse: function(data) { return data.Answer ? data.Answer.find(function(a) { return a.type === 1; }).data : null; } },
    { url: "https://dns.google/resolve?name=" + encodeURIComponent(proxyHost) + "&type=A", parse: function(data) { return data.Answer ? data.Answer.find(function(a) { return a.type === 1; }).data : null; } },
    { url: "https://1.1.1.1/dns-query?name=" + encodeURIComponent(proxyHost) + "&type=A", parse: function(data) { return data.Answer ? data.Answer.find(function(a) { return a.type === 1; }).data : null; } }
  ];

  for (var i = 0; i < dnsAPIs.length; i++) {
    var api = dnsAPIs[i];
    try {
      var response = fetch(api.url, { headers: { 'accept': 'application/dns-json' } });
      if (response.ok) {
        var data = response.json();
        var ip = api.parse(data);
        if (ip && ipv4Regex.test(ip)) return ip;
      }
    } catch (e) {
      // Silent fail
    }
  }
  return proxyHost; // Fallback to host if resolution fails
}

function getGeo(ip) {
  var geoAPIs = [
    { url: "https://ipapi.co/" + ip + "/json/", parse: function(data) { return { city: data.city || '', country: data.country_name || '', isp: data.org || '' }; } },
    { url: "https://ip-api.com/json/" + ip + "?fields=status,message,city,country,isp", parse: function(data) { return data.status !== 'fail' ? { city: data.city || '', country: data.country || '', isp: data.isp || '' } : null; } },
    { url: "https://ipwho.is/" + ip, parse: function(data) { return data.success ? { city: data.city || '', country: data.country || '', isp: data.connection ? data.connection.isp : '' } : null; } },
    { url: "https://freegeoip.app/json/" + ip, parse: function(data) { return { city: data.city || '', country: data.country_name || '', isp: '' }; } },
    { url: "https://ipapi.is/" + ip + ".json", parse: function(data) { return { city: data.location ? data.location.city : '', country: data.location ? data.location.country : '', isp: data.asn ? data.asn.org : '' }; } },
    { url: "https://freeipapi.com/api/json/" + ip, parse: function(data) { return { city: data.cityName || '', country: data.countryName || '', isp: '' }; } }
  ];

  for (var i = 0; i < geoAPIs.length; i++) {
    var api = geoAPIs[i];
    try {
      var response = fetch(api.url);
      if (response.ok) {
        var data = response.json();
        var geo = api.parse(data);
        if (geo && (geo.city || geo.country)) return geo;
      }
    } catch (e) {
      // Silent fail
    }
  }
  return null;
}

function handleUserPanel(userID, hostName, proxyAddress, userData) {
  var subXrayUrl = "https://" + hostName + "/xray/" + userID;
  var subSbUrl = "https://" + hostName + "/sb/" + userID;
  
  var singleXrayConfig = buildLink({ 
    core: 'xray', proto: 'tls', userID: userID, hostName: hostName, address: hostName, port: 443, tag: 'Main'  });
  
  var singleSingboxConfig = buildLink({ 
    core: 'sb', proto: 'tls', userID: userID, hostName: hostName, address: hostName, port: 443, tag: 'Main'
  });

  var clientUrls = {
    universalAndroid: "v2rayng://install-config?url=" + encodeURIComponent(subXrayUrl),
    windows: "clash://install-config?url=" + encodeURIComponent(subSbUrl),
    macos: "clash://install-config?url=" + encodeURIComponent(subSbUrl),
    karing: "karing://install-config?url=" + encodeURIComponent(subXrayUrl),
    shadowrocket: "shadowrocket://add/sub?url=" + encodeURIComponent(subXrayUrl) + "&name=" + encodeURIComponent(hostName),
    streisand: "streisand://install-config?url=" + encodeURIComponent(subXrayUrl)
  };

  var isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
  var expirationDateTime = userData.expiration_date && userData.expiration_time 
    ? userData.expiration_date + "T" + userData.expiration_time + "Z" 
    : null;

  var usagePercentage = 0;
  if (userData.traffic_limit && userData.traffic_limit > 0) {
    usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
  }

  var usagePercentageDisplay;
  if (usagePercentage > 0 && usagePercentage < 0.01) {
    usagePercentageDisplay = '< 0.01%';
  } else if (usagePercentage === 0) {
    usagePercentageDisplay = '0%';
  } else if (usagePercentage === 100) {
    usagePercentageDisplay = '100%';
  } else {
    usagePercentageDisplay = usagePercentage.toFixed(2) + '%';
  }

  // Server-side geo detection
  var proxyHost = proxyAddress.split(':')[0];
  var proxyIP = resolveProxyIP(proxyHost);
  var clientIp = request.headers.get('CF-Connecting-IP');
  var clientGeo = getGeo(clientIp);
  var proxyGeo = getGeo(proxyIP);

  var clientLocation = clientGeo ? [clientGeo.city, clientGeo.country].filter(Boolean).join(', ') : 'Detection failed';
  var clientIsp = clientGeo ? clientGeo.isp : 'Detection failed';
  var proxyLocation = proxyGeo ? [proxyGeo.city, proxyGeo.country].filter(Boolean).join(', ') : 'Detection failed';

  var userPanelHTML = [
  '<!doctype html>',
  '<html lang="en">',
  '<head>',
  '  <meta charset="utf-8" />',
  '  <meta name="viewport" content="width=device-width,initial-scale=1" />',
  '  <title>User Panel — VLESS Configuration</title>',
  '  <style nonce="CSP_NONCE_PLACEHOLDER">',
  '    :root{',
  '      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;',
  '      --accent-2:#60a5fa; --success:#22c55e; --danger:#ef4444; --warning:#f59e0b;',
  '      --glass: rgba(255,255,255,0.03); --radius:12px; --mono: "SF Mono", "Fira Code", monospace;',
  '    }',
  '    *{box-sizing:border-box}',
  '    body{',
  '      margin:0; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;',
  '      background: linear-gradient(180deg,#061021 0%, #071323 100%);',
  '      color:#e6eef8; -webkit-font-smoothing:antialiased;',
  '      min-height:100vh; padding:28px;',
  '    }',
  '    .container{max-width:1100px;margin:0 auto}',
  '    .card{background:var(--card); border-radius:var(--radius); padding:20px;',
  '      border:1px solid rgba(255,255,255,0.03); box-shadow:0 8px 30px rgba(2,6,23,0.5); margin-bottom:20px;}',
  '    h1,h2{margin:0 0 14px;font-weight:600}',
  '    h1{font-size:28px}',
  '    h2{font-size:20px}',
  '    p.lead{color:var(--muted);margin:6px 0 20px;font-size:15px}',
  '',
  '    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:10px}',
  '    .stat{padding:14px;background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent);',
  '      border-radius:10px;text-align:center;border:1px solid rgba(255,255,255,0.02)}',
  '    .stat .val{font-weight:700;font-size:22px;margin-bottom:4px}',
  '    .stat .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.5px}',
  '    .stat.status-active .val{color:var(--success)}',
  '    .stat.status-expired .val{color:var(--danger)}',
  '    .stat.status-warning .val{color:var(--warning)}',
  '',
  '    .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}',
  '    @media (max-width:980px){ .grid{grid-template-columns:1fr} }',
  '',
  '    .info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}',
  '    .info-item{background:var(--glass);padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.02)}',
  '    .info-item .label{font-size:11px;color:var(--muted);display:block;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}',
  '    .info-item .value{font-weight:600;word-break:break-all;font-size:14px}',
  '    .info-item .value.detecting{color:var(--warning);font-style:italic}',
  '',
  '    .progress-bar{height:12px;background:#071529;border-radius:6px;overflow:hidden;margin:12px 0}',
  '    .progress-fill{',
  '      height:100%;',
  '      transition:width 0.6s ease;',
  '      border-radius:6px;',
  '      width:0%;',
  '    }',
  '    .progress-fill.low{background:linear-gradient(90deg,#22c55e,#16a34a)}',
  '    .progress-fill.medium{background:linear-gradient(90deg,#f59e0b,#d97706)}',
  '    .progress-fill.high{background:linear-gradient(90deg,#ef4444,#dc2626)}',
  '',
  '    pre.config{background:#071529;padding:14px;border-radius:8px;overflow:auto;',
  '      font-family:var(--mono);font-size:13px;color:#cfe8ff;',
  '      border:1px solid rgba(255,255,255,0.02);max-height:200px}',
  '    .buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}',
  '',
  '    .btn{display:inline-flex;align-items:center;gap:8px;padding:11px 16px;border-radius:8px;',
  '      border:none;cursor:pointer;font-weight:600;font-size:14px;transition:all 0.2s;',
  '      text-decoration:none;color:inherit}',
  '    .btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;box-shadow:0 4px 12px rgba(59,130,246,0.3)}',
  '    .btn.primary:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(59,130,246,0.4)}',
  '    .btn.ghost{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:var(--muted)}',
  '    .btn.ghost:hover{background:rgba(255,255,255,0.06);border-color:rgba(255,255,255,0.12);color:#fff}',
  '    .btn.small{padding:8px 12px;font-size:13px}',
  '    .btn:active{transform:translateY(0) scale(0.98)}',
  '    .btn:disabled{opacity:0.5;cursor:not-allowed}',
  '',
  '    .qr-container{background:#fff;padding:16px;border-radius:10px;display:inline-block;box-shadow:0 4px 12px rgba(0,0,0,0.2);margin:16px auto;text-align:center}',
  '    #qr-display{min-height:280px;display:flex;align-items:center;justify-content:center;flex-direction:column}',
  '',
  '    #toast{position:fixed;right:20px;top:20px;background:#0f1b2a;padding:14px 18px;',
  '      border-radius:10px;border:1px solid rgba(255,255,255,0.08);display:none;',
  '      color:#cfe8ff;box-shadow:0 8px 24px rgba(2,6,23,0.7);z-index:1000;min-width:200px}',
  '    #toast.show{display:block;animation:toastIn .3s ease}',
  '    #toast.success{border-left:4px solid var(--success)}',
  '    #toast.error{border-left:4px solid var(--danger)}',
  '    @keyframes toastIn{from{transform:translateY(-10px);opacity:0}to{transform:translateY(0);opacity:1}}',
  '',
  '    .section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;',
  '      padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.05)}',
  '    .muted{color:var(--muted);font-size:14px;line-height:1.6}',
  '    .stack{display:flex;flex-direction:column;gap:10px}',
  '    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}',
  '    .hidden{display:none}',
  '    .text-center{text-align:center}',
  '    .mb-2{margin-bottom:12px}',
  '    ',
  '    .expiry-warning{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);',
  '      padding:12px;border-radius:8px;margin-top:12px;color:#fca5a5}',
  '    .expiry-info{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);',
  '      padding:12px;border-radius:8px;margin-top:12px;color:#86efac}',
  '',
  '    @media (max-width: 768px) {',
  '      body{padding:16px}',
  '      .container{padding:0}',
  '      h1{font-size:24px}',
  '      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}',
  '      .info-grid{grid-template-columns:1fr}',
  '      .btn{padding:9px 12px;font-size:13px}',
  '    }',
  '  </style>',
  '</head>',
  '<body>',
  '  <div class="container">',
  '    <h1>🚀 VXR.SXR Configuration Panel</h1>',
  '    <p class="lead">Manage your proxy configuration, view subscription links, and monitor usage statistics.</p>',
  '',
  '    <div class="stats">',
  '      <div class="stat ' + (isUserExpired ? 'status-expired' : 'status-active') + '">',
  '        <div class="val" id="status-badge">' + (isUserExpired ? 'Expired' : 'Active') + '</div>',
  '        <div class="lbl">Account Status</div>',
  '      </div>',
  '      <div class="stat">',
  '        <div class="val" id="usage-display">' + formatBytes(userData.traffic_used || 0) + '</div>',
  '        <div class="lbl">Data Used</div>',
  '      </div>',
  '      <div class="stat ' + (usagePercentage > 80 ? 'status-warning' : '') + '">',
  '        <div class="val">' + (userData.traffic_limit && userData.traffic_limit > 0 ? formatBytes(userData.traffic_limit) : 'Unlimited') + '</div>',
  '        <div class="lbl">Data Limit</div>',
  '      </div>',
  '      <div class="stat">',
  '        <div class="val" id="expiry-countdown">—</div>',
  '        <div class="lbl">Time Remaining</div>',
  '      </div>',
  '    </div>',
  '',
  ((userData.traffic_limit && userData.traffic_limit > 0) ? 
  '    <div class="card">' +
  '      <div class="section-title">' +
  '        <h2>📊 Usage Statistics</h2>' +
  '        <span class="muted">' + usagePercentageDisplay + ' Used</span>' +
  '      </div>' +
  '      <div class="progress-bar">' +
  '        <div class="progress-fill ' + (usagePercentage > 80 ? 'high' : (usagePercentage > 50 ? 'medium' : 'low')) + '" ' +
  '             id="progress-bar-fill"' +
  '             style="width: 0%"' +
  '             data-target-width="' + usagePercentage.toFixed(2) + '"></div>' +
  '      </div>' +
  '      <p class="muted text-center mb-2">' + formatBytes(userData.traffic_used || 0) + ' of ' + formatBytes(userData.traffic_limit) + ' used</p>' +
  '    </div>' : ''),

  ((expirationDateTime) ? 
  '    <div class="card">' +
  '      <div class="section-title">' +
  '        <h2>⏰ Expiration Information</h2>' +
  '      </div>' +
  '      <div id="expiration-display" data-expiry="' + expirationDateTime + '">' +
  '        <p class="muted" id="expiry-local">Loading expiration time...</p>' +
  '        <p class="muted" id="expiry-utc" style="font-size:13px;margin-top:4px"></p>' +
  '      </div>' +
 ((isUserExpired) ? 
  '      <div class="expiry-warning">' +
  '        ⚠️ Your account has expired. Please contact your administrator to renew access.' +
  '      </div>' : 
  '      <div class="expiry-info">' +
  '        ✓ Your account is currently active and working normally.' +
  '      </div>'
  ) +
  '    </div>' : ''),

  '    <div class="grid">',
  '      <div>',
  '        <div class="card">',
  '          <div class="section-title">',
  '            <h2>🌐 Network Information</h2>',
  '            <button class="btn ghost small" id="btn-refresh-ip">Refresh</button>',
  '          </div>',
  '          <p class="muted">Connection details and IP information for your proxy server and current location.</p>',
  '          <div class="info-grid">',
  '            <div class="info-item">',
  '              <span class="label">Proxy Host</span>',
  '              <span class="value" id="proxy-host">' + (proxyAddress || hostName) + '</span>',
  '            </div>',
  '            <div class="info-item">',
  '              <span class="label">Proxy IP</span>',
  '              <span class="value" id="proxy-ip">' + (proxyIP || 'Detection failed') + '</span>',
  '            </div>',
  '            <div class="info-item">',
  '              <span class="label">Proxy Location</span>',
  '              <span class="value" id="proxy-location">' + (proxyLocation || 'Detection failed') + '</span>',
  '            </div>',
  '            <div class="info-item">',
  '              <span class="label">Your IP</span>',
  '              <span class="value" id="client-ip">' + (clientIp || 'Detection failed') + '</span>',
  '            </div>',
  '            <div class="info-item">',
  '              <span class="label">Your Location</span>',
  '              <span class="value" id="client-location">' + (clientLocation || 'Detection failed') + '</span>',
  '            </div>',
  '            <div class="info-item">',
  '              <span class="label">Your ISP</span>',
  '              <span class="value" id="client-isp">' + (clientIsp || 'Detection failed') + '</span>',
  '            </div>',
  '          </div>',
  '        </div>',
  '',
  '        <div class="card">',
  '          <div class="section-title">',
  '            <h2>📱 Subscription Links</h2>',
  '          </div>',
  '          <p class="muted">Copy subscription URLs or import directly into your VPN client application.</p>',
  '',
  '          <div class="stack">',
  '            <div>',
  '              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Xray / V2Ray Subscription</h3>',
  '              <div class="buttons">',
  '                <button class="btn primary" id="copy-xray-sub">📋 Copy Xray Link</button>',
  '                <button class="btn ghost" id="show-xray-config">View Config</button>',
  '                <button class="btn ghost" id="qr-xray-sub-btn">QR Code</button>',
  '              </div>',
  '              <pre class="config hidden" id="xray-config">' + escapeHTML(singleXrayConfig) + '</pre>',
  '            </div>',
  '',
  '            <div>',
  '              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Sing-Box / Clash Subscription</h3>',
  '              <div class="buttons">',
  '                <button class="btn primary" id="copy-sb-sub">📋 Copy Singbox Link</button>',
  '                <button class="btn ghost" id="show-sb-config">View Config</button>',
  '                <button class="btn ghost" id="qr-sb-sub-btn">QR Code</button>',
  '              </div>',
  '              <pre class="config hidden" id="sb-config">' + escapeHTML(singleSingboxConfig) + '</pre>',
  '            </div>',
  '',
  '            <div>',
  '              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Quick Import</h3>',
  '              <div class="buttons">',
  '                <a href="' + clientUrls.universalAndroid + '" rel="noopener noreferrer" class="btn ghost">📱 Android (V2rayNG)</a>',
  '                <a href="' + clientUrls.shadowrocket + '" rel="noopener noreferrer" class="btn ghost">🍎 iOS (Shadowrocket)</a>',
  '                <a href="' + clientUrls.streisand + '" rel="noopener noreferrer" class="btn ghost">🍎 iOS Streisand</a>',
  '                <a href="' + clientUrls.karing + '" rel="noopener noreferrer" class="btn ghost">🔧 Android/iOS Karing</a>',
  '              </div>',
  '            </div>',
  '          </div>',
  '        </div>',
  '      </div>',
  '',
  '      <aside>',
  '        <div class="card">',
  '          <h2>QR Code Scanner</h2>',
  '          <p class="muted mb-2">Scan with your mobile device to quickly import configuration.</p>',
  '          <div id="qr-display" class="text-center">',
  '            <p class="muted">Click any "QR Code" button to generate a scannable code.</p>',
  '          </div>',
  '          <div class="buttons" style="justify-content:center;margin-top:16px">',
  '            <button class="btn ghost small" id="qr-xray-config-btn">Xray Config QR</button>',
  '            <button class="btn ghost small" id="qr-sb-config-btn">Singbox Config QR</button>',
  '          </div>',
  '        </div>',
  '',
  '        <div class="card">',
  '          <h2>👤 Account Details</h2>',
  '          <div class="info-item" style="margin-top:12px">',
  '            <span class="label">User UUID</span>',
  '            <span class="value" style="font-family:var(--mono);font-size:12px;word-break:break-all">' + userID + '</span>',
  '          </div>',
  '          <div class="info-item" style="margin-top:12px">',
  '            <span class="label">Created Date</span>',
  '            <span class="value">' + new Date(userData.created_at).toLocaleDateString() + '</span>',
  '          </div>',
 ((userData.notes) ? 
  '          <div class="info-item" style="margin-top:12px">' +
  '            <span class="label">Notes</span>' +
  '            <span class="value">' + escapeHTML(userData.notes) + '</span>' +
  '          </div>' : ''),
  '          <div class="info-item" style="margin-top:12px">',
  '            <span class="label">IP Limit</span>',
  '            <span class="value">' + (userData.ip_limit === -1 ? 'Unlimited' : userData.ip_limit) + '</span>',
  '          </div>',
  '        </div>',
  '',
  '        <div class="card">',
  '          <h2>💾 Export Configuration</h2>',
  '          <p class="muted mb-2">Download configuration file for manual import or backup purposes.</p>',
  '          <div class="buttons">',
  '            <button class="btn primary small" id="download-xray">Download Xray</button>',
  '            <button class="btn primary small" id="download-sb">Download Singbox</button>',
  '          </div>',
  '        </div>',
  '      </aside>',
  '    </div>',
  '',
  '    <div class="card">',
  '      <p class="muted text-center" style="margin:0">',
  '        🔒 This is your personal configuration panel. Keep your subscription links private and secure.',
  '        <br>For support or questions, contact your service administrator.',
  '      </p>',
  '    </div>',
  '',
  '    <div id="toast"></div>',
  '  </div>',
  '',
  '  <script nonce="CSP_NONCE_PLACEHOLDER">',
  '    window.CONFIG = {',
  '      uuid: "' + userID + '",',
  '      host: "' + hostName + '",',
  '      proxyAddress: "' + (proxyAddress || hostName) + '",',
  '      subXrayUrl: "' + subXrayUrl + '",',
  '      subSbUrl: "' + subSbUrl + '",',
  '      singleXrayConfig: ' + JSON.stringify(singleXrayConfig) + ',',
  '      singleSingboxConfig: ' + JSON.stringify(singleSingboxConfig) + ',',
  '      expirationDateTime: ' + (expirationDateTime ? `"${expirationDateTime}"` : 'null') + ',',
  '      isExpired: ' + isUserExpired + ',',
  '      clientUrls: ' + JSON.stringify(clientUrls) + ',',
  '      trafficLimit: ' + (userData.traffic_limit || 'null') + ',',
  '      initialTrafficUsed: ' + (userData.traffic_used || 0) + '',
  '    };',
  '',
  '    window.formatBytes = formatBytes;',
  '    window.generateQRCode = generateQRCode;',
  '    window.showToast = showToast;',
  '    window.copyToClipboard = copyToClipboard;',
  '    window.downloadConfig = downloadConfig;',
  '    window.fetchIPInfo = fetchIPInfo;',
  '    window.updateExpirationDisplay = updateExpirationDisplay;',
  '    window.animateProgressBar = animateProgressBar;',
  '    window.refreshUserPanel = refreshUserPanel;',
  '    window.startUserAutoRefresh = startUserAutoRefresh;',
  '  </script>',
  '</body>',
  '</html>'
].join('\n');

  var nonce = generateNonce();
  var headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
  addSecurityHeaders(headers, nonce, {
    img: 'data: https://api.qrserver.com',
    connect: 'https://api.qrserver.com'
  });
  
  var finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
  finalHtml = finalHtml.replace('window.CLIENT_GEO = null;', "window.CLIENT_GEO = " + JSON.stringify(clientGeo) + ";");
  finalHtml = finalHtml.replace('window.PROXY_GEO = null;', "window.PROXY_GEO = " + JSON.stringify(proxyGeo) + ";");
  finalHtml = finalHtml.replace('window.PROXY_IP = null;', "window.PROXY_IP = \"" + proxyIP + "\";");
  finalHtml = finalHtml.replace('window.CLIENT_IP = null;', "window.CLIENT_IP = \"" + clientIp + "\";");

  return new Response(finalHtml, { headers: headers });
}

// ============================================================================
// VLESS PROTOCOL HANDLERS (complete, unchanged from original)
// ============================================================================

function ProtocolOverWSHandler(request, config, env, ctx) {
  var clientIp = request.headers.get('CF-Connecting-IP');
  if (isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
    return new Response('Access denied', { status: 403 });
  }

  var webSocketPair = new WebSocketPair();
  var client = webSocketPair[0];
  var webSocket = webSocketPair[1];
  webSocket.accept();

  var address = '';
  var portWithRandomLog = '';
  var sessionUsage = 0;
  var userUUID = '';
  var udpStreamWriter = null;

  var log = function(info, event) { console.log("[" + address + ":" + portWithRandomLog + "] " + info, event || ''); };

  var deferredUsageUpdate = function() {
    if (sessionUsage > 0 && userUUID) {
      var usageToUpdate = sessionUsage;
      var uuidToUpdate = userUUID;
      
      sessionUsage = 0;
      
      ctx.waitUntil(
        updateUsage(env, uuidToUpdate, usageToUpdate, ctx).catch(function(err) { console.error("Deferred usage update failed for " + uuidToUpdate + ":", err); })
      );
    }
  };

  var updateInterval = setInterval(deferredUsageUpdate, 10000);

  var finalCleanup = function() {
    clearInterval(updateInterval);
    deferredUsageUpdate();
  };

  webSocket.addEventListener('close', finalCleanup, { once: true });
  webSocket.addEventListener('error', finalCleanup, { once: true });

  var earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  var readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  var remoteSocketWrapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        write: function(chunk, controller) {
          sessionUsage += chunk.byteLength;

          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWrapper.value) {
            var writer = remoteSocketWrapper.value.writable.getWriter();
            writer.write(chunk).then(function() {
              writer.releaseLock();
            });
            return;
          }

          var processResult = ProcessProtocolHeader(chunk, env, ctx);
          var user = processResult.user;
          var hasError = processResult.hasError;
          var message = processResult.message;
          var addressType = processResult.addressType;
          var portRemote = processResult.portRemote || 443;
          var addressRemote = processResult.addressRemote || '';
          var rawDataIndex = processResult.rawDataIndex;
          var ProtocolVersion = processResult.ProtocolVersion || new Uint8Array([0, 0]);
          var isUDP = processResult.isUDP;

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
            var totalUsage = (user.traffic_used || 0) + sessionUsage;
            if (totalUsage >= user.traffic_limit) {
              controller.error(new Error('Authentication failed'));
              return;
            }
          }

          // IP Limit Check
          if (user.ip_limit && user.ip_limit > -1) {
            var ipCount = env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?").bind(userUUID).first('count');
            if (ipCount >= user.ip_limit) {
              controller.error(new Error('IP limit exceeded'));
              return;
            }
            // Update current IP
            env.DB.prepare("INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)").bind(userUUID, clientIp).run();
          }

          address = addressRemote;
          portWithRandomLog = portRemote + "--" + Math.random() + " " + (isUDP ? 'udp' : 'tcp');
          var vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          var rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              var dnsPipeline = createDnsPipeline(webSocket, vlessResponseHeader, log, function(bytes) {
                sessionUsage += bytes;
              });
              udpStreamWriter = dnsPipeline.write;
              udpStreamWriter(rawClientData);
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
            function(bytes) { sessionUsage += bytes; }
          );
        },
        close: function() {
          log('readableWebSocketStream closed');
          finalCleanup();
        },
        abort: function(err) {
          log('readableWebSocketStream aborted', err);
          finalCleanup();
        }
      })
    )
    .catch(function(err) {
      console.error('Pipeline failed:', err.stack || err);
      safeCloseWebSocket(webSocket);
      finalCleanup();
    });

  return new Response(null, { status: 101, webSocket: client });
}

function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }
  
  var dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
  var version = dataView.getUint8(0);

  var uuid;
  try {
    uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  } catch (e) {
    return { hasError: true, message: 'invalid UUID format' };
  }

  var userData = getUserData(env, uuid, ctx);
  if (!userData) {
    return { hasError: true, message: 'invalid user' };
  }

  var payloadStart = 17;
  if (protocolBuffer.byteLength < payloadStart + 1) {
    return { hasError: true, message: 'invalid data length' };
  }

  var optLength = dataView.getUint8(payloadStart);
  var commandIndex = payloadStart + 1 + optLength;
  
  if (protocolBuffer.byteLength < commandIndex + 1) {
    return { hasError: true, message: 'invalid data length (command)' };
  }
  
  var command = dataView.getUint8(commandIndex);
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: "command " + command + " is not supported" };
  }

  var portIndex = commandIndex + 1;
  if (protocolBuffer.byteLength < portIndex + 2) {
    return { hasError: true, message: 'invalid data length (port)' };
  }
  
  var portRemote = dataView.getUint16(portIndex, false);

  var addressTypeIndex = portIndex + 2;
  if (protocolBuffer.byteLength < addressTypeIndex + 1) {
    return { hasError: true, message: 'invalid data length (address type)' };
  }
  
  var addressType = dataView.getUint8(addressTypeIndex);

  var addressValue, addressLength, addressValueIndex;

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
      addressValue = (function() {
        var arr = [];
        for (var i = 0; i < 8; i++) {
          arr.push(dataView.getUint16(addressValueIndex + i * 2, false).toString(16));
        }
        return arr.join(':');
      })();
      break;
      
    default:
      return { hasError: true, message: "invalid addressType: " + addressType };
  }

  var rawDataIndex = addressValueIndex + addressLength;
  if (protocolBuffer.byteLength < rawDataIndex) {
    return { hasError: true, message: 'invalid data length (raw data)' };
  }

  return {
    user: userData,
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: rawDataIndex,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
}

function HandleTCPOutBound(
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
  function connectAndWrite(address, port, socks) {
    socks = socks || false;
    var tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log("connected to " + address + ":" + port);
    var writer = tcpSocket.writable.getWriter();
    writer.write(rawClientData).then(function() {
      writer.releaseLock();
    });
    return tcpSocket;
  }

  function retry() {
    var tcpSocket = config.enableSocks
      ? connectAndWrite(addressRemote, portRemote, true)
      : connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

    tcpSocket.closed
      .catch(function(error) {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(function() {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  var tcpSocket = connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start: function(controller) {
      webSocketServer.addEventListener('message', function(event) { controller.enqueue(event.data); });
      webSocketServer.addEventListener('close', function() {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', function(err) {
        log('webSocketServer has error');
        controller.error(err);
      });
      var earlyDataResult = base64ToArrayBuffer(earlyDataHeader);
      var earlyData = earlyDataResult.earlyData;
      var error = earlyDataResult.error;
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull: function(_controller) { },
    cancel: function(reason) {
      log("ReadableStream was canceled, due to " + reason);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  var hasIncomingData = false;
  remoteSocket.readable.pipeTo(
    new WritableStream({
      write: function(chunk) {
        if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
          throw new Error('WebSocket is not open');
        hasIncomingData = true;
        
        if (trafficCallback) {
          trafficCallback(chunk.byteLength);
        }
        
        var dataToSend = protocolResponseHeader
          ? new Blob([protocolResponseHeader, chunk]).arrayBuffer()
          : chunk;
        webSocket.send(dataToSend);
        protocolResponseHeader = null;
      },
      close: function() {
        log("Remote connection readable closed. Had incoming data: " + hasIncomingData);
      },
      abort: function(reason) {
        console.error('Remote connection readable aborted:', reason);
      },
    })
  ).catch(function(error) {
    console.error('RemoteSocketToWS error:', error.stack || error);
    safeCloseWebSocket(webSocket);
  });
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying');
    retry().catch(function(e) {
      console.error('Retry failed:', e);
    });
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    var binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    var buffer = new ArrayBuffer(binaryStr.length);
    var view = new Uint8Array(buffer);
    for (var i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error: error };
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
    console.error('safeCloseWebSocket error:', error);
  }
}

function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  var isHeaderSent = false;
  var transformStream = new TransformStream({
    transform(chunk, controller) {
      var index = 0;
      while (index < chunk.byteLength) {
        if (index + 2 > chunk.byteLength) break;
        var lengthBuffer = chunk.slice(index, index + 2);
        var udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        var udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        write: function(chunk) {
          fetch('https://1.1.1.1/dns-query', {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: chunk,
          }).then(function(resp) {
            return resp.arrayBuffer();
          }).then(function(dnsQueryResult) {
            var udpSize = dnsQueryResult.byteLength;
            var udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log("DNS query successful, length: " + udpSize);
              var responseChunk;
              if (isHeaderSent) {
                responseChunk = new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) {
                trafficCallback(responseChunk.byteLength);
              }
              webSocket.send(responseChunk);
            }
          }).catch(function(error) {
            log('DNS query error: ' + error);
          });
        },
      })
    )
    .catch(function(e) {
      log('DNS stream error: ' + e);
    });

  var writer = transformStream.writable.getWriter();
  return {
    write: function(chunk) { return writer.write(chunk); },
  };
}

function parseIPv6(ipv6) {
    var buffer = new ArrayBuffer(16);
    var view = new DataView(buffer);
    
    var parts = ipv6.split('::');
    var left = parts[0] ? parts[0].split(':') : [];
    var right = parts[1] ? parts[1].split(':') : [];
    
    if (left.length === 1 && left[0] === '') left = [];
    if (right.length === 1 && right[0] === '') right = [];
    
    var missing = 8 - (left.length + right.length);
    var expansion = [];
    if (missing > 0) {
        for (var i = 0; i < missing; i++) {
            expansion.push('0000');
        }
    }
    
    var hextets = [].concat(left, expansion, right);
    
    for (var i = 0; i < 8; i++) {
        var val = parseInt(hextets[i] || '0', 16);
        view.setUint16(i * 2, val, false);
    }
    
    return new Uint8Array(buffer);
}

// @ts-ignore
function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  var username = parsedSocks5Address.username;
  var password = parsedSocks5Address.password;
  var hostname = parsedSocks5Address.hostname;
  var port = parsedSocks5Address.port;
  
  var socket;
  var reader;
  var writer;
  var success = false;

  try {
    socket = connect({ hostname: hostname, port: port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    
    var encoder = new TextEncoder();

    writer.write(new Uint8Array([5, 2, 0, 2]));
    var res = reader.read().value;
    if (!res || res[0] !== 0x05 || res[1] === 0xff) {
      throw new Error('SOCKS5 handshake failed. Server rejected methods.');
    }

    if (res[1] === 0x02) {
      if (!username || !password) {
        throw new Error('SOCKS5 server requires credentials, but none provided.');
      }
      var authRequest = new Uint8Array([
        1,
        username.length,
        encoder.encode(username),
        password.length,
        encoder.encode(password)
      ]);
      writer.write(authRequest);
      res = reader.read().value;
      if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
        throw new Error("SOCKS5 authentication failed (Code: " + res[1] + ")");
      }
    }

    var dstAddr;
    switch (addressType) {
      case 1:
        dstAddr = new Uint8Array([1].concat(addressRemote.split('.').map(Number)));
        break;
      case 2:
        dstAddr = new Uint8Array([3, addressRemote.length].concat(encoder.encode(addressRemote)));
        break;
      case 3:
        var ipv6Bytes = parseIPv6(addressRemote);
        if (ipv6Bytes.length !== 16) {
          throw new Error("Failed to parse IPv6 address: " + addressRemote);
        }
        dstAddr = new Uint8Array([4].concat(Array.from(ipv6Bytes)));
        break;
      default:
        throw new Error("Invalid address type: " + addressType);
    }

    var socksRequest = new Uint8Array([5, 1, 0].concat(Array.from(dstAddr), [portRemote >> 8, portRemote & 0xff]));
    writer.write(socksRequest);
    
    res = reader.read().value;
    if (!res || res[1] !== 0x00) {
      throw new Error("SOCKS5 connection failed. Server responded with code: " + res[1]);
    }

    log("SOCKS5 connection to " + addressRemote + ":" + portRemote + " established.");
    success = true;
    return socket;

  } catch (err) {
    log("socks5Connect Error: " + err.message, err);
    throw err;
  } finally {
    if (writer) writer.releaseLock();
    if (reader) reader.releaseLock();
    
    if (!success && socket) {
      try {
        socket.abort();
      } catch (e) {
        log('Error aborting SOCKS5 socket during cleanup', e);
      }
    }
  }
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  var parts = address.includes('@') ? address.split('@') : [null, address];
  var authPart = parts[0];
  var hostPart = parts[1];
  var lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  var hostname;
  if (hostPart.startsWith('[')) {
      var closingBracketIndex = hostPart.lastIndexOf(']');
      if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
          throw new Error('Invalid IPv6 SOCKS5 address format');
      }
      hostname = hostPart.substring(1, closingBracketIndex);
  } else {
      hostname = hostPart.substring(0, lastColonIndex);
  }

  var portStr = hostPart.substring(lastColonIndex + 1);
  var port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  var username, password;
  if (authPart) {
    var auth = authPart.split(':');
    username = auth[0];
    password = auth[1];
  }
  
  return { username: username, password: password, hostname: hostname, port: port };
}

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    var cfg = Config.fromEnv(env);
    
    var url = new URL(request.url);
    var clientIp = request.headers.get('CF-Connecting-IP');

    var adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
    
    if (url.pathname.startsWith("/" + adminPrefix + "/")) {
      return await handleAdminRequest(request, env, ctx, adminPrefix);
    }

    if (url.pathname === '/health') {
      var headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('OK', { status: 200, headers: headers });
    }

    if (url.pathname.startsWith('/api/user/')) {
      var uuid = url.pathname.substring('/api/user/'.length);
      var headers = new Headers({ 'Content-Type': 'application/json' });
      addSecurityHeaders(headers, null, {});
      if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers: headers });
      }
      if (!isValidUUID(uuid)) {
        return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers: headers });
      }
      var userData = getUserData(env, uuid, ctx);
      if (!userData) {
        return new Response(JSON.stringify({ error: 'Authentication failed' }), { status: 403, headers: headers });
      }
      return new Response(JSON.stringify({
        traffic_used: userData.traffic_used || 0,
        traffic_limit: userData.traffic_limit,
        expiration_date: userData.expiration_date,
        expiration_time: userData.expiration_time
      }), { status: 200, headers: headers });
    }

    var upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      if (!env.DB) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service not configured properly', { status: 503, headers: headers });
      }
      
      var requestConfig = {
        userID: cfg.userID,
        proxyIP: cfg.proxyIP,
        proxyPort: cfg.proxyPort,
        socks5Address: cfg.socks5.address,
        socks5Relay: cfg.socks5.relayMode,
        enableSocks: cfg.socks5.enabled,
        parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
        scamalytics: cfg.scamalytics,
      };
      
      var wsResponse = ProtocolOverWSHandler(request, requestConfig, env, ctx);
      
      var headers = new Headers(wsResponse.headers);
      addSecurityHeaders(headers, null, {});
      
      return new Response(wsResponse.body, { status: wsResponse.status, webSocket: wsResponse.webSocket, headers: headers });
    }

    async function handleSubscription(core) {
      var rateLimitKey = "user_path_rate:" + clientIp;
      if (checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers: headers });
      }

      var uuid = url.pathname.substring(("/" + core + "/").length);
      if (!isValidUUID(uuid)) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Invalid UUID', { status: 400, headers: headers });
      }
      
      var userData = getUserData(env, uuid, ctx);
      if (!userData) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers: headers });
      }
      
      if (isExpired(userData.expiration_date, userData.expiration_time)) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers: headers });
      }
      
      if (userData.traffic_limit && userData.traffic_limit > 0 && 
          (userData.traffic_used || 0) >= userData.traffic_limit) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers: headers });
      }
      
      return handleIpSubscription(core, uuid, url.hostname);
    }

    if (url.pathname.startsWith('/xray/')) {
      return await handleSubscription('xray');
    }
    
    if (url.pathname.startsWith('/sb/')) {
      return await handleSubscription('sb');
    }

    var path = url.pathname.slice(1);
    if (isValidUUID(path)) {
      var rateLimitKey = "user_path_rate:" + clientIp;
      if (checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers: headers });
      }

      var userData = getUserData(env, path, ctx);
      if (!userData) {
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers: headers });
      }
      
      return handleUserPanel(path, url.hostname, cfg.proxyAddress, userData);
    }

    if (env.ROOT_PROXY_URL) {
      var proxyUrl;
      try {
        proxyUrl = new URL(env.ROOT_PROXY_URL);
      } catch (urlError) {
        console.error("Invalid ROOT_PROXY_URL: " + env.ROOT_PROXY_URL, urlError);
        var headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Proxy configuration error: Invalid URL format', { status: 500, headers: headers });
      }

      var targetUrl = new URL(request.url);
      targetUrl.hostname = proxyUrl.hostname;
      targetUrl.protocol = proxyUrl.protocol;
      if (proxyUrl.port) {
        targetUrl.port = proxyUrl.port;
      }
      
      var newRequest = new Request(targetUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: 'manual'
      });
      
      newRequest.headers.set('Host', proxyUrl.hostname);
      newRequest.headers.set('X-Forwarded-For', clientIp);
      newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', ''));
      newRequest.headers.set('X-Real-IP', clientIp);
      
      var response = await fetch(newRequest);
      var mutableHeaders = new Headers(response.headers);
      
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
    }

    var headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers: headers });
  }
};
