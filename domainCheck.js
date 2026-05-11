// monitor.js — drop this file next to your server.js
// Install deps first: npm install whois-json axios
// Then in server.js: const { registerMonitorRoutes } = require("./monitor");
//                    registerMonitorRoutes(app);

const dns = require("dns").promises;
const tls = require("tls");
const whois = require("whois-json");
const axios = require("axios");

// ─── SITES CONFIG ─────────────────────────────────────────────────────────────
// strictContent: set to a short phrase that ONLY exists in your real site HTML
// (e.g. a nav label, button text, footer text) — not on any parking lander
const SITES = [
  {
    name: "Telth Main",
    domain: "mytelth.com",
    url: "https://www.mytelth.com",
    expectedText: "telth",
    strictContent: null,        // replace with e.g. "patient portal"
    whoisServer: null,
  },
  {
    name: "Telth Care",
    domain: "telth.care",
    url: "https://www.telth.care",
    expectedText: "telth",
    strictContent: null,
    whoisServer: null,
  },
  {
    name: "Telth AI",
    domain: "telth.ai",
    url: "https://telth.ai",
    expectedText: "telth",
    strictContent: null,
    whoisServer: "whois.nic.ai", // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "Telth Org",
    domain: "telth.org",
    url: "https://telth.org",
    expectedText: "telth",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "CCM App",
    domain: "telth.care",
    url: "https://app.telth.care",
    expectedText: "telth",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "Eterna",
    domain: "harleyhealthsystem.com",
    url: "https://www.harleyhealthsystem.com",
    expectedText: "Eterna by Harley Health ",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "NATLIFE",
    domain: "natlife.org.in",
    url: "https://www.nahm-som.org",
    expectedText: "NatLife - Purely Organic, Naturally Fresh",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "Nahm-som",
    domain: "nahmsom.org",
    url: "https://www.natlife.org.in/",
    expectedText: "NAHM-SOM | National AI Health Mission for Soul-Oriented Medicine",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "gmedid",
    domain: "gmedid.org",
    url: "https://www.gmedid.org/",
    expectedText: "gmedid",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
  {
    name: "healthcu.org",
    domain: "healthcu.org",
    url: "https://www.healthcu.org/",
    expectedText: "healthcu ",
    strictContent: null,
    whoisServer: null, // Anguilla ccTLD — must be set explicitly
  },
];

// ─── CONSTANTS ───────────────────────────────────────────────────────────────
const CRITICAL_ISSUES = [
  "DNS FAILED",
  "HTTP DOWN",
  "DOMAIN EXPIRED",
  "DOMAIN PARKED",
  "REDIRECTED TO PARKING",
  "CONTENT MISMATCH",
];

const PARKING_SIGNALS = [
  "domain for sale",
  "buy this domain",
  "parked free",
  "parked by",
  "godaddy.com/parking",
  "sedoparking",
  "namecheap.com/domains",
  "afternic",
  "this domain is for sale",
  "make an offer",
  "this web page is parked",
  "web page is currently unavailable",
];

const PARKING_HOSTS = [
  "parkingpage.namecheap.com",
  "sedoparking.com",
  "parking.godaddy.com",
  "afternic.com",
  "dan.com",
  "hugedomains.com",
];

// ─── UTILS ────────────────────────────────────────────────────────────────────
function daysLeft(date) {
  if (!date) return null;
  return (new Date(date) - new Date()) / (1000 * 60 * 60 * 24);
}

function parseExpiry(data) {
  const EXPIRY_KEYS = [
    "expirationDate",
    "registrarRegistrationExpirationDate", // confirmed for .com / .care / .ai
    "registryExpiryDate",
    "expires",
    "expiryDate",
    "domainExpirationDate",
    "paidTill",                            // .ru / .su
    "expiry",                              // .nz
    "validity",                            // .in
  ];
  for (const key of EXPIRY_KEYS) {
    if (data[key]) {
      const val = data[key];
      return Array.isArray(val) ? val[0] : val;
    }
  }
  return { _unknownKeys: Object.keys(data) }; // for debugging
}

// ─── CHECK: DNS ───────────────────────────────────────────────────────────────
async function checkDNS(site) {
  try {
    const records = await dns.resolve(site.domain);
    return { records, failed: false };
  } catch (e) {
    return { records: null, failed: true, error: e.code };
  }
}

// ─── CHECK: SSL ───────────────────────────────────────────────────────────────
async function checkSSL(site) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(
        443,
        site.domain,
        { servername: site.domain, timeout: 8000 },
        () => {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          socket.end();
          resolve({
            expiry: cert.valid_to,
            subject: cert.subject && cert.subject.CN,
            issuer: cert.issuer && cert.issuer.O,
            authorized,
            daysLeft: Math.floor(daysLeft(cert.valid_to)),
            failed: false,
          });
        }
      );
      socket.on("error", (e) => resolve({ failed: true, error: e.message }));
      socket.setTimeout(8000, () => {
        socket.destroy();
        resolve({ failed: true, error: "TIMEOUT" });
      });
    } catch (e) {
      resolve({ failed: true, error: e.message });
    }
  });
}

// ─── CHECK: WHOIS ─────────────────────────────────────────────────────────────
async function checkWhois(site) {
  try {
    const opts = site.whoisServer ? { server: site.whoisServer } : {};
    const data = await whois(site.domain, opts);
    const expiry = parseExpiry(data);

    if (expiry && expiry._unknownKeys) {
      return { expiry: null, unknownKeys: expiry._unknownKeys, failed: false };
    }

    return {
      expiry,
      daysLeft: expiry ? Math.floor(daysLeft(expiry)) : null,
      registrar: data.registrar || data.registrarName || null,
      failed: false,
    };
  } catch (e) {
    return { expiry: null, failed: true, error: e.message };
  }
}

// ─── CHECK: HTTP + parking detection ─────────────────────────────────────────
async function checkHTTP(site) {
  try {
    const start = Date.now();
    const res = await axios.get(site.url, {
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true,  // don't throw on 4xx/5xx
      headers: { "User-Agent": "Mozilla/5.0 (compatible; TelthMonitor/1.0)" },
    });
    const elapsed = Date.now() - start;
    const body = res.data.toLowerCase();

    const finalURL = (res.request && res.request.res && res.request.res.responseUrl)
      || res.config.url
      || site.url;
    const finalHost = new URL(finalURL).hostname;

    const redirectedToParking = PARKING_HOSTS.some((h) => finalHost.includes(h));
    const parkedByContent = PARKING_SIGNALS.some((sig) => body.includes(sig));
    const isParked = redirectedToParking || parkedByContent;

    let contentValid = false;
    if (!isParked) {
      const hasExpected = body.includes(site.expectedText.toLowerCase());
      const hasStrict = site.strictContent
        ? body.includes(site.strictContent.toLowerCase())
        : true;
      contentValid = hasExpected && hasStrict;
    }

    return {
      status: res.status,
      time: elapsed,
      finalURL,
      redirectedToParking,
      parkedByContent,
      isParked,
      contentValid,
      failed: false,
    };
  } catch (e) {
    return { status: null, failed: true, error: e.code || e.message };
  }
}

// ─── MAIN ORCHESTRATOR ────────────────────────────────────────────────────────
async function checkSite(site) {
  const [dnsResult, sslResult, whoisResult, httpResult] = await Promise.all([
    checkDNS(site),
    checkSSL(site),
    checkWhois(site),
    checkHTTP(site),
  ]);

  const issues = [];

  if (dnsResult.failed) issues.push("DNS FAILED");

  if (sslResult.failed) {
    issues.push("SSL FAILED");
  } else if (!sslResult.authorized) {
    issues.push("SSL NOT TRUSTED");
  } else if (sslResult.daysLeft < 7) {
    issues.push("SSL EXPIRING CRITICAL (<7d)");
  } else if (sslResult.daysLeft < 30) {
    issues.push("SSL EXPIRING (<30d)");
  }

  if (whoisResult.failed) {
    issues.push("WHOIS FAILED");
  } else if (!whoisResult.expiry) {
    issues.push("EXPIRY UNKNOWN");
  } else if (whoisResult.daysLeft < 0) {
    issues.push("DOMAIN EXPIRED");
  } else if (whoisResult.daysLeft < 7) {
    issues.push("DOMAIN EXPIRING CRITICAL (<7d)");
  } else if (whoisResult.daysLeft < 30) {
    issues.push("DOMAIN EXPIRING SOON (<30d)");
  }

  if (httpResult.failed) {
    issues.push("HTTP DOWN");
  } else {
    if (httpResult.redirectedToParking) issues.push("REDIRECTED TO PARKING");
    else if (httpResult.parkedByContent) issues.push("DOMAIN PARKED");
    if (httpResult.status >= 400) issues.push("HTTP ERROR " + httpResult.status);
    if (!httpResult.isParked && !httpResult.contentValid) issues.push("CONTENT MISMATCH");
  }

  return {
    name: site.name,
    domain: site.domain,
    url: site.url,
    checkedAt: new Date().toISOString(),
    status: issues.some((i) => CRITICAL_ISSUES.includes(i)) ? "DOWN" : "UP",
    issues,
    dns: dnsResult,
    ssl: sslResult,
    whois: whoisResult,
    http: httpResult,
  };
}

// ─── ROUTE REGISTRAR — call this in your server.js ───────────────────────────
function registerMonitorRoutes(app) {
  // Check all domains in parallel
  app.get("/api/check", async (req, res) => {
    try {
      const results = await Promise.all(SITES.map(checkSite));
      res.json({ success: true, checkedAt: new Date().toISOString(), results });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // Check one domain by name: /api/check/mytelth.com
  app.get("/api/check/:domain", async (req, res) => {
    const site = SITES.find((s) => s.domain === req.params.domain);
    if (!site) return res.status(404).json({ error: "Domain not in config" });
    try {
      const result = await checkSite(site);
      res.json({ success: true, result });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
}

module.exports = { registerMonitorRoutes, checkSite, SITES };