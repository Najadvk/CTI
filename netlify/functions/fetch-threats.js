import fetch from "node-fetch";

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;
  if (!API_KEY) {
    console.error("API key missing");
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "API key not configured in environment variables" })
    };
  }

  // Handle IP lookup (AbuseIPDB)
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;
    try {
      const res = await fetchWithRetry(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, API_KEY);
      console.log(`IP check for ${ip}: status ${res.status}`);
      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get("Retry-After")) || 3600;
          console.log(`IP check 429: Retry-After ${retryAfter}s`);
          return { statusCode: 429, body: JSON.stringify({ error: `Rate limit exceeded, retry after ${retryAfter} seconds` }) };
        }
        if (res.status === 422) return { statusCode: 422, body: JSON.stringify({ error: "Invalid IP address" }) };
        if (res.status === 401) return { statusCode: 401, body: JSON.stringify({ error: "Invalid API key" }) };
        throw new Error(`HTTP error: ${res.status}`);
      }
      const data = await res.json();
      console.log("IP check response:", data);

      return {
        statusCode: 200,
        body: JSON.stringify({ type: "lookup", data })
      };
    } catch (err) {
      console.error("IP check error:", err);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: `Failed to fetch IP data: ${err.message}` })
      };
    }
  }

  // Handle combined FireHOL, Spamhaus, URLhaus, and MalwareBazaar fetch
  try {
    // Fetch FireHOL level1.netset
    const fireholRes = await fetchWithRetry("https://iplists.firehol.org/files/firehol_level1.netset");
    console.log("FireHOL fetch status:", fireholRes.status);
    if (!firefoxRes.ok) throw new Error(`FireHOL HTTP error: ${firefoxRes.status}`);
    const fireholText = await fireholRes.text();
    const fireholLines = fireholText.split("\n").filter(line => line && !line.startsWith("#"));
    const fireholFeed = fireholLines.slice(0, 50).map(line => ({
      ipAddress: line.trim(),
      status: "Malicious",
      source: "FireHOL"
    }));

    // Fetch Spamhaus DROP list
    const spamhausRes = await fetchWithRetry("https://www.spamhaus.org/drop/drop.txt");
    console.log("Spamhaus fetch status:", spamhausRes.status);
    if (!spamhausRes.ok) throw new Error(`Spamhaus HTTP error: ${spamhausRes.status}`);
    const spamhausText = await spamhausRes.text();
    const spamhausLines = spamhausText.split("\n").filter(line => line && !line.startsWith(";"));
    const spamhausFeed = spamhausLines.slice(0, 50).map(line => ({
      ipAddress: line.split(";")[0].trim(),
      status: "Malicious",
      source: "Spamhaus"
    }));

    // Combine IP feeds (deduplicate by ipAddress)
    const ipFeed = [...new Map([...firefoxFeed, ...spamhausFeed].map(item => [item.ipAddress, item])).values()].slice(0, 100);

    // Fetch URLhaus malicious domains
    const urlhausRes = await fetchWithRetry("https://urlhaus.abuse.ch/downloads/text/");
    console.log("URLhaus fetch status:", urlhausRes.status);
    if (!urlhausRes.ok) throw new Error(`URLhaus HTTP error: ${urlhausRes.status}`);
    const urlhausText = await urlhausRes.text();
    const urlhausLines = urlhausText.split("\n").filter(line => line && !line.startsWith("#"));
    const domainFeed = urlhausLines.slice(0, 50).map(line => {
      try {
        const url = new URL(line.trim().startsWith("http") ? line.trim() : `http://${line.trim()}`);
        return {
          domain: url.hostname,
          status: "Malicious",
          source: "URLhaus"
        };
      } catch {
        return null;
      }
    }).filter(item => item).slice(0, 50);

    // Fetch MalwareBazaar recent hashes
    const bazaarRes = await fetchWithRetry("https://bazaar.abuse.ch/export/csv/recent/");
    console.log("MalwareBazaar fetch status:", bazaarRes.status);
    if (!bazaarRes.ok) throw new Error(`MalwareBazaar HTTP error: ${bazaarRes.status}`);
    const bazaarText = await bazaarRes.text();
    const bazaarLines = bazaarText.split("\n").filter(line => line && !line.startsWith("#"));
    const hashFeed = bazaarLines.slice(1, 51).map(line => {
      const cols = line.split(",");
      const hash = cols[2]?.replace(/"/g, "");
      return hash && hash.length === 64 ? {
        hash,
        status: "Malicious",
        source: "MalwareBazaar"
      } : null;
    }).filter(item => item).slice(0, 50);

    console.log("Combined feed parsed:", {
      ipFeed: ipFeed.length,
      domainFeed: domainFeed.length,
      hashFeed: hashFeed.length
    });

    if (ipFeed.length === 0 && domainFeed.length === 0 && hashFeed.length === 0) {
      console.warn("No data in FireHOL/Spamhaus/URLhaus/MalwareBazaar response");
      return {
        statusCode: 200,
        body: JSON.stringify({ error: "No data returned from FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds" })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ type: "feed", ipFeed, domainFeed, hashFeed })
    };
  } catch (err) {
    console.error("Blocklist fetch error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: `Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds: ${err.message}` })
    };
  }
}

async function fetchWithRetry(url, apiKey = null, retries = 1, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    const headers = apiKey ? { Accept: "application/json", Key: apiKey } : {};
    const res = await fetch(url, { headers });
    console.log(`Fetch attempt ${i + 1} for ${url}: status ${res.status}`);

    if (res.ok) return res;

    if (res.status === 429 && i < retries) {
      const retryAfter = parseInt(res.headers.get("Retry-After")) || 60;
      console.log(`Rate limit hit, retrying after ${backoff * (i + 1)}ms`);
      await new Promise(resolve => setTimeout(resolve, backoff * (i + 1)));
      continue;
    }
    return res;
  }
}
