import fetch from "node-fetch";

export const handler = async (event) => {
  console.log("fetch-threats function invoked.");
  console.log("Query string parameters:", event.queryStringParameters);

  // Handle lookup (IP, domain, hash)
  if (event.queryStringParameters && (event.queryStringParameters.ip || event.queryStringParameters.domain || event.queryStringParameters.hash)) {
    const indicator = event.queryStringParameters.ip || event.queryStringParameters.domain || event.queryStringParameters.hash;
    const type = event.queryStringParameters.ip ? "ip" : event.queryStringParameters.domain ? "domain" : "hash";
    const abuseIpDbApiKey = process.env.ABUSEIPDB_API_KEY;

    if (!abuseIpDbApiKey && type === "ip") {
      console.error("AbuseIPDB API key not configured.");
      return { statusCode: 500, body: JSON.stringify({ error: "AbuseIPDB API key not configured." }) };
    }

    try {
      let url = "";
      let options = { method: "GET", headers: { Accept: "application/json" } };
      if (type === "ip") {
        url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose=true`;
        options.headers["Key"] = abuseIpDbApiKey;
      } else if (type === "domain") {
        url = `https://urlhaus-api.abuse.ch/v1/urls/recent/`;
      } else if (type === "hash") {
        url = `https://mb-api.abuse.ch/api/v1/`;
        options = { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ query: "get_info", hash: indicator }) };
      }

      const response = await fetchWithRetry(url, options);
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${type} API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      if (type === "domain") {
        const match = data.urls?.find((url) => new URL(url.url).hostname === indicator);
        return {
          statusCode: 200,
          body: JSON.stringify({
            type: "lookup",
            data: match
              ? { indicator, status: "malicious", source: "URLhaus", category: match.threat || "malware" }
              : { indicator, status: "clean", source: "URLhaus", category: "none" },
          }),
        };
      } else if (type === "hash") {
        return {
          statusCode: 200,
          body: JSON.stringify({
            type: "lookup",
            data: data.query_status === "ok"
              ? { indicator, status: "malicious", source: "MalwareBazaar", category: data.data?.[0]?.file_type || "malware" }
              : { indicator, status: "clean", source: "MalwareBazaar", category: "none" },
          }),
        };
      }
      return { statusCode: 200, body: JSON.stringify({ type: "lookup", data }) };
    } catch (error) {
      console.error(`${type} lookup error:`, error);
      return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
  }

  // Fetch feeds
  const feed = [];
  const errors = [];
  const MAX_ENTRIES_PER_FEED = 20; // Limit to ~1 MB total (20 entries × ~500 bytes × 5 sources ≈ 50 KB)

  // FireHOL
  try {
    const ipResponse = await fetchWithRetry("https://iplists.firehol.org/files/firehol_level1.netset");
    console.log("FireHOL fetch status:", ipResponse.status);
    if (!ipResponse.ok) throw new Error(`FireHOL fetch error: ${ipResponse.status}`);
    const ipText = await ipResponse.text();
    const ipLines = ipText.split("\n").filter((line) => line && !line.startsWith("#")).slice(0, MAX_ENTRIES_PER_FEED);
    feed.push(...ipLines.map((ip) => ({
      ipAddress: ip.trim(),
      status: "malicious",
      category: "blocklist",
      source: "FireHOL",
      confidence: "high",
      first_seen: new Date().toISOString(),
    })));
    console.log("FireHOL parsed:", ipLines.length, "IPs");
  } catch (error) {
    errors.push(`FireHOL: ${error.message}`);
    console.error("Error fetching FireHOL feed:", error);
  }

  // Spamhaus
  try {
    const spamhausResponse = await fetchWithRetry("https://www.spamhaus.org/drop/drop.txt");
    console.log("Spamhaus fetch status:", spamhausResponse.status);
    if (!spamhausResponse.ok) throw new Error(`Spamhaus fetch error: ${spamhausResponse.status}`);
    const spamhausText = await spamhausResponse.text();
    const spamhausLines = spamhausText.split("\n").filter((line) => line && !line.startsWith(";")).slice(0, MAX_ENTRIES_PER_FEED);
    feed.push(...spamhausLines.map((line) => ({
      ipAddress: line.split(";")[0].trim(),
      status: "malicious",
      category: "drop",
      source: "Spamhaus",
      confidence: "high",
      first_seen: new Date().toISOString(),
    })));
    console.log("Spamhaus parsed:", spamhausLines.length, "IPs");
  } catch (error) {
    errors.push(`Spamhaus: ${error.message}`);
    console.error("Error fetching Spamhaus feed:", error);
  }

  // URLhaus
  try {
    const urlhausResponse = await fetchWithRetry("https://urlhaus.abuse.ch/downloads/text/");
    console.log("URLhaus fetch status:", urlhausResponse.status);
    if (!urlhausResponse.ok) throw new Error(`URLhaus fetch error: ${urlhausResponse.status}`);
    const urlhausText = await urlhausResponse.text();
    const urlhausLines = urlhausText.split("\n").filter((line) => line && !line.startsWith("#")).slice(0, MAX_ENTRIES_PER_FEED);
    feed.push(
      ...urlhausLines
        .map((line) => {
          try {
            const url = new URL(line.trim().startsWith("http") ? line.trim() : `http://${line.trim()}`);
            return {
              domain: url.hostname,
              status: "malicious",
              category: "malware",
              source: "URLhaus",
              confidence: "high",
              first_seen: new Date().toISOString(),
            };
          } catch {
            return null;
          }
        })
        .filter((item) => item)
    );
    console.log("URLhaus parsed:", feed.filter((item) => item.domain).length, "domains");
  } catch (error) {
    errors.push(`URLhaus: ${error.message}`);
    console.error("Error fetching URLhaus feed:", error);
  }

  // MalwareBazaar
  try {
    const hashResponse = await fetchWithRetry("https://bazaar.abuse.ch/export/csv/recent/");
    console.log("MalwareBazaar fetch status:", hashResponse.status);
    if (!hashResponse.ok) throw new Error(`MalwareBazaar fetch error: ${hashResponse.status}`);
    const hashText = await hashResponse.text();
    const hashLines = hashText.split("\n").filter((line) => line && !line.startsWith("#")).slice(1, MAX_ENTRIES_PER_FEED + 1);
    feed.push(
      ...hashLines
        .map((line) => {
          const cols = line.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/);
          const hash = cols[2]?.replace(/"/g, "");
          return hash && hash.length === 64
            ? {
                hash,
                status: "malicious",
                category: cols[6]?.replace(/"/g, "") || "malware",
                source: "MalwareBazaar",
                confidence: "high",
                first_seen: cols[0]?.replace(/"/g, "") || new Date().toISOString(),
              }
            : null;
        })
        .filter((item) => item)
    );
    console.log("MalwareBazaar parsed:", feed.filter((item) => item.hash).length, "hashes");
  } catch (error) {
    errors.push(`MalwareBazaar: ${error.message}`);
    console.error("Error fetching MalwareBazaar feed:", error);
  }

  // AlienVault OTX (Optional)
  const otxApiKey = process.env.OTX_API_KEY || "YOUR_OTX_API_KEY_HERE";
  if (otxApiKey && otxApiKey !== "YOUR_OTX_API_KEY_HERE") {
    try {
      const otxResponse = await fetchWithRetry("https://otx.alienvault.com/api/v1/pulses/subscribed", {
        headers: { "X-OTX-API-KEY": otxApiKey },
      });
      console.log("OTX fetch status:", otxResponse.status);
      if (!otxResponse.ok) throw new Error(`OTX fetch error: ${otxResponse.status}`);
      const otxJson = await otxResponse.json();
      if (otxJson.results) {
        const otxEntries = [];
        otxJson.results.slice(0, 5).forEach((pulse) => {
          if (pulse.indicators) {
            pulse.indicators.slice(0, 4).forEach((indicator) => {
              const type = indicator.type;
              const indicatorValue = indicator.indicator;
              const source = "AlienVault OTX";
              const firstSeen = indicator.created || new Date().toISOString();
              if (type === "IPv4" || type === "IPv6") {
                otxEntries.push({
                  ipAddress: indicatorValue,
                  status: "malicious",
                  category: pulse.name,
                  source,
                  confidence: "medium",
                  first_seen: firstSeen,
                });
              } else if (type === "domain") {
                otxEntries.push({
                  domain: indicatorValue,
                  status: "malicious",
                  category: pulse.name,
                  source,
                  confidence: "medium",
                  first_seen: firstSeen,
                });
              } else if (type === "FileHash-MD5" || type === "FileHash-SHA1" || type === "FileHash-SHA256") {
                otxEntries.push({
                  hash: indicatorValue,
                  status: "malicious",
                  category: pulse.name,
                  source,
                  confidence: "medium",
                  first_seen: firstSeen,
                });
              }
            });
          }
        });
        feed.push(...otxEntries.slice(0, MAX_ENTRIES_PER_FEED));
        console.log("OTX parsed:", otxEntries.length, "items");
      }
    } catch (error) {
      errors.push(`OTX: ${error.message}`);
      console.error("Error fetching OTX feed:", error);
    }
  } else {
    console.warn("OTX API key not configured. Skipping OTX feed.");
  }

  console.log("Combined feed:", {
    ipCount: feed.filter((item) => item.ipAddress).length,
    domainCount: feed.filter((item) => item.domain).length,
    hashCount: feed.filter((item) => item.hash).length,
    totalSize: JSON.stringify({ type: "feed", feed, errors }).length,
  });

  if (feed.length === 0 && errors.length > 0) {
    return { statusCode: 200, body: JSON.stringify({ error: `Failed to fetch feeds: ${errors.join(", ")}`, errors }) };
  }

  return { statusCode: 200, body: JSON.stringify({ type: "feed", feed, errors }) };
};

async function fetchWithRetry(url, options/

System: = {}, retries = 2, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok) return response;
      if (response.status === 429 && i < retries) {
        const retryAfter = parseInt(response.headers.get("Retry-After") || backoff, 10);
        console.log(`Rate limit hit for ${url}, retrying after ${retryAfter}ms`);
        await new Promise((resolve) => setTimeout(resolve, retryAfter));
        continue;
      }
      return response;
    } catch (error) {
      if (i === retries) throw error;
      console.log(`Fetch error for ${url}, retrying after ${backoff}ms`);
      await new Promise((resolve) => setTimeout(resolve, backoff));
    }
  }
}
