import fetch from "node-fetch";

export const handler = async () => {
  console.log("fetch-threats function invoked at", new Date().toISOString());

  const feed = [];
  const errors = [];
  const MAX_ENTRIES_PER_FEED = 5; // ~2.5 KB per source
  const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
  const now = Date.now();

  // FireHOL (prioritize level3 for malicious IPs, fallback to level2)
  try {
    let ipResponse;
    const fireholUrls = [
      "https://iplists.firehol.org/files/firehol_level3.netset",
      "https://iplists.firehol.org/files/firehol_level2.netset",
      "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
    ];
    for (const url of fireholUrls) {
      try {
        ipResponse = await fetchWithRetry(url, {
          headers: { "User-Agent": "CTI-SOC-Dashboard/1.0" },
        });
        console.log(`FireHOL fetch status for ${url}:`, ipResponse.status);
        if (ipResponse.ok) break;
        throw new Error(`FireHOL fetch error: ${ipResponse.status}`);
      } catch (error) {
        console.error(`Error fetching FireHOL from ${url}:`, error);
        if (url === fireholUrls[firebaseUrls.length - 1]) throw error;
      }
    }
    const ipText = await ipResponse.text();
    const ipLines = ipText
      .split("\n")
      .filter((line) => {
        const trimmed = line.trim();
        return trimmed && !trimmed.startsWith("#") && /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(trimmed);
      })
      .slice(0, MAX_ENTRIES_PER_FEED);
    if (ipLines.length === 0) throw new Error("FireHOL: No valid IPs found");
    feed.push(...ipLines.map((ip) => ({
      ipAddress: ip.trim(),
      status: "malicious",
      category: "malware/C2",
      source: "FireHOL",
      confidence: "high",
      first_seen: new Date().toISOString(),
    })));
    console.log("FireHOL parsed:", ipLines.length, "IPs");
  } catch (error) {
    errors.push(`FireHOL: ${error.message}`);
    console.error("Error fetching FireHOL feed:", error);
  }

  // Spamhaus (use DROP and EDROP for high-risk IPs)
  try {
    let spamhausResponse;
    const spamhausUrls = [
      "https://www.spamhaus.org/drop/edrop.txt",
      "https://www.spamhaus.org/drop/drop.txt",
    ];
    let spamhausLines = [];
    for (const url of spamhausUrls) {
      try {
        spamhausResponse = await fetchWithRetry(url, {
          headers: { "User-Agent": "CTI-SOC-Dashboard/1.0" },
        });
        console.log(`Spamhaus fetch status for ${url}:`, spamhausResponse.status);
        if (!spamhausResponse.ok) throw new Error(`Spamhaus fetch error: ${spamhausResponse.status}`);
        const spamhausText = await spamhausResponse.text();
        const lines = spamhausText
          .split("\n")
          .filter((line) => {
            const trimmed = line.trim();
            return trimmed && !trimmed.startsWith(";") && /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?/.test(trimmed.split(";")[0]);
          });
        spamhausLines.push(...lines.map((line) => ({
          ip: line.split(";")[0].trim(),
          priority: url.includes("edrop") ? 1 : 0, // Prioritize EDROP
        })));
      } catch (error) {
        console.error(`Error fetching Spamhaus from ${url}:`, error);
        if (url === spamhausUrls[spamhausUrls.length - 1] && spamhausLines.length === 0) throw error;
      }
    }
    spamhausLines = spamhausLines
      .sort((a, b) => b.priority - a.priority) // EDROP first
      .slice(0, MAX_ENTRIES_PER_FEED)
      .map(({ ip }) => ip);
    feed.push(...spamhausLines.map((ip) => ({
      ipAddress: ip,
      status: "malicious",
      category: "botnet/C2",
      source: "Spamhaus",
      confidence: "high",
      first_seen: new Date().toISOString(),
    })));
    console.log("Spamhaus parsed:", spamhausLines.length, "IPs");
  } catch (error) {
    errors.push(`Spamhaus: ${error.message}`);
    console.error("Error fetching Spamhaus feed:", error);
  }

  // URLhaus (24-hour recent feed, fallback URL)
  try {
    let urlhausResponse;
    const urlhausUrls = [
      "https://urlhaus-api.abuse.ch/v1/urls/recent/",
      "https://urlhaus.abuse.ch/downloads/csv/",
    ];
    for (const url of urlhausUrls) {
      try {
        urlhausResponse = await fetchWithRetry(url, {
          headers: { Accept: "application/json", "User-Agent": "CTI-SOC-Dashboard/1.0" },
        });
        console.log(`URLhaus fetch status for ${url}:`, urlhausResponse.status);
        if (urlhausResponse.ok) break;
        throw new Error(`URLhaus fetch error: ${urlhausResponse.status}`);
      } catch (error) {
        console.error(`Error fetching URLhaus from ${url}:`, error);
        if (url === urlhausUrls[urlhausUrls.length - 1]) throw error;
      }
    }
    if (urlhausResponse.url.includes("csv")) {
      const urlhausText = await urlhausResponse.text();
      const urlhausLines = urlhausText
        .split("\n")
        .filter((line) => line && !line.startsWith("#"))
        .slice(1)
        .map((line) => {
          const cols = line.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/);
          const firstSeen = cols[1]?.replace(/"/g, "");
          const url = cols[2]?.replace(/"/g, "");
          const firstSeenTime = firstSeen ? new Date(firstSeen).getTime() : null;
          return firstSeen && url && firstSeenTime && !isNaN(firstSeenTime) && now - firstSeenTime <= TWENTY_FOUR_HOURS_MS
            ? { firstseen: firstSeen, url, threat: cols[5]?.replace(/"/g, "") || "malware" }
            : null;
        })
        .filter((item) => item);
      const recentUrls = urlhausLines
        .slice(0, MAX_ENTRIES_PER_FEED)
        .map((url) => {
          try {
            const hostname = new URL(url.url.startsWith("http") ? url.url : `http://${url.url}`).hostname;
            if (!hostname || hostname.includes(" ")) return null;
            return {
              domain: hostname,
              status: "malicious",
              category: url.threat,
              source: "URLhaus",
              confidence: "high",
              first_seen: url.firstseen,
            };
          } catch {
            return null;
          }
        })
        .filter((item) => item);
      feed.push(...recentUrls);
      console.log("URLhaus parsed (CSV):", recentUrls.length, "domains");
    } else {
      const urlhausJson = await urlhausResponse.json();
      if (!urlhausJson.urls || !Array.isArray(urlhausJson.urls)) {
        throw new Error("URLhaus: Invalid response format");
      }
      const recentUrls = urlhausJson.urls
        .filter((url) => {
          const firstSeen = url.firstseen ? new Date(url.firstseen).getTime() : null;
          return firstSeen && !isNaN(firstSeen) && now - firstSeen <= TWENTY_FOUR_HOURS_MS;
        })
        .slice(0, MAX_ENTRIES_PER_FEED)
        .map((url) => {
          try {
            const hostname = new URL(url.url.startsWith("http") ? url.url : `http://${url.url}`).hostname;
            if (!hostname || hostname.includes(" ")) return null;
            return {
              domain: hostname,
              status: "malicious",
              category: url.threat || "malware",
              source: "URLhaus",
              confidence: "high",
              first_seen: url.firstseen,
            };
          } catch {
            return null;
          }
        })
        .filter((item) => item);
      feed.push(...recentUrls);
      console.log("URLhaus parsed (JSON):", recentUrls.length, "domains");
    }
  } catch (error) {
    errors.push(`URLhaus: ${error.message}`);
    console.error("Error fetching URLhaus feed:", error);
  }

  // MalwareBazaar (24-hour filter from 48-hour feed)
  try {
    const hashResponse = await fetchWithRetry("https://bazaar.abuse.ch/export/txt/sha256/recent/", {
      headers: { "User-Agent": "CTI-SOC-Dashboard/1.0" },
    });
    console.log("MalwareBazaar fetch status:", hashResponse.status);
    if (!hashResponse.ok) throw new Error(`MalwareBazaar fetch error: ${hashResponse.status}`);
    const hashText = await hashResponse.text();
    const hashLines = hashText.split("\n").filter((line) => line && !line.startsWith("#")).slice(1);
    const recentHashes = hashLines
      .map((line) => {
        const cols = line.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/);
        const firstSeen = cols[0]?.replace(/"/g, "");
        const hash = cols[2]?.replace(/"/g, "");
        const firstSeenTime = firstSeen ? new Date(firstSeen).getTime() : null;
        return firstSeen && hash && /^[a-fA-F0-9]{64}$/.test(hash) && firstSeenTime && !isNaN(firstSeenTime) && now - firstSeenTime <= TWENTY_FOUR_HOURS_MS
          ? {
              hash,
              status: "malicious",
              category: cols[6]?.replace(/"/g, "") || "malware",
              source: "MalwareBazaar",
              confidence: "high",
              first_seen: firstSeen,
            }
          : null;
      })
      .filter((item) => item)
      .slice(0, MAX_ENTRIES_PER_FEED);
    feed.push(...recentHashes);
    console.log("MalwareBazaar parsed:", recentHashes.length, "hashes");
  } catch (error) {
    errors.push(`MalwareBazaar: ${error.message}`);
    console.error("Error fetching MalwareBazaar feed:", error);
  }

  const responseBody = { type: "feed", feed, errors };
  const responseSize = Buffer.byteLength(JSON.stringify(responseBody), "utf8");
  console.log("Combined feed:", {
    ipCount: feed.filter((item) => item.ipAddress).length,
    domainCount: feed.filter((item) => item.domain).length,
    hashCount: feed.filter((item) => item.hash).length,
    responseSizeBytes: responseSize,
  });

  if (responseSize > 5 * 1024 * 1024) {
    console.warn("Response size exceeds 5 MB, may trigger 413 error:", responseSize / 1024 / 1024, "MB");
    return { statusCode: 200, body: JSON.stringify({ error: "Response too large, please try again later", errors }) };
  }

  if (feed.length === 0 && errors.length > 0) {
    return { statusCode: 200, body: JSON.stringify({ error: `Failed to fetch feeds: ${errors.join(", ")}`, errors }) };
  }

  return { statusCode: 200, body: JSON.stringify(responseBody) };
};

async function fetchWithRetry(url, options = {}, retries = 2, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetch(url, { ...options, headers: { ...options.headers, "User-Agent": "CTI-SOC-Dashboard/1.0" } });
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
