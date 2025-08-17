import fetch from "node-fetch";

export const handler = async () => {
  console.log("fetch-threats function invoked at", new Date().toISOString());

  // Fetch feeds (last 24 hours where possible)
  const feed = [];
  const errors = [];
  const MAX_ENTRIES_PER_FEED = 5; // Limit to ~2.5 KB per source (5 × ~500 bytes)
  const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
  const now = Date.now();

  // FireHOL (no timestamps, cap entries)
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

  // Spamhaus (no timestamps, cap entries)
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

  // URLhaus (24-hour recent feed)
  try {
    const urlhausResponse = await fetchWithRetry("https://urlhaus-api.abuse.ch/v1/urls/recent/", {
      headers: { Accept: "application/json" },
    });
    console.log("URLhaus fetch status:", urlhausResponse.status);
    if (!urlhausResponse.ok) throw new Error(`URLhaus fetch error: ${urlhausResponse.status}`);
    const urlhausJson = await urlhausResponse.json();
    const recentUrls = urlhausJson.urls
      ?.filter((url) => {
        const firstSeen = new Date(url.firstseen).getTime();
        return firstSeen && !isNaN(firstSeen) && now - firstSeen <= TWENTY_FOUR_HOURS_MS;
      })
      .slice(0, MAX_ENTRIES_PER_FEED)
      .map((url) => {
        try {
          const hostname = new URL(url.url.startsWith("http") ? url.url : `http://${url.url}`).hostname;
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
    console.log("URLhaus parsed:", recentUrls.length, "domains");
  } catch (error) {
    errors.push(`URLhaus: ${error.message}`);
    console.error("Error fetching URLhaus feed:", error);
  }

  // MalwareBazaar (24-hour filter from 48-hour feed)
  try {
    const hashResponse = await fetchWithRetry("https://bazaar.abuse.ch/export/csv/recent/");
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
        return firstSeen && hash && hash.length === 64 && firstSeenTime && !isNaN(firstSeenTime) && now - firstSeenTime <= TWENTY_FOUR_HOURS_MS
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
  const responseSize = JSON.stringify(responseBody).length;
  console.log("Combined feed:", {
    ipCount: feed.filter((item) => item.ipAddress).length,
    domainCount: feed.filter((item) => item.domain).length,
    hashCount: feed.filter((item) => item.hash).length,
    responseSizeBytes: responseSize,
  });

  if (responseSize > 5 * 1024 * 1024) {
    console.warn("Response size exceeds 5 MB, may trigger 413 error:", responseSize / 1024 / 1024, "MB");
  }

  if (feed.length === 0 && errors.length > 0) {
    return { statusCode: 200, body: JSON.stringify({ error: `Failed to fetch feeds: ${errors.join(", ")}`, errors }) };
  }

  return { statusCode: 200, body: JSON.stringify(responseBody) };
};

async function fetchWithRetry(url, options = {}, retries = 2, backoff = 1000) {
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
