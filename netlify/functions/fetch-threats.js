// netlify/functions/fetch-threats.js
import fetch from "node-fetch";

let cachedFeed = null;
let lastFetchTime = null;

export async function handler(event) {
  try {
    const params = event.queryStringParameters;
    const now = Date.now();

    // Refresh if cache is empty or older than 24h
    if (!cachedFeed || !lastFetchTime || (now - lastFetchTime > 24 * 60 * 60 * 1000)) {
      console.log("Refreshing threat feeds...");

      const feeds = { ips: {}, domains: {}, hashes: {} };

      // --- FireHOL Malicious IPs ---
      try {
        const res = await fetch("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset");
        const text = await res.text();
        text.split("\n").forEach(ip => {
          if (ip && !ip.startsWith("#")) {
            feeds.ips[ip.trim()] = {
              indicator: ip.trim(),
              status: "malicious",
              source: "FireHOL"
            };
          }
        });
      } catch (err) {
        console.error("FireHOL fetch failed:", err.message);
      }

      // --- URLhaus Malicious Domains ---
      try {
        const res = await fetch("https://urlhaus.abuse.ch/downloads/text/");
        const text = await res.text();
        text.split("\n").forEach(line => {
          if (line && !line.startsWith("#")) {
            feeds.domains[line.trim()] = {
              indicator: line.trim(),
              status: "malicious",
              source: "URLhaus"
            };
          }
        });
      } catch (err) {
        console.error("URLhaus fetch failed:", err.message);
      }

      // --- MalwareBazaar Hashes ---
      try {
        const res = await fetch("https://bazaar.abuse.ch/export/txt/md5/recent/");
        const text = await res.text();
        text.split("\n").forEach(line => {
          if (line && /^[a-f0-9]{32}$/i.test(line)) {
            feeds.hashes[line.trim()] = {
              indicator: line.trim(),
              status: "malicious",
              source: "MalwareBazaar"
            };
          }
        });
      } catch (err) {
        console.error("MalwareBazaar fetch failed:", err.message);
      }

      cachedFeed = feeds;
      lastFetchTime = now;
    }

    // --- Lookup mode ---
    if (params && params.type && params.indicator) {
      const { type, indicator } = params;

      if (type === "ip" && cachedFeed.ips[indicator]) {
        return { statusCode: 200, body: JSON.stringify({ type: "lookup", data: cachedFeed.ips[indicator] }) };
      } else if (type === "domain" && cachedFeed.domains[indicator]) {
        return { statusCode: 200, body: JSON.stringify({ type: "lookup", data: cachedFeed.domains[indicator] }) };
      } else if (type === "hash" && cachedFeed.hashes[indicator]) {
        return { statusCode: 200, body: JSON.stringify({ type: "lookup", data: cachedFeed.hashes[indicator] }) };
      } else {
        return {
          statusCode: 200,
          body: JSON.stringify({ type: "lookup", data: { indicator, status: "unknown", source: "cached feeds" } })
        };
      }
    }

    // --- Feed mode (return everything) ---
    return { statusCode: 200, body: JSON.stringify({ type: "feed", feed: cachedFeed }) };

  } catch (err) {
    console.error("Handler failed:", err);
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
}
