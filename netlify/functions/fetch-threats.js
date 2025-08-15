// /functions/fetch-threats.js
const fetch = require("node-fetch");

exports.handler = async function () {
  try {
    // Sources: Public threat feeds
    const feeds = {
      ips: [
        "https://www.abuseipdb.com/blacklist?format=csv", // example CSV feed
        "https://www.spamhaus.org/drop/drop.txt"
      ],
      domains: [
        "https://otx.alienvault.com/api/v1/indicators/export?type=domain&limit=50"
      ],
      hashes: [
        "https://bazaar.abuse.ch/export/txt/recent/"
      ]
    };

    const result = { ips: {}, domains: {}, hashes: {} };

    // --- FETCH IPS ---
    for (const url of feeds.ips) {
      const res = await fetch(url);
      const text = await res.text();
      text.split("\n").forEach(line => {
        const ip = line.trim();
        if (ip && !ip.startsWith("#")) result.ips[ip] = "malicious";
      });
    }

    // --- FETCH DOMAINS ---
    for (const url of feeds.domains) {
      const res = await fetch(url);
      const data = await res.json();
      data.forEach(item => {
        if (item.indicator) result.domains[item.indicator] = "malicious";
      });
    }

    // --- FETCH HASHES ---
    for (const url of feeds.hashes) {
      const res = await fetch(url);
      const text = await res.text();
      text.split("\n").forEach(line => {
        const hash = line.trim();
        if (hash && hash.length >= 32) result.hashes[hash] = "malicious";
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify(result)
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
};
