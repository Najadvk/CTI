// /functions/fetch-threats.js
const fetch = require("node-fetch"); // Netlify Functions uses Node.js

exports.handler = async function () {
  try {
    // AbuseIPDB DROP list CSV (static)
    const url = "https://www.abuseipdb.com/blacklist?list=all&format=csv";

    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const text = await res.text();
    const lines = text.split("\n");

    let ips = {};
    let domains = {}; // You can add domain feeds later
    let hashes = {}; // You can add hash feeds later

    // Parse CSV: first line is headers
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const ip = line.split(",")[0].replace(/"/g, "");
      ips[ip] = "malicious";
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ ips, domains, hashes }),
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
};
