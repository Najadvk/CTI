const fetch = require("node-fetch");

exports.handler = async function () {
  try {
    const url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);

    const text = await res.text();
    const lines = text.split("\n");

    let ips = {};
    lines.forEach(line => {
      line = line.trim();
      if (!line || line.startsWith("#")) return; // skip comments
      ips[line] = "malicious";
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ ips, domains: {}, hashes: {} }),
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};
