const fetch = require("node-fetch");

exports.handler = async () => {
  try {
    // Example sources (free public threat feeds)
    const feeds = [
      "https://raw.githubusercontent.com/stamparm/ipsum/main/ipsum.txt", // Malicious IPs
      "https://mirror.cedia.org.ec/malwaredomains/justdomains", // Malicious Domains
    ];

    const threatData = { ips: {}, domains: {}, hashes: {} };

    // Fetch IPs
    const ipRes = await fetch(feeds[0]);
    const ipText = await ipRes.text();
    ipText.split("\n").forEach(line => {
      const ip = line.trim();
      if (ip) threatData.ips[ip] = "malicious";
    });

    // Fetch Domains
    const domRes = await fetch(feeds[1]);
    const domText = await domRes.text();
    domText.split("\n").forEach(line => {
      const dom = line.trim();
      if (dom && !dom.startsWith("#")) threatData.domains[dom] = "malicious";
    });

    return {
      statusCode: 200,
      body: JSON.stringify(threatData),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message }),
    };
  }
};
