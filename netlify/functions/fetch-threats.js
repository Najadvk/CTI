import fetch from "node-fetch";

export const handler = async (event, context) => {
  console.log("fetch-threats function invoked.");
  console.log("Query string parameters:", event.queryStringParameters);

  if (event.queryStringParameters && (event.queryStringParameters.ip || event.queryStringParameters.domain || event.queryStringParameters.hash)) {
    // Handle IP, Domain, or Hash lookup
    const indicator = event.queryStringParameters.ip || event.queryStringParameters.domain || event.queryStringParameters.hash;
    const type = event.queryStringParameters.ip ? 'ip' : (event.queryStringParameters.domain ? 'domain' : 'hash');
    const abuseIpDbApiKey = process.env.ABUSEIPDB_API_KEY;

    if (!abuseIpDbApiKey) {
      return { statusCode: 500, body: JSON.stringify({ error: "AbuseIPDB API key not configured." }) };
    }

    try {
      let url = '';
      if (type === 'ip') {
        url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${indicator}&maxAgeInDays=90&verbose=true`;
      } else if (type === 'domain') {
        // AbuseIPDB does not directly support domain lookups, so we'll simulate a response or use another API if available
        // For now, return a placeholder response
        return { statusCode: 200, body: JSON.stringify({ type: "lookup", data: { indicator: indicator, status: "clean", source: "Simulated", category: "N/A" } }) };
      } else if (type === 'hash') {
        // AbuseIPDB does not directly support hash lookups, so we'll simulate a response or use another API if available
        // For now, return a placeholder response
        return { statusCode: 200, body: JSON.stringify({ type: "lookup", data: { indicator: indicator, status: "clean", source: "Simulated", category: "N/A" } }) };
      }

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Key': abuseIpDbApiKey,
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`AbuseIPDB API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      return { statusCode: 200, body: JSON.stringify({ type: "lookup", data }) };
    } catch (error) {
      console.error("AbuseIPDB lookup error:", error);
      return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
  } else {
    // Handle feed fetching
    const feed = {
      ips: {},
      domains: {},
      hashes: {}
    };

    // ---------- Fetch IP feed (FireHOL) ----------
    try {
      const ipResponse = await fetch("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset");
      if (!ipResponse.ok) throw new Error(`FireHOL fetch error: ${ipResponse.status}`);
      const ipText = await ipResponse.text();
      const ipLines = ipText.split("\n").filter(line => line && !line.startsWith("#"));
      ipLines.forEach(ip => {
        feed.ips[ip] = {
          status: "malicious",
          category: "firehol",
          source: "FireHOL",
          confidence: "high",
          first_seen: new Date().toISOString()
        };
      });
    } catch (error) {
      console.error("Error fetching FireHOL feed:", error);
    }

    // ---------- Fetch IP feed (ISC SANS DShield Intelfeed) ----------
    try {
      const dshieldResponse = await fetch("https://isc.sans.edu/api/intelfeed?json");
      if (!dshieldResponse.ok) throw new Error(`DShield fetch error: ${dshieldResponse.status}`);
      const dshieldJson = await dshieldResponse.json();
      if (Array.isArray(dshieldJson)) {
        dshieldJson.forEach(item => {
          if (item.ip) {
            feed.ips[item.ip] = {
              status: "malicious",
              category: item.description || "dshield",
              source: "ISC SANS DShield",
              confidence: "high",
              first_seen: new Date().toISOString()
            };
          }
        });
      }
    } catch (error) {
      console.error("Error fetching ISC SANS DShield feed:", error);
    }

    // ---------- Fetch Domain feed (URLhaus) ----------
    try {
      const domainResponse = await fetch("https://urlhaus.abuse.ch/downloads/csv_recent/");
      if (!domainResponse.ok) throw new Error(`URLhaus fetch error: ${domainResponse.status}`);
      const domainText = await domainResponse.text();
      const domainLines = domainText.split("\n").filter(line => line && !line.startsWith("#")).slice(1); // skip header
      domainLines.forEach(line => {
        const cols = line.split(",");
        const domain = cols[2]?.replace(/"/g, ""); // Corrected index for domain
        if (domain) {
          feed.domains[domain] = {
            status: "malicious",
            category: cols[4]?.replace(/"/g, "") || "malware",
            source: "URLhaus",
            confidence: "high",
            first_seen: cols[1]?.replace(/"/g, "") || new Date().toISOString() // Corrected index for first_seen
          };
        }
      });
    } catch (error) {
      console.error("Error fetching URLhaus feed:", error);
    }

    // ---------- Fetch Domain feed (PhishTank) ----------
    try {
      const phishTankResponse = await fetch("http://data.phishtank.com/data/online-valid.json");
      if (!phishTankResponse.ok) throw new Error(`PhishTank fetch error: ${phishTankResponse.status}`);
      const phishTankJson = await phishTankResponse.json();
      if (Array.isArray(phishTankJson)) {
        phishTankJson.slice(0, 100).forEach(item => { // Limit to first 100 entries to avoid overwhelming the feed
          try {
            const url = new URL(item.url);
            const domain = url.hostname;
            if (domain) {
              feed.domains[domain] = {
                status: "malicious",
                category: "phishing",
                source: "PhishTank",
                confidence: "high",
                first_seen: item.submission_time || new Date().toISOString(),
                target: item.target || "Unknown"
              };
            }
          } catch (urlError) {
            console.warn("Invalid URL in PhishTank data:", item.url);
          }
        });
      }
    } catch (error) {
      console.error("Error fetching PhishTank feed:", error);
    }

    // ---------- Fetch Hash feed (MalwareBazaar) ----------
    try {
      const hashResponse = await fetch("https://mb-api.abuse.ch/api/v1/", {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'query=get_recent'
      });
      if (!hashResponse.ok) throw new Error(`MalwareBazaar fetch error: ${hashResponse.status}`);
      const hashJson = await hashResponse.json();
      if (hashJson.query_status === 'ok' && hashJson.data) {
        hashJson.data.slice(0, 100).forEach(item => { // Limit to first 100 entries
          if (item.sha256_hash) {
            feed.hashes[item.sha256_hash] = {
              status: "malicious",
              category: item.file_type || "malware",
              source: "MalwareBazaar",
              confidence: "high",
              first_seen: item.first_seen || new Date().toISOString(),
              file_name: item.file_name || "Unknown"
            };
          }
        });
      }
    } catch (error) {
      console.error("Error fetching MalwareBazaar feed:", error);
    }

    // ---------- Fetch AlienVault OTX feed ----------
    try {
      const otxApiKey = process.env.OTX_API_KEY || "YOUR_OTX_API_KEY_HERE"; // Use environment variable or placeholder
      if (otxApiKey && otxApiKey !== "YOUR_OTX_API_KEY_HERE") {
        // Example: Fetching pulses from OTX. You might need to adjust the endpoint and parsing based on specific OTX API usage.
        const otxResponse = await fetch("https://otx.alienvault.com/api/v1/pulses/subscribed", {
          headers: {
            "X-OTX-API-KEY": otxApiKey
          }
        });
        if (!otxResponse.ok) throw new Error(`AlienVault OTX fetch error: ${otxResponse.status}`);
        const otxJson = await otxResponse.json();

        if (otxJson.results) {
          otxJson.results.slice(0, 10).forEach(pulse => { // Limit to first 10 pulses
            if (pulse.indicators) {
              pulse.indicators.slice(0, 50).forEach(indicator => { // Limit indicators per pulse
                const type = indicator.type;
                const indicatorValue = indicator.indicator;
                const source = "AlienVault OTX";
                const firstSeen = indicator.created || new Date().toISOString();

                if (type === "IPv4" || type === "IPv6") {
                  feed.ips[indicatorValue] = {
                    status: "malicious",
                    category: pulse.name,
                    source: source,
                    confidence: "medium",
                    first_seen: firstSeen
                  };
                } else if (type === "domain") {
                  feed.domains[indicatorValue] = {
                    status: "malicious",
                    category: pulse.name,
                    source: source,
                    confidence: "medium",
                    first_seen: firstSeen
                  };
                } else if (type === "FileHash-MD5" || type === "FileHash-SHA1" || type === "FileHash-SHA256") {
                  feed.hashes[indicatorValue] = {
                    status: "malicious",
                    category: pulse.name,
                    source: source,
                    confidence: "medium",
                    first_seen: firstSeen
                  };
                }
              });
            }
          });
        }
      } else {
        console.warn("AlienVault OTX API key not configured or is placeholder. Skipping OTX feed.");
      }
    } catch (error) {
      console.error("Error fetching AlienVault OTX feed:", error);
    }

    const feedArray = [];
    for (const ip in feed.ips) {
      feedArray.push({ ipAddress: ip, ...feed.ips[ip] });
    }
    for (const domain in feed.domains) {
      feedArray.push({ domain: domain, ...feed.domains[domain] });
    }
    for (const hash in feed.hashes) {
      feedArray.push({ hash: hash, ...feed.hashes[hash] });
    }

    console.log("Feed object before returning:", feed);
    console.log("Feed array before returning:", feedArray.length, "items");
    return { statusCode: 200, body: JSON.stringify({ type: "feed", feed: feedArray }) };
  }
};

