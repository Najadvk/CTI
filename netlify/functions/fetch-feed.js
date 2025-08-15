import fetch from "node-fetch";
import fs from "fs";
import path from "path";

const feedFile = path.join(process.cwd(), "feed.json");

export async function handler() {
  try {
    const feed = {
      ips: {},
      domains: {},
      hashes: {}
    };

    // ---------- Fetch IP feed ----------
    const ipResponse = await fetch("https://raw.githubusercontent.com/ktsaou/firehol/master/firehol_level1.netset");
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

    // ---------- Fetch Domain feed ----------
    const domainResponse = await fetch("https://urlhaus.abuse.ch/downloads/csv_recent/");
    const domainText = await domainResponse.text();
    const domainLines = domainText.split("\n").slice(1); // skip header
    domainLines.forEach(line => {
      const cols = line.split(",");
      const domain = cols[1]?.replace(/"/g, "");
      if (domain) {
        feed.domains[domain] = {
          status: "malicious",
          category: cols[4]?.replace(/"/g, "") || "malware",
          source: "URLhaus",
          confidence: "high",
          first_seen: cols[2]?.replace(/"/g, "") || new Date().toISOString()
        };
      }
    });

    // ---------- Fetch Hash feed ----------
    const hashResponse = await fetch("https://mb-api.abuse.ch/api/v1/");
    const hashJson = await hashResponse.json();
    if (hashJson.data) {
      hashJson.data.forEach(item => {
        feed.hashes[item.sha256] = {
          status: "malicious",
          category: item.file_type || "malware",
          source: "MalwareBazaar",
          confidence: "high",
          first_seen: item.date_added || new Date().toISOString()
        };
      });
    }

    // ---------- Save feed.json ----------
    fs.writeFileSync(feedFile, JSON.stringify(feed, null, 2));
    return { statusCode: 200, body: "Feed updated successfully!" };

  } catch (error) {
    console.error(error);
    return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
  }
}
