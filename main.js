document.addEventListener("DOMContentLoaded", () => {
  console.log("Main.js loaded, DOM ready");
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.querySelector(".results");
  const detectedTypeSpan = document.querySelector(".detected");
  const summaryDiv = document.getElementById("summary");

  // Verify DOM elements
  if (!form || !input || !resultDiv || !detectedTypeSpan || !summaryDiv) {
    console.error("Missing DOM elements:", { form, input, resultDiv, detectedTypeSpan, summaryDiv });
    resultDiv.innerHTML = "<p>Error: Required HTML elements missing. Check index.html.</p>";
    return;
  }

  const sources = {
    ip: ["abuseipdb", "virustotal", "otx", "threatfox"],
    domain: ["virustotal", "otx", "threatfox"],
    hash: ["virustotal", "otx", "threatfox"]
  };

  // Map status to color
  function getStatusColor(status) {
    status = String(status).toLowerCase();
    if (status.includes("malicious") || status === "error") return "red";
    if (status.includes("suspicious") || status.includes("unknown")) return "orange";
    if (status.includes("clean") || status.includes("safe")) return "green";
    return "black";
  }

  // IOC detection
  function detectIOC(ioc) {
    console.log("Detecting IOC:", ioc);
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    console.warn("Invalid IOC format:", ioc);
    return null;
  }

  // Fetch with retry
  async function fetchWithRetry(url, retries = 2) {
    console.log(`Fetching: ${url}`);
    for (let i = 0; i < retries; i++) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          const data = await res.json();
          console.log(`Raw response from ${url}:`, data);
          return data;
        }
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        console.error(`Attempt ${i + 1} failed for ${url}:`, err.message);
        if (i === retries - 1) return { error: err.message };
      }
    }
  }

  // Summarize results
  function summarizeResults(results) {
    console.log("Summarizing results:", results);
    const statuses = results.map(r => r.status.toLowerCase());
    const maliciousCount = statuses.filter(s => s.includes("malicious")).length;
    const cleanCount = statuses.filter(s => s.includes("clean") || s.includes("safe")).length;
    const unknownCount = statuses.filter(s => s.includes("unknown") || s.includes("suspicious")).length;
    const errorCount = statuses.filter(s => s.includes("error")).length;

    let summary = "Summary: ";
    if (maliciousCount > cleanCount && maliciousCount > 0) {
      summary += `Likely malicious (${maliciousCount}/${results.length} sources).`;
    } else if (cleanCount > maliciousCount && cleanCount > 0) {
      summary += `Likely safe (${cleanCount}/${results.length} sources).`;
    } else if (unknown
