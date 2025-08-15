document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");
  const summaryDiv = document.getElementById("summary");

  const sources = {
    ip: ["abuseipdb", "virustotal", "talos", "xforce"],
    domain: ["virustotal", "talos", "xforce"],
    hash: ["virustotal", "hybridanalysis"]
  };

  // Helper to map status to color
  function getStatusColor(status) {
    status = String(status).toLowerCase();
    if (status.includes("malicious") || status.includes("bad") || status === "error") return "red";
    if (status.includes("suspicious") || status.includes("unknown")) return "orange";
    if (status.includes("clean") || status.includes("ok") || status === "safe") return "green";
    return "black";
  }

  // Strict IOC detection
  function detectIOC(ioc) {
    // IPv4 address (0-255 per octet)
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    // Domain (e.g., example.com, sub.example.co.uk)
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    // Hash (MD5: 32 chars, SHA-1: 40 chars, SHA-256: 64 chars)
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    return null;
  }

  // Fetch with retry logic
  async function fetchWithRetry(url, retries = 3) {
    for (let i = 0; i < retries; i++) {
      try {
        const res = await fetch(url);
        if (res.ok) return await res.json();
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        if (i === retries - 1) return { error: err.message };
      }
    }
  }

  // Summarize results for decision-making
  function summarizeResults(results) {
    const statuses = results.map(r => r.status.toLowerCase());
    const maliciousCount = statuses.filter(s => s.includes("malicious")).length;
    const cleanCount = statuses.filter(s => s.includes("clean") || s.includes("safe") || s.includes("ok")).length;
    const unknownCount = statuses.filter(s => s.includes("unknown") || s.includes("suspicious")).length;
    const errorCount = statuses.filter(s => s.includes("error")).length;

    let summary = "Summary: ";
    if (maliciousCount > cleanCount && maliciousCount > 0) {
      summary += `Likely malicious (${maliciousCount}/${results.length} sources report malicious).`;
    } else if (cleanCount > maliciousCount && cleanCount > 0) {
      summary += `Likely safe (${cleanCount}/${results.length} sources report clean/safe).`;
    } else if (unknownCount > 0) {
      summary += `Inconclusive (${unknownCount}/${results.length} sources report unknown/suspicious).`;
    } else if (errorCount === results.length) {
      summary += "All sources failed; try again later.";
    } else {
      summary += "Mixed results; review details for context.";
    }
    return summary;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();

    // Input validation
    if (!ioc) {
      resultDiv.innerHTML = "<p>Please enter an IOC.</p>";
      detectedTypeDiv.textContent = "";
      summaryDiv.textContent = "";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";

    if (!type) {
      resultDiv.innerHTML = "<p>Invalid IOC format. Please enter a valid IP, domain, or hash.</p>";
      summaryDiv.textContent = "";
      return;
    }

    // Initialize table with loading placeholders
    let tableHTML = `<table border="1" cellpadding="5" cellspacing="0">
      <thead>
        <tr><th>Source</th><th>Status</th><th>Details</th></tr>
      </thead>
      <tbody>`;
    sources[type].forEach(src => {
      tableHTML += `<tr id="row-${src}">
        <td>${src}</td>
        <td style="color: gray;">Loading...</td>
        <td>-</td>
      </tr>`;
    });
    tableHTML += "</tbody></table>";
    resultDiv.innerHTML = tableHTML;
    summaryDiv.textContent = "Fetching results...";

    // Fetch from all sources in parallel and store results
    const fetchPromises = sources[type].map(async (source) => {
      try {
        const data = await fetchWithRetry(`/.netlify/functions/lookup-${source}?q=${encodeURIComponent(ioc)}`);
        const row = document.getElementById(`row-${source}`);
        if (!row) return { source, status: "Error", details: "Row not found" };

        let statusText, detailsText;
        if (data.error) {
          statusText = "Error";
          detailsText = data.error;
        } else if (data.status) {
          statusText = data.status;
          detailsText = data.details || JSON.stringify(data);
        } else {
          statusText = "OK";
          detailsText = JSON.stringify(data);
        }

        row.cells[1].textContent = statusText;
        row.cells[1].style.color = getStatusColor(statusText);
        row.cells[2].textContent = detailsText;

        return { source, status: statusText, details: detailsText };
      } catch (err) {
        const row = document.getElementById(`row-${source}`);
        if (row) {
          row.cells[1].textContent = "Error";
          row.cells[1].style.color = "red";
          row.cells[2].textContent = err.message;
        }
        return { source, status: "Error", details: err.message };
      }
    });

    // Update summary after all fetches complete
    const results = await Promise.all(fetchPromises);
    summaryDiv.textContent = summarizeResults(results);
  });
});
