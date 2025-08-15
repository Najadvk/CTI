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
    ip: ["virustotal"],
    domain: ["virustotal"],
    hash: ["virustotal"]
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
        const res = await fetch(url, { method: 'GET' });
        if (res.ok) {
          const data = await res.json();
          console.log(`Raw response from ${url}:`, JSON.stringify(data, null, 2));
          return data;
        }
        console.error(`HTTP error from ${url}: ${res.status}`);
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        console.error(`Attempt ${i + 1} failed for ${url}:`, err.message);
        if (i === retries - 1) {
          console.error(`All retries failed for ${url}`);
          return { error: err.message };
        }
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
    } else if (unknownCount > 0) {
      summary += `Inconclusive (${unknownCount}/${results.length} sources).`;
    } else if (errorCount === results.length) {
      summary += "All sources failed; check API setup or try again.";
    } else {
      summary += "Mixed results; review details.";
    }
    return summary;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    console.log("Form submitted with IOC:", input.value);
    const ioc = input.value.trim();

    if (!ioc) {
      console.warn("Empty IOC input");
      resultDiv.innerHTML = "<p>Please enter an IOC.</p>";
      detectedTypeSpan.innerText = "";
      summaryDiv.innerText = "";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeSpan.innerText = type || "unknown";
    console.log("Detected IOC type:", type);

    if (!type) {
      resultDiv.innerHTML = "<p>Invalid IOC format. Enter a valid IP, domain, or hash.</p>";
      summaryDiv.innerText = "";
      return;
    }

    let tableHTML = `<table class="source-table">
      <thead>
        <tr><th>Source</th><th>Status</th><th>Details</th></tr>
      </thead>
      <tbody>`;
    sources[type].forEach(src => {
      const sourceName = { virustotal: "VirusTotal" }[src] || src;
      tableHTML += `<tr id="row-${src}">
        <td>${sourceName}</td>
        <td style="color: gray;">Loading...</td>
        <td>-</td>
      </tr>`;
    });
    tableHTML += "</tbody></table>";
    resultDiv.innerHTML = tableHTML;
    summaryDiv.innerText = "Fetching results...";

    const fetchPromises = sources[type].map(async (source) => {
      const url = `/.netlify/functions/lookup-${source}?q=${encodeURIComponent(ioc)}`;
      const data = await fetchWithRetry(url);
      const row = document.getElementById(`row-${source}`);
      if (!row) {
        console.error(`Row for ${source} not found`);
        return { source, status: "Error", details: "Row not found" };
      }

      let statusText, detailsText;
      if (data.error) {
        statusText = "Error";
        detailsText = data.error;
      } else if (data.status) {
        statusText = data.status;
        detailsText = data.details || "No details available";
      } else {
        statusText = "Unknown";
        detailsText = "No data returned";
      }

      row.cells[1].innerText = statusText;
      row.cells[1].style.color = getStatusColor(statusText);
      row.cells[2].innerText = detailsText;

      return { source, status: statusText, details: detailsText };
    });

    try {
      const results = await Promise.all(fetchPromises);
      summaryDiv.innerText = summarizeResults(results);
    } catch (err) {
      console.error("Error in fetch promises:", err);
      summaryDiv.innerText = "Error fetching results; check console for details.";
    }
  });
});
