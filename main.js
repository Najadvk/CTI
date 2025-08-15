console.log("Main.js: Script loaded (v3.0)");
document.addEventListener("DOMContentLoaded", () => {
  console.log("Main.js: DOMContentLoaded fired");
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeP = document.getElementById("detected-type");
  const summaryDiv = document.getElementById("summary");
  const errorDiv = document.getElementById("error");

  // Log DOM elements individually
  console.log("Main.js: DOM element - search-form:", !!form);
  console.log("Main.js: DOM element - ioc:", !!input);
  console.log("Main.js: DOM element - results:", !!resultDiv);
  console.log("Main.js: DOM element - detected-type:", !!detectedTypeP);
  console.log("Main.js: DOM element - summary:", !!summaryDiv);
  console.log("Main.js: DOM element - error:", !!errorDiv);

  // Check DOM elements
  if (!form || !input || !resultDiv || !detectedTypeP || !summaryDiv) {
    console.error("Main.js: Missing DOM elements:", {
      "search-form": !!form,
      "ioc": !!input,
      "results": !!resultDiv,
      "detected-type": !!detectedTypeP,
      "summary": !!summaryDiv
    });
    if (resultDiv) {
      resultDiv.innerHTML = "<p>Error: Required HTML elements missing. Check index.html or deployment.</p>";
    }
    if (errorDiv) {
      errorDiv.style.display = "block";
      errorDiv.innerText = "Error: Missing HTML elements. Check console (F12) for details.";
    }
    return;
  } else {
    if (errorDiv) errorDiv.style.display = "none";
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
    console.log("Main.js: Detecting IOC:", ioc);
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    console.warn("Main.js: Invalid IOC format:", ioc);
    return null;
  }

  // Fetch with retry
  async function fetchWithRetry(url, retries = 2) {
    console.log(`Main.js: Fetching ${url}`);
    for (let i = 0; i < retries; i++) {
      try {
        const res = await fetch(url, { method: 'GET' });
        if (res.ok) {
          const data = await res.json();
          console.log(`Main.js: Raw response from ${url}:`, JSON.stringify(data, null, 2));
          return data;
        }
        console.error(`Main.js: HTTP error from ${url}: ${res.status}`);
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        console.error(`Main.js: Attempt ${i + 1} failed for ${url}:`, err.message);
        if (i === retries - 1) {
          console.error(`Main.js: All retries failed for ${url}`);
          return { error: err.message };
        }
      }
    }
  }

  // Summarize results
  function summarizeResults(results) {
    console.log("Main.js: Summarizing results:", results);
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
    console.log("Main.js: Form submitted with IOC:", input.value);
    const ioc = input.value.trim();

    if (!ioc) {
      console.warn("Main.js: Empty IOC input");
      resultDiv.innerHTML = "<p>Please enter an IOC.</p>";
      detectedTypeP.innerText = "Detected: unknown";
      summaryDiv.innerText = "";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeP.innerText = `Detected: ${type || "unknown"}`;
    console.log("Main.js: Detected IOC type:", type);

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
        console.error(`Main.js: Row for ${source} not found`);
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
      console.error("Main.js: Error in fetch promises:", err);
      summaryDiv.innerText = "Error fetching results; check console for details.";
    }
  });
});
