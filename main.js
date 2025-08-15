document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeSpan = document.querySelector(".detected");
  const summaryDiv = document.getElementById("summary");
  const errorDiv = document.getElementById("error");

  if (!form || !input || !resultDiv || !detectedTypeSpan || !summaryDiv) {
    if (resultDiv) resultDiv.innerHTML = "<p>Error: Missing HTML elements.</p>";
    if (errorDiv) {
      errorDiv.style.display = "block";
      errorDiv.innerText = "Error: Missing HTML elements. Check console for details.";
    }
    return;
  } else if (errorDiv) {
    errorDiv.style.display = "none";
  }

  function getStatusColor(status) {
    status = String(status).toLowerCase();
    if (status.includes("malicious") || status === "error") return "red";
    if (status.includes("suspicious") || status.includes("unknown")) return "orange";
    if (status.includes("clean") || status.includes("safe") || status.includes("resolved")) return "green";
    return "black";
  }

  function detectIOC(ioc) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    return null;
  }

  function summarizeResults(results) {
    const statuses = results.map(r => r.status.toLowerCase());
    const maliciousCount = statuses.filter(s => s.includes("malicious")).length;
    const cleanCount = statuses.filter(s => s.includes("clean") || s.includes("safe") || s.includes("resolved")).length;
    const unknownCount = statuses.filter(s => s.includes("unknown") || s.includes("not found") || s.includes("suspicious")).length;
    const errorCount = statuses.filter(s => s.includes("error")).length;

    let summary = "Summary: ";
    if (maliciousCount > cleanCount && maliciousCount > 0) {
      summary += `Likely malicious (${maliciousCount}/${results.length} sources).`;
    } else if (cleanCount > maliciousCount && cleanCount > 0) {
      summary += `Likely safe (${cleanCount}/${results.length} sources).`;
    } else if (unknownCount > 0) {
      summary += `Inconclusive (${unknownCount}/${results.length} sources).`;
    } else if (errorCount === results.length) {
      summary += "All sources failed; check network or try again.";
    } else {
      summary += "Mixed results; review details.";
    }
    return summary;
  }

  async function fetchWithRetry(url, retries = 2) {
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

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    const type = detectIOC(ioc);
    detectedTypeSpan.innerText = type || "unknown";

    if (!ioc || !type) {
      resultDiv.innerHTML = "<p>Please enter a valid IOC (IP, domain, or hash).</p>";
      summaryDiv.innerText = "";
      return;
    }

    resultDiv.innerHTML = "<p>Fetching data...</p>";
    let results = [];

    if (type === "ip") {
      const data = await fetchWithRetry(`http://ip-api.com/json/${ioc}`);
      results.push({ source: "IP-API", status: data.status || "unknown", details: data });
    }

    if (type === "domain") {
      const data = await fetchWithRetry(`https://dns.google/resolve?name=${ioc}`);
      const status = data.Answer ? "resolved" : "not found";
      results.push({ source: "Google DNS", status, details: data });
    }

    if (type === "hash") {
      results.push({ source: "Local Check", status: "unknown", details: "No free hash reputation available" });
    }

    resultDiv.innerHTML = results.map(r => `
      <div style="color:${getStatusColor(r.status)};">
        <strong>${r.source}:</strong> ${r.status}
      </div>
    `).join("");

    summaryDiv.innerText = summarizeResults(results);
  });
});
