document.addEventListener("DOMContentLoaded", () => {
  console.log("Main.js: DOMContentLoaded fired");
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeSpan = document.querySelector(".detected");
  const summaryDiv = document.getElementById("summary");
  const errorDiv = document.getElementById("error");

  // Debug each DOM element
  console.log("Main.js: Checking DOM - search-form:", !!form);
  console.log("Main.js: Checking DOM - ioc:", !!input);
  console.log("Main.js: Checking DOM - results:", !!resultDiv);
  console.log("Main.js: Checking DOM - detected:", !!detectedTypeSpan);
  console.log("Main.js: Checking DOM - summary:", !!summaryDiv);
  console.log("Main.js: Checking DOM - error:", !!errorDiv);

  if (!form || !input || !resultDiv || !detectedTypeSpan || !summaryDiv) {
    console.error("Main.js: Missing DOM elements:", {
      "search-form": !!form,
      "ioc": !!input,
      "results": !!resultDiv,
      "detected": !!detectedTypeSpan,
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

  function getStatusColor(status) {
    status = String(status).toLowerCase();
    if (status.includes("malicious") || status === "error") return "red";
    if (status.includes("suspicious") || status.includes("unknown")) return "orange";
    if (status.includes("clean") || status.includes("safe")) return "green";
    return "black";
  }

  function detectIOC(ioc) {
    console.log("Main.js: Detecting IOC:", ioc);
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    console.warn("Main.js: Invalid IOC format:", ioc);
    return null;
  }

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
      detectedTypeSpan.innerText = "unknown";
      summaryDiv.innerText = "";
      return;
