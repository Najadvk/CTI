document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeSpan = document.getElementById("detected-type");

  if (!form || !input || !resultDiv || !detectedTypeSpan) {
    console.error("Missing required HTML elements.");
    return;
  }

  // Detect IOC type
  function detectIOC(ioc) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "IP";
    if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(ioc)) return "Domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "Hash";
    return null;
  }

  // Fetch free IP info from ip-api.com
  async function fetchFreeData(type, ioc) {
    if (type === "IP") {
      try {
        const res = await fetch(`http://ip-api.com/json/${ioc}`);
        return await res.json();
      } catch (err) {
        return { error: err.message };
      }
    }
    // For domain and hash, just return the value (no free API)
    return { value: ioc, note: "No free data available" };
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    if (!ioc) {
      resultDiv.innerHTML = "<p>Please enter an IOC.</p>";
      detectedTypeSpan.innerText = "unknown";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeSpan.innerText = type || "unknown";

    if (!type) {
      resultDiv.innerHTML = "<p>Invalid IOC format.</p>";
      return;
    }

    resultDiv.innerHTML = "<p>Fetching data...</p>";
    const data = await fetchFreeData(type, ioc);
    resultDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  });
});
