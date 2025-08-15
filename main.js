document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

  // Form submit handler
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";

    if (!type) {
      resultDiv.textContent = "Unable to detect IOC type.";
      return;
    }

    try {
      const url = `/.netlify/functions/lookup-${type}?q=${encodeURIComponent(ioc)}`;
      console.log("Fetching:", url);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      resultDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    } catch (err) {
      console.error(err);
      resultDiv.textContent = `Error: ${err.message}`;
    }
  });

  // IOC type detection
  function detectIOC(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    return null;
  }
});
