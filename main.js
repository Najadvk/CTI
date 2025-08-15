document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";
    if (!type) return;

    try {
      const res = await fetch(`/.netlify/functions/lookup-${type}?q=${encodeURIComponent(ioc)}`);
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();
      renderResults(data);
    } catch (err) {
      console.error(err);
      resultDiv.textContent = `Error: ${err.message}`;
    }
  });

  function detectIOC(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
    if (/^[a-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$/.test(ioc)) return "hash";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    return null;
  }

  function renderResults(data) {
    resultDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }
});
