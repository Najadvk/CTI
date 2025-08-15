document.addEventListener("DOMContentLoaded", () => {
  console.log("Main.js: DOMContentLoaded fired");

  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeSpan = document.querySelector(".detected");
  const summaryDiv = document.getElementById("summary");
  const errorDiv = document.getElementById("error");

  // Check required elements
  if (!form || !input || !resultDiv || !detectedTypeSpan || !summaryDiv) {
    console.warn("Main.js: Some DOM elements are missing. JS will run partially.", {
      "search-form": !!form,
      "ioc": !!input,
      "results": !!resultDiv,
      "detected": !!detectedTypeSpan,
      "summary": !!summaryDiv
    });
    if (resultDiv) resultDiv.innerHTML = "<p>Warning: Some UI elements are missing. Check HTML.</p>";
    if (errorDiv) {
      errorDiv.style.display = "block";
      errorDiv.innerText = "Warning: Missing some elements. Functionality may be limited.";
    }
  } else {
    if (errorDiv) errorDiv.style.display = "none";
  }

  function detectIOC(ioc) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) return "ip";
    if (/^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    return null;
  }

  async function fetchFreeData(iocType, iocValue) {
    try {
      if (iocType === "ip") {
        const res = await fetch(`http://ip-api.com/json/${iocValue}`);
        return await res.json();
      }
      // Add more free sources here if needed
      return { message: "No free data for this type" };
    } catch (err) {
      console.error("Fetch error:", err);
      return { error: err.message };
    }
  }

  if (form && input) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const ioc = input.value.trim();
      if (!ioc) return;

      const type = detectIOC(ioc);
      if (detectedTypeSpan) detectedTypeSpan.innerText = type || "unknown";

      const results = [];
      if (type) {
        const freeData = await fetchFreeData(type, ioc);
        results.push(freeData);
        if (resultDiv) resultDiv.innerHTML = `<pre>${JSON.stringify(freeData, null, 2)}</pre>`;
      } else {
        if (resultDiv) resultDiv.innerHTML = "<p>Invalid IOC format</p>";
      }
    });
  }
});
