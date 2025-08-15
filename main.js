document.getElementById("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ioc = document.getElementById("ioc").value.trim();
  const type = detectIOC(ioc);
  document.getElementById("detected-type").textContent = type || "unknown";
  if (!type) return;

  const res = await fetch(`/.netlify/functions/lookup-${type}?q=${encodeURIComponent(ioc)}`);
  const data = await res.json();
  renderResults(data);
});

function detectIOC(ioc) {
  if (/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(ioc)) return "ip";
  if (/^[a-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$/.test(ioc)) return "hash";
  if (/^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
  return null;
}

function renderResults(data) {
  document.getElementById("results").innerHTML =
    `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}
try {
  const response = await fetch(`/.netlify/functions/lookup-ip?q=${inputValue}`);
  if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
  const data = await response.json();
  console.log(data);
  resultDiv.textContent = JSON.stringify(data, null, 2);
} catch (err) {
  console.error(err);
  resultDiv.textContent = `Error: ${err.message}`;
}
