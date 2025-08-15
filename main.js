// main.js
async function loadThreats() {
  const res = await fetch("/.netlify/functions/fetch-threats");
  const data = await res.json();
  displayThreats(data);
}

function displayThreats(data) {
  const results = document.getElementById("results");
  results.innerHTML = "";

  // Display IPs
  const ipList = Object.keys(data.ips);
  if (ipList.length > 0) {
    results.innerHTML += `<h2>Malicious IPs</h2><ul>${ipList.map(ip => `<li>${ip}</li>`).join("")}</ul>`;
  }

  // Display Domains
  const domainList = Object.keys(data.domains);
  if (domainList.length > 0) {
    results.innerHTML += `<h2>Malicious Domains</h2><ul>${domainList.map(d => `<li>${d}</li>`).join("")}</ul>`;
  }

  // Display Hashes
  const hashList = Object.keys(data.hashes);
  if (hashList.length > 0) {
    results.innerHTML += `<h2>Malicious Hashes</h2><ul>${hashList.map(h => `<li>${h}</li>`).join("")}</ul>`;
  }
}

// Search form
document.getElementById("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ioc = document.getElementById("ioc").value.trim();
  const res = await fetch("/.netlify/functions/fetch-threats");
  const data = await res.json();

  let detectedType = "unknown";
  if (data.ips[ioc]) detectedType = "IP";
  if (data.domains[ioc]) detectedType = "Domain";
  if (data.hashes[ioc]) detectedType = "Hash";

  document.getElementById("detected-type").innerText = detectedType;
});

window.onload = loadThreats;
