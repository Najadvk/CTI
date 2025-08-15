// main.js

const form = document.getElementById("search-form");
const input = document.getElementById("ioc");
const resultsDiv = document.getElementById("results");
const detectedType = document.getElementById("detected-type");

let threatData = { ips: {}, domains: {}, hashes: {} };

// --- FETCH THREAT DATA FROM NETLIFY FUNCTION ---
async function fetchThreats() {
  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    threatData = await res.json();
    displayAllThreats();
  } catch (err) {
    resultsDiv.innerHTML = `<p style="color:red">Failed to load threat feed: ${err.message}</p>`;
  }
}

// --- DISPLAY ALL THREATS ---
function displayAllThreats() {
  let html = "<h2>All Threats</h2>";

  // IPs
  html += "<h3>Malicious IPs</h3><ul>";
  for (const ip in threatData.ips) {
    html += `<li>${ip} - ${threatData.ips[ip]}</li>`;
  }
  html += "</ul>";

  // Domains
  html += "<h3>Malicious Domains</h3><ul>";
  for (const domain in threatData.domains) {
    html += `<li>${domain} - ${threatData.domains[domain]}</li>`;
  }
  html += "</ul>";

  // Hashes
  html += "<h3>Malicious Hashes</h3><ul>";
  for (const hash in threatData.hashes) {
    html += `<li>${hash} - ${threatData.hashes[hash]}</li>`;
  }
  html += "</ul>";

  resultsDiv.innerHTML = html;
}

// --- SEARCH FUNCTION ---
form.addEventListener("submit", (e) => {
  e.preventDefault();
  const query = input.value.trim();
  if (!query) return;

  let found = false;

  if (threatData.ips[query]) {
    detectedType.textContent = `IP - ${threatData.ips[query]}`;
    found = true;
  } else if (threatData.domains[query]) {
    detectedType.textContent = `Domain - ${threatData.domains[query]}`;
    found = true;
  } else if (threatData.hashes[query]) {
    detectedType.textContent = `Hash - ${threatData.hashes[query]}`;
    found = true;
  } else {
    detectedType.textContent = "unknown";
  }

  if (found) {
    alert(`Threat found: ${query}`);
  }
});

// --- INITIAL LOAD ---
fetchThreats();
