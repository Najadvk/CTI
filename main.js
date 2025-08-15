const searchForm = document.getElementById("search-form");
const iocInput = document.getElementById("ioc");
const resultsDiv = document.getElementById("results");
const detectedType = document.getElementById("detected-type");

let feed = {};

async function loadFeed() {
  try {
    const res = await fetch("feed.json"); // your JSON database
    feed = await res.json();
  } catch (err) {
    resultsDiv.innerHTML = `<p style="color:red;">Failed to load feed</p>`;
    console.error(err);
  }
}

searchForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const query = iocInput.value.trim().toLowerCase();
  let output = "";

  if (feed.ips[query]) {
    const info = feed.ips[query];
    detectedType.textContent = "IP";
    output = `
      <p>Status: ${info.status}</p>
      <p>First Seen: ${info.first_seen || "N/A"}</p>
      <p>Last Seen: ${info.last_seen || "N/A"}</p>
      <p>Tags: ${info.tags ? info.tags.join(", ") : "N/A"}</p>
      <p>Source: ${info.source || "Unknown"}</p>
    `;
  } else if (feed.domains[query]) {
    const info = feed.domains[query];
    detectedType.textContent = "Domain";
    output = `
      <p>Status: ${info.status}</p>
      <p>First Seen: ${info.first_seen || "N/A"}</p>
      <p>Tags: ${info.tags ? info.tags.join(", ") : "N/A"}</p>
      <p>Source: ${info.source || "Unknown"}</p>
    `;
  } else if (feed.hashes[query]) {
    const info = feed.hashes[query];
    detectedType.textContent = "Hash";
    output = `
      <p>Status: ${info.status}</p>
      <p>Tags: ${info.tags ? info.tags.join(", ") : "N/A"}</p>
      <p>Source: ${info.source || "Unknown"}</p>
    `;
  } else {
    detectedType.textContent = "Unknown";
    output = `<p>No info found in feed</p>`;
  }

  resultsDiv.innerHTML = output;
});

// Load the feed on page load
loadFeed();
