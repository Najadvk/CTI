const feedUrl = "/feed.json"; // This is the JSON created by fetch-feed.js

let feedData = null;

// Fetch feed.json on page load
async function loadFeed() {
  try {
    const res = await fetch(feedUrl);
    feedData = await res.json();
    displayFeed(feedData);
  } catch (err) {
    console.error("Failed to load feed:", err);
    document.getElementById("results").innerHTML = "<p>Failed to load feed</p>";
  }
}

// Display the feed in a table
function displayFeed(feed) {
  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "";

  // IPs
  const ipTable = createTable("IPs", feed.ips);
  resultsDiv.appendChild(ipTable);

  // Domains
  const domainTable = createTable("Domains", feed.domains);
  resultsDiv.appendChild(domainTable);

  // Hashes
  const hashTable = createTable("Hashes", feed.hashes);
  resultsDiv.appendChild(hashTable);
}

// Create a table for a feed section
function createTable(title, data) {
  const section = document.createElement("div");
  section.innerHTML = `<h2>${title}</h2>`;

  const table = document.createElement("table");
  table.innerHTML = `
    <tr>
      <th>Value</th>
      <th>Status</th>
      <th>Category</th>
      <th>Source</th>
      <th>Confidence</th>
      <th>First Seen</th>
    </tr>
  `;

  for (const key in data) {
    const row = document.createElement("tr");
    const entry = data[key];
    row.innerHTML = `
      <td>${key}</td>
      <td>${entry.status}</td>
      <td>${entry.category}</td>
      <td>${entry.source}</td>
      <td>${entry.confidence}</td>
      <td>${entry.first_seen}</td>
    `;
    table.appendChild(row);
  }

  section.appendChild(table);
  return section;
}

// Search form
document.getElementById("search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const query = document.getElementById("ioc").value.trim();
  if (!feedData) return;

  const result = searchFeed(query);
  displayFeed(result);
});

// Search function
function searchFeed(query) {
  const result = { ips: {}, domains: {}, hashes: {} };
  if (feedData.ips[query]) result.ips[query] = feedData.ips[query];
  if (feedData.domains[query]) result.domains[query] = feedData.domains[query];
  if (feedData.hashes[query]) result.hashes[query] = feedData.hashes[query];
  return result;
}

// Load feed on page load
loadFeed();
