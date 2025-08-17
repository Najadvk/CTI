// main.js

// Helper: Map category to status badge
function getStatusBadge(category) {
  if (!category) return '<span class="status-badge status-clean">Unknown</span>';

  const c = category.toLowerCase();
  if (c.includes("drop") || c.includes("sbl") || c.includes("malware") || c.includes("botnet")) {
    return '<span class="status-badge status-malicious">Malicious</span>';
  }
  if (c.includes("pbl") || c.includes("policy")) {
    return '<span class="status-badge status-suspicious">Policy Blocked</span>';
  }
  if (c.includes("spam")) {
    return '<span class="status-badge status-suspicious">Spam Source</span>';
  }
  return '<span class="status-badge status-clean">Clean/Unknown</span>';
}

// Render feed items
function renderFeeds(feeds) {
  const container = document.getElementById("feed-container");
  container.innerHTML = ""; // clear existing

  feeds.forEach(item => {
    const badge = getStatusBadge(item.category);
    
    const feedEl = document.createElement("div");
    feedEl.classList.add("feed-item");
    feedEl.innerHTML = `
      <div class="feed-header">
        <span class="feed-ip">${item.ip}</span>
        ${badge}
      </div>
      <div class="feed-details">
        <p>Category: ${item.category || "Unknown"}</p>
        <p>Source: ${item.source || "N/A"}</p>
        <p>Added: ${item.date || "Unknown"}</p>
      </div>
    `;
    container.appendChild(feedEl);
  });
}

// Example usage
const exampleFeeds = [
  { ip: "192.0.2.1", category: "DROP", source: "Spamhaus", date: "2025-08-18" },
  { ip: "198.51.100.2", category: "PBL", source: "Spamhaus", date: "2025-08-18" },
  { ip: "203.0.113.5", category: "SBL", source: "Spamhaus", date: "2025-08-18" },
  { ip: "203.0.113.20", category: "Spam", source: "Spamhaus", date: "2025-08-18" },
  { ip: "203.0.113.50" } // unknown category
];

renderFeeds(exampleFeeds);
