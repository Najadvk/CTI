let refreshInterval;

// Configuration for different threat intelligence sources
const TI_SOURCES = {
  abuseipdb: {
    name: 'AbuseIPDB',
    endpoint: '/.netlify/functions/fetch-threats',
    type: 'ip',
    enabled: true
  },
  virustotal: {
    name: 'VirusTotal',
    endpoint: '/.netlify/functions/virustotal-lookup',
    type: 'multi',
    enabled: false // Will be enabled when API is implemented
  },
  otx: {
    name: 'AlienVault OTX',
    endpoint: '/.netlify/functions/otx-lookup',
    type: 'multi',
    enabled: false // Will be enabled when API is implemented
  }
};

async function loadThreatFeeds(refresh = false) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");
  const feedStatus = document.getElementById("feedStatus");
  
  feedStatus.innerHTML = "Loading threat feeds...";
  ipFeedDiv.innerHTML = "Loading...";
  domainFeedDiv.innerHTML = "Loading...";
  hashFeedDiv.innerHTML = "Loading...";

  // Check for cached feed unless refreshing
  if (!refresh) {
    const cachedFeed = localStorage.getItem("threatFeed");
    const cacheTime = localStorage.getItem("threatFeedTime");
    const cacheAge = cacheTime ? (Date.now() - parseInt(cacheTime)) / (1000 * 60 * 60) : Infinity;

    console.log("Cache age (hours):", cacheAge, "Cached feed exists:", !!cachedFeed);

    if (cachedFeed && cacheAge < 24) {
      try {
        const result = JSON.parse(cachedFeed);
        console.log("Cached feed:", result);
        if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
          renderFeeds(result);
          feedStatus.innerHTML = "Loaded from cache (valid for 24 hours). Auto-updates every 10 minutes.";
          startAutoRefresh();
          return;
        } else {
          console.warn("Invalid cached feed structure");
          localStorage.removeItem("threatFeed");
          localStorage.removeItem("threatFeedTime");
        }
      } catch (err) {
        console.error("Failed to parse cached feed:", err);
        localStorage.removeItem("threatFeed");
        localStorage.removeItem("threatFeedTime");
      }
    }
    // No cache, show static feed
    renderStaticFeeds();
    feedStatus.innerHTML = "Showing sample data. Click 'Refresh Feeds' to fetch latest threat intelligence.";
    startAutoRefresh();
    return;
  }

  // Fetch combined blocklist on refresh
  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    
    if (!res.ok) {
      throw new Error(`HTTP error: ${res.status}`);
    }
    
    const result = await res.json();
    console.log("Fetch response:", result);

    if (result.error) {
      feedStatus.innerHTML = `Error: ${result.error}. Using cached data if available.`;
      const cachedFeed = localStorage.getItem("threatFeed");
      if (cachedFeed) {
        try {
          const cachedResult = JSON.parse(cachedFeed);
          if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
            renderFeeds(cachedResult);
            feedStatus.innerHTML += " Showing cached data due to error.";
            startAutoRefresh();
          } else {
            renderStaticFeeds();
            feedStatus.innerHTML = "No valid cached data. Failed to fetch threat intelligence.";
          }
        } catch (err) {
          renderStaticFeeds();
          feedStatus.innerHTML = "No valid cached data. Failed to fetch threat intelligence.";
          console.error("Failed to parse cached feed on error:", err);
          localStorage.removeItem("threatFeed");
          localStorage.removeItem("threatFeedTime");
        }
      } else {
        renderStaticFeeds();
        feedStatus.innerHTML = "No cached data. Failed to fetch threat intelligence.";
      }
      return;
    }

    if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      console.log("Cached new feed:", result);
      renderFeeds(result);
      feedStatus.innerHTML = "Fetched latest threat intelligence. Auto-updates every 10 minutes.";
      startAutoRefresh();
    } else {
      feedStatus.innerHTML = `No feed data available: ${result.error || "Unexpected response format"}`;
      renderStaticFeeds();
    }
  } catch (err) {
    console.error("Feed fetch error:", err);
    feedStatus.innerHTML = `Error: ${err.message}. Using cached data if available.`;
    
    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        const cachedResult = JSON.parse(cachedFeed);
        if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
          renderFeeds(cachedResult);
          feedStatus.innerHTML += " Showing cached data due to error.";
          startAutoRefresh();
        } else {
          renderStaticFeeds();
          feedStatus.innerHTML = "No valid cached data. Failed to fetch threat intelligence.";
        }
      } catch (err) {
        renderStaticFeeds();
        feedStatus.innerHTML = "No valid cached data. Failed to fetch threat intelligence.";
        console.error("Failed to parse cached feed on error:", err);
        localStorage.removeItem("threatFeed");
        localStorage.removeItem("threatFeedTime");
      }
    } else {
      renderStaticFeeds();
      feedStatus.innerHTML = "No cached data. Failed to fetch threat intelligence.";
    }
  }
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(() => loadThreatFeeds(true), 600000); // Refresh every 10 minutes
}

function renderFeeds(result) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  // Render IP feed
  const ipSelect = document.createElement("select");
  ipSelect.className = "feed-select";
  ipSelect.innerHTML = '<option value="">Select an IP</option>';
  
  if (result.feed && result.feed.length > 0) {
    result.feed.slice(0, 50).forEach(item => {
      const option = document.createElement("option");
      option.value = item.ipAddress;
      option.textContent = `${item.ipAddress} (${item.source})`;
      ipSelect.appendChild(option);
    });
  }
  
  ipFeedDiv.innerHTML = "";
  ipFeedDiv.appendChild(ipSelect);

  // Render domain feed (placeholder for now)
  domainFeedDiv.innerHTML = '<select class="feed-select"><option value="">No domain feeds available yet</option></select>';

  // Render hash feed (placeholder for now)
  hashFeedDiv.innerHTML = '<select class="feed-select"><option value="">No hash feeds available yet</option></select>';
}

function renderStaticFeeds() {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  // Render static IP feed
  const ipSelect = document.createElement("select");
  ipSelect.className = "feed-select";
  ipSelect.innerHTML = '<option value="">Select an IP</option>';
  const sampleIPs = [
    { ipAddress: "45.146.164.125", status: "Malicious", source: "Sample" },
    { ipAddress: "118.25.6.39", status: "Malicious", source: "Sample" },
    { ipAddress: "185.173.35.14", status: "Malicious", source: "Sample" },
    { ipAddress: "103.196.36.10", status: "Malicious", source: "Sample" },
    { ipAddress: "192.168.1.100", status: "Suspicious", source: "Sample" }
  ];
  sampleIPs.forEach(item => {
    const option = document.createElement("option");
    option.value = item.ipAddress;
    option.textContent = `${item.ipAddress} (${item.source})`;
    ipSelect.appendChild(option);
  });
  ipFeedDiv.innerHTML = "";
  ipFeedDiv.appendChild(ipSelect);

  // Render static domain feed
  const domainSelect = document.createElement("select");
  domainSelect.className = "feed-select";
  domainSelect.innerHTML = '<option value="">Select a domain</option>';
  const sampleDomains = [
    { domain: "malicious-example.com", status: "Malicious", source: "Sample" },
    { domain: "phishing-site.net", status: "Phishing", source: "Sample" },
    { domain: "spam-domain.org", status: "Spam", source: "Sample" },
    { domain: "suspicious-site.biz", status: "Suspicious", source: "Sample" }
  ];
  sampleDomains.forEach(item => {
    const option = document.createElement("option");
    option.value = item.domain;
    option.textContent = `${item.domain} (${item.source})`;
    domainSelect.appendChild(option);
  });
  domainFeedDiv.innerHTML = "";
  domainFeedDiv.appendChild(domainSelect);

  // Render static hash feed
  const hashSelect = document.createElement("select");
  hashSelect.className = "feed-select";
  hashSelect.innerHTML = '<option value="">Select a hash</option>';
  const sampleHashes = [
    { hash: "d41d8cd98f00b204e9800998ecf8427e", status: "Malicious", source: "Sample" },
    { hash: "098f6bcd4621d373cade4e832627b4f6", status: "Suspicious", source: "Sample" },
    { hash: "5d41402abc4b2a76b9719d911017c592", status: "Malicious", source: "Sample" },
    { hash: "e3b0c44298fc1c149afbf4c8996fb924", status: "Clean", source: "Sample" }
  ];
  sampleHashes.forEach(item => {
    const option = document.createElement("option");
    option.value = item.hash;
    option.textContent = `${item.hash.substring(0, 16)}... (${item.source})`;
    hashSelect.appendChild(option);
  });
  hashFeedDiv.innerHTML = "";
  hashFeedDiv.appendChild(hashSelect);
}

async function refreshFeed() {
  localStorage.removeItem("threatFeed");
  localStorage.removeItem("threatFeedTime");
  console.log("Cache cleared, refreshing feeds...");
  await loadThreatFeeds(true);
}

function validateInput(input, type) {
  switch (type) {
    case 'ip':
      const ipRegex = /^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/;
      return ipRegex.test(input);
    case 'domain':
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
      return domainRegex.test(input);
    case 'hash':
      const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
      return hashRegex.test(input);
    default:
      return false;
  }
}

function detectInputType(input) {
  if (validateInput(input, 'ip')) return 'ip';
  if (validateInput(input, 'domain')) return 'domain';
  if (validateInput(input, 'hash')) return 'hash';
  return 'unknown';
}

async function searchIndicator() {
  const input = document.getElementById("searchInput").value.trim();
  const searchDiv = document.getElementById("searchResult");

  if (!input) {
    searchDiv.innerHTML = "<h3>Search Result</h3><p style='color: #ff4d4d;'>Please enter an IP address, domain, or hash.</p>";
    return;
  }

  const inputType = detectInputType(input);
  
  if (inputType === 'unknown') {
    searchDiv.innerHTML = "<h3>Search Result</h3><p style='color: #ff4d4d;'>Invalid input. Please enter a valid IP address, domain, or hash.</p>";
    return;
  }

  searchDiv.innerHTML = `<h3>Search Result</h3><p>Searching ${inputType}: ${input}...</p>`;

  try {
    let endpoint = '';
    let queryParam = '';
    
    switch (inputType) {
      case 'ip':
        endpoint = '/.netlify/functions/fetch-threats';
        queryParam = `ip=${encodeURIComponent(input)}`;
        break;
      case 'domain':
        endpoint = '/.netlify/functions/fetch-threats';
        queryParam = `domain=${encodeURIComponent(input)}`;
        break;
      case 'hash':
        endpoint = '/.netlify/functions/fetch-threats';
        queryParam = `hash=${encodeURIComponent(input)}`;
        break;
    }

    const res = await fetch(`${endpoint}?${queryParam}`);
    console.log("Search response status:", res.status);
    
    if (!res.ok) {
      throw new Error(`HTTP error: ${res.status}`);
    }
    
    const result = await res.json();
    console.log("Search response:", result);

    searchDiv.innerHTML = "<h3>Search Result</h3>";

    if (result.error) {
      searchDiv.innerHTML += `<p style='color: #ff4d4d;'>Error: ${result.error}</p>`;
      return;
    }

    if (inputType === 'ip' && result.type === "lookup" && result.data && result.data.data) {
      renderIPResult(result.data.data, searchDiv);
    } else if (inputType === 'domain' && result.domain) {
      renderDomainResult(result, searchDiv);
    } else if (inputType === 'hash' && result.hash) {
      renderHashResult(result, searchDiv);
    } else {
      searchDiv.innerHTML += `<p style='color: #ff4d4d;'>No results found: ${result.error || "Unexpected response format"}</p>`;
    }
  } catch (err) {
    console.error("Search error:", err);
    searchDiv.innerHTML = `<h3>Search Result</h3><p style='color: #ff4d4d;'>Error: ${err.message}</p>`;
    
    // Show offline fallback for demonstration
    if (err.message.includes('Failed to fetch') || err.message.includes('HTTP error')) {
      searchDiv.innerHTML += `
        <div style="background-color: #334466; padding: 15px; border-radius: 6px; margin-top: 10px;">
          <p style="color: #ffaa00; margin: 0 0 10px;"><strong>⚠️ Offline Mode</strong></p>
          <p style="margin: 0;">The backend services are not available. This would normally query:</p>
          <ul style="margin: 10px 0; padding-left: 20px;">
            <li>AbuseIPDB for IP reputation</li>
            <li>VirusTotal for comprehensive analysis</li>
            <li>Multiple threat intelligence feeds</li>
          </ul>
          <p style="margin: 0; font-size: 12px; color: #a1b2c3;">Deploy to Netlify with proper API keys to enable full functionality.</p>
        </div>
      `;
    }
  }
}

function renderIPResult(data, container) {
  const statusClass = data.abuseConfidenceScore >= 50 ? 'status-malicious' : 'status-clean';
  const verdict = data.abuseConfidenceScore >= 75 ? 'HIGH RISK' : 
                 data.abuseConfidenceScore >= 50 ? 'MEDIUM RISK' : 
                 data.abuseConfidenceScore >= 25 ? 'LOW RISK' : 'CLEAN';
  
  container.innerHTML += `
    <div style="background-color: #334466; padding: 15px; border-radius: 6px; margin-top: 10px;">
      <table style="width: 100%; border-collapse: collapse;">
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">IP Address</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.ipAddress}</td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Verdict</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;" class="${statusClass}"><strong>${verdict}</strong></td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Abuse Score</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;" class="${statusClass}"><strong>${data.abuseConfidenceScore}%</strong></td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Country</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.countryCode || "N/A"}</td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">ISP</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.isp || "N/A"}</td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Domain</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.domain || "N/A"}</td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Usage Type</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.usageType || "N/A"}</td></tr>
        <tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #3b4a6b;">Last Reported</th><td style="padding: 8px; border-bottom: 1px solid #3b4a6b;">${data.lastReportedAt || "Never"}</td></tr>
        <tr><th style="text-align: left; padding: 8px;">Total Reports</th><td style="padding: 8px;">${data.totalReports || 0}</td></tr>
      </table>
    </div>
  `;
}

function renderDomainResult(data, container) {
  // Placeholder for domain results
  container.innerHTML += `
    <div style="background-color: #334466; padding: 1
(Content truncated due to size limit. Use page ranges or line ranges to read remaining content)
