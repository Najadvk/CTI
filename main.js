let refreshInterval;

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
    // No cache, show static feed for initial load if no cached data
    renderStaticFeeds(); // This will be replaced by actual data once fetched
    feedStatus.innerHTML = "Showing sample data. Click 'Refresh Feeds' to fetch latest threat intelligence.";
    startAutoRefresh();
    return;
  }

  // Fetch combined blocklist on refresh
  try {
    console.log("Attempting to fetch from /.netlify/functions/fetch-threats");
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
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
    console.error("Feed fetch error:", err);
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

  // Filter and render IP feed
  const ips = result.feed.filter(item => item.ipAddress);
  renderFeedList(ipFeedDiv, ips, 'ipAddress', 'IP');

  // Filter and render Domain feed
  const domains = result.feed.filter(item => item.domain);
  renderFeedList(domainFeedDiv, domains, 'domain', 'Domain');

  // Filter and render Hash feed
  const hashes = result.feed.filter(item => item.hash);
  renderFeedList(hashFeedDiv, hashes, 'hash', 'Hash');
}

function renderFeedList(container, items, keyField, type) {
  container.innerHTML = "";
  
  if (items.length === 0) {
    container.innerHTML = `<p style="color: #888; font-style: italic;">No ${type.toLowerCase()}s available</p>`;
    return;
  }

  // Create header with count
  const header = document.createElement('div');
  header.className = 'feed-header';
  header.innerHTML = `
    <h4 style="margin: 0; color: #4a9eff;">${items.length} ${type}${items.length > 1 ? 's' : ''}</h4>
    <button onclick="refreshFeed()" style="background: #4a9eff; border: none; color: white; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px;">↻ Refresh</button>
  `;
  container.appendChild(header);

  // Create scrollable list
  const listContainer = document.createElement('div');
  listContainer.className = 'feed-list';
  listContainer.style.cssText = `
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid #334466;
    border-radius: 6px;
    margin-top: 10px;
  `;

  items.slice(0, 100).forEach((item, index) => {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'feed-item';
    itemDiv.style.cssText = `
      padding: 8px 12px;
      border-bottom: 1px solid #334466;
      cursor: pointer;
      transition: background-color 0.2s;
      display: flex;
      justify-content: space-between;
      align-items: center;
    `;
    
    const value = item[keyField];
    const displayValue = type === 'Hash' ? `${value.substring(0, 16)}...` : value;
    
    itemDiv.innerHTML = `
      <div>
        <div style="color: #e1e8f0; font-weight: 500;">${displayValue}</div>
        <div style="color: #888; font-size: 12px;">${item.source} • ${item.category}</div>
      </div>
      <div style="text-align: right;">
        <div class="status-badge status-${item.status.toLowerCase()}" style="
          padding: 2px 6px;
          border-radius: 12px;
          font-size: 10px;
          font-weight: bold;
          text-transform: uppercase;
        ">${item.status}</div>
        <div style="color: #666; font-size: 10px; margin-top: 2px;">${item.confidence}</div>
      </div>
    `;
    
    itemDiv.onmouseover = () => {
      itemDiv.style.backgroundColor = '#334466';
    };
    
    itemDiv.onmouseout = () => {
      itemDiv.style.backgroundColor = 'transparent';
    };
    
    itemDiv.onclick = () => {
      document.getElementById("searchInput").value = value;
      searchIndicator();
      // Scroll to search result
      document.getElementById("searchResult").scrollIntoView({ behavior: 'smooth' });
    };
    
    listContainer.appendChild(itemDiv);
  });

  container.appendChild(listContainer);
}

function renderStaticFeeds() {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

 

  renderFeedList(ipFeedDiv, sampleIPs, 'ipAddress', 'IP');
  renderFeedList(domainFeedDiv, sampleDomains, 'domain', 'Domain');
  renderFeedList(hashFeedDiv, sampleHashes, 'hash', 'Hash');
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

  searchDiv.innerHTML = `
    <h3>Search Result</h3>
    <div style="display: flex; align-items: center; gap: 10px; margin: 15px 0;">
      <div class="loading-spinner"></div>
      <p>Searching ${inputType}: <strong>${input}</strong>...</p>
    </div>
  `;

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
    } else if (inputType === 'domain' && result.type === "lookup" && result.data) {
      renderDomainResult(result.data, searchDiv);
    } else if (inputType === 'hash' && result.type === "lookup" && result.data) {
      renderHashResult(result.data, searchDiv);
    } else {
      searchDiv.innerHTML += `<p style='color: #ff4d4d;'>No results found: ${result.error || "Unexpected response format"}</p>`;
    }
  } catch (err) {
    console.error("Search error:", err);
    searchDiv.innerHTML = `<h3>Search Result</h3><p style='color: #ff4d4d;'>Error: ${err.message}</p>`;
    
    // Show offline fallback for demonstration
    if (err.message.includes('Failed to fetch') || err.message.includes('HTTP error')) {
      renderOfflineFallback(searchDiv, input, inputType);
    }
  }
}

function renderOfflineFallback(container, input, type) {
  container.innerHTML += `
    <div class="result-card" style="
      background: linear-gradient(135deg, #334466 0%, #2a3a52 100%);
      border: 1px solid #4a5568;
      border-radius: 12px;
      padding: 20px;
      margin: 15px 0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 15px;">
        <div style="
          width: 40px;
          height: 40px;
          background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
        ">⚠️</div>
        <div>
          <h4 style="margin: 0; color: #ff6b35; font-size: 18px;">Offline Mode</h4>
          <p style="margin: 0; color: #a1b2c3; font-size: 14px;">Backend services unavailable</p>
        </div>
      </div>
      
      <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px; margin-bottom: 15px;">
        <h5 style="margin: 0 0 10px; color: #4a9eff;">Query Details</h5>
        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 8px; font-size: 14px;">
          <span style="color: #888;">Type:</span>
          <span style="color: #e1e8f0; text-transform: capitalize;">${type}</span>
          <span style="color: #888;">Value:</span>
          <span style="color: #e1e8f0; font-family: monospace;">${input}</span>
        </div>
      </div>
      
      <div style="margin-bottom: 15px;">
        <h5 style="margin: 0 0 10px; color: #4a9eff;">Would Query These Sources:</h5>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
          <div style="background: rgba(74, 158, 255, 0.1); padding: 8px; border-radius: 6px; border-left: 3px solid #4a9eff;">
            <strong style="color: #4a9eff;">AbuseIPDB</strong><br>
            <small style="color: #888;">IP reputation & abuse reports</small>
          </div>
          <div style="background: rgba(74, 158, 255, 0.1); padding: 8px; border-radius: 6px; border-left: 3px solid #4a9eff;">
            <strong style="color: #4a9eff;">ISC SANS DShield</strong><br>
            <small style="color: #888;">Threat intelligence feeds</small>
          </div>
          <div style="background: rgba(74, 158, 255, 0.1); padding: 8px; border-radius: 6px; border-left: 3px solid #4a9eff;">
            <strong style="color: #4a9eff;">PhishTank</strong><br>
            <small style="color: #888;">Phishing domain database</small>
          </div>
          <div style="background: rgba(74, 158, 255, 0.1); padding: 8px; border-radius: 6px; border-left: 3px solid #4a9eff;">
            <strong style="color: #4a9eff;">URLhaus</strong><br>
            <small style="color: #888;">Malware URL sharing</small>
          </div>
        </div>
      </div>
      
      <div style="background: rgba(255, 107, 53, 0.1); padding: 12px; border-radius: 6px; border-left: 3px solid #ff6b35;">
        <p style="margin: 0; font-size: 12px; color: #a1b2c3;">
          <strong>Note:</strong> Deploy to Netlify with proper API keys to enable full threat intelligence functionality.
        </p>
      </div>
    </div>
  `;
}

function renderIPResult(data, container) {
  const statusClass = data.abuseConfidenceScore >= 50 ? 'status-malicious' : 'status-clean';
  const verdict = data.abuseConfidenceScore >= 75 ? 'HIGH RISK' :
                 data.abuseConfidenceScore >= 50 ? 'MEDIUM RISK' :
                 data.abuseConfidenceScore >= 25 ? 'LOW RISK' : 'CLEAN';
  
  container.innerHTML += `
    <div class="result-card" style="
      background: linear-gradient(135deg, #334466 0%, #2a3a52 100%);
      border: 1px solid #4a5568;
      border-radius: 12px;
      padding: 20px;
      margin: 15px 0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
          <h4 style="margin: 0; color: #4a9eff; font-size: 20px;">IP Address Analysis</h4>
          <p style="margin: 5px 0 0; color: #888; font-size: 14px;">AbuseIPDB Report</p>
        </div>
        <div class="status-badge ${statusClass}" style="
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
        ">${verdict}</div>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px;">
        <div class="info-card">
          <h5 style="margin: 0 0 8px; color: #4a9eff;">Basic Information</h5>
          <div class="info-grid">
            <span>IP Address:</span><span style="font-family: monospace;">${data.ipAddress}</span>
            <span>Country:</span><span>${data.countryCode || 'Unknown'}</span>
            <span>ISP:</span><span>${data.isp || 'Unknown'}</span>
            <span>Usage Type:</span><span>${data.usageType || 'Unknown'}</span>
          </div>
        </div>
        
        <div class="info-card">
          <h5 style="margin: 0 0 8px; color: #4a9eff;">Threat Assessment</h5>
          <div class="info-grid">
            <span>Confidence Score:</span><span style="color: ${data.abuseConfidenceScore >= 50 ? '#ff4d4d' : '#4ade80'};">${data.abuseConfidenceScore}%</span>
            <span>Total Reports:</span><span>${data.totalReports || 0}</span>
            <span>Whitelisted:</span><span>${data.isWhitelisted ? 'Yes' : 'No'}</span>
            <span>Last Reported:</span><span>${data.lastReportedAt ? new Date(data.lastReportedAt).toLocaleDateString() : 'Never'}</span>
          </div>
        </div>
      </div>
      
      ${data.domain ? `
        <div class="info-card" style="margin-bottom: 15px;">
          <h5 style="margin: 0 0 8px; color: #4a9eff;">Domain Information</h5>
          <p style="margin: 0; font-family: monospace; color: #e1e8f0;">${data.domain}</p>
        </div>
      ` : ''}
      
      <div class="info-card">
        <h5 style="margin: 0 0 8px; color: #4a9eff;">Analysis Summary</h5>
        <p style="margin: 0; color: #e1e8f0; line-height: 1.5;">
          This IP address has been reported <strong>${data.totalReports || 0}</strong> times with an abuse confidence score of <strong>${data.abuseConfidenceScore}%</strong>.
          ${data.abuseConfidenceScore >= 75 ? 'This indicates a high likelihood of malicious activity.' :
            data.abuseConfidenceScore >= 50 ? 'This suggests potential suspicious activity.' :
            data.abuseConfidenceScore >= 25 ? 'This shows minimal suspicious activity.' :
            'This appears to be a clean IP address.'}
        </p>
      </div>
    </div>
  `;
}

function renderDomainResult(data, container) {
  container.innerHTML += `
    <div class="result-card" style="
      background: linear-gradient(135deg, #334466 0%, #2a3a52 100%);
      border: 1px solid #4a5568;
      border-radius: 12px;
      padding: 20px;
      margin: 15px 0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
          <h4 style="margin: 0; color: #4a9eff; font-size: 20px;">Domain Analysis</h4>
          <p style="margin: 5px 0 0; color: #888; font-size: 14px;">Threat Intelligence Report</p>
        </div>
        <div class="status-badge status-${data.status.toLowerCase()}" style="
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
          text-transform: uppercase;
        ">${data.status}</div>
      </div>
      
      <div class="info-card">
        <h5 style="margin: 0 0 8px; color: #4a9eff;">Domain Information</h5>
        <div class="info-grid">
          <span>Domain:</span><span style="font-family: monospace;">${data.indicator}</span>
          <span>Source:</span><span>${data.source}</span>
          <span>Category:</span><span style="text-transform: capitalize;">${data.category}</span>
          <span>Status:</span><span style="text-transform: capitalize; color: ${data.status === 'malicious' ? '#ff4d4d' : '#4ade80'};">${data.status}</span>
        </div>
      </div>
      
      <div class="info-card" style="margin-top: 15px;">
        <h5 style="margin: 0 0 8px; color: #4a9eff;">Analysis Summary</h5>
        <p style="margin: 0; color: #e1e8f0; line-height: 1.5;">
          This domain has been flagged as <strong>${data.status}</strong> by ${data.source}. 
          ${data.status === 'malicious' ? 'Exercise caution when accessing this domain.' : 'This domain appears to be safe.'}
        </p>
      </div>
    </div>
  `;
}

function renderHashResult(data, container) {
  container.innerHTML += `
    <div class="result-card" style="
      background: linear-gradient(135deg, #334466 0%, #2a3a52 100%);
      border: 1px solid #4a5568;
      border-radius: 12px;
      padding: 20px;
      margin: 15px 0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
          <h4 style="margin: 0; color: #4a9eff; font-size: 20px;">Hash Analysis</h4>
          <p style="margin: 5px 0 0; color: #888; font-size: 14px;">Malware Intelligence Report</p>
        </div>
        <div class="status-badge status-${data.status.toLowerCase()}" style="
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
          text-transform: uppercase;
        ">${data.status}</div>
      </div>
      
      <div class="info-card">
        <h5 style="margin: 0 0 8px; color: #4a9eff;">Hash Information</h5>
        <div class="info-grid">
          <span>Hash:</span><span style="font-family: monospace; word-break: break-all;">${data.indicator}</span>
          <span>Source:</span><span>${data.source}</span>
          <span>Category:</span><span style="text-transform: capitalize;">${data.category}</span>
          <span>Status:</span><span style="text-transform: capitalize; color: ${data.status === 'malicious' ? '#ff4d4d' : '#4ade80'};">${data.status}</span>
        </div>
      </div>
      
      <div class="info-card" style="margin-top: 15px;">
        <h5 style="margin: 0 0 8px; color: #4a9eff;">Analysis Summary</h5>
        <p style="margin: 0; color: #e1e8f0; line-height: 1.5;">
          This file hash has been identified as <strong>${data.status}</strong> by ${data.source}. 
          ${data.status === 'malicious' ? 'This file should be considered dangerous and quarantined.' : 'This file appears to be safe.'}
        </p>
      </div>
    </div>
  `;
}

// Initialize the application
document.addEventListener("DOMContentLoaded", function() {
  loadThreatFeeds();
  
  // Add search on Enter key
  document.getElementById("searchInput").addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
      searchIndicator();
    }
  });
});

