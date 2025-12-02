document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = decodeURIComponent(urlParams.get('url'));
  
  // Fixed URL display
  const blockedUrlElement = document.getElementById('blockedUrl');
  if (blockedUrlElement) {
    blockedUrlElement.textContent = blockedUrl;
  }

  // Risk display logic
  try {
      const response = await chrome.runtime.sendMessage({
          action: 'getRiskData',
          url: blockedUrl
      });
      
      document.getElementById('riskFill').style.width = `${response.risk_score}%`;
      document.getElementById('riskScore').textContent = `${response.risk_score}% Risk`;
      
      let flagsHTML = response.flags.map(flag => {
          let icon = "⚠️";
          let description = flag;
          
          // Enhance SSL error descriptions
          if (flag.includes('SSL Error') && flag.includes('expired')) {
              icon = "📅";
              description = "Expired Security Certificate - This website's security certificate has expired";
          } else if (flag.includes('Untrusted Certificate')) {
              icon = "🔓";
              description = "Untrusted Security Certificate - This website uses invalid security credentials";
          } else if (flag.includes('Unregistered Domain')) {
              icon = "🌐";
              description = "Unregistered Domain - This domain appears to be improperly registered";
          }
          
          return `<div class="risk-flag-item">
              <span class="risk-flag-icon">${icon}</span>
              <span>${description}</span>
          </div>`;
      }).join('');
      
      // Add AI analysis if available
      if (response.ai_analysis) {
          const ai = response.ai_analysis;
          if (ai.suspicious_keywords && ai.suspicious_keywords.length > 0) {
              flagsHTML += `
                  <div class="risk-flag-item">
                      <span class="risk-flag-icon">🤖</span>
                      <span>AI detected suspicious keywords: ${ai.suspicious_keywords.join(', ')}</span>
                  </div>`;
          }
          if (ai.urgency_score > 50) {
              flagsHTML += `
                  <div class="risk-flag-item">
                      <span class="risk-flag-icon">🚨</span>
                      <span>High urgency language detected (score: ${ai.urgency_score})</span>
                  </div>`;
          }
      }
      
      document.getElementById('reasonsList').innerHTML = flagsHTML;
      
  } catch (error) {
      document.getElementById('reasonsList').innerHTML =
          `<div class="risk-flag-item">❌ Error loading analysis: ${error.message}</div>`;
  }

  // Button handlers
  document.getElementById('proceedBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({
      action: 'allowUrl',
      url: blockedUrl
    }, () => {
      window.location.href = blockedUrl;
    });
  });

  document.getElementById('backBtn').addEventListener('click', () => {
    chrome.tabs.update({ url: 'https://www.google.com' });
  });
});
