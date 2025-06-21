/* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/. */

const secrets = [];

browser.webRequest.onHeadersReceived.addListener(
  details => {
    return { responseHeaders: details.responseHeaders.filter(header => {
      return !header.name.toLowerCase().includes('access-control-allow-origin');
    }).concat([{ name: 'Access-Control-Allow-Origin', value: '*' }]) };
  },
  { urls: ['<all_urls>'], types: ['script'] },
  ['blocking', 'responseHeaders']
);

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'storeSecrets') {
    secrets.push(...message.secrets);
  } else if (message.action === 'getSecrets') {
    sendResponse(secrets);
  } else if (message.action === 'clearSecrets') {
    secrets.length = 0;
    sendResponse({ success: true });
  } else if (message.action === 'scanExternalScript') {
    fetch(message.url, { mode: 'cors' })
      .then(response => response.text())
      .then(text => {
        const lines = text.split('\n');
        const patterns = [
          { type: 'AWS Key', regex: /\bAKIA[0-9A-Z]{16}\b/, exclude: /AKIAIOSFODNN7EXAMPLE/ },
          { type: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, exclude: /AIzaSyDUMMYKEY1234567890EXAMPLE/ },
          { type: 'GitHub Token', regex: /\bghp_[0-9A-Za-z]{36}\b/, exclude: null },
          { type: 'Password', regex: /\b(password|pass|pwd)=["']?[^"'\s]{8,}\b/i, exclude: null },
          { type: 'Cloudinary', regex: /cloudinary:\/\/.*/, exclude: null },
          { type: 'Firebase URL', regex: /.*firebaseio\.com/, exclude: null },
          { type: 'Slack Token', regex: /(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})/, exclude: null },
          { type: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/, exclude: null },
          { type: 'SSH (DSA) Private Key', regex: /-----BEGIN DSA PRIVATE KEY-----/, exclude: null },
          { type: 'SSH (EC) Private Key', regex: /-----BEGIN EC PRIVATE KEY-----/, exclude: null },
          { type: 'PGP Private Key Block', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, exclude: null },
          { type: 'Amazon AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/, exclude: /AKIAIOSFODNN7EXAMPLE/ },
          { type: 'Amazon MWS Auth Token', regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, exclude: null },
          { type: 'AWS API Key', regex: /\bAKIA[0-9A-Z]{16}\b/, exclude: /AKIAIOSFODNN7EXAMPLE/ },
          { type: 'Facebook Access Token', regex: /EAACEdEose0cBA[0-9A-Za-z]+/, exclude: null },
          { type: 'Facebook OAuth', regex: /[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|"][0-9a-f]{32}['|"]/i, exclude: null },
          { type: 'GitHub', regex: /[g|G][i|I][t|T][h|H][u|U][b|B].*['|"][0-9a-zA-Z]{35,40}['|"]/i, exclude: null },
          { type: 'Generic API Key', regex: /[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|"][0-9a-zA-Z]{32,45}['|"]/i, exclude: null },
          { type: 'Generic Secret', regex: /[s|S][e|E][c|C][r|R][e|E][t|T].*['|"][0-9a-zA-Z]{32,45}['|"]/i, exclude: null },
          { type: 'Google Cloud Platform API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, exclude: /AIzaSyDUMMYKEY1234567890EXAMPLE/ },
          { type: 'Google Cloud Platform OAuth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, exclude: null },
          { type: 'Google Drive API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, exclude: /AIzaSyDUMMYKEY1234567890EXAMPLE/ },
          { type: 'Google Drive OAuth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, exclude: null },
          { type: 'Google (GCP) Service-account', regex: /"type":\s*"service_account"/, exclude: null },
          { type: 'Google Gmail API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, exclude: /AIzaSyDUMMYKEY1234567890EXAMPLE/ },
          { type: 'Google Gmail OAuth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, exclude: null },
          { type: 'Google OAuth Access Token', regex: /ya29\.[0-9A-Za-z\-_]+/, exclude: null },
          { type: 'Google YouTube API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, exclude: /AIzaSyDUMMYKEY1234567890EXAMPLE/ },
          { type: 'Google YouTube OAuth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, exclude: null },
          { type: 'Heroku API Key', regex: /[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/i, exclude: null },
          { type: 'MailChimp API Key', regex: /[0-9a-f]{32}-us[0-9]{1,2}/, exclude: null },
          { type: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/, exclude: null },
          { type: 'Password in URL', regex: /[a-zA-Z]{3,10}:\/\/[^\/\s:@]{3,20}:[^\/\s:@]{3,20}@.{1,100}["'\s]/, exclude: null },
          { type: 'PayPal Braintree Access Token', regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, exclude: null },
          { type: 'Picatic API Key', regex: /sk_live_[0-9a-z]{32}/, exclude: null },
          { type: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/, exclude: null },
          { type: 'Stripe API Key', regex: /sk_live_[0-9a-zA-Z]{24}/, exclude: null },
          { type: 'Stripe Restricted API Key', regex: /rk_live_[0-9a-zA-Z]{24}/, exclude: null },
          { type: 'Square Access Token', regex: /sq0atp-[0-9A-Za-z\-_]{22}/, exclude: null },
          { type: 'Square OAuth Secret', regex: /sq0csp-[0-9A-Za-z\-_]{43}/, exclude: null },
          { type: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/, exclude: null },
          { type: 'Twitter Access Token', regex: /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}/i, exclude: null },
          { type: 'Twitter OAuth', regex: /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|"][0-9a-zA-Z]{35,44}['|"]/i, exclude: null }
        ];

        function calculateEntropy(str) {
          const len = str.length;
          const frequencies = {};
          for (let char of str) {
            frequencies[char] = (frequencies[char] || 0) + 1;
          }
          return -Object.values(frequencies).reduce((sum, freq) => {
            const p = freq / len;
            return sum + (p * Math.log2(p));
          }, 0);
        }

        lines.forEach((line, index) => {
          patterns.forEach(pattern => {
            const matches = line.match(pattern.regex);
            if (matches) {
              matches.forEach(match => {
                if (pattern.exclude && pattern.exclude.test(match)) return;
                if (match.length > 20 && calculateEntropy(match) > 4.0) {
                  secrets.push({
                    type: pattern.type,
                    value: match,
                    file: message.url,
                    line: index + 1
                  });
                }
              });
            }
          });
        });
      })
      .catch(error => {
        secrets.push({
          type: 'Error',
          value: `Failed to fetch: ${message.url}`,
          file: message.url,
          line: 0
        });
      });
  }
});

// Scan external scripts
browser.webNavigation.onCompleted.addListener(details => {
  browser.tabs.executeScript(details.tabId, {
    code: `
      Array.from(document.querySelectorAll('script[src]')).forEach(script => {
        browser.runtime.sendMessage({
          action: 'scanExternalScript',
          url: script.src
        });
      });
    `
  });
});