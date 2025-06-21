/* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/. */

const secrets = [];
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

function scanText(text, source, lineOffset = 1) {
  const lines = text.split('\n');
  lines.forEach((line, index) => {
    patterns.forEach(pattern => {
      const matches = line.match(pattern.regex);
      if (matches) {
        matches.forEach(match => {
          if (pattern.exclude && pattern.exclude.test(match)) return;
          if (match.length > 20 && calculateEntropy(match) > 4.0) {
            const exactLineNumber = index + lineOffset;
            
            secrets.push({
              type: pattern.type,
              value: match,
              file: source,
              line: exactLineNumber,
              context: line.trim().substring(0, 50) + (line.length > 50 ? '...' : '')
            });
          }
        });
      }
    });
  });
}

function getPageName() {
  const url = window.location.href;
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  const pathname = urlObj.pathname;
  
  let pageName = pathname;
  if (pathname === '/' || pathname === '') {
    pageName = 'homepage';
  } else {
    pageName = pathname.split('/').filter(p => p).pop() || 'page';
    pageName = pageName.replace(/\.[^/.]+$/, '');
  }
  
  return `${hostname}${pageName !== 'homepage' ? '/' + pageName : ''}`;
}

function scanHTML() {
  const pageName = getPageName();
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT,
    {
      acceptNode: node => {
        if (node.parentNode.tagName === 'SCRIPT') return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );
  let node;
  while (node = walker.nextNode()) {
    if (node.nodeType === Node.TEXT_NODE) {
      scanText(node.textContent, `${pageName} - HTML Content`, 1);
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      for (let attr of node.attributes) {
        scanText(attr.value, `${pageName} - HTML Attribute: ${attr.name}`, 1);
      }
    }
  }
}

function scanInlineScripts() {
  const pageName = getPageName();
  const scripts = document.querySelectorAll('script:not([src])');
  scripts.forEach((script, index) => {
    const scriptId = script.id ? script.id : `script-${index + 1}`;
    let scriptLocation = '';
    if (script.hasAttribute('data-location')) {
      scriptLocation = script.getAttribute('data-location');
    } else if (script.parentElement) {
      if (script.parentElement.id) {
        scriptLocation = `in #${script.parentElement.id}`;
      } else if (script.parentElement.tagName) {
        scriptLocation = `in ${script.parentElement.tagName.toLowerCase()}`;
      }
    }
    
    const fileName = `${pageName} - Inline Script: ${scriptId}${scriptLocation ? ' ' + scriptLocation : ''}`;
    scanText(script.textContent, fileName, 1);
  });
}

async function scanExternalScripts() {
  const pageName = getPageName();
  const scripts = document.querySelectorAll('script[src]');
  for (let script of scripts) {
    const src = script.getAttribute('src');
    try {
      const url = new URL(src, window.location.href);
      
      let scriptName = url.pathname.split('/').pop() || 'unknown';
      
      if (url.origin === window.location.origin || script.crossOrigin) {
        const response = await fetch(url.href);
        if (response.ok) {
          const content = await response.text();
          const fileName = url.origin === window.location.origin ?
            `${pageName} - Local Script: ${scriptName}` :
            `${url.hostname} - External Script: ${scriptName}`;
          scanText(content, fileName, 1);
        }
      }
    } catch (error) {
      console.warn(`Failed to scan external script ${src}:`, error);
    }
  }
}

function reportSecrets() {
  browser.runtime.sendMessage({
    action: 'storeSecrets',
    secrets: secrets
  });
}

(async function() {
  scanHTML();
  scanInlineScripts();
  await scanExternalScripts();
  reportSecrets();
})();