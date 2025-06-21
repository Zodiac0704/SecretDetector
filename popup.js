/* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/. */

document.addEventListener('DOMContentLoaded', () => {
    loadSecrets();
    
    document.getElementById('clearBtn').addEventListener('click', () => {
      if (confirm('Are you sure you want to clear all detected secrets?')) {
        browser.runtime.sendMessage({ action: 'clearSecrets' }, () => {
          loadSecrets();
        });
      }
    });
    
    document.getElementById('exportBtn').addEventListener('click', () => {
      browser.runtime.sendMessage({ action: 'getSecrets' }, secrets => {
        const now = new Date();
        const dateStr = now.toISOString().split('T')[0];
        const timeStr = now.toTimeString().split(' ')[0].replace(/:/g, '-');
        
        let domain = "unknown";
        if (secrets.length > 0 && secrets[0].file) {
          const fileSource = secrets[0].file;
          const domainMatch = fileSource.match(/^([^\s-]+)/);
          if (domainMatch && domainMatch[1]) {
            domain = domainMatch[1];
          }
        }
        
        const filename = `secrets_${domain}_${dateStr}_${timeStr}.json`;
        
        const json = JSON.stringify(secrets, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
      });
    });
});

function loadSecrets() {
  browser.runtime.sendMessage({ action: 'getSecrets' }, secrets => {
    const tableBody = document.getElementById('secretsTable');
    tableBody.innerHTML = '';
    
    if (secrets.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="4" class="text-muted text-center">No secrets detected.</td></tr>';
      return;
    }
    
    secrets.forEach(secret => {
      const row = document.createElement('tr');
      row.className = secret.type === 'Error' ? 'table-danger' : '';
      
      const contextTooltip = secret.context ? 
        `data-mdb-toggle="tooltip" title="${secret.context.replace(/"/g, '&quot;')}"` : '';
      
      row.innerHTML = `
        <td>${secret.type}</td>
        <td>${secret.value}</td>
        <td>${secret.file}</td>
        <td ${contextTooltip}>${secret.line}</td>
      `;
      tableBody.appendChild(row);
    });
    
    if (typeof mdb !== 'undefined' && mdb.Tooltip) {
      document.querySelectorAll('[data-mdb-toggle="tooltip"]').forEach(el => {
        new mdb.Tooltip(el);
      });
    }
  });

}
