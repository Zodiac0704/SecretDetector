# Secret Detector Browser Extension

<!-- This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
     If a copy of the MPL was not distributed with this file, You can obtain one at
     https://mozilla.org/MPL/2.0/. -->

## Overview

Secret Detector is a browser extension that scans web pages for sensitive information such as API keys, tokens, passwords, and other credentials. It helps security professionals, developers, and privacy-conscious users identify potential security risks on websites they visit.

## Features

- **Comprehensive Detection**: Identifies over 40 types of secrets including:
  - AWS Keys
  - Google API Keys
  - GitHub Tokens
  - Passwords
  - Private Keys (RSA, DSA, EC)
  - OAuth Tokens
  - And many more

- **Contextual Information**: Provides detailed context for each detected secret:
  - Secret type and value
  - Source file and location
  - Line number with context snippet
  - Page and element information

- **Smart Naming**: Generates descriptive names for sources based on:
  - Page URL and context
  - Script locations and IDs
  - Element attributes

- **Export Functionality**: Export detected secrets as JSON with:
  - Descriptive filenames including domain and timestamp
  - Complete secret details for further analysis

- **Secret Management**: Clear detected secrets with a single click

## Installation

### Firefox

1. Download the extension files
2. Open Firefox and navigate to `about:debugging`
3. Click "This Firefox"
4. Click "Load Temporary Add-on"
5. Select any file in the extension directory

### Chrome

1. Download the extension files
2. Open Chrome and navigate to `chrome://extensions`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the extension directory

## Usage

1. **Scanning**: The extension automatically scans web pages you visit
   - HTML content
   - Inline scripts
   - External scripts (same-origin or CORS-enabled)

2. **Viewing Results**: Click the extension icon in the toolbar to see detected secrets
   - The popup displays all detected secrets in a table
   - Hover over line numbers to see context snippets

3. **Managing Results**:
   - Click "Export as JSON" to save the results
   - Click "Clear All" to remove all detected secrets

## Technical Details

### Detection Mechanism

The extension uses a combination of:

- Regular expression pattern matching for known secret formats
- Entropy calculation to reduce false positives
- Context analysis to provide meaningful information

### File Structure

- `manifest.json`: Extension configuration
- `content.js`: Page scanning and secret detection
- `background.js`: Secret storage and message handling
- `popup.html`: User interface
- `popup.js`: UI interaction and export functionality
- `icon.png`: Extension icon

### Security Considerations

- All scanning is performed locally in the browser
- No data is sent to external servers
- Secrets are stored in memory only while the browser is open

## Development

### Adding New Secret Patterns

To add new secret patterns, modify the `patterns` array in both `content.js` and `background.js`:

```javascript
{ 
  type: 'New Secret Type', 
  regex: /your-regex-pattern/, 
  exclude: /optional-exclusion-pattern/ 
}
```

### Modifying the UI

The extension uses Material Design Bootstrap (MDB) for styling. Modify `popup.html` to change the UI appearance.

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## Privacy Policy

This extension:
- Does not collect or transmit any data
- Processes all information locally
- Does not use cookies or tracking
- Does not store any detected secrets beyond the current browser session
