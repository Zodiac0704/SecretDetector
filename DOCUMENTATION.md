# Secret Detector - Technical Documentation

<!-- This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
     If a copy of the MPL was not distributed with this file, You can obtain one at
     https://mozilla.org/MPL/2.0/. -->

## Architecture Overview

The Secret Detector browser extension is built using standard web technologies and follows a modular architecture with three main components:

1. **Content Script** (`content.js`): Executes in the context of web pages to scan for secrets
2. **Background Script** (`background.js`): Manages persistent state and handles message passing
3. **Popup UI** (`popup.html` and `popup.js`): Provides the user interface for viewing and managing detected secrets

## Component Details

### Content Script (content.js)

The content script is injected into web pages and performs the following functions:

#### Secret Detection

- **Pattern Matching**: Uses regular expressions to identify over 40 types of secrets
- **Entropy Calculation**: Reduces false positives by calculating the entropy of potential secrets
- **Context Extraction**: Captures surrounding text to provide context for each detected secret

#### Page Scanning

- **HTML Content**: Scans text nodes and element attributes
- **Inline Scripts**: Examines script tags without src attributes
- **External Scripts**: Fetches and scans same-origin or CORS-enabled external scripts

#### Source Naming

Generates descriptive source names for detected secrets:

- **HTML Content**: `hostname/pathname - HTML Content`
- **HTML Attributes**: `hostname/pathname - HTML Attribute: attributeName`
- **Inline Scripts**: `hostname/pathname - Inline Script: scriptId [location]`
- **External Scripts**: 
  - Local: `hostname/pathname - Local Script: filename`
  - External: `hostname - External Script: filename`

### Background Script (background.js)

The background script manages the extension's state and handles cross-component communication:

#### State Management

- Maintains an in-memory array of detected secrets
- Handles storage and retrieval of secrets
- Provides functionality to clear all stored secrets

#### CORS Handling

- Modifies response headers to allow cross-origin script scanning
- Enables fetching external scripts that would otherwise be blocked by CORS

#### Message Handling

Processes messages from the content script and popup:

- `storeSecrets`: Adds newly detected secrets to the storage
- `getSecrets`: Returns all stored secrets to the popup
- `clearSecrets`: Removes all stored secrets
- `scanExternalScript`: Fetches and scans external scripts

### Popup UI (popup.html, popup.js)

The popup provides a user interface for viewing and managing detected secrets:

#### UI Components

- Table display of detected secrets with type, value, file, and line information
- Export functionality for saving secrets as JSON
- Clear button for removing all detected secrets
- Tooltips showing context snippets when hovering over line numbers

#### Export Functionality

Generates descriptive filenames for exported JSON files:

- Format: `secrets_[domain]_[date]_[time].json`
- Example: `secrets_example.com_2023-05-15_14-30-22.json`

## Data Flow

1. Content script scans the page and detects secrets
2. Detected secrets are sent to the background script via messages
3. Background script stores the secrets in memory
4. When the popup is opened, it requests secrets from the background script
5. Popup displays the secrets and provides management options

## Security Considerations

- All scanning is performed locally in the browser
- No data is sent to external servers
- Secrets are stored only in memory and are cleared when the browser is closed
- The extension has access only to pages that the user visits

## Extension Permissions

- `activeTab`: Access to the current tab's content
- `webRequest` and `webRequestBlocking`: Modify headers for CORS handling
- `<all_urls>`: Access to all websites for scanning
- `storage`: For potential future persistent storage implementation

## Performance Optimization

- Entropy calculation reduces false positives
- Asynchronous scanning of external scripts
- Efficient DOM traversal using TreeWalker API
- Exclusion patterns for common test values

## Future Enhancements

- Persistent storage option for long-term tracking
- Custom pattern definition by users
- Severity classification for detected secrets
- Integration with security scanning services
- Automated reporting capabilities