# Phishing Check

A client-side web application that analyzes email headers and content to detect potential phishing attempts. All analysis happens locally in your browser - no data is sent to any server.

## Features

### Header Analysis
- **SPF Verification** - Checks if the sending server is authorized for the domain
- **DKIM Validation** - Verifies email signature authenticity
- **DMARC Compliance** - Checks domain-based message authentication
- **Sender Alignment** - Compares From, Reply-To, and Return-Path addresses
- **Typosquat Detection** - Identifies lookalike domains (e.g., `gmai1.com` vs `gmail.com`)
- **Display Name Spoofing** - Detects when display names contain deceptive email addresses

### Content Analysis
- Urgency and threat language detection
- Suspicious URL identification (IP addresses, URL shorteners, lookalike domains)
- Sensitive information request detection
- Generic greeting identification
- Text obfuscation detection
- Brand impersonation checks
- Tech support scam pattern recognition

## Usage

1. Open the application in your browser
2. Copy the full email headers (and optionally the body) from a suspicious email
3. Paste into the text area
4. Click "Phishing Check" to analyze

### How to Get Email Headers

**Gmail (Web):**
1. Open the email
2. Click the three-dot menu (More)
3. Select "Show original"

## Development

### Prerequisites
- Node.js

### Setup
```bash
npm install
```

### Run Development Server
```bash
npm run dev
```

### Build for Production
```bash
npm run build
```

### Preview Production Build
```bash
npm run preview
```

## Tech Stack
- Vite
- Vanilla JavaScript
- CSS

## Privacy

All analysis is performed entirely in your browser. No email content is transmitted to any external server.
