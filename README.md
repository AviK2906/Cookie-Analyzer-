# Cookie & Session Hijacking Detector

A Chrome Extension that analyzes cookies, HTTP security headers, session behavior, and browser security configurations in real time.

The extension helps identify vulnerabilities that could lead to:

- Session Hijacking
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Mixed Content Attacks
- Tracking and Privacy Risks
- Security Header Misconfigurations

- <img width="499" height="669" alt="image" src="https://github.com/user-attachments/assets/3c0fdb26-aefe-447e-b362-d7edf8c6b249" />


---

## Features

### Cookie Security Analysis

The extension evaluates cookies using security best practices:

- Secure flag validation
- HttpOnly flag validation
- SameSite policy analysis
- Session cookie detection
- Domain scope analysis
- Tracker cookie identification

Each cookie receives a risk score and severity level.

<img width="486" height="670" alt="image" src="https://github.com/user-attachments/assets/a046f3ad-2656-4505-90c7-b6838f539558" />


---

### Session Hijacking Detection

The extension continuously monitors cookie changes and detects:

- Suspicious session mutations
- Authentication cookie modifications
- Session-related anomalies

Potential session hijacking indicators are highlighted.

---

### HTTP Security Header Analysis

The extension inspects response headers and evaluates:

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Missing or weak headers increase the overall security risk score.

<img width="493" height="749" alt="image" src="https://github.com/user-attachments/assets/4e9d70d7-5982-4748-a695-2d53e32c1743" />


---

### CSP Analysis

The extension identifies dangerous CSP configurations such as:

- unsafe-inline
- unsafe-eval
- Wildcard permissions (*)
- Missing script restrictions

These configurations are common causes of XSS vulnerabilities.

---

### Mixed Content Detection

Detects insecure HTTP resources loaded inside HTTPS pages.

Examples:

- HTTP images
- HTTP scripts
- HTTP stylesheets

Mixed content can expose users to man-in-the-middle attacks.

---

### Tracker Detection

Known tracking cookies and domains are identified using a built-in tracker database.

Examples include:

- Google Analytics
- Facebook Tracking
- DoubleClick
- TikTok Tracking
- Mixpanel
- Segment
- Intercom

---

### Threat Scoring Engine

The extension combines:

- Cookie Risk Score
- Security Header Score
- Tracker Presence
- Mixed Content Findings

into a unified threat assessment.

Risk Levels:

| Score | Level |
|---------|---------|
| 0-19 | Low |
| 20-39 | Medium |
| 40-59 | High |
| 60+ | Critical |

---

## Installation

### Developer Mode Installation

1. Download or clone the repository.

```bash
git clone https://github.com/YOUR_USERNAME/cookie-extension.git
```

2. Open Chrome.

3. Navigate to:

```
chrome://extensions
```

4. Enable **Developer Mode**.

5. Click **Load Unpacked**.

6. Select the project folder.

7. The extension should now appear in Chrome.

---

## Permissions

The extension requires the following permissions:

| Permission | Purpose |
|------------|----------|
| cookies | Analyze cookie security |
| webRequest | Inspect response headers |
| tabs | Access active tab information |
| activeTab | Analyze current page |
| storage | Save extension data |
| notifications | Alert users to security risks |

---

## Technologies Used

- JavaScript
- HTML
- CSS
- Chrome Extension Manifest V3

---

## Educational Purpose

This project was developed for educational and cybersecurity research purposes.

It is intended to help users understand:

- Browser security
- Cookie security
- Session management
- Security headers
- Web application attack vectors

---

## Disclaimer

This extension performs passive analysis only.

It does not exploit vulnerabilities, bypass security controls, or modify website behavior.

Users are responsible for complying with all applicable laws and organizational policies.

---

## Author

Avi 
