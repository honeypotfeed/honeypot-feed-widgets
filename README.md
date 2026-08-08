# Honeypot Feed Widget

![npm](https://img.shields.io/npm/v/@honeypotfeed/honeypot-feed-widget)
![license](https://img.shields.io/npm/l/@honeypotfeed/honeypot-feed-widget)
![bundle size](https://img.shields.io/bundlephobia/minzip/@honeypotfeed/honeypot-feed-widget)

Embeddable widget for token honeypot detection on external websites. Lightweight, zero runtime dependencies, and fully customizable.

Scan any token across **15+ networks** (Ethereum, BSC, Solana, TRON, TON, and more) for scams, rugpulls, and honeypots.

## Features

- 🔍 **Full scan** — Buy/sell simulation, function analysis, ownership, liquidity, fees
- 🏷️ **Risk badge** — Inline badge showing risk score for any token
- 🔘 **Scan button** — Click-to-scan popup with results
- 🎨 **Shadow DOM** — Complete style isolation, no CSS conflicts
- 🌓 **Dark/Light/Auto** — Automatic theme detection
- 📱 **Responsive** — Works on all screen sizes
- 🔐 **Secure auth** — API key stays on your server, JWT in browser
- 📦 **Zero dependencies** — Pure TypeScript, no runtime deps

## Quick Start

### 1. Get Your API Key

1. Create a free account at [honeypotfeed.com](https://honeypotfeed.info/register)
2. Go to [Dashboard](https://honeypotfeed.info/dashboard) and generate an API key
3. Copy your key (starts with `sk_live_`)

### 2. Backend Setup (REQUIRED)

**The API key NEVER goes in frontend code.** Your backend obtains a JWT token:

```javascript
// Your backend (Node.js, Python, Go, etc.)
const response = await fetch('https://honeypotfeed.info/api/auth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ apiKey: process.env.HPF_API_KEY }),  // API key from env
})

const { token, expiresIn } = await response.json()
// Send 'token' to your frontend
```

### 3. Frontend Setup

#### NPM

```bash
npm install @honeypotfeed/honeypot-feed-widget
```

```javascript
import { HoneypotFeedWidget } from '@honeypotfeed/honeypot-feed-widget'

const widget = new HoneypotFeedWidget({
  apiUrl: 'https://honeypotfeed.info/api',
  token: token,  // JWT from your backend (NOT API key)
  theme: 'auto',
  defaultNetwork: 'ethereum',
  onScanComplete: (result) => {
    console.log('Risk score:', result.riskScore)
  },
})

await widget.mount('#my-container')
```

#### CDN

```html
<!-- Get JWT from your backend first -->
<script>
  window.honeypotFeedWidgetConfig = {
    apiUrl: 'https://honeypotfeed.info/api',
    token: 'eyJ...',  // JWT from your backend
    theme: 'dark',
  }
</script>
<script src="https://cdn.honeypotfeed.info/widget/v1/honeypot-feed-widget.js"></script>
```

## Security Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Your Backend   │────▶│  Honeypot API   │     │   Frontend      │
│  (holds API key)│     │  /auth/token    │     │   (gets JWT)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                              ▲
        │  apiKey: "sk_live_..."                       │
        │  (NEVER leaves server)                       │
        │                                              │
        │  token: "eyJ..."                             │
        └────────────── (sent via API) ────────────────┘
```

**Security Principles:**
- ✅ API key stays on your server (in environment variables)
- ✅ Only JWT tokens go to the browser
- ✅ JWT expires in 15 minutes
- ✅ Widget never handles API keys

## React Integration

### Installation

```bash
# React components are included in the main package
npm install @honeypotfeed/honeypot-feed-widget
```

### Usage

```tsx
import { HoneypotWidget } from '@honeypotfeed/honeypot-feed-widget/react'

function App() {
  const [token, setToken] = useState('')

  useEffect(() => {
    // Get JWT from YOUR backend
    fetch('/api/hpf-token')
      .then(r => r.json())
      .then(data => setToken(data.token))
  }, [])

  if (!token) return <div>Loading...</div>

  return (
    <HoneypotWidget
      apiUrl="https://honeypotfeed.info/api"
      token={token}
      theme="auto"
      onScanComplete={(result) => console.log(result)}
    />
  )
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | `string` | **Required** | Backend API URL |
| `token` | `string` | **Required** | JWT token from your backend |
| `theme` | `'light' \| 'dark' \| 'auto'` | `'auto'` | Color theme |
| `defaultNetwork` | `string` | `'ethereum'` | Default network ID |
| `networks` | `string[]` | All | Filter available networks |
| `showBranding` | `boolean` | `true` | Show "Powered by Honeypot Feed" |
| `onScanComplete` | `(result) => void` | — | Callback when scan completes |
| `onError` | `(error) => void` | — | Callback on error |

## API Methods

```javascript
// Scan programmatically
const result = await widget.scan('0x...', 'ethereum')

// Change network
widget.setNetwork('polygon')

// Set address programmatically
widget.setAddress('0x...')

// Update JWT token (when expired)
widget.setToken(newJwtToken)

// Destroy widget
widget.destroy()
```

## API Endpoints

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/auth/token` | POST | Exchange API key for JWT | API Key |
| `/api/auth/refresh` | POST | Refresh expired JWT | Refresh Token |
| `/api/scan` | POST | Scan a token | JWT Bearer |
| `/api/networks` | GET | Get supported networks | None |

## Development

```bash
git clone https://github.com/honeypot-feed/honeypot-feed-widget.git
cd honeypot-feed-widget
npm install
npm run dev          # Watch mode
npm run build        # Production build
npm run typecheck    # Type check
```

## Publishing

```bash
npm run build
npm publish
```

Or trigger via GitHub Actions by creating a tag:

```bash
git tag widget-v1.0.0
git push origin widget-v1.0.0
```

## License

MIT © [Honeypot Feed](https://honeypotfeed.info)
