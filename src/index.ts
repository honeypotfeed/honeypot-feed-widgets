/**
 * Honeypot Feed Widget
 * Embeddable widget for honeypot detection on external websites
 *
 * SECURITY ARCHITECTURE:
 * ──────────────────────
 * The API key NEVER leaves your backend server. The flow is:
 *
 *   1. YOUR BACKEND calls POST /api/auth/token { apiKey: "sk_live_..." }
 *   2. YOUR BACKEND receives JWT token: { token: "eyJ...", expiresIn: 900 }
 *   3. YOUR BACKEND sends JWT to frontend (via API, session, etc.)
 *   4. FRONTEND widget uses JWT for all requests: Authorization: Bearer <token>
 *   5. JWT expires in 15 minutes - frontend must request new JWT from your backend
 *
 * The widget ONLY accepts a JWT token. It NEVER handles API keys.
 *
 * Usage:
 *   // Backend (Node.js, Python, etc.)
 *   const response = await fetch('https://honeypotfeed.com/api/auth/token', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ apiKey: process.env.HPF_API_KEY }),
 *   })
 *   const { token } = await response.json()
 *
 *   // Frontend (browser)
 *   import { HoneypotFeedWidget } from 'honeypot-feed-widget'
 *   const widget = new HoneypotFeedWidget({
 *     apiUrl: 'https://honeypotfeed.com/api',
 *     token: token,  // JWT from your backend
 *   })
 *   await widget.mount('#my-container')
 */

interface WidgetConfig {
  apiUrl: string
  token: string  // JWT token from your backend (NOT API key)
  theme?: 'light' | 'dark' | 'auto'
  defaultNetwork?: string
  networks?: string[]
  showBranding?: boolean
  container?: string | HTMLElement
  onScanComplete?: (result: ScanResult) => void
  onError?: (error: Error) => void
}

interface ScanResult {
  network: string
  chain: string
  address: string
  tokenInfo: TokenInfo | null
  simulation: SimulationResult | null
  functionAnalysis: FunctionAnalysis | null
  ownership: OwnershipInfo | null
  liquidity: LiquidityInfo | null
  fees: FeeInfo | null
  riskScore: number
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'honeypot'
  reasons: string[]
  timestamp: string
}

interface TokenInfo {
  address: string
  name: string | null
  symbol: string | null
  decimals: number | null
  totalSupply: string | null
  owner: string | null
  isContract: boolean
}

interface SimulationResult {
  canBuy: boolean
  canSell: boolean
  buyResult: string | null
  sellResult: string | null
  revertReason: string | null
  gasUsed?: string
}

interface FunctionAnalysis {
  dangerousFunctions: string[]
  hasPause: boolean
  hasBlacklist: boolean
  hasMint: boolean
  hasFeeChange: boolean
  isUpgradeable: boolean
  hasTradingToggle: boolean
  allFunctions: string[]
}

interface OwnershipInfo {
  owner: string | null
  isRenounced: boolean
  isMultisig: boolean
  isProxy: boolean
  implementationAddress?: string
}

interface LiquidityInfo {
  hasLiquidity: boolean
  liquidityLocked: boolean
  lockContract?: string
  dexName?: string
  poolAddress?: string
  liquidityAmount?: string
}

interface FeeInfo {
  buyFee: number | null
  sellFee: number | null
  totalFee: number | null
  isHiddenFee: boolean
}

interface NetworkInfo {
  id: string
  name: string
  chain: string
  chainId?: number
  rpcUrl: string
  explorerUrl: string
  type: 'evm' | 'solana' | 'tron' | 'ton' | 'sui' | 'aptos' | 'bitcoin'
}

declare global {
  interface Window {
    HoneypotFeedWidget: typeof HoneypotFeedWidget
    honeypotFeedWidgetConfig?: WidgetConfig
    honeypotFeedWidget?: HoneypotFeedWidget
  }
}

// ─── Theme: Obsidian & Gold ─────────────────────────────────────────────────

const THEME = {
  dark: {
    bg: '#0d141e',
    bgCard: '#19202a',
    bgSurface: '#121417',
    text: '#dce3f1',
    textMuted: '#d5c4ab',
    border: '#514532',
    primary: '#ffb800',
    primaryHover: '#ffc933',
    primaryForeground: '#6b4c00',
    danger: '#ef4444',
    warning: '#f59e0b',
    success: '#22c55e',
  },
  light: {
    bg: '#ffffff',
    bgCard: '#f8fafc',
    bgSurface: '#f1f5f9',
    text: '#0f172a',
    textMuted: '#64748b',
    border: '#e2e8f0',
    primary: '#ffb800',
    primaryHover: '#e6a600',
    primaryForeground: '#6b4c00',
    danger: '#ef4444',
    warning: '#f59e0b',
    success: '#22c55e',
  },
}

function getTheme(isDark: boolean) {
  return isDark ? THEME.dark : THEME.light
}

// ─── Shared API Client ───────────────────────────────────────────────────────

class HoneypotFeedClient {
  private apiUrl: string
  private token: string | null = null
  private tokenExpiry: number = 0

  constructor(apiUrl: string, token?: string) {
    this.apiUrl = apiUrl
    if (token) {
      this.token = token
      // JWT expires in 15 minutes by default
      this.tokenExpiry = Date.now() + (15 * 60 * 1000)
    }
  }

  /**
   * Set or update the JWT token.
   * Call this when your backend provides a new token.
   */
  setToken(token: string): void {
    this.token = token
    this.tokenExpiry = Date.now() + (15 * 60 * 1000)
  }

  /**
   * Check if client has a valid token
   */
  isAuthenticated(): boolean {
    return this.token !== null && Date.now() < this.tokenExpiry
  }

  /**
   * Get time until token expires (in seconds)
   */
  getTokenTimeToLive(): number {
    if (!this.token) return 0
    return Math.max(0, Math.floor((this.tokenExpiry - Date.now()) / 1000))
  }

  async scan(address: string, network: string): Promise<ScanResult> {
    if (!this.token) {
      throw new Error('Not authenticated. Request JWT token from your backend first.')
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`,
    }

    const body = JSON.stringify({ address, network })
    const response = await fetch(`${this.apiUrl}/scan`, {
      method: 'POST',
      headers,
      body,
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: `HTTP ${response.status}` }))
      throw new Error(error.error || 'Scan failed')
    }

    return response.json()
  }

  async getNetworks(): Promise<NetworkInfo[]> {
    const response = await fetch(`${this.apiUrl}/networks`)
    if (!response.ok) throw new Error('Failed to fetch networks')
    const data = await response.json()
    return data.networks || Object.values(data).flat()
  }
}

// ─── Risk Badge Component ────────────────────────────────────────────────────

function createRiskBadgeStyles(isDark: boolean): string {
  const t = getTheme(isDark)

  return `
    .hpf-risk-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      font-family: 'Hanken Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 12px;
      font-weight: 600;
      background: ${t.bgCard};
      border: 1px solid ${t.border};
      color: ${t.text};
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .hpf-risk-badge:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 12px rgba(255, 184, 0, 0.15);
      border-color: ${t.primary};
    }
    .hpf-risk-badge.loading {
      opacity: 0.6;
      cursor: wait;
    }
    .hpf-risk-badge .hpf-badge-score {
      font-weight: 700;
      color: ${t.primary};
    }
    .hpf-risk-badge .hpf-badge-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .hpf-risk-badge.safe { border-color: ${t.success}40; color: ${t.success}; }
    .hpf-risk-badge.safe .hpf-badge-score { color: ${t.success}; }
    .hpf-risk-badge.low { border-color: ${t.success}40; color: ${t.success}; }
    .hpf-risk-badge.low .hpf-badge-score { color: ${t.success}; }
    .hpf-risk-badge.medium { border-color: ${t.warning}40; color: ${t.warning}; }
    .hpf-risk-badge.medium .hpf-badge-score { color: ${t.warning}; }
    .hpf-risk-badge.high { border-color: ${t.danger}40; color: ${t.danger}; }
    .hpf-risk-badge.high .hpf-badge-score { color: ${t.danger}; }
    .hpf-risk-badge.honeypot { border-color: ${t.danger}40; color: ${t.danger}; }
    .hpf-risk-badge.honeypot .hpf-badge-score { color: ${t.danger}; }
  `
}

async function initRiskBadge(el: HTMLElement, client: HoneypotFeedClient): Promise<void> {
  const address = el.dataset.address
  const network = el.dataset.network || 'ethereum'
  const showScore = el.dataset.showScore !== 'false'
  const showLabel = el.dataset.showLabel !== 'false'
  const scanUrl = el.dataset.scanUrl || `https://honeypotfeed.com/scan?address=${address}&network=${network}`

  if (!address) {
    console.warn('[HoneypotFeed] Risk badge missing data-address')
    return
  }

  const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const shadow = el.attachShadow({ mode: 'open' })

  const style = document.createElement('style')
  style.textContent = createRiskBadgeStyles(isDark)
  shadow.appendChild(style)

  const link = document.createElement('a')
  link.href = scanUrl
  link.target = '_blank'
  link.rel = 'noopener noreferrer'
  link.style.cssText = 'text-decoration: none; cursor: pointer; display: inline-flex;'

  const badge = document.createElement('div')
  badge.className = 'hpf-risk-badge loading'
  badge.textContent = 'Loading...'
  link.appendChild(badge)
  shadow.appendChild(link)

  try {
    const result = await client.scan(address, network)
    badge.className = `hpf-risk-badge ${result.riskLevel}`
    badge.innerHTML = ''

    if (showScore) {
      const scoreEl = document.createElement('span')
      scoreEl.className = 'hpf-badge-score'
      scoreEl.textContent = `${result.riskScore}`
      badge.appendChild(scoreEl)
    }

    if (showLabel) {
      const labelEl = document.createElement('span')
      labelEl.className = 'hpf-badge-label'
      labelEl.textContent = result.riskLevel.toUpperCase()
      badge.appendChild(labelEl)
    }
  } catch {
    badge.className = 'hpf-risk-badge'
    badge.textContent = 'Error'
  }
}

// ─── Scan Button Component ───────────────────────────────────────────────────

function createScanButtonStyles(isDark: boolean): string {
  const t = getTheme(isDark)

  return `
    .hpf-scan-popup {
      position: fixed;
      width: 380px;
      max-height: 80vh;
      overflow-y: auto;
      background: ${t.bg};
      border: 1px solid ${t.border};
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      z-index: 999999;
      font-family: 'Hanken Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: hpf-slide-in 0.2s ease;
    }
    @keyframes hpf-slide-in {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .hpf-popup-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      border-bottom: 1px solid ${t.border};
      background: ${t.bgCard};
    }
    .hpf-popup-title {
      font-size: 14px;
      font-weight: 600;
      color: ${t.text};
    }
    .hpf-popup-close {
      background: none;
      border: none;
      color: ${t.textMuted};
      cursor: pointer;
      padding: 4px;
      opacity: 0.6;
      transition: opacity 0.15s ease;
    }
    .hpf-popup-close:hover { opacity: 1; color: ${t.primary}; }
    .hpf-popup-body { padding: 16px; }
    .hpf-popup-result {
      padding: 12px;
      background: ${t.bgSurface};
      border: 1px solid ${t.border};
      border-radius: 8px;
      margin-top: 12px;
    }
    .hpf-popup-score {
      font-size: 32px;
      font-weight: 700;
      color: ${t.primary};
    }
    .hpf-popup-level {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .hpf-popup-level.safe { background: ${t.success}20; color: ${t.success}; }
    .hpf-popup-level.low { background: ${t.success}20; color: ${t.success}; }
    .hpf-popup-level.medium { background: ${t.warning}20; color: ${t.warning}; }
    .hpf-popup-level.high { background: ${t.danger}20; color: ${t.danger}; }
    .hpf-popup-level.honeypot { background: ${t.danger}20; color: ${t.danger}; }
    .hpf-popup-spinner {
      display: inline-block;
      width: 16px;
      height: 16px;
      border: 2px solid ${t.border};
      border-top-color: ${t.primary};
      border-radius: 50%;
      animation: hpf-spin 0.8s linear infinite;
    }
    @keyframes hpf-spin { to { transform: rotate(360deg); } }
  `
}

function bindScanButton(btn: HTMLButtonElement, client: HoneypotFeedClient): void {
  const address = btn.dataset.address
  const network = btn.dataset.network || 'ethereum'
  const position = btn.dataset.position || 'bottom-right'

  if (!address) {
    console.warn('[HoneypotFeed] Scan button missing data-address')
    return
  }

  btn.addEventListener('click', async () => {
    const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    const t = getTheme(isDark)

    const existing = document.querySelector('.hpf-scan-popup')
    if (existing) existing.remove()

    const popup = document.createElement('div')
    popup.className = 'hpf-scan-popup'

    const positionStyles: Record<string, string> = {
      'bottom-right': 'bottom: 20px; right: 20px;',
      'bottom-left': 'bottom: 20px; left: 20px;',
      'top-right': 'top: 20px; right: 20px;',
      'top-left': 'top: 20px; left: 20px;',
      'center': 'top: 50%; left: 50%; transform: translate(-50%, -50%);',
    }
    popup.style.cssText = positionStyles[position] || positionStyles['bottom-right']

    const shadow = popup.attachShadow({ mode: 'open' })
    const style = document.createElement('style')
    style.textContent = createScanButtonStyles(isDark)
    shadow.appendChild(style)

    const container = document.createElement('div')
    container.innerHTML = `
      <div class="hpf-popup-header">
        <span class="hpf-popup-title">Honeypot Scan</span>
        <button class="hpf-popup-close" id="hpf-close">✕</button>
      </div>
      <div class="hpf-popup-body">
        <div style="font-size:12px;color:${t.textMuted};margin-bottom:8px;">
          ${address.slice(0, 10)}...${address.slice(-8)} on ${network}
        </div>
        <div id="hpf-popup-content">
          <div class="hpf-popup-spinner"></div> Scanning...
        </div>
      </div>
    `
    shadow.appendChild(container)

    document.body.appendChild(popup)

    shadow.getElementById('hpf-close')?.addEventListener('click', () => popup.remove())

    const closeHandler = (e: MouseEvent) => {
      if (!popup.contains(e.target as Node)) {
        popup.remove()
        document.removeEventListener('click', closeHandler)
      }
    }
    setTimeout(() => document.addEventListener('click', closeHandler), 100)

    try {
      const result = await client.scan(address, network)
      const content = shadow.getElementById('hpf-popup-content')
      if (content) {
        content.innerHTML = ''
        const resultDiv = document.createElement('div')
        resultDiv.className = 'hpf-popup-result'
        const scoreDiv = document.createElement('div')
        scoreDiv.className = 'hpf-popup-score'
        scoreDiv.textContent = String(result.riskScore)
        const levelDiv = document.createElement('div')
        levelDiv.className = `hpf-popup-level ${result.riskLevel}`
        levelDiv.textContent = result.riskLevel.toUpperCase()
        const tokenDiv = document.createElement('div')
        tokenDiv.style.cssText = 'margin-top:8px;font-size:12px;'
        tokenDiv.textContent = result.tokenInfo?.name ? `${result.tokenInfo.name} (${result.tokenInfo.symbol})` : 'Unknown token'
        resultDiv.appendChild(scoreDiv)
        resultDiv.appendChild(levelDiv)
        resultDiv.appendChild(tokenDiv)
        content.appendChild(resultDiv)
      }
    } catch {
      const content = shadow.getElementById('hpf-popup-content')
      if (content) {
        content.innerHTML = `<div style="color:${t.danger};font-size:13px;">Scan failed. Please try again.</div>`
      }
    }
  })
}

// ─── Main Widget Class ───────────────────────────────────────────────────────

class HoneypotFeedWidget {
  private config: Required<WidgetConfig>
  private shadowRoot: ShadowRoot | null = null
  private container: HTMLElement | null = null
  private networks: NetworkInfo[] = []
  private selectedNetwork: string = ''
  private isScanning = false
  private client: HoneypotFeedClient

  constructor(config: WidgetConfig) {
    this.config = {
      apiUrl: config.apiUrl,
      token: config.token,
      theme: config.theme || 'auto',
      defaultNetwork: config.defaultNetwork || 'ethereum',
      networks: config.networks || [],
      showBranding: config.showBranding !== false,
      container: config.container || '#honeypot-feed-widget',
      onScanComplete: config.onScanComplete || (() => {}),
      onError: config.onError || (() => {}),
    }
    this.selectedNetwork = this.config.defaultNetwork
    this.client = new HoneypotFeedClient(this.config.apiUrl, this.config.token)
  }

  mount(selector: string | HTMLElement): void {
    const target = typeof selector === 'string'
      ? document.querySelector(selector)
      : selector

    if (!target) {
      throw new Error(`Widget container not found: ${selector}`)
    }

    this.container = target as HTMLElement
    this.createShadowDOM()
    this.injectStyles()
    this.fetchNetworks()
    this.render()
  }

  private createShadowDOM(): void {
    if (!this.container) return
    this.shadowRoot = this.container.attachShadow({ mode: 'open' })
  }

  private injectStyles(): void {
    if (!this.shadowRoot) return
    const style = document.createElement('style')
    style.textContent = this.getStyles()
    this.shadowRoot.appendChild(style)
  }

  private getStyles(): string {
    const isDark = this.config.theme === 'dark' ||
      (this.config.theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)
    const t = getTheme(isDark)

    return `
      * { box-sizing: border-box; margin: 0; padding: 0; }
      :host {
        font-family: 'Hanken Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        font-size: 14px; line-height: 1.5; color: ${t.text}; background: ${t.bg};
        border-radius: 12px; border: 1px solid ${t.border};
        box-shadow: 0 4px 24px rgba(0,0,0,0.2); display: block; max-width: 420px; width: 100%; overflow: hidden;
      }
      .hpf-widget { width: 100%; }
      .hpf-header { display: flex; align-items: center; justify-content: space-between; padding: 16px; border-bottom: 1px solid ${t.border}; background: ${t.bgCard}; }
      .hpf-logo { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 16px; color: ${t.text}; text-decoration: none; }
      .hpf-logo svg { width: 24px; height: 24px; color: ${t.primary}; }
      .hpf-version { font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; background: ${t.primary}15; color: ${t.primary}; }
      .hpf-network-selector { padding: 16px; border-bottom: 1px solid ${t.border}; }
      .hpf-network-label { display: block; font-size: 12px; font-weight: 500; color: ${t.textMuted}; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
      .hpf-network-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
      .hpf-network-btn { display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 10px 8px; border: 1px solid ${t.border}; border-radius: 8px; background: ${t.bgCard}; color: ${t.text}; font-size: 11px; font-weight: 500; cursor: pointer; transition: all 0.15s ease; }
      .hpf-network-btn:hover { border-color: ${t.primary}; background: ${t.primary}10; }
      .hpf-network-btn.active { border-color: ${t.primary}; background: ${t.primary}15; color: ${t.primary}; }
      .hpf-network-btn svg { width: 24px; height: 24px; }
      .hpf-network-btn-more { display: flex; align-items: center; justify-content: center; padding: 10px 8px; border: 1px dashed ${t.border}; border-radius: 8px; background: transparent; color: ${t.textMuted}; font-size: 11px; font-weight: 500; cursor: pointer; transition: all 0.15s ease; }
      .hpf-network-btn-more:hover { border-color: ${t.primary}; color: ${t.primary}; }
      .hpf-input-section { padding: 16px; border-bottom: 1px solid ${t.border}; }
      .hpf-input-wrapper { position: relative; display: flex; gap: 8px; }
      .hpf-input { flex: 1; padding: 12px 16px; border: 1px solid ${t.border}; border-radius: 8px; background: ${t.bgCard}; color: ${t.text}; font-size: 14px; font-family: 'SF Mono', 'Fira Code', monospace; outline: none; transition: border-color 0.15s ease, box-shadow 0.15s ease; }
      .hpf-input:focus { border-color: ${t.primary}; box-shadow: 0 0 0 3px ${t.primary}20; }
      .hpf-input::placeholder { color: ${t.textMuted}; }
      .hpf-scan-btn { padding: 12px 20px; border: none; border-radius: 8px; background: ${t.primary}; color: ${t.primaryForeground}; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.15s ease; white-space: nowrap; }
      .hpf-scan-btn:hover:not(:disabled) { background: ${t.primaryHover}; }
      .hpf-scan-btn:disabled { opacity: 0.6; cursor: not-allowed; }
      .hpf-scan-btn .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid ${t.primaryForeground}30; border-top-color: ${t.primaryForeground}; border-radius: 50%; animation: hpf-spin 0.8s linear infinite; margin-right: 8px; }
      @keyframes hpf-spin { to { transform: rotate(360deg); } }
      .hpf-results { padding: 16px; display: none; }
      .hpf-results.visible { display: block; animation: hpf-fade-in 0.3s ease; }
      @keyframes hpf-fade-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      .hpf-risk-score { display: flex; align-items: center; justify-content: center; gap: 24px; margin-bottom: 20px; }
      .hpf-gauge { position: relative; width: 100px; height: 100px; }
      .hpf-gauge svg { width: 100%; height: 100%; transform: rotate(-90deg); }
      .hpf-gauge circle { fill: none; stroke-width: 8; stroke-linecap: round; }
      .hpf-gauge-bg { stroke: ${t.border}; }
      .hpf-gauge-progress { stroke: ${t.primary}; stroke-dasharray: 283; stroke-dashoffset: 283; transition: stroke-dashoffset 0.8s ease, stroke 0.3s ease; }
      .hpf-gauge-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
      .hpf-gauge-score { font-size: 28px; font-weight: 700; color: ${t.primary}; line-height: 1; }
      .hpf-gauge-label { font-size: 11px; color: ${t.textMuted}; text-transform: uppercase; letter-spacing: 0.05em; }
      .hpf-risk-info { text-align: left; }
      .hpf-risk-level { display: inline-block; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
      .hpf-risk-level.safe { background: ${t.success}20; color: ${t.success}; }
      .hpf-risk-level.low { background: ${t.success}20; color: ${t.success}; }
      .hpf-risk-level.medium { background: ${t.warning}20; color: ${t.warning}; }
      .hpf-risk-level.high { background: ${t.danger}20; color: ${t.danger}; }
      .hpf-risk-level.honeypot { background: ${t.danger}20; color: ${t.danger}; }
      .hpf-token-info { margin-top: 8px; font-size: 13px; color: ${t.textMuted}; }
      .hpf-token-info strong { color: ${t.text}; }
      .hpf-detections { display: flex; flex-direction: column; gap: 10px; }
      .hpf-detection-card { display: flex; align-items: flex-start; gap: 12px; padding: 12px; background: ${t.bgCard}; border: 1px solid ${t.border}; border-radius: 8px; transition: border-color 0.15s ease; }
      .hpf-detection-card:hover { border-color: ${t.primary}40; }
      .hpf-detection-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
      .hpf-detection-icon.pass { background: ${t.success}20; color: ${t.success}; }
      .hpf-detection-icon.warning { background: ${t.warning}20; color: ${t.warning}; }
      .hpf-detection-icon.fail { background: ${t.danger}20; color: ${t.danger}; }
      .hpf-detection-icon.info { background: ${t.primary}20; color: ${t.primary}; }
      .hpf-detection-content { flex: 1; min-width: 0; }
      .hpf-detection-title { font-size: 13px; font-weight: 600; color: ${t.text}; margin-bottom: 4px; }
      .hpf-detection-detail { font-size: 12px; color: ${t.textMuted}; line-height: 1.4; }
      .hpf-detection-status { display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
      .hpf-detection-status.pass { color: ${t.success}; }
      .hpf-detection-status.warning { color: ${t.warning}; }
      .hpf-detection-status.fail { color: ${t.danger}; }
      .hpf-detection-status.info { color: ${t.primary}; }
      .hpf-error { padding: 16px; background: ${t.danger}15; border: 1px solid ${t.danger}40; border-radius: 8px; color: ${t.danger}; font-size: 13px; display: none; }
      .hpf-error.visible { display: block; animation: hpf-fade-in 0.3s ease; }
      .hpf-branding { padding: 12px 16px; border-top: 1px solid ${t.border}; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 11px; color: ${t.textMuted}; }
      .hpf-branding a { color: ${t.primary}; text-decoration: none; font-weight: 500; }
      .hpf-branding a:hover { text-decoration: underline; }
      @media (max-width: 480px) {
        :host { max-width: 100%; border-radius: 0; border-left: none; border-right: none; }
        .hpf-network-grid { grid-template-columns: repeat(3, 1fr); }
        .hpf-input-wrapper { flex-direction: column; }
        .hpf-scan-btn { width: 100%; }
      }
      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
      }
    `
  }

  private render(): void {
    if (!this.shadowRoot) return

    this.shadowRoot.innerHTML = `
      <style>${this.getStyles()}</style>
      <div class="hpf-widget">
        <header class="hpf-header">
          <a href="https://honeypotfeed.com" target="_blank" rel="noopener noreferrer" class="hpf-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
            Honeypot Feed
            <span class="hpf-version">v1.0</span>
          </a>
        </header>
        <section class="hpf-network-selector">
          <label class="hpf-network-label">Select Network</label>
          <div class="hpf-network-grid" id="hpf-network-grid"></div>
        </section>
        <section class="hpf-input-section">
          <div class="hpf-input-wrapper">
            <input type="text" class="hpf-input" id="hpf-address-input" placeholder="Enter token contract address" autocomplete="off" spellcheck="false"/>
            <button class="hpf-scan-btn" id="hpf-scan-btn" disabled>Scan</button>
          </div>
        </section>
        <section class="hpf-results" id="hpf-results">
          <div class="hpf-risk-score">
            <div class="hpf-gauge" id="hpf-gauge">
              <svg viewBox="0 0 100 100">
                <circle class="hpf-gauge-bg" cx="50" cy="50" r="45"/>
                <circle class="hpf-gauge-progress" id="hpf-gauge-progress" cx="50" cy="50" r="45"/>
              </svg>
              <div class="hpf-gauge-text">
                <div class="hpf-gauge-score" id="hpf-gauge-score">0</div>
                <div class="hpf-gauge-label">Score</div>
              </div>
            </div>
            <div class="hpf-risk-info">
              <span class="hpf-risk-level" id="hpf-risk-level">Safe</span>
              <div class="hpf-token-info" id="hpf-token-info"></div>
            </div>
          </div>
          <div class="hpf-detections" id="hpf-detections"></div>
        </section>
        <div class="hpf-error" id="hpf-error"></div>
        ${this.config.showBranding ? `<footer class="hpf-branding">Powered by <a href="https://honeypotfeed.com" target="_blank" rel="noopener noreferrer">Honeypot Feed</a></footer>` : ''}
      </div>
    `
    this.bindEvents()
    this.renderNetworks()
  }

  private bindEvents(): void {
    if (!this.shadowRoot) return
    const addressInput = this.shadowRoot.getElementById('hpf-address-input') as HTMLInputElement
    const scanBtn = this.shadowRoot.getElementById('hpf-scan-btn') as HTMLButtonElement

    addressInput?.addEventListener('input', () => this.validateInput())
    addressInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !this.isScanning) this.handleScan()
    })
    scanBtn?.addEventListener('click', () => this.handleScan())
  }

  private validateInput(): void {
    if (!this.shadowRoot) return
    const addressInput = this.shadowRoot.getElementById('hpf-address-input') as HTMLInputElement
    const scanBtn = this.shadowRoot.getElementById('hpf-scan-btn') as HTMLButtonElement
    const address = addressInput?.value.trim() || ''
    const isValid = this.validateAddress(address, this.selectedNetwork)
    if (scanBtn) scanBtn.disabled = !isValid || this.isScanning
  }

  private validateAddress(address: string, networkId: string): boolean {
    if (!address) return false
    const network = this.networks.find(n => n.id === networkId)
    if (!network) return address.length > 10
    switch (network.type) {
      case 'evm': return /^0x[a-fA-F0-9]{40}$/.test(address)
      case 'solana': return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)
      case 'tron': return /^T[A-Za-z0-9]{33}$/.test(address)
      case 'ton': return /^[A-Za-z0-9_-]{48}$/.test(address) || address.startsWith('EQ') || address.startsWith('UQ')
      case 'sui': return /^0x[a-fA-F0-9]{64}$/.test(address)
      case 'aptos': return /^0x[a-fA-F0-9]{64}$/.test(address)
      case 'bitcoin': return /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/.test(address)
      default: return address.length > 10
    }
  }

  private async fetchNetworks(): Promise<void> {
    try {
      const allNetworks = await this.client.getNetworks()
      if (this.config.networks && this.config.networks.length > 0) {
        const allowedIds = this.config.networks.map(n => n.toLowerCase())
        this.networks = allNetworks.filter(n => allowedIds.includes(n.id.toLowerCase()))
      } else {
        this.networks = allNetworks
      }
      this.renderNetworks()
    } catch (error) {
      console.warn('Failed to fetch networks, using defaults:', error)
      this.networks = this.getDefaultNetworks()
      this.renderNetworks()
    }
  }

  private getDefaultNetworks(): NetworkInfo[] {
    return [
      { id: 'ethereum', name: 'Ethereum', chain: 'EVM', chainId: 1, rpcUrl: '', explorerUrl: 'https://etherscan.io', type: 'evm' },
      { id: 'bsc', name: 'BSC', chain: 'EVM', chainId: 56, rpcUrl: '', explorerUrl: 'https://bscscan.com', type: 'evm' },
      { id: 'polygon', name: 'Polygon', chain: 'EVM', chainId: 137, rpcUrl: '', explorerUrl: 'https://polygonscan.com', type: 'evm' },
      { id: 'arbitrum', name: 'Arbitrum', chain: 'EVM', chainId: 42161, rpcUrl: '', explorerUrl: 'https://arbiscan.io', type: 'evm' },
      { id: 'base', name: 'Base', chain: 'EVM', chainId: 8453, rpcUrl: '', explorerUrl: 'https://basescan.org', type: 'evm' },
      { id: 'solana', name: 'Solana', chain: 'Solana', rpcUrl: '', explorerUrl: 'https://solscan.io', type: 'solana' },
      { id: 'tron', name: 'TRON', chain: 'TRON', rpcUrl: '', explorerUrl: 'https://tronscan.org', type: 'tron' },
      { id: 'ton', name: 'TON', chain: 'TON', rpcUrl: '', explorerUrl: 'https://tonscan.org', type: 'ton' },
    ]
  }

  private renderNetworks(): void {
    if (!this.shadowRoot) return
    const grid = this.shadowRoot.getElementById('hpf-network-grid')
    if (!grid) return
    const displayNetworks = this.networks.slice(0, 7)
    const hasMore = this.networks.length > 7
    grid.innerHTML = displayNetworks.map(network => `
      <button class="hpf-network-btn ${network.id === this.selectedNetwork ? 'active' : ''}" data-network="${network.id}" title="${network.name}">
        ${this.getNetworkIcon(network.type)}
        <span>${network.name}</span>
      </button>
    `).join('') + (hasMore ? `
      <button class="hpf-network-btn-more" id="hpf-more-networks">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        +${this.networks.length - 7} more
      </button>
    ` : '')
    grid.querySelectorAll('.hpf-network-btn[data-network]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget as HTMLElement
        this.selectNetwork(target.dataset.network!)
      })
    })
    grid.querySelector('#hpf-more-networks')?.addEventListener('click', () => this.showAllNetworks())
  }

  private getNetworkIcon(type: string): string {
    const icons: Record<string, string> = {
      evm: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
      solana: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.5 1.5c-2.2 0-4.2.9-5.7 2.4l-2.1-2.1c1.8-1.8 4.2-2.9 6.8-2.9 3.9 0 7 3.1 7 7 0 2.6-1.1 5-2.9 6.8l2.1 2.1c1.5-1.5 2.4-3.5 2.4-5.7 0-3.9-3.1-7-7-7z"/></svg>',
      tron: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>',
      ton: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
    }
    return icons[type] || '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/></svg>'
  }

  private selectNetwork(networkId: string): void {
    this.selectedNetwork = networkId
    this.renderNetworks()
    this.validateInput()
  }

  private showAllNetworks(): void {
    const currentIndex = this.networks.findIndex(n => n.id === this.selectedNetwork)
    const nextIndex = (currentIndex + 1) % this.networks.length
    this.selectNetwork(this.networks[nextIndex].id)
  }

  private async handleScan(): Promise<void> {
    if (!this.shadowRoot || this.isScanning) return
    const addressInput = this.shadowRoot.getElementById('hpf-address-input') as HTMLInputElement
    const address = addressInput?.value.trim()
    if (!address || !this.validateAddress(address, this.selectedNetwork)) {
      this.showError('Invalid address for selected network')
      return
    }
    this.isScanning = true
    this.updateScanButton(true)
    this.hideError()
    this.hideResults()
    try {
      const result = await this.client.scan(address, this.selectedNetwork)
      this.displayResults(result)
      this.config.onScanComplete(result)
    } catch (error) {
      const err = error as Error
      this.showError(err.message || 'Scan failed. Please try again.')
      this.config.onError(err)
    } finally {
      this.isScanning = false
      this.updateScanButton(false)
    }
  }

  private updateScanButton(loading: boolean): void {
    if (!this.shadowRoot) return
    const scanBtn = this.shadowRoot.getElementById('hpf-scan-btn') as HTMLButtonElement
    if (!scanBtn) return
    if (loading) {
      scanBtn.innerHTML = '<span class="spinner"></span>Scanning...'
      scanBtn.disabled = true
    } else {
      scanBtn.innerHTML = 'Scan'
      scanBtn.disabled = false
    }
    this.validateInput()
  }

  private displayResults(result: ScanResult): void {
    if (!this.shadowRoot) return
    this.updateRiskGauge(result.riskScore, result.riskLevel)
    this.updateTokenInfo(result)
    this.renderDetections(result)
    this.showResults()
  }

  private updateRiskGauge(score: number, level: string): void {
    if (!this.shadowRoot) return
    const progress = this.shadowRoot.getElementById('hpf-gauge-progress')
    const scoreEl = this.shadowRoot.getElementById('hpf-gauge-score')
    const levelEl = this.shadowRoot.getElementById('hpf-risk-level')
    if (progress) {
      const circumference = 2 * Math.PI * 45
      const offset = circumference - (score / 100) * circumference
      progress.style.strokeDashoffset = `${offset}`
      const colors: Record<string, string> = { safe: '#22c55e', low: '#22c55e', medium: '#f59e0b', high: '#ef4444', honeypot: '#ef4444' }
      progress.style.stroke = colors[level] || '#ffb800'
    }
    if (scoreEl) scoreEl.textContent = score.toString()
    if (levelEl) {
      levelEl.textContent = level.charAt(0).toUpperCase() + level.slice(1)
      levelEl.className = `hpf-risk-level ${level}`
    }
  }

  private updateTokenInfo(result: ScanResult): void {
    if (!this.shadowRoot || !result.tokenInfo) return
    const infoEl = this.shadowRoot.getElementById('hpf-token-info')
    if (!infoEl) return
    const { name, symbol, decimals } = result.tokenInfo
    const parts: string[] = []
    if (name) parts.push(name)
    if (symbol) parts.push(`$${symbol}`)
    if (decimals !== null) parts.push(`${decimals} decimals`)
    infoEl.textContent = parts.length > 0 ? `${parts[0]} ${parts.slice(1).join(' • ')}` : 'Unknown token'
  }

  private renderDetections(result: ScanResult): void {
    if (!this.shadowRoot) return
    const container = this.shadowRoot.getElementById('hpf-detections')
    if (!container) return
    const detections = [
      { key: 'simulation', title: 'Buy/Sell Simulation', icon: '🔄', pass: result.simulation?.canBuy && result.simulation?.canSell, detail: result.simulation?.canSell ? 'Buy and sell successful' : 'Sell blocked - likely honeypot', status: result.simulation?.canSell ? 'pass' : 'fail' },
      { key: 'functions', title: 'Dangerous Functions', icon: '⚠️', pass: !result.functionAnalysis?.dangerousFunctions.length, detail: result.functionAnalysis?.dangerousFunctions.length ? `Found: ${result.functionAnalysis.dangerousFunctions.join(', ')}` : 'No dangerous functions detected', status: result.functionAnalysis?.dangerousFunctions.length ? 'fail' : 'pass' },
      { key: 'ownership', title: 'Ownership', icon: '👤', pass: result.ownership?.isRenounced || false, detail: result.ownership?.isRenounced ? 'Ownership renounced' : `Owner: ${result.ownership?.owner?.slice(0, 10)}...`, status: result.ownership?.isRenounced ? 'pass' : 'warning' },
      { key: 'liquidity', title: 'Liquidity', icon: '💧', pass: result.liquidity?.hasLiquidity && result.liquidity?.liquidityLocked, detail: result.liquidity?.hasLiquidity ? (result.liquidity.liquidityLocked ? 'Liquidity locked' : 'Liquidity NOT locked') : 'No liquidity found', status: result.liquidity?.hasLiquidity && result.liquidity?.liquidityLocked ? 'pass' : 'warning' },
      { key: 'fees', title: 'Buy/Sell Fees', icon: '💰', pass: (result.fees?.sellFee ?? 0) <= 0.1 && (result.fees?.buyFee ?? 0) <= 0.1, detail: `Buy: ${((result.fees?.buyFee ?? 0) * 100).toFixed(1)}% • Sell: ${((result.fees?.sellFee ?? 0) * 100).toFixed(1)}%`, status: (result.fees?.sellFee ?? 0) > 0.5 ? 'fail' : (result.fees?.sellFee ?? 0) > 0.1 ? 'warning' : 'pass' },
    ]
    container.innerHTML = ''
    for (const d of detections) {
      const card = document.createElement('div')
      card.className = 'hpf-detection-card'
      const icon = document.createElement('div')
      icon.className = `hpf-detection-icon ${d.status}`
      icon.textContent = d.icon
      const content = document.createElement('div')
      content.className = 'hpf-detection-content'
      const title = document.createElement('div')
      title.className = 'hpf-detection-title'
      title.textContent = d.title
      const detail = document.createElement('div')
      detail.className = 'hpf-detection-detail'
      detail.textContent = d.detail
      content.appendChild(title)
      content.appendChild(detail)
      const status = document.createElement('span')
      status.className = `hpf-detection-status ${d.status}`
      status.textContent = d.status
      card.appendChild(icon)
      card.appendChild(content)
      card.appendChild(status)
      container.appendChild(card)
    }
  }

  private showError(message: string): void {
    if (!this.shadowRoot) return
    const errorEl = this.shadowRoot.getElementById('hpf-error')
    if (errorEl) { errorEl.textContent = message; errorEl.classList.add('visible') }
  }

  private hideError(): void {
    if (!this.shadowRoot) return
    const errorEl = this.shadowRoot.getElementById('hpf-error')
    if (errorEl) errorEl.classList.remove('visible')
  }

  private showResults(): void {
    if (!this.shadowRoot) return
    const resultsEl = this.shadowRoot.getElementById('hpf-results')
    if (resultsEl) resultsEl.classList.add('visible')
  }

  private hideResults(): void {
    if (!this.shadowRoot) return
    const resultsEl = this.shadowRoot.getElementById('hpf-results')
    if (resultsEl) resultsEl.classList.remove('visible')
  }

  async scan(address: string, network?: string): Promise<ScanResult> {
    const net = network || this.selectedNetwork
    if (!this.validateAddress(address, net)) throw new Error('Invalid address for selected network')
    const result = await this.client.scan(address, net)
    this.displayResults(result)
    return result
  }

  setNetwork(networkId: string): void {
    if (this.networks.some(n => n.id === networkId)) this.selectNetwork(networkId)
  }

  setAddress(address: string): void {
    if (!this.shadowRoot) return
    const input = this.shadowRoot.getElementById('hpf-address-input') as HTMLInputElement
    if (input) { input.value = address; this.validateInput() }
  }

  destroy(): void {
    if (this.container && this.shadowRoot) this.container.removeChild(this.shadowRoot.host)
    this.shadowRoot = null
    this.container = null
  }

  isAuthenticated(): boolean {
    return this.client.isAuthenticated()
  }

  getTokenTimeToLive(): number {
    return this.client.getTokenTimeToLive()
  }

  setToken(token: string): void {
    this.config.token = token
    this.client.setToken(token)
  }
}

// ─── Auto-Initialize on DOM Ready ────────────────────────────────────────────

function getApiUrl(): string {
  const btn = document.querySelector('.honeypot-scan-btn')
  const container = document.querySelector('[data-token]')
  const fromBtn = btn?.getAttribute('data-api-url')
  const fromContainer = container?.getAttribute('data-api-url')
  return fromBtn || fromContainer || window.honeypotFeedWidgetConfig?.apiUrl || 'https://honeypotfeed.com/api'
}

function getToken(): string {
  const btn = document.querySelector('.honeypot-scan-btn')
  const container = document.querySelector('[data-token]')
  return btn?.getAttribute('data-token') || container?.getAttribute('data-token') || ''
}

function initAutoComponents(): void {
  const apiUrl = getApiUrl()
  const token = getToken()

  if (!token) {
    console.error('[HoneypotFeed] No token provided. Your backend must obtain JWT via POST /api/auth/token')
    return
  }

  const client = new HoneypotFeedClient(apiUrl, token)

  // 1. Init scan buttons
  document.querySelectorAll<HTMLButtonElement>('.honeypot-scan-btn').forEach(btn => {
    bindScanButton(btn, client)
  })

  // 2. Init risk badges
  document.querySelectorAll<HTMLElement>('.honeypot-risk-badge').forEach(el => {
    initRiskBadge(el, client)
  })

  // 3. Init full widget containers
  document.querySelectorAll<HTMLElement>('[data-token]').forEach(el => {
    if (el.classList.contains('honeypot-scan-btn') || el.classList.contains('honeypot-risk-badge')) return
    if (el.id === 'honeypot-scanner-container' || el.dataset.networks) {
      const networksList = el.dataset.networks ? el.dataset.networks.split(',').map(n => n.trim()) : []
      const config: WidgetConfig = {
        apiUrl,
        token,
        theme: (el.dataset.theme as WidgetConfig['theme']) || 'auto',
        defaultNetwork: networksList[0] || 'ethereum',
        networks: networksList,
        showBranding: el.dataset.showBranding !== 'false',
      }
      const widget = new HoneypotFeedWidget(config)
      widget.mount(el)
    }
  })
}

// ─── Global Exports & Auto-Init ──────────────────────────────────────────────

if (typeof window !== 'undefined') {
  window.HoneypotFeedWidget = HoneypotFeedWidget

  // Auto-init from global config
  if (window.honeypotFeedWidgetConfig) {
    const config = window.honeypotFeedWidgetConfig
    const widget = new HoneypotFeedWidget(config)
    widget.mount(config.container || '#honeypot-feed-widget')
    window.honeypotFeedWidget = widget
  }

  // Auto-init data-* components
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAutoComponents)
  } else {
    initAutoComponents()
  }
}

export { HoneypotFeedWidget, HoneypotFeedClient, type WidgetConfig, type ScanResult, type NetworkInfo }
export default HoneypotFeedWidget
