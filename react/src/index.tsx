/**
 * @honeypot-feed/react
 * React wrapper for Honeypot Feed Widget
 *
 * SECURITY ARCHITECTURE:
 * ──────────────────────
 * The API key NEVER leaves your backend server. The flow is:
 *
 *   1. YOUR BACKEND calls POST /api/auth/token { apiKey: "sk_live_..." }
 *   2. YOUR BACKEND receives JWT token: { token: "eyJ...", expiresIn: 900 }
 *   3. YOUR BACKEND sends JWT to frontend (via API, session, etc.)
 *   4. FRONTEND widget uses JWT for all requests
 *
 * The widget ONLY accepts a JWT token. It NEVER handles API keys.
 */

import {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
  type CSSProperties,
} from 'react'

import {
  HoneypotFeedWidget as VanillaWidget,
  HoneypotFeedClient,
  type WidgetConfig,
  type ScanResult,
  type NetworkInfo,
} from 'honeypot-feed-widget'

export type { WidgetConfig, ScanResult, NetworkInfo }

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

// ─── HoneypotWidget Component ───────────────────────────────────────────────

export interface HoneypotWidgetProps {
  apiUrl: string
  token: string  // JWT from your backend (NOT API key)
  theme?: WidgetConfig['theme']
  defaultNetwork?: string
  networks?: string[]
  showBranding?: boolean
  onScanComplete?: (result: ScanResult) => void
  onError?: (error: Error) => void
  className?: string
  style?: CSSProperties
}

/**
 * Full honeypot scanner widget for React.
 *
 * The JWT token must come from your backend:
 *   POST /api/auth/token { apiKey: "sk_live_..." }
 *   → { token: "eyJ...", expiresIn: 900 }
 *
 * @example
 * ```tsx
 * // Backend: get JWT from your API
 * const { token } = await fetch('/api/hpf-token').then(r => r.json())
 *
 * // Frontend: use JWT in widget
 * import { HoneypotWidget } from '@honeypot-feed/react'
 *
 * function App() {
 *   return (
 *     <HoneypotWidget
 *       apiUrl="https://honeypotfeed.com/api"
 *       token={token}  // JWT from your backend
 *       theme="auto"
 *     />
 *   )
 * }
 * ```
 */
export function HoneypotWidget({
  apiUrl,
  token,
  theme = 'auto',
  defaultNetwork = 'ethereum',
  networks,
  showBranding = true,
  onScanComplete,
  onError,
  className,
  style,
}: HoneypotWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const widgetRef = useRef<VanillaWidget | null>(null)
  const callbacksRef = useRef({ onScanComplete, onError })

  callbacksRef.current = { onScanComplete, onError }

  const networksKey = useMemo(
    () => (networks ? networks.sort().join(',') : ''),
    [networks]
  )

  useEffect(() => {
    if (!containerRef.current) return

    const config: WidgetConfig = {
      apiUrl,
      token,
      theme,
      defaultNetwork,
      networks,
      showBranding,
      onScanComplete: (result) => callbacksRef.current.onScanComplete?.(result),
      onError: (error) => callbacksRef.current.onError?.(error),
    }

    const widget = new VanillaWidget(config)
    widget.mount(containerRef.current)
    widgetRef.current = widget

    return () => {
      widget.destroy()
      widgetRef.current = null
    }
  }, [apiUrl, token, theme, defaultNetwork, networksKey, showBranding])

  return (
    <div
      ref={containerRef}
      className={className}
      style={{ width: '100%', maxWidth: 420, ...style }}
    />
  )
}

// ─── HoneypotRiskBadge Component ────────────────────────────────────────────

export interface HoneypotRiskBadgeProps {
  address: string
  network?: string
  apiUrl?: string
  token?: string  // JWT from your backend
  showScore?: boolean
  showLabel?: boolean
  scanUrl?: string
  className?: string
  style?: CSSProperties
}

export function HoneypotRiskBadge({
  address,
  network = 'ethereum',
  apiUrl = 'https://honeypotfeed.com/api',
  token,
  showScore = true,
  showLabel = true,
  scanUrl,
  className,
  style,
}: HoneypotRiskBadgeProps) {
  const [state, setState] = useState<{
    score: number | null
    level: string
    loading: boolean
    error: boolean
  }>({ score: null, level: '', loading: true, error: false })

  const finalScanUrl = useMemo(
    () => scanUrl || `https://honeypotfeed.com/scan?address=${address}&network=${network}`,
    [scanUrl, address, network]
  )

  useEffect(() => {
    let cancelled = false
    const client = new HoneypotFeedClient(apiUrl, token)

    client
      .scan(address, network)
      .then((result) => {
        if (!cancelled) {
          setState({
            score: result.riskScore,
            level: result.riskLevel,
            loading: false,
            error: false,
          })
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({ score: null, level: '', loading: false, error: true })
        }
      })

    return () => { cancelled = true }
  }, [address, network, apiUrl, token])

  const t = getTheme(true)

  const levelColors: Record<string, { bg: string; text: string; border: string }> = {
    safe: { bg: `${t.success}20`, text: t.success, border: `${t.success}40` },
    low: { bg: `${t.success}20`, text: t.success, border: `${t.success}40` },
    medium: { bg: `${t.warning}20`, text: t.warning, border: `${t.warning}40` },
    high: { bg: `${t.danger}20`, text: t.danger, border: `${t.danger}40` },
    honeypot: { bg: `${t.danger}20`, text: t.danger, border: `${t.danger}40` },
  }

  const colors = levelColors[state.level] || levelColors.safe

  if (state.error) {
    return (
      <span className={className} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 600, fontFamily: "'Hanken Grotesk', sans-serif", background: t.bgCard, border: `1px solid ${t.border}`, color: t.textMuted, ...style }}>
        Error
      </span>
    )
  }

  return (
    <a href={finalScanUrl} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none', cursor: 'pointer', display: 'inline-flex' }}>
      <span className={className} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 600, fontFamily: "'Hanken Grotesk', sans-serif", background: t.bgCard, border: `1px solid ${colors.border}`, color: colors.text, cursor: 'pointer', transition: 'all 0.15s ease', opacity: state.loading ? 0.6 : 1, ...style }}>
        {state.loading ? 'Loading...' : (
          <>
            {showScore && state.score !== null && <span style={{ fontWeight: 700, color: colors.text }}>{state.score}</span>}
            {showLabel && state.level && <span style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{state.level}</span>}
          </>
        )}
      </span>
    </a>
  )
}

// ─── useHoneypotScan Hook ───────────────────────────────────────────────────

export interface UseHoneypotScanOptions {
  apiUrl: string
  token: string  // JWT from your backend
}

export interface UseHoneypotScanReturn {
  scan: (address: string, network?: string) => Promise<ScanResult>
  result: ScanResult | null
  isScanning: boolean
  error: Error | null
  clearResult: () => void
}

export function useHoneypotScan({ apiUrl, token }: UseHoneypotScanOptions): UseHoneypotScanReturn {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const clientRef = useRef<HoneypotFeedClient | null>(null)

  useEffect(() => {
    clientRef.current = new HoneypotFeedClient(apiUrl, token)
  }, [apiUrl, token])

  const scan = useCallback(async (address: string, network: string = 'ethereum'): Promise<ScanResult> => {
    if (!clientRef.current) throw new Error('Client not initialized')
    setIsScanning(true)
    setError(null)
    try {
      const scanResult = await clientRef.current.scan(address, network)
      setResult(scanResult)
      return scanResult
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      setError(error)
      throw error
    } finally {
      setIsScanning(false)
    }
  }, [])

  const clearResult = useCallback(() => { setResult(null); setError(null) }, [])

  return { scan, result, isScanning, error, clearResult }
}

// ─── useHoneypotNetworks Hook ───────────────────────────────────────────────

export interface UseHoneypotNetworksOptions {
  apiUrl: string
}

export interface UseHoneypotNetworksReturn {
  networks: NetworkInfo[]
  isLoading: boolean
  error: Error | null
}

export function useHoneypotNetworks({ apiUrl }: UseHoneypotNetworksOptions): UseHoneypotNetworksReturn {
  const [networks, setNetworks] = useState<NetworkInfo[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    const client = new HoneypotFeedClient(apiUrl)
    client.getNetworks()
      .then(setNetworks)
      .catch((err) => setError(err instanceof Error ? err : new Error(String(err))))
      .finally(() => setIsLoading(false))
  }, [apiUrl])

  return { networks, isLoading, error }
}

export default HoneypotWidget
