export interface User { id: string; username: string; role: 'admin' | 'restricted'; enabled: boolean; totp_enabled: boolean; preferences: Record<string, unknown> }
export interface Session { user: User; csrf_token: string; domain_id?: string }
export interface Account { id: string; name: string; provider: string; remark: string; status: string; last_error: string }
export interface Domain { id: string; account_id: string; provider_domain_id: string; name: string; ascii_name: string; provider: string; category: string; remark: string; quicklogin_enabled: boolean; hidden: boolean }
export interface DNSRecord { id?: string; type: string; name: string; value: string; ttl: number; line?: string; enabled: boolean; priority?: number; weight?: number; remark?: string; proxied: boolean; version?: string; metadata?: Record<string, unknown> }
export interface Provider { id: string; name: string; category: string; implemented: boolean; fields?: { name: string; label: string; secret: boolean; required: boolean }[] }
export interface Resource { id: string; kind: string; name: string; domain_id?: string; owner_id: string; data: Record<string, unknown>; version: number; active: boolean; created_at: string; updated_at: string }
export class APIError extends Error { constructor(public status: number, public code: string, message: string, public requestId?: string) { super(message) } }
let csrfToken = ''
export function setCSRF(value: string) { csrfToken = value }
export async function request<T>(path: string, options: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const response = await fetch('/api/v1' + path, {
    method: options.method || 'GET', credentials: 'same-origin', signal: options.signal,
    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  })
  const result = await response.json().catch(() => ({ message: '服务器响应格式不正确' }))
  if (!response.ok) throw new APIError(response.status, result.code || 'request_failed', result.message || '请求失败', result.request_id)
  return result as T
}
