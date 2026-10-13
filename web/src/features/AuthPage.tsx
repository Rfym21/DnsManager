import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Globe, ArrowRight } from 'lucide-react'
import { request, setCSRF, APIError } from '../api/client'
import type { Session } from '../api/client'
import { Button, Field } from '../components/ui/primitives'

export function AuthPage({ install, tokenRequired }: { install: boolean; tokenRequired: boolean }) {
  const client = useQueryClient()
  const [error, setError] = useState(''), [totp, setTOTP] = useState(false), [pending, setPending] = useState(false)
  return <main className="auth-screen"><div className="auth-card"><div className="auth-brand"><Globe size={30} /><span>DNS Manager</span></div><h1>{install ? '创建你的控制台' : '欢迎回来'}</h1><p className="muted">{install ? '连接、管理和自动化你的 DNS 基础设施。' : '登录以管理你的域名、证书与自动化任务。'}</p><form onSubmit={async e => { e.preventDefault(); const form = new FormData(e.currentTarget); setPending(true); setError(''); try { const data = await request<Session>(install ? '/setup' : '/auth/login', { method: 'POST', body: { username: form.get('username'), password: form.get('password'), ...(install ? { setup_token: form.get('setup_token') || '' } : { code: form.get('code') || '' }) } }); setCSRF(data.csrf_token); client.setQueryData(['session'], data) } catch (error) { if (error instanceof APIError && error.code === 'totp_required') setTOTP(true); setError((error as Error).message) } finally { setPending(false) } }}><Field label={install ? '管理员用户名' : '用户名'}><input name="username" autoComplete="username" required minLength={2} autoFocus /></Field><Field label="密码" help={install ? '至少 12 个字符，最多 72 字节。' : undefined}><input name="password" type="password" autoComplete={install ? 'new-password' : 'current-password'} minLength={install ? 12 : undefined} required /></Field>{install && tokenRequired && <Field label="安装令牌" help="由实例管理员提供，存放在 SETUP_TOKEN_FILE。"><input name="setup_token" type="password" required autoComplete="off" /></Field>}{totp && <Field label="动态口令"><input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required maxLength={6} /></Field>}{error && <div className="form-error" role="alert">{error}</div>}<Button variant="primary" type="submit" disabled={pending}>{pending ? '请稍候…' : install ? '创建管理员并进入' : '登录控制台'}<ArrowRight size={16} /></Button></form><small>自部署 · 多平台 DNS · 安全与权限</small></div></main>
}
