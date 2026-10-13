import { createContext, useContext, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { Globe, LayoutDashboard, ShieldCheck, Activity, CalendarClock, Zap, Users, KeyRound, Settings, ScrollText, Cable, LogOut, Menu, X, CircleCheck } from 'lucide-react'
import { request, setCSRF } from './api/client'
import type { Session } from './api/client'
import { Button } from './components/ui/primitives'
import { PendingPage } from './components/shared/loading'
import { AuthPage } from './features/AuthPage'
import { Dashboard, AccountsPage, DomainsPage, RecordsPage } from './features/DNSPages'
import { ResourcePage, UsersPage, AuditPage, SettingsPage, TokensPage } from './features/ManagementPages'

const SessionContext = createContext<Session | null>(null)
export const useSession = () => useContext(SessionContext)!
const navigation = [
  { label: '总览', path: '/', icon: LayoutDashboard, group: '概览' },
  { label: '域名', path: '/domains', icon: Globe, group: 'DNS' },
  { label: '平台账户', path: '/accounts', icon: Cable, group: '', admin: true },
  { label: '监控容灾', path: '/monitors', icon: Activity, group: '自动化', admin: true },
  { label: '定时切换', path: '/schedules', icon: CalendarClock, group: '', admin: true },
  { label: '优选 IP', path: '/optimizations', icon: Zap, group: '', admin: true },
  { label: '证书订单', path: '/certificates', icon: ShieldCheck, group: '证书', admin: true },
  { label: '签发账户', path: '/issuer-accounts', icon: KeyRound, group: '', admin: true },
  { label: '部署任务', path: '/deployments', icon: Cable, group: '', admin: true },
  { label: '部署账户', path: '/deployment-accounts', icon: KeyRound, group: '', admin: true },
  { label: 'DNS 委托', path: '/delegations', icon: Globe, group: '', admin: true },
  { label: '用户与权限', path: '/users', icon: Users, group: '管理', admin: true },
  { label: 'API 凭据', path: '/tokens', icon: KeyRound, group: '' },
  { label: '审计日志', path: '/audit', icon: ScrollText, group: '' },
  { label: '通知渠道', path: '/notification-channels', icon: Activity, group: '', admin: true },
  { label: '系统设置', path: '/settings', icon: Settings, group: '', admin: true },
]
export function App() {
  const query = useQuery({ queryKey: ['session'], queryFn: () => request<Session>('/auth/me'), retry: false })
  const setup = useQuery({ queryKey: ['setup'], queryFn: () => request<{ installed: boolean; setup_token_required: boolean }>('/setup'), enabled: query.isError })
  if (query.isPending || (query.isError && setup.isPending)) return <div className="app-initial"><PendingPage /></div>
  if (!query.data) return <AuthPage install={setup.data?.installed === false} tokenRequired={setup.data?.setup_token_required !== false} />
  setCSRF(query.data.csrf_token)
  return <SessionContext.Provider value={query.data}><Shell /></SessionContext.Provider>
}
function Shell() {
  const session = useSession(), client = useQueryClient(), navigate = useNavigate()
  const [theme, setTheme] = useState(() => localStorage.getItem('dnsmgr-theme') || 'light')
  const [mobile, setMobile] = useState(false)
  useEffect(() => { const media = matchMedia('(prefers-color-scheme: dark)'); const apply = () => { document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme }; apply(); localStorage.setItem('dnsmgr-theme', theme); media.addEventListener('change', apply); return () => media.removeEventListener('change', apply) }, [theme])
  const admin = session.user.role === 'admin' && !session.domain_id
  const routes = navigation.filter(item => !item.admin || admin)
  return <div className="app-shell"><aside className={`sidebar ${mobile ? 'mobile-open' : ''}`}><div className="brand"><Globe size={24} /><strong>DNS Manager</strong><Button variant="ghost" className="mobile-close icon-button" onClick={() => setMobile(false)} aria-label="关闭导航"><X size={18} /></Button></div><div className="instance"><CircleCheck size={13} />自部署实例</div><nav>{routes.map(item => <div key={item.path}>{item.group && <div className="nav-group">{item.group}</div>}<NavLink to={item.path} end={item.path === '/'} onClick={() => setMobile(false)}><item.icon size={17} /><span>{item.label}</span></NavLink></div>)}</nav><div className="profile"><span className="avatar">{session.user.username[0].toUpperCase()}</span><div><strong>{session.user.username}</strong><small>{session.domain_id ? '域名单独登录' : admin ? '管理员' : '受限用户'}</small></div><Button variant="ghost" className="icon-button" aria-label="退出登录" onClick={async () => { await request('/auth/logout', { method: 'POST' }); client.clear(); navigate('/'); location.reload() }}><LogOut size={16} /></Button></div></aside>{mobile && <button className="mobile-backdrop" aria-label="关闭导航" onClick={() => setMobile(false)} />}<div className="main"><header className="topbar"><Button variant="ghost" className="mobile-menu icon-button" onClick={() => setMobile(true)} aria-label="打开导航"><Menu size={18} /></Button><span>控制台 <span className="separator">/</span> {session.domain_id ? '域名工作区' : '你的基础设施'}</span><select aria-label="主题" value={theme} onChange={e => setTheme(e.target.value)}><option value="light">浅色</option><option value="dark">深色</option><option value="system">跟随系统</option></select></header><main className="content"><Routes><Route path="/" element={session.domain_id ? <Navigate to={`/domains/${session.domain_id}`} /> : <Dashboard />} /><Route path="/domains" element={<DomainsPage />} /><Route path="/domains/:id" element={<RecordsPage />} /><Route path="/audit" element={<AuditPage />} /><Route path="/tokens" element={<TokensPage />} />{admin && <><Route path="/accounts" element={<AccountsPage />} /><Route path="/users" element={<UsersPage />} /><Route path="/settings" element={<SettingsPage />} />{['certificates', 'issuer-accounts', 'deployment-accounts', 'deployments', 'delegations', 'monitors', 'schedules', 'optimizations', 'notification-channels'].map(kind => <Route key={kind} path={`/${kind}`} element={<ResourcePage key={kind} kind={kind} />} />)}</>}<Route path="*" element={<Navigate to="/" replace />} /></Routes></main></div></div>
}
