import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { AlertCircle, RefreshCw } from 'lucide-react'
import { Button } from '../ui/primitives'

export function LoadingBoundary({ pending, children }: { pending: boolean; children: ReactNode }) {
  const [shown, setShown] = useState(false)
  useEffect(() => { if (!pending) return; const timer = setTimeout(() => setShown(true), 150); return () => clearTimeout(timer) }, [pending])
  useEffect(() => { if (pending || !shown) return; const timer = setTimeout(() => setShown(false), 500); return () => clearTimeout(timer) }, [pending, shown])
  return <div className="loading-boundary" aria-busy={pending}><div className={pending && shown ? 'loading-content-hidden' : ''}>{children}</div>{shown && <div className={`light-tide ${pending ? '' : 'revealing'}`} aria-hidden="true"><div className="skeleton-heading" />{Array.from({ length: 6 }, (_, i) => <div className="skeleton-row" key={i}><span /><span /><span /><span /></div>)}</div>}</div>
}
export function PendingPage() { return <LoadingBoundary pending><div style={{ minHeight: 360 }} /></LoadingBoundary> }
export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) { return <div className="empty-state"><AlertCircle size={26} /><h3>操作暂时未完成</h3><p>{error.message}</p>{retry && <Button onClick={retry}><RefreshCw size={16} />重试</Button>}</div> }
export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) { return <div className="empty-state"><h3>{title}</h3><p>{description}</p>{action}</div> }
