import type { ButtonHTMLAttributes, ReactNode } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { clsx } from 'clsx'

export function Button({ className, variant = 'secondary', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' }) {
  return <button className={clsx('button', variant, className)} {...props} />
}
export function Drawer({ open, onOpenChange, title, description, children, footer }: { open: boolean; onOpenChange: (value: boolean) => void; title: string; description?: string; children: ReactNode; footer?: ReactNode }) {
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="drawer-overlay" /><Dialog.Content className="drawer-content"><div className="drawer-header"><Dialog.Title>{title}</Dialog.Title><Dialog.Close asChild><Button variant="ghost" className="icon-button" aria-label="关闭"><X size={18} /></Button></Dialog.Close></div><Dialog.Description className="drawer-description">{description || '填写信息并检查后保存。'}</Dialog.Description><div className="drawer-body">{children}</div>{footer && <div className="drawer-footer">{footer}</div>}</Dialog.Content></Dialog.Portal></Dialog.Root>
}
export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' | 'danger' }) { return <span className={clsx('badge', tone)}>{children}</span> }
export function Field({ label, help, children }: { label: string; help?: string; children: ReactNode }) { return <label className="field"><span className="field-label">{label}</span>{children}{help && <small>{help}</small>}</label> }
