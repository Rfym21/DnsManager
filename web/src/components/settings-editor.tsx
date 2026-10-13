import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { toast } from 'sonner';
import { apiOperation } from '../lib/api';
import type { Schemas } from '../generated/contracts';
import { Button, ErrorState, Field, LoadingBoundary, PageHeader } from './ui';

type Site = Schemas['SiteSettings'] & { certificate_renew_before_days?: number };
type Deployment = Schemas['DeploymentSecuritySettings'];
type Settings = Schemas['SettingsItems'] & { site?: Site };

export function SettingsEditor() {
  const query = useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => apiOperation('get_api_v1_settings', { params:{}, signal }) });
  const [changes, setChanges] = useState<Settings>({});
  const [error, setError] = useState<unknown>();
  const values: Settings = {
    site: { ...query.data?.items.site, ...changes.site },
    network: { ...query.data?.items.network, ...changes.network },
    deployment_security: { ...query.data?.items.deployment_security, ...changes.deployment_security },
    security:{...query.data?.items.security,...changes.security}, retention:{...query.data?.items.retention,...changes.retention},
  };
  const save = useMutation({ mutationFn: () => apiOperation('put_api_v1_settings', { params:{}, json: { items: changes } }), onSuccess: () => { setChanges({}); query.refetch(); setError(undefined); toast.success('系统设置已保存'); }, onError: setError });
  const site = (key: keyof Site, value: string | number) => setChanges({ ...changes, site: { ...values.site, [key]: value } });
  const deployment = (key: keyof Deployment, value: string[] | boolean) => setChanges({ ...changes, deployment_security: { ...values.deployment_security, [key]: value } });
  return <><PageHeader title="系统设置" description="设置域名提醒、网络连接和证书部署目录。" /><LoadingBoundary pending={query.isPending} error={query.error} hasData={!!query.data}><form className="form-width" onSubmit={e => { e.preventDefault(); save.mutate(); }}>{!!error && <ErrorState inline error={error} />}<section className="card"><h2>实例与提醒</h2><Field label="实例名称"><input value={values.site?.name ?? 'DNS Manager'} onChange={e => site('name', e.target.value)} /></Field><Field label="调度时区" help="使用 IANA 时区，例如 Asia/Shanghai。"><input value={values.site?.timezone ?? 'Asia/Shanghai'} onChange={e => site('timezone', e.target.value)} /></Field><Field label="域名到期提醒天数" help="以逗号分隔，例如 30,15,7,3,1；本地时间 9 点后发送。"><input value={values.site?.domain_expiry_days ?? ''} onChange={e => site('domain_expiry_days', e.target.value)} /></Field><Field label="证书到期默认提醒天数" help="证书未单独设置提前天数时采用此值，默认 7 天。"><input type="number" min={1} max={365} value={values.site?.certificate_renew_before_days ?? 7} onChange={e => site('certificate_renew_before_days', Number(e.target.value))} /></Field></section><section className="card"><h2>登录与日志</h2><label className="check-field"><input type="checkbox" checked={values.security?.login_captcha??false} onChange={e=>setChanges({...changes,security:{...values.security,login_captcha:e.target.checked}})}/>登录时要求图片验证码</label><Field label="审计日志保留天数"><input type="number" min={7} max={3650} value={values.retention?.audit_days??180} onChange={e=>setChanges({...changes,retention:{...values.retention,audit_days:Number(e.target.value)}})}/></Field><Field label="已完成任务保留天数"><input type="number" min={7} max={3650} value={values.retention?.job_days??90} onChange={e=>setChanges({...changes,retention:{...values.retention,job_days:Number(e.target.value)}})}/></Field></section><section className="card"><h2>网络</h2><Field label="默认代理 URL" help="支持 HTTP、HTTPS、SOCKS4/4a/5/5h；账户需单独勾选代理。输入完整地址更新，留空保留已有凭据。"><input type="password" autoComplete="new-password" placeholder="留空保留已有代理" value={values.network?.proxy_url ?? ''} onChange={e => setChanges({ ...changes, network: { proxy_url: e.target.value } })} /></Field></section><section className="card"><h2>部署权限</h2><Field label="本地部署目录" help="每行一个绝对路径；Docker 的证书输出卷挂载在 /exports。目录需已存在。"><textarea value={(values.deployment_security?.allowed_directories ?? []).join('\n')} onChange={e => deployment('allowed_directories', e.target.value.split('\n').map(v => v.trim()).filter(Boolean))} /></Field><Field label="远程部署目录" help="限制 SSH/FTP 写入范围，每行一个绝对路径。"><textarea value={(values.deployment_security?.remote_allowed_directories ?? []).join('\n')} onChange={e => deployment('remote_allowed_directories', e.target.value.split('\n').map(v => v.trim()).filter(Boolean))} /></Field><label className="check-field"><input type="checkbox" checked={values.deployment_security?.allow_trusted_hooks ?? false} onChange={e => deployment('allow_trusted_hooks', e.target.checked)} />允许管理员配置部署前后命令</label></section><div className="form-actions"><span className="sub">{Object.keys(changes).length ? '有未保存的修改' : '设置已同步'}</span><Button type="submit" variant="primary" pending={save.isPending} disabled={!Object.keys(changes).length}>保存设置</Button></div></form></LoadingBoundary></>;
}
