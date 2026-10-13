import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../lib/api';
import { Button, ErrorState, Field } from './ui';

type Dates = { registered_at?: string; expires_at?: string; checked_at?: string; expiry_notice_enabled: boolean };
export function DomainDates({ id, canWrite }: { id: string; canWrite: boolean }) {
  const client = useQueryClient();
  const [error, setError] = useState<unknown>();
 const [manual,setManual]=useState<{registered_at:string;expires_at:string}>();
  const query = useQuery({ queryKey: ['domain-dates', id], queryFn: ({ signal }) => api<Dates>(`/domains/${id}/dates`, { signal }) });
  const refresh = useMutation({ mutationFn: () => api(`/domains/${id}/dates/refresh`, { method: 'POST', json: {} }), onSuccess: () => { setError(undefined); client.invalidateQueries({ queryKey: ['domain-dates', id] }); }, onError: setError });
  const save = useMutation({ mutationFn: (enabled: boolean) => api(`/domains/${id}/dates`, { method: 'PUT', json: { expiry_notice_enabled: enabled } }), onSuccess: () => client.invalidateQueries({ queryKey: ['domain-dates', id] }), onError: setError });
  const edit=useMutation({mutationFn:()=>api(`/domains/${id}/dates`,{method:'PUT',json:manual}),onSuccess:()=>{setManual(undefined);setError(undefined);client.invalidateQueries({queryKey:['domain-dates',id]});},onError:setError});
  const date = (value?: string) => value ? new Date(value).toLocaleDateString() : '尚未查询';
  return <section className="card" aria-label="域名注册与到期信息"><div className="card-header"><h2>注册与到期</h2>{canWrite && <Button pending={refresh.isPending} onClick={() => refresh.mutate()}>查询注册局</Button>}</div><p>注册日期 {date(query.data?.registered_at)} · 到期日期 {date(query.data?.expires_at)}</p>{canWrite && <div className="field"><span className="field-label">到期提醒</span><span className="field-help">提醒天数在实例设置中配置；查询未返回的日期会保留。手动日期作为备用值，自动刷新可用注册局返回的日期更新。</span><label className="check-field"><input type="checkbox" checked={query.data?.expiry_notice_enabled ?? false} disabled={save.isPending} onChange={e => save.mutate(e.target.checked)} />启用此域名的到期提醒</label></div>}{canWrite&&<><Button variant="ghost" onClick={()=>setManual({registered_at:query.data?.registered_at?.slice(0,10)??'',expires_at:query.data?.expires_at?.slice(0,10)??''})}>手动维护日期</Button>{manual&&<form onSubmit={e=>{e.preventDefault();edit.mutate();}}><div className="form-grid"><Field label="注册日期"><input type="date" value={manual.registered_at} onChange={e=>setManual({...manual,registered_at:e.target.value})}/></Field><Field label="到期日期"><input type="date" value={manual.expires_at} min={manual.registered_at} onChange={e=>setManual({...manual,expires_at:e.target.value})}/></Field></div><Button type="submit" pending={edit.isPending}>保存日期</Button><Button variant="ghost" onClick={()=>setManual(undefined)}>取消</Button></form>}</>}{!!(error || query.error) && <ErrorState inline error={error || query.error} />}</section>;
}
