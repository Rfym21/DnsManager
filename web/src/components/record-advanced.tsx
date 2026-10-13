import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { Button, ErrorState, Field } from './ui';

type Caps = Record<string, unknown>;
type Weight = { name: string; type: string; line: string; enabled: boolean };
export function RecordAdvanced({ id, caps, canWrite, selected }: { id: string; caps: Caps; canWrite: boolean; selected: string[] }) {
  const client = useQueryClient();
  const [section, setSection] = useState('');
  const [group, setGroup] = useState('');
  const [alias, setAlias] = useState('');
  const [error, setError] = useState<unknown>();
  const groups = useQuery({ queryKey: ['record-groups', id], queryFn: () => api<{ items: { id: string; name: string }[] }>(`/domains/${id}/record-groups`), enabled: section === 'groups' });
  const logs = useQuery({ queryKey: ['provider-logs', id], queryFn: () => api<{ items: { time: string; message: string; ip?: string }[] }>(`/domains/${id}/record-logs`), enabled: section === 'logs' });
  const weights = useQuery({ queryKey: ['record-weights', id], queryFn: () => api<{ items: Weight[] }>(`/domains/${id}/weights`), enabled: section === 'weights' });
  const aliases = useQuery({ queryKey: ['provider-aliases', id], queryFn: () => api<{ items: { id: string; name: string }[] }>(`/domains/${id}/provider-aliases`), enabled: section === 'aliases' });
  const write = useMutation({ mutationFn: ({ path, method = 'PUT', data }: { path: string; method?: string; data?: unknown }) => api(`/domains/${id}/${path}`, { method, json: data }), onSuccess: () => { setError(undefined); client.invalidateQueries({ queryKey: ['records', id] }); client.invalidateQueries({ queryKey: ['record-weights', id] }); client.invalidateQueries({ queryKey: ['provider-aliases', id] }); }, onError: setError });
  const choices = [['groups', '记录分组', caps.groups], ['logs', '平台操作日志', caps.logs], ['weights', '权重分组', caps.weight_groups], ['aliases', '平台域名别名', caps.aliases]].filter(item => item[2]);
  if (!choices.length) return null;
  return <section className="card"><div className="toolbar-group">{choices.map(([key, label]) => <Button key={String(key)} variant={section === key ? 'primary' : 'ghost'} onClick={() => { setSection(section === key ? '' : String(key)); setError(undefined); }}>{String(label)}</Button>)}</div>
    {!!(error || (section === 'groups' && groups.error) || (section === 'logs' && logs.error) || (section === 'weights' && weights.error) || (section === 'aliases' && aliases.error)) && <ErrorState inline error={error || groups.error || logs.error || weights.error || aliases.error} />}
    {section === 'groups' && <><Field label="平台分组" help={`分组变更应用到当前页选中的 ${selected.length} 条记录。`}><select value={group} onChange={e => setGroup(e.target.value)}><option value="">选择分组</option>{groups.data?.items.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>{canWrite && <Button disabled={!group || !selected.length} pending={write.isPending} onClick={() => write.mutate({ path: 'record-groups', data: { group_id: group, record_ids: selected } })}>应用分组</Button>}</>}
    {section === 'logs' && <div className="table-scroll"><table><thead><tr><th>时间</th><th>操作</th><th>来源 IP</th></tr></thead><tbody>{logs.data?.items.map((l, i) => <tr key={i}><td>{l.time}</td><td>{l.message}</td><td>{l.ip}</td></tr>)}</tbody></table><Button pending={logs.isFetching} onClick={() => logs.refetch()}>刷新平台日志</Button></div>}
    {section === 'weights' && <div className="table-scroll"><table><thead><tr><th>主机</th><th>类型</th><th>线路</th><th>权重策略</th></tr></thead><tbody>{weights.data?.items.map((g, i) => <tr key={i}><td>{g.name}</td><td>{g.type}</td><td>{g.line}</td><td><label className="check-field"><input type="checkbox" aria-label={`${g.name} ${g.type} 权重分组`} checked={g.enabled} disabled={!canWrite || write.isPending} onChange={e => write.mutate({ path: 'weights', data: { ...g, enabled: e.target.checked } })} />启用</label></td></tr>)}</tbody></table></div>}
    {section === 'aliases' && <><div className="table-scroll"><table><thead><tr><th>平台别名</th><th>操作</th></tr></thead><tbody>{aliases.data?.items.map(a => <tr key={a.id}><td>{a.name}</td><td>{canWrite && <Button pending={write.isPending} onClick={() => write.mutate({ path: `provider-aliases/${encodeURIComponent(a.id)}`, method: 'DELETE' })}>删除别名</Button>}</td></tr>)}</tbody></table></div>{canWrite && <form onSubmit={e => { e.preventDefault(); write.mutate({ path: 'provider-aliases', method: 'POST', data: { name: alias } }); }}><Field label="新增平台别名"><input required value={alias} onChange={e => setAlias(e.target.value)} /></Field><Button type="submit" pending={write.isPending}>添加别名</Button></form>}</>}
  </section>;
}
