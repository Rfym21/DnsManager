import { useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import {applyRecordCapabilities,type RecordCapabilities} from '../lib/batch-capabilities';
import { parseSmartRecords, type SmartRecord } from '../lib/smart-records';
import type { Domain, Job } from '../lib/types';
import { Button, ErrorState, Field } from './ui';

export function SmartRecords({ domains, initialDomain = '' }: { domains: Domain[]; initialDomain?: string }) {
  const [text, setText] = useState(''), [domainId, setDomainId] = useState(initialDomain), [value, setValue] = useState(''), [type, setType] = useState(''), [ttl, setTTL] = useState(300), [line, setLine] = useState('');
  const [preview, setPreview] = useState<SmartRecord[]>([]), [error, setError] = useState<unknown>();
  const keys=useRef(new Map<string,string>());const [jobs, setJobs] = useState<{ name: string; id: string }[]>([]);
  const submit = useMutation({ mutationFn: async () => {
    const grouped = new Map<string, SmartRecord[]>();
    for (const row of preview) grouped.set(row.domain.id,[...(grouped.get(row.domain.id)??[]),row]);
    const prepared=await Promise.all([...grouped].filter(([id])=>!jobs.some(j=>j.name===id)).map(async([id,rows])=>{const caps=await api<RecordCapabilities>(`/domains/${id}/capabilities`);return{id,rows,records:rows.map(row=>applyRecordCapabilities(row.record,caps,line))};}));
    for(const group of prepared){let key=keys.current.get(group.id);if(!key){key=crypto.randomUUID();keys.current.set(group.id,key);}const result=await api<{job:Job}>('/record-batches',{method:'POST',json:{domain_ids:[group.id],records:group.records,operation:'create'},headers:{'Idempotency-Key':key}});setJobs(current=>[...current.filter(j=>j.id!==result.job.id),{name:group.id,id:result.job.id}]);}

  }, onError: setError });
  const editable=!submit.isPending&&!jobs.length;const reset = () => { keys.current.clear(); setPreview([]); setJobs([]); setError(undefined); };
  return <section className="card"><h2>智能批量添加</h2><p>支持“主机 值 域名”“值 完整主机名”“主机 值”，或使用默认值的完整主机名；多域名分别提交任务。</p>
    <Field label="智能解析内容"><textarea rows={6} value={text} disabled={!editable} onChange={e => { setText(e.target.value); reset(); }} placeholder={'www 192.0.2.10 example.com\n2001:db8::1 api.example.com'} /></Field>
    <div className="field-row"><Field label="智能解析默认域名"><select disabled={!editable} value={domainId} onChange={e => { setDomainId(e.target.value); reset(); }}><option value="">每行指定域名</option>{domains.map(d => <option key={d.id} value={d.id}>{d.name} · {d.provider}</option>)}</select></Field><Field label="智能解析默认值"><input disabled={!editable} value={value} onChange={e => { setValue(e.target.value); reset(); }} /></Field></div>
    <div className="field-row"><Field label="智能解析类型"><select disabled={!editable} value={type} onChange={e => { setType(e.target.value); reset(); }}><option value="">自动判断 A / AAAA / CNAME</option>{['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'CAA'].map(t => <option key={t}>{t}</option>)}</select></Field><Field label="智能解析 TTL"><input disabled={!editable} type="number" min={1} value={ttl} onChange={e => { setTTL(Number(e.target.value)); reset(); }} /></Field></div>
    <Field label="智能解析线路" help="填平台线路 ID 或线路名称；留空匹配各平台默认线路。"><input disabled={!editable} value={line} onChange={e => { setLine(e.target.value); reset(); }} /></Field>
    {!!error && <ErrorState inline error={error} />}<Button disabled={!editable} onClick={() => { try { setPreview(parseSmartRecords(text, domains, { domainId, value, type, ttl })); setError(undefined); setJobs([]); } catch (e) { setError(e); } }}>预览智能解析</Button>
    {!!preview.length && <><div className="table-scroll"><table><thead><tr><th>域名</th><th>类型</th><th>主机</th><th>值</th></tr></thead><tbody>{preview.map(r => <tr key={r.row}><td>{r.domain.name}</td><td>{r.record.type}</td><td>{r.record.name}</td><td>{r.record.value}</td></tr>)}</tbody></table></div><Button variant="primary" pending={submit.isPending} disabled={jobs.length === new Set(preview.map(r => r.domain.id)).size} onClick={() => submit.mutate()}>确认提交 {preview.length} 条记录</Button></>}
    {!!jobs.length && <><Button disabled={submit.isPending} onClick={()=>{reset();setText('');}}>开始新的智能批次</Button><p>已提交：{jobs.map(j => <Link key={j.id} to={`/jobs/${j.id}`} style={{ marginInline: 8 }}>{domains.find(d => d.id === j.name)?.name}的任务</Link>)}</p></>}
  </section>;
}
