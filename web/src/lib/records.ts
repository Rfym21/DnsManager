import type {DNSRecord} from './types';
export function absoluteName(name:string,zone:string){name=name.trim();if(!name||name==='@')return zone;if(name.endsWith('.'))return name.slice(0,-1);if(name===zone||name.endsWith('.'+zone))return name;return name+'.'+zone;}
export function validateRecord(record:DNSRecord):string|undefined{
 if(!record.name.trim()||!record.value.trim())return '主机记录与记录值不能为空';
 if(!Number.isInteger(record.ttl)||record.ttl<1||record.ttl>2147483647)return 'TTL 需为正整数秒，1 表示自动';
 if(record.type==='A'&&!/^(\d{1,3}\.){3}\d{1,3}$/.test(record.value)||record.type==='A'&&record.value.split('.').some(p=>Number(p)>255))return 'A 记录需要有效 IPv4 地址';
 if(record.type==='AAAA'&&!validIPv6(record.value))return 'AAAA 记录需要有效 IPv6 地址';
 if(record.type==='MX'&&(record.priority===undefined||!Number.isInteger(record.priority)||record.priority<0||record.priority>65535))return 'MX 优先级需为 0–65535';
 if(record.weight!==undefined&&(!Number.isInteger(record.weight)||record.weight<0))return '权重需为非负整数';
 if(!['A','AAAA','CNAME','MX','TXT','NS','SRV','CAA','PTR','HTTPS','SVCB','TLSA','DS','DNSKEY','SSHFP','SOA','NAPTR','URI','SPF','DNAME','ALIAS','ANAME','APP','REDIRECT_URL','FORWARD_URL'].includes(record.type))return '记录类型不受支持';
 if(['REDIRECT_URL','FORWARD_URL'].includes(record.type)){try{const url=new URL(record.value);if(!['http:','https:'].includes(url.protocol))return 'URL 跳转需要 HTTP 或 HTTPS 地址';}catch{return 'URL 跳转需要有效地址';}}
 if(record.proxied&&!['A','AAAA','CNAME'].includes(record.type))return '仅 A、AAAA、CNAME 可启用代理';
}
export function parseRecordImport(text:string):DNSRecord[]{const trimmed=text.trim();if(!trimmed)throw new Error('请输入记录内容');if(trimmed.startsWith('[')){const parsed:unknown=JSON.parse(trimmed);if(!Array.isArray(parsed))throw new Error('JSON 应为记录数组');return parsed.map((item,index)=>normalizeImport(item,index));}return trimmed.split(/\r?\n/).filter(line=>line.trim()&&!line.trim().startsWith('#')).map((line,index)=>{const [name,type,value,ttl='300',priority]=line.split('\t');if(!type||!value)throw new Error(`第 ${index+1} 行需使用 Tab 分隔 主机、类型、值、TTL`);return normalizeImport({name,type,value,ttl:Number(ttl),priority:priority?Number(priority):undefined},index);});}
function normalizeImport(item:unknown,index:number):DNSRecord{if(!item||typeof item!=='object')throw new Error(`第 ${index+1} 条记录格式不正确`);const raw=item as Partial<DNSRecord>;const result:DNSRecord={id:raw.id?String(raw.id):undefined,version:raw.version,type:String(raw.type??'').toUpperCase(),name:String(raw.name??''),value:String(raw.value??''),ttl:Number(raw.ttl??300),enabled:raw.enabled!==false,proxied:raw.proxied===true,line:raw.line??'default',priority:raw.priority,weight:raw.weight,remark:raw.remark};const error=validateRecord(result);if(error)throw new Error(`第 ${index+1} 条：${error}`);return result;}

function validIPv6(value:string):boolean{if(!value.includes(':')||value.includes('%')||!/^([0-9a-f:]|[0-9.])+$/i.test(value))return false;const halves=value.split('::');if(halves.length>2)return false;let count=0;for(const half of halves){if(!half)continue;for(const group of half.split(':')){if(!group)return false;if(group.includes('.')){const parts=group.split('.');if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))return false;count+=2;}else{if(!/^[0-9a-f]{1,4}$/i.test(group))return false;count++;}}}return halves.length===2?count<8:count===8;}
