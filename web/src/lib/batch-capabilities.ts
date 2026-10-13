import type {DNSRecord} from './types';
export interface RecordCapabilities{capabilities:Record<string,unknown>;lines:{id:string;name:string}[];min_ttl:number;proxy?:boolean;}
export function matchRecordLine(lines:RecordCapabilities['lines'],value:string):string|undefined{
 if(!value)return lines.find(l=>['default','0','-1','default_view','Default',''].includes(l.id)||['默认','默认线路'].includes(l.name))?.id??lines[0]?.id;
 const exact=lines.find(l=>l.id===value||l.name===value);if(exact)return exact.id;
 const aliases:Record<string,string[]>={default:['默认','默认线路'],telecom:['电信','中国电信'],unicom:['联通','中国联通'],mobile:['移动','中国移动'],oversea:['海外','境外']};const names=aliases[value.toLowerCase()];return names?lines.find(l=>names.includes(l.name))?.id:undefined;
}
export function applyRecordCapabilities(record:DNSRecord,caps:RecordCapabilities,line:string):DNSRecord{
 if(['REDIRECT_URL','FORWARD_URL'].includes(record.type)&&!caps.capabilities?.redirect)throw new Error('平台不支持 URL 跳转记录');
 const lineID=matchRecordLine(caps.lines,line);if(lineID===undefined)throw new Error(`平台没有匹配线路「${line||'默认'}」`);
 if(record.ttl!==1&&record.ttl<caps.min_ttl)throw new Error(`平台最小 TTL 为 ${caps.min_ttl} 秒，请修改后重新预览`);
 return {...record,line:lineID};
}
