import {describe,expect,it} from 'vitest';
import {applyRecordCapabilities,matchRecordLine} from './batch-capabilities';
import type {DNSRecord} from './types';
const record:DNSRecord={name:'api',type:'A',value:'192.0.2.10',ttl:300,enabled:true,proxied:false};
describe('batch provider capabilities',()=>{
 it('maps carrier aliases and exact provider IDs without inventing unknown lines',()=>{const lines=[{id:'10=0',name:'电信'},{id:'0',name:'默认'}];expect(matchRecordLine(lines,'telecom')).toBe('10=0');expect(matchRecordLine(lines,'')).toBe('0');expect(matchRecordLine(lines,'unknown')).toBeUndefined();});
 it('rejects unsupported redirects and too-low TTL before a batch is submitted',()=>{const caps={capabilities:{redirect:false},lines:[{id:'default',name:'默认'}],min_ttl:600};expect(()=>applyRecordCapabilities(record,caps,'')).toThrow('TTL');expect(()=>applyRecordCapabilities({...record,type:'REDIRECT_URL',value:'https://example.test'},caps,'')).toThrow('URL');expect(applyRecordCapabilities({...record,ttl:1},caps,'')).toMatchObject({ttl:1,line:'default'});});
});
