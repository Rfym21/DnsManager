import {describe,it,expect} from 'vitest';
import {absoluteName,parseRecordImport,validateRecord} from './records';
describe('record names and import contracts',()=>{
 it('preserves absolute names and root zone',()=>{expect(absoluteName('@','example.com')).toBe('example.com');expect(absoluteName('www.example.com.','example.com')).toBe('www.example.com');expect(absoluteName('api','example.com')).toBe('api.example.com');});
 it('validates imported records before submitting batch',()=>{const result=parseRecordImport('www\tA\t192.0.2.10\t300\n@\tMX\tmail.example.com\t600\t10');expect(result).toHaveLength(2);expect(result[1].priority).toBe(10);expect(()=>parseRecordImport('www\tA\t999.0.2.10\t300')).toThrow('IPv4');expect(()=>parseRecordImport('[{"name":"@","type":"MX","value":"mail.example.com","ttl":300}]')).toThrow('优先级');});
 it('does not silently normalize TXT or accept non-list JSON',()=>{const rows=parseRecordImport('[{"name":"@","type":"TXT","value":"v=spf1 include:example.net ~all","ttl":1}]');expect(rows[0].value).toBe('v=spf1 include:example.net ~all');expect(()=>parseRecordImport('{"name":"bad"}')).toThrow();});
 it('rejects invalid TTL and proxy for TXT',()=>{expect(validateRecord({name:'@',type:'TXT',value:'x',ttl:0,enabled:true,proxied:false})).toContain('TTL');expect(validateRecord({name:'@',type:'TXT',value:'x',ttl:300,enabled:true,proxied:true})).toContain('代理');});
});
