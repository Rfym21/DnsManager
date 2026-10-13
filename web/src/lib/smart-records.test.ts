import { describe, expect, it } from 'vitest';
import { parseSmartRecords } from './smart-records';
import type { Domain } from './types';
const domains = [{ id: 'a', name: 'example.com' }, { id: 'b', name: 'sub.example.com' }, { id: 'c', name: 'other.net' }] as Domain[];
describe('smart record boundaries', () => {
  it('maps mixed formats to the longest explicitly managed zone', () => {
    const result = parseSmartRecords('www 192.0.2.1 example.com\n2001:db8::1 api.sub.example.com\nwww.other.net', domains, { ttl: 300, value: 'target.example.org' });
    expect(result.map(r => [r.domain.id, r.record.name, r.record.type])).toEqual([['a', 'www', 'A'], ['b', 'api', 'AAAA'], ['c', 'www', 'CNAME']]);
  });
  it('supports CNAME value-first hosts and ambiguous account selection',()=>{expect(parseSmartRecords('target.other.net www.example.com',domains,{ttl:300})[0].record).toMatchObject({name:'www',type:'CNAME',value:'target.other.net'});expect(parseSmartRecords('www.example.com 192.0.2.10',[...domains,{id:'dup',name:'example.com'} as Domain],{ttl:300,domainId:'dup'})[0].domain.id).toBe('dup');});
  it('rejects unowned and ambiguous accounts and invalid addresses', () => {
    expect(() => parseSmartRecords('www 192.0.2.1 unknown.com', domains, { ttl: 300 })).toThrow(/未授权/);
    expect(() => parseSmartRecords('www.example.com 192.0.2.1', [...domains, { id: 'dup', name: 'example.com' } as Domain], { ttl: 300 })).toThrow(/多个平台/);
    expect(() => parseSmartRecords('www 999.1.1.1', domains, { ttl: 300, domainId: 'a' })).toThrow(/IPv4/);
  });
});
