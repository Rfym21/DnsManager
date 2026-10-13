import type { DNSRecord, Domain } from './types';
import { validateRecord } from './records';

export type SmartRecord = { domain: Domain; record: DNSRecord; row: number };
const canonical = (value: string) => { try { return new URL('https://' + value.replace(/\.$/, '')).hostname; } catch { return value.toLowerCase(); } };
export function parseSmartRecords(text: string, domains: Domain[], options: { domainId?: string; value?: string; type?: string; ttl: number }): SmartRecord[] {
  const fallback = domains.find(d => d.id === options.domainId);
  const rows = text.split(/\r?\n/).filter(v => v.trim() && !v.trim().startsWith('#'));
  if (!rows.length || rows.length > 10000) throw new Error('请输入1–10000条记录');
  const select = (full: string, exact = false) => {
    const name = canonical(full);
    const matches = domains.filter(d => name === canonical(d.name) || !exact && name.endsWith('.' + canonical(d.name))).sort((a, b) => b.name.length - a.name.length);
    if (!matches.length) return undefined;
    const candidates = matches.filter(d => canonical(d.name) === canonical(matches[0].name));
    if (candidates.length > 1) {
      if (fallback && candidates.some(d => d.id === fallback.id)) return fallback;
      throw new Error(`${full} 有多个平台账户，请选择对应默认域名`);
    }
    return matches[0];
  };
  return rows.map((line, index) => {
    const words = line.trim().split(/\s+/);
    let name: string, value: string, domain: Domain | undefined;
    if (words.length === 3) { [name, value] = words; domain = select(words[2], true); if (!domain) throw new Error(`第${index + 1}行的域名未授权或未添加`); }
    else if (words.length === 2) {
      const valueFirst = /^(\d{1,3}\.){3}\d{1,3}$/.test(words[0]) || words[0].includes(':') || words[0].includes('.')&&!!select(words[1]);
      [name, value] = valueFirst ? [words[1], words[0]] : words;
      domain = select(name) ?? fallback;
    } else if (words.length === 1 && options.value) { name = words[0]; value = options.value; domain = select(name) ?? fallback; }
    else throw new Error(`第${index + 1}行格式不正确；使用“主机 值 域名”或“值 完整主机名”`);
    if (!domain) throw new Error(`第${index + 1}行需要选择默认域名或指定已授权域名`);
    const zone = canonical(domain.name), full = canonical(name);
    if (full === zone) name = '@'; else if (full.endsWith('.' + zone)) name = full.slice(0, -(zone.length + 1));
    else if (name !== '@' && name.includes('.') && !name.startsWith('_')) throw new Error(`第${index + 1}行的主机名不属于所选域名`);
    const type = options.type || (/^(\d{1,3}\.){3}\d{1,3}$/.test(value) ? 'A' : value.includes(':') && !/^https?:/.test(value) ? 'AAAA' : /^https?:\/\//.test(value) ? 'REDIRECT_URL' : /^(?:[\w-]+\.)+[\w-]+\.?$/.test(value) ? 'CNAME' : 'TXT');
    const record: DNSRecord = { name, value, type, ttl: options.ttl, enabled: true, proxied: false };
    if (type === 'MX') record.priority = 10;
    const error = validateRecord(record); if (error) throw new Error(`第${index + 1}行：${error}`);
    return { domain, record, row: index + 1 };
  });
}
