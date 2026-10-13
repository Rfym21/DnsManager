import type { DNSRecord } from './types';
import { parseRecordImport } from './records';

const columns: Record<string, string> = {
  name: 'name', 主机: 'name', 主机记录: 'name', rr: 'name',
  type: 'type', 类型: 'type', 记录类型: 'type',
  value: 'value', 记录值: 'value', 内容: 'value',
  ttl: 'ttl', 优先级: 'priority', priority: 'priority', mx: 'priority',
  id: 'id', recordid: 'id', 记录id: 'id', line: 'line', 线路: 'line',
  enabled: 'enabled', status: 'enabled', 状态: 'enabled',
  proxied: 'proxied', 代理: 'proxied', remark: 'remark', 备注: 'remark',
  weight: 'weight', 权重: 'weight', version: 'version',
};

export async function readRecordFile(file: File): Promise<string> {
  if (file.size > 2 * 1024 * 1024) throw new Error('文件不可超过 2MB');
  if (/\.xlsx?$/i.test(file.name)) {
    const xlsx = await import('xlsx');
    const workbook = xlsx.read(await file.arrayBuffer(), { type: 'array', sheetRows: 2002 });
    const first = workbook.SheetNames[0];
    if (!first) throw new Error('工作簿没有可读取的工作表');
    const rows = xlsx.utils.sheet_to_json<unknown[]>(workbook.Sheets[first], { header: 1, defval: '', blankrows: false });
    return rowsToJSON(rows);
  }
  const text = await file.text();
  if (/\.csv$/i.test(file.name)) {
    const xlsx = await import('xlsx');
    const book = xlsx.read(text, { type: 'string', raw: true });
    return rowsToJSON(xlsx.utils.sheet_to_json<unknown[]>(book.Sheets[book.SheetNames[0]], { header: 1, defval: '', blankrows: false }));
  }
  if (/\.zone$/i.test(file.name) || /^\s*\$(ORIGIN|TTL)\s/im.test(text)) return JSON.stringify(parseBIND(text));
  if (/\.tsv$/i.test(file.name)) {
    const rows = text.trim().split(/\r?\n/).map(row => row.split('\t'));
    if (rows[0]?.some(value => columns[value.toLowerCase()] === 'type')) return rowsToJSON(rows);
  }
  return text;
}

export function rowsToJSON(rows: unknown[][]): string {
  if (rows.length < 2) throw new Error('表格需要标题行及至少一条记录');
  if (rows.length > 2001) throw new Error('单次最多导入 2000 条记录');
  const header = rows[0].map(cell => columns[String(cell).trim().toLowerCase()]);
  if (!['name', 'type', 'value'].every(name => header.includes(name))) throw new Error('标题需包含 主机记录/name、类型/type、记录值/value');
  const records = rows.slice(1).map(row => {
    const value: Record<string, unknown> = {};
    header.forEach((field, index) => {
      if (!field || row[index] === '') return;
      const cell = row[index];
      if (['ttl', 'priority', 'weight'].includes(field)) value[field] = Number(cell);
      else if (field === 'enabled') value[field] = !['false', '0', 'disabled', '暂停', '禁用'].includes(String(cell).toLowerCase());
      else if (field === 'proxied') value[field] = ['true', '1', '启用'].includes(String(cell).toLowerCase());
      else value[field] = String(cell);
    });
    return value;
  });
  // Use the same validation path for spreadsheets and pasted text.
  return JSON.stringify(parseRecordImport(JSON.stringify(records)), null, 2);
}

export function parseBIND(text: string): DNSRecord[] {
  let ttl = 300;
  let origin = '';
  let previous = '';
  let logical = '';
  let depth = 0;
  let quote = false;
  let escaped = false;
  const statements: string[] = [];
  // Strip only unquoted comments and join parenthesized multi-line records.
  for (const line of text.split(/\r?\n/)) {
    let cleaned = '';
    for (const char of line) {
      if (escaped) { cleaned += char; escaped = false; continue; }
      if (char === '\\') { cleaned += char; escaped = true; continue; }
      if (char === '"') quote = !quote;
      if (char === ';' && !quote) break;
      if (!quote && char === '(') { depth++; cleaned += ' '; continue; }
      if (!quote && char === ')') { depth--; cleaned += ' '; continue; }
      cleaned += char;
    }
    logical += (logical ? ' ' : '') + cleaned;
    if (depth === 0 && !quote) { if (logical.trim()) statements.push(logical); logical = ''; }
    if (depth < 0) throw new Error('BIND 括号不匹配');
  }
  if (depth || quote || logical.trim()) throw new Error('BIND 括号或引号不匹配');
  const records: DNSRecord[] = [];
  for (const statement of statements) {
    const tokens = statement.trim().match(/"(?:\\.|[^"\\])*"|\S+/g) ?? [];
    if (tokens[0]?.toUpperCase() === '$ORIGIN') { origin = (tokens[1] ?? '').replace(/\.$/, ''); continue; }
    if (tokens[0]?.toUpperCase() === '$TTL') { ttl = ttlSeconds(tokens[1]); continue; }
    if (tokens[0]?.startsWith('$')) throw new Error('仅支持 $ORIGIN 与 $TTL，不能导入包含外部文件的区域');
    let name = /^\s/.test(statement) ? previous : tokens.shift() ?? '';
    if (!name) throw new Error('BIND 省略主机名时需要前一条记录');
    previous = name;
    let recordTTL = ttl;
    while (tokens[0] && (/^\d+[wdhms\d]*$/i.test(tokens[0] ?? '') || tokens[0]?.toUpperCase() === 'IN')) {
      const token = tokens.shift()!;
      if (token.toUpperCase() !== 'IN') recordTTL = ttlSeconds(token);
    }
    const type = (tokens.shift() ?? '').toUpperCase();
    const priority = type === 'MX' ? Number(tokens.shift()) : undefined;
    if (name.endsWith('.')) name = name.replace(/\.$/, '');
    if (origin && name === origin) name = '@';
    else if (origin && name.endsWith('.' + origin)) name = name.slice(0, -origin.length - 1);
    // TXT segments are one DNS value; retain spaces and quoted semicolons.
    const value = type === 'TXT' ? tokens.map(token => token.startsWith('"') ? token.slice(1, -1).replace(/\\(["\\])/g, '$1') : token).join('') : tokens.join(' ');
    records.push({ name, type, value, priority, ttl: recordTTL, line: 'default', enabled: true, proxied: false });
  }
  return parseRecordImport(JSON.stringify(records));
}
function ttlSeconds(token: string | undefined): number {
  if (!token || !/^\d+(?:[wdhms]\d*)*$/i.test(token)) throw new Error('BIND TTL 不正确');
  const units: Record<string, number> = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  return [...token.matchAll(/(\d+)([wdhms]?)/gi)].reduce((sum, part) => sum + Number(part[1]) * (units[part[2].toLowerCase()] ?? 1), 0);
}
export function validateBatchIDs(records: DNSRecord[], operation: string, domainCount: number): void {
  if (records.length < 1 || records.length > 5000) throw new Error('单次需要 1–5000 条记录');
  if (records.length * domainCount > 10000) throw new Error('批次最多 10000 项变更，请缩小域名范围');
  if (operation !== 'create' && records.some(record => !record.id)) throw new Error('更新、删除与状态操作必须保留平台记录 ID，请使用 JSON 导出记录');
  if (operation !== 'create' && domainCount > 1) throw new Error('平台记录 ID 属于单一域名，更新或删除时仅选择一个域名');
}

export function downloadRecords(records: DNSRecord[], filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
