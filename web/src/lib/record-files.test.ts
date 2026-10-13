import { describe, expect, it } from 'vitest';
import { parseBIND, rowsToJSON, validateBatchIDs } from './record-files';
import { parseRecordImport } from './records';

describe('record file safety and fidelity', () => {
  it('preserves identifiers and status in spreadsheet exports', () => {
    const records = JSON.parse(rowsToJSON([['记录ID', '主机记录', '类型', '记录值', 'TTL', '状态'], ['abc', 'www', 'A', '192.0.2.1', 300, '禁用']]));
    expect(records[0]).toMatchObject({ id: 'abc', name: 'www', enabled: false });
  });
  it('parses BIND origin, inherited name, units, MX and quoted TXT', () => {
    const rows = parseBIND('$ORIGIN example.com.\n$TTL 1h\n@ IN MX 10 mail.example.com.\nwww 300 IN A 192.0.2.1\n    IN A 192.0.2.2\n@ IN TXT ( "v=spf1; "\n"include:example.net ~all" ); comment');
    expect(rows).toHaveLength(4);
    expect(rows[0]).toMatchObject({ name: '@', priority: 10, ttl: 3600 });
    expect(rows[2].name).toBe('www');
    expect(rows[3].value).toBe('v=spf1; include:example.net ~all');
  });
  it('rejects destructive imports without IDs or spanning domains', () => {
    const rows = parseRecordImport('[{"name":"www","type":"A","value":"192.0.2.1","id":"abc"}]');
    expect(() => validateBatchIDs(rows, 'delete', 1)).not.toThrow();
    expect(() => validateBatchIDs(rows, 'delete', 2)).toThrow('一个域名');
    expect(() => validateBatchIDs([{ ...rows[0], id: undefined }], 'delete', 1)).toThrow('记录 ID');
    expect(() => parseBIND('$INCLUDE secret.zone')).toThrow('外部文件');
  });
});
