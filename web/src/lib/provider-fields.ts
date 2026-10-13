import type {FieldSpec} from './types';
export function fieldVisible(field:FieldSpec,values:Record<string,unknown>):boolean {
 const condition=field.visible_when;
 if(!condition)return true;
 if(Array.isArray(condition))return condition.some(group=>group.every(test=>test.not?String(values[test.field]??'')!==test.equals:String(values[test.field]??'')===test.equals));
 return Object.entries(condition).every(([key,value])=>String(values[key]??'')===value);
}
export function fieldDefaults(fields:FieldSpec[]):Record<string,string>{return Object.fromEntries(fields.filter(f=>f.default!==undefined).map(f=>[f.name,f.default!]));}
export function blankSecrets(fields:FieldSpec[],values:Record<string,string>):Record<string,string>{const next={...values};for(const field of fields)if(field.secret)next[field.name]='';return next;}
