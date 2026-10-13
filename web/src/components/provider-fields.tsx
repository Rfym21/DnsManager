import {Field} from './ui';
import type {FieldSpec} from '../lib/types';

import {fieldDefaults,fieldVisible} from '../lib/provider-fields';
export function ProviderFields({fields,value,onChange,editing=false}:{fields:FieldSpec[];value:Record<string,string>;onChange:(v:Record<string,string>)=>void;editing?:boolean}){
 const resolved={...fieldDefaults(fields),...value};
 return <>{fields.filter(f=>fieldVisible(f,resolved)).map(field=>{const props={required:field.required&&!(editing&&field.secret),value:resolved[field.name]??'',onChange:(e:React.ChangeEvent<HTMLInputElement|HTMLSelectElement|HTMLTextAreaElement>)=>onChange({...resolved,[field.name]:e.target.value}),autoComplete:field.secret?'new-password':'off',placeholder:field.placeholder};return <Field key={field.name} label={field.label} help={editing&&field.secret?'留空保留已保存的密钥':field.help}>{field.options?.length?<select {...props}><option value="">选择</option>{field.options.map(o=><option key={o.value} value={o.value}>{o.label}</option>)}</select>:field.type==='textarea'?<textarea {...props} rows={field.secret?5:3} className={field.secret?'mono':undefined}/>:<input {...props} type={field.secret?'password':field.type==='number'?'number':field.type==='url'?'url':field.type==='email'?'email':'text'}/>}</Field>;})}</>;
}
