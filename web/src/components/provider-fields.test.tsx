import {render,screen,fireEvent} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import type {FieldSpec} from '../lib/types';
import {ProviderFields} from './provider-fields';
import {blankSecrets,fieldVisible} from '../lib/provider-fields';
describe('provider conditional forms',()=>{
 it('clears secrets only in the editable copy and preserves ordinary metadata',()=>{const old={url:'https://example.invalid?key=fixture',host:'mail.example.invalid'};expect(blankSecrets([{name:'url',label:'Webhook',secret:true},{name:'host',label:'主机'}],old)).toEqual({url:'',host:'mail.example.invalid'});expect(old.url).toContain('fixture');});
 it('supports DNS map predicates and deployment OR-of-AND predicates',()=>{expect(fieldVisible({name:'privatekey',label:'key',visible_when:{auth:'1'}},{auth:'0'})).toBe(false);expect(fieldVisible({name:'cmd',label:'cmd',visible_when:[[{field:'format',equals:'pem'}],[{field:'format',equals:'pfx'},{field:'uptype',equals:'0'}]]},{format:'pfx',uptype:'1'})).toBe(false);expect(fieldVisible({name:'cmd',label:'cmd',visible_when:[[{field:'format',equals:'pem'}],[{field:'uptype',equals:'0'}]]},{format:'pem'})).toBe(true);});
 it('renders only relevant required fields and submits metadata defaults',()=>{const change=vi.fn();render(<ProviderFields fields={[{name:'auth',label:'认证方式',default:'0',options:[{value:'0',label:'密码'},{value:'1',label:'密钥'}]},{name:'password',label:'密码',secret:true,required:true,visible_when:{auth:'0'}},{name:'privatekey',label:'私钥',required:true,type:'textarea',visible_when:{auth:'1'}}]} value={{}} onChange={change}/>);expect(screen.getByLabelText('密码')).toBeRequired();expect(screen.queryByLabelText('私钥')).toBeNull();fireEvent.change(screen.getByLabelText('密码'),{target:{value:'local-fixture'}});expect(change).toHaveBeenCalledWith({auth:'0',password:'local-fixture'});});
});

 it('supports negated cloud deployment target conditions',()=>{const field:FieldSpec={name:'domain',label:'部署域名',visible_when:[[{field:'product',equals:'upload',not:true},{field:'product',equals:'clb',not:true}]]};expect(fieldVisible(field,{product:'cdn'})).toBe(true);expect(fieldVisible(field,{product:'upload'})).toBe(false);expect(fieldVisible(field,{product:'clb'})).toBe(false);});
