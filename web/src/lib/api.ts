import type {Session} from './types';
import {endpointPath,endpoints,type OperationID,type Operations} from '../generated/contracts';
type ConsoleOperationID = {[K in OperationID]: Operations[K]['path'] extends `/api/v1/${string}` ? K : never}[OperationID];
export type OperationResponse<K extends OperationID> = Operations[K]['responses'][Extract<keyof Operations[K]['responses'],'200'|'201'|'202'|'204'>];
type OperationOptions<K extends ConsoleOperationID> = Omit<RequestInit,'method'|'body'> & {params:Operations[K]['pathParams'];query?:Operations[K]['queryParams']} & ([Operations[K]['body']] extends [never] ? {json?:never} : {json:Operations[K]['body']});
let csrf='';
export function setSession(value:Session|null) {csrf=value?.csrf_token??'';}
export class APIError extends Error {constructor(public status:number,public code:string,message:string,public requestId?:string,public fields?:Record<string,string>){super(message);this.name='APIError';}}
export async function api<T=any>(path:string,options:RequestInit&{json?:unknown}={}):Promise<T>{
 const {json,...init}=options;const headers=new Headers(init.headers);headers.set('Accept','application/json');
 if(json!==undefined)headers.set('Content-Type','application/json');
 if(csrf && init.method && !['GET','HEAD'].includes(init.method))headers.set('X-CSRF-Token',csrf);
 let response:Response;
 try{response=await fetch('/api/v1'+path,{...init,credentials:'same-origin',headers,body:json!==undefined?JSON.stringify(json):init.body});}catch(error){if(error instanceof DOMException&&error.name==='AbortError')throw error;throw new APIError(0,'offline','无法连接服务，请检查网络后重试');}
 let data:any;try{data=await response.json();}catch{throw new APIError(response.status,'invalid_response','服务返回了无法读取的结果，请核对服务状态');}
 if(!response.ok){if(response.status===401&&!path.startsWith('/auth/login'))window.dispatchEvent(new Event('dnsmgr:unauthorized'));throw new APIError(response.status,data.code??'request_failed',data.message??'操作未完成',data.request_id,data.field_errors);}
 return data as T;
}
export function apiOperation<K extends ConsoleOperationID>(operation:K,options:OperationOptions<K>):Promise<OperationResponse<K>>{
 const {params,query,json,...init}=options;const search=new URLSearchParams();
 for(const[key,value]of Object.entries(query??{})){if(value===undefined||value==='')continue;for(const item of Array.isArray(value)?value:[value])search.append(key,String(item));}
 const path=endpointPath(operation,params).slice('/api/v1'.length)+(search.size?'?'+search.toString():'');
 return api<OperationResponse<K>>(path,{...init,method:endpoints[operation].method,json});
}
export function errorMessage(error:unknown){return error instanceof Error?error.message:'操作未完成，请重试';}
export function queryString(params:Record<string,string|number|undefined>){const q=new URLSearchParams();for(const[key,value]of Object.entries(params))if(value!==undefined&&value!=='')q.set(key,String(value));return q.size?'?'+q.toString():'';}
export function formatTime(value?:string){if(!value)return '—';const date=new Date(value);return Number.isNaN(date.getTime())?value:new Intl.DateTimeFormat('zh-CN',{dateStyle:'short',timeStyle:'medium'}).format(date);}
