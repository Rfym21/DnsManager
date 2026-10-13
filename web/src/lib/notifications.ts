import type {FieldSpec} from './types';
const field=(name:string,label:string,options:Partial<FieldSpec>={}):FieldSpec=>({name,label,required:true,...options});
export const notificationProviders=[{value:'smtp',label:'SMTP 邮件'},{value:'sendcloud',label:'SendCloud 邮件'},{value:'aliyun_mail',label:'阿里云邮件推送'},{value:'telegram',label:'Telegram 机器人'},{value:'wechat',label:'微信公众号'},{value:'wxpusher',label:'WxPusher'},{value:'qq',label:'QQ 官方机器人'},{value:'dingtalk',label:'钉钉机器人'},{value:'feishu',label:'飞书机器人'},{value:'wecom',label:'企业微信机器人'},{value:'webhook',label:'Webhook'},{value:'custom_webhook',label:'自定义 Webhook'}];
const optional=(name:string,label:string,options:Partial<FieldSpec>={}):FieldSpec=>field(name,label,{required:false,...options});
const select=(name:string,label:string,values:string[],defaultValue:string):FieldSpec=>field(name,label,{default:defaultValue,options:values.map(value=>({value,label:value}))});
const templates=[optional('title_template','标题模板',{help:'可用 {{title}}、{{event}}、{{resource_id}}、{{data.domain}}。'}),optional('content_template','内容模板',{type:'textarea',help:'可用 {{content}} 等占位符；留空发送原始通知内容。'})];
export const notificationFields:Record<string,FieldSpec[]>={
 smtp:[field('host','SMTP 主机'),field('port','SMTP 端口',{type:'number',default:'465',help:'465 使用 TLS；其它端口要求 STARTTLS。'}),field('username','SMTP 用户名',{required:false}),field('password','SMTP 密码',{secret:true,required:false}),field('from','发件邮箱',{type:'email'}),field('to','收件邮箱',{help:'多个地址使用英文逗号分隔。'})],
 sendcloud:[field('api_user','API User'),field('api_key','API Key',{secret:true}),field('from','发件邮箱',{type:'email'}),field('to','收件邮箱',{help:'使用 SendCloud 支持的收件地址格式。'})],
 telegram:[field('token','Bot Token',{secret:true}),field('chat_id','Chat ID')],
 wechat:[field('app_id','App ID'),field('app_secret','App Secret',{secret:true}),field('open_id','接收人 Open ID'),field('template_id','模板 ID')],
 qq:[field('app_id','App ID'),field('app_secret','App Secret',{secret:true}),field('openid','接收人 Open ID')],
 dingtalk:[field('url','钉钉机器人 Webhook',{type:'url',secret:true})],
 feishu:[field('url','飞书机器人 Webhook',{type:'url',secret:true})],
 wecom:[field('url','企业微信机器人 Webhook',{type:'url',secret:true})],
 webhook:[field('url','接收 URL',{type:'url',secret:true}),field('headers','请求头',{type:'textarea',secret:true,required:false,help:'JSON 对象，例如 {"Authorization":"Bearer …"}。'})],
 custom_webhook:[field('url','接收 URL',{type:'url',secret:true}),field('headers','请求头',{type:'textarea',secret:true,required:false,help:'JSON 对象。'}),field('body_template','JSON 消息模板',{type:'textarea',default:'{"title":"{{title}}","content":"{{content}}","event":"{{event}}"}',help:'支持 {{title}}、{{content}}、{{event}}、{{resource_id}}；消息值会安全转义。'})],
};
notificationFields.smtp.push(select('tls_mode','TLS 模式',['auto','implicit','starttls','plain'],'auto'),optional('from_name','发件人名称'),select('content_format','内容格式',['text','html'],'text'));
notificationFields.sendcloud.push(optional('from_name','发件人名称'),select('content_format','内容格式',['text','html'],'text'));
notificationFields.aliyun_mail=[field('AccessKeyId','AccessKey ID'),field('AccessKeySecret','AccessKey Secret',{secret:true}),field('from','发件邮箱',{type:'email'}),field('to','收件邮箱'),optional('from_name','发件人名称'),field('region','区域',{default:'cn-hangzhou'}),select('content_format','内容格式',['text','html'],'text')];
notificationFields.wxpusher=[field('app_token','App Token',{secret:true}),field('uids','用户 UID',{required:false,help:'多个 UID 使用英文逗号分隔。'}),optional('topic_ids','主题 ID',{help:'多个 ID 使用英文逗号分隔。'})];
notificationFields.telegram.push(optional('message_thread_id','话题 ID',{type:'number'}),optional('api_base','Telegram API 反向代理',{type:'url',help:'留空使用 api.telegram.org。'}),optional('proxy_url','HTTP / SOCKS5 代理 URL',{secret:true}));
notificationFields.qq.push(optional('msg_id','被动回复消息 ID'));
for(const provider of ['dingtalk','feishu'])notificationFields[provider].push(optional('secret','机器人签名密钥',{secret:true}),optional('at_users','提醒用户',{help:'多个用户用英文逗号分隔；all 表示所有人。'}));
notificationFields.wechat.push(optional('template_data','模板数据',{type:'textarea',help:'JSON 对象，支持通知占位符。'}),optional('link_url','模板点击 URL',{type:'url'}));
notificationFields.wecom.push(optional('at_users','提醒用户',{help:'多个用户用英文逗号分隔；all 表示所有人。'}));
for(const provider of ['webhook','custom_webhook']){const headers=notificationFields[provider].find(f=>f.name==='headers');if(headers)headers.help='支持 JSON 对象或每行 Name: value。';}
notificationFields.custom_webhook.push(select('method','请求方法',['GET','POST','PUT','PATCH'],'POST'),select('content_type','请求内容类型',['application/json','application/x-www-form-urlencoded','text/plain'],'application/json'),select('content_format','消息格式',['text','html','markdown'],'text'));
for(const provider of Object.keys(notificationFields))notificationFields[provider].push(...templates);
export const notificationEvents=[{value:'*',label:'所有业务事件'},{value:'job.failed',label:'任务失败'},{value:'job.succeeded',label:'任务成功'},{value:'certificate.expiring',label:'证书即将到期'},{value:'domain.expiring',label:'域名即将到期'},{value:'certificate.issued',label:'证书签发成功'},{value:'certificate.failed',label:'证书签发失败'},{value:'deployment.succeeded',label:'证书部署成功'},{value:'deployment.failed',label:'证书部署失败'},{value:'monitor.failure',label:'监控故障切换'},{value:'monitor.recovery',label:'监控恢复主状态'}];
