"""Ten-minute personal router monitor. No account/device/address values in logs."""
import base64,hashlib,hmac,io,json,os,ssl,time,urllib.error,urllib.parse,urllib.request,uuid,zipfile
from pathlib import Path

class CloudError(Exception):
 def __init__(self,code):self.code=code;super().__init__(f'Cloud error {code}')

def trusted_base(value):
 u=urllib.parse.urlsplit(value);host=u.hostname or ''
 if u.scheme!='https' or not host.endswith(('.tplinkcloud.com','.tplinknbu.com')) or u.username or u.password or u.port not in (None,443) or u.path not in ('','/') or u.query or u.fragment:raise ValueError('Untrusted cloud host')
 return 'https://'+host

def cloud_call(session,index):
 path='/api/v2/common/getDeviceListByPage';body=json.dumps({'index':index,'limit':50},separators=(',',':')).encode()
 digest=base64.b64encode(hashlib.md5(body).digest()).decode();nonce=str(uuid.uuid4());stamp=9999999999
 sig=hmac.new(b'da6f8c67a372455cb3a4ab9a6d953cd5',f'{digest}\n{stamp}\n{nonce}\n{path}'.encode(),hashlib.sha1).hexdigest()
 query=urllib.parse.urlencode({'appName':'TP-LINK Tether_Android','appVer':'4.16.27','termID':session['terminalId'],'ospf':'Android','locale':'ru_RU','token':session['token']})
 req=urllib.request.Request(trusted_base(session['deviceUrl'])+path+'?'+query,data=body,headers={'Content-Type':'application/json','Content-MD5':digest,'X-Authorization':f'Timestamp={stamp}, Nonce={nonce}, AccessKey=5fc820961d5944d6ba05af6a3180caec, Signature={sig}'})
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args):return None
 ctx=ssl.create_default_context();ctx.load_verify_locations(str(Path(__file__).with_name('tplink_ca.pem')))
 opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ctx))
 with opener.open(req,timeout=25) as response:r=json.load(response)
 code=r.get('error_code',-1)
 if code!=0:raise CloudError(code)
 result=r.get('result')
 if not isinstance(result,dict) or result.get('errorCode',0) not in (0,'0'):raise CloudError(-1)
 if not isinstance(result.get('deviceList'),list):raise CloudError(-1)
 return result

def get_devices(session,call=cloud_call):
 result={};index=0
 for _ in range(100):
  page=call(session,index);rows=page['deviceList']
  for row in rows:
   identity=row.get('deviceId')
   if identity:result[identity]='online' if row.get('status')==1 else 'offline' if row.get('status')==0 else 'unknown'
  index+=len(rows)
  if not rows or index>=int(page.get('totalNum',index)):return result
 raise CloudError(-1)

def events(config,observed,previous,epoch):
 """Return transitions and new state; missing/unknown/cloud errors never imply offline."""
 state=json.loads(json.dumps(previous));records=state.setdefault('routers',{});pending=[]
 for device in config['routers']:
  identity=device['id'];current=observed.get(identity,'unknown');old=records.get(identity,{})
  if current not in ('online','offline'):continue
  before=old.get('state')
  if before!=current and (before is not None or current=='offline'):
   title=f"{device['model']}: {'не в сети' if current=='offline' else 'снова в сети'}"
   body=(device.get('address') or 'Адрес не привязан')+' · по ответу облака TP-Link'
   pending.append({'title':title,'body':body,'id':hashlib.sha256(f'{identity}:{current}:{epoch}'.encode()).hexdigest()[:24]})
  records[identity]={'state':current,'checked':epoch}
 state['health']='ok';state['checked']=epoch
 return pending,state

def health_event(previous,code,epoch):
 state=json.loads(json.dumps(previous));kind='auth' if code in (-20651,-20652) else 'missing' if code==-10001 else 'cloud'
 pending=[]
 if state.get('health')!=kind:
  pending=[{'title':'Мониторинг роутеров приостановлен' if kind=='auth' else 'Выбранные роутеры не найдены' if kind=='missing' else 'Облако TP-Link недоступно','body':'Откройте приложение, войдите заново и обновите секрет конфигурации GitHub.' if kind=='auth' else 'Статусы роутеров неизвестны. Это не считается отключением роутеров. Следующая попытка через 10 минут.','id':f'health-{kind}'}]
 state['health']=kind;state['lastError']=epoch
 return pending,state

def validate_fcm_info(info):
 required=('type','project_id','client_email','private_key','token_uri')
 missing=[key for key in required if not isinstance(info.get(key),str) or not info[key].strip()]
 if missing:raise ValueError('FCM_SERVICE_ACCOUNT_JSON: missing fields: '+', '.join(missing))
 if info['type']!='service_account' or '-----BEGIN PRIVATE KEY-----' not in info['private_key']:raise ValueError('FCM_SERVICE_ACCOUNT_JSON is not a service-account key')
 if info['token_uri'] not in ('https://oauth2.googleapis.com/token','https://accounts.google.com/o/oauth2/token'):raise ValueError('FCM_SERVICE_ACCOUNT_JSON: unsupported token endpoint')

def send_push(config,event):
 from google.oauth2 import service_account
 from google.auth.transport.requests import Request
 import requests
 info=json.loads(os.environ['FCM_SERVICE_ACCOUNT_JSON']);validate_fcm_info(info)
 credentials=service_account.Credentials.from_service_account_info(info,scopes=['https://www.googleapis.com/auth/firebase.messaging']);credentials.refresh(Request())
 data={'title':event['title'],'body':event['body'],'eventId':event['id'],'kind':'router_status'}
 message={'token':config['fcmToken'],'notification':{'title':event['title'],'body':event['body']},'data':data,'android':{'priority':'high','ttl':'3600s','notification':{'channel_id':'updates','tag':event['id']}}}
 response=requests.post(f"https://fcm.googleapis.com/v1/projects/{info['project_id']}/messages:send",json={'message':message},headers={'Authorization':'Bearer '+credentials.token},timeout=25)
 if response.status_code not in (200,201):raise RuntimeError('FCM delivery rejected: '+str(response.status_code))

def github_json(url):
 req=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
 with urllib.request.urlopen(req,timeout=25) as response:return json.load(response)

def restore_state():
 """Restore most recent encrypted state artifact; fail closed on unexpected errors."""
 repo=os.environ['GITHUB_REPOSITORY'];url=f'https://api.github.com/repos/{repo}/actions/artifacts?name=monitor-state&per_page=20'
 artifacts=github_json(url)['artifacts'];valid=[a for a in artifacts if not a['expired']]
 if not valid:return {}
 artifact=max(valid,key=lambda a:a['id']);download=f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact['id']}/zip"
 # Do not forward the GitHub bearer token to the signed storage redirect.
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args):return None
 req=urllib.request.Request(download,headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN']})
 try:
  with urllib.request.build_opener(NoRedirect()).open(req,timeout=25) as response:raw=response.read()
 except urllib.error.HTTPError as error:
  if error.code!=302:raise
  redirect=error.headers.get('Location','');u=urllib.parse.urlsplit(redirect)
  if u.scheme!='https' or not (u.hostname or '').endswith(('.blob.core.windows.net','.actions.githubusercontent.com','.githubusercontent.com')):raise RuntimeError('Unexpected artifact storage host')
  with urllib.request.urlopen(redirect,timeout=25) as response:raw=response.read()
 from cryptography.fernet import Fernet
 with zipfile.ZipFile(io.BytesIO(raw)) as archive:encrypted=archive.read('state.enc')
 return json.loads(Fernet(os.environ['STATE_KEY'].encode()).decrypt(encrypted))

def save_state(state):
 from cryptography.fernet import Fernet
 path=Path('.state');path.mkdir(exist_ok=True)
 (path/'state.enc').write_bytes(Fernet(os.environ['STATE_KEY'].encode()).encrypt(json.dumps(state).encode()))

def validate_config(config):
 if not config.get('session',{}).get('token') or not config.get('session',{}).get('terminalId') or not config.get('fcmToken'):raise ValueError('Incomplete monitoring configuration')
 trusted_base(config['session']['deviceUrl'])
 routers=config.get('routers',[])
 if not isinstance(routers,list) or not routers or len(routers)>10:raise ValueError('Select between 1 and 10 routers')
 ids=[d.get('id') for d in routers]
 if any(not identity for identity in ids) or len(set(ids))!=len(ids) or any(not d.get('model') for d in routers):raise ValueError('Invalid router identifiers')

def run():
 config=json.loads(os.environ['MONITOR_CONFIG_JSON']);validate_config(config)
 try:validate_fcm_info(json.loads(os.environ['FCM_SERVICE_ACCOUNT_JSON']))
 except (ValueError,TypeError) as error:
  # Only our schema errors contain field names; never print arbitrary credential contents.
  print('FCM key validation failed. Required fields: type, project_id, client_email, private_key, token_uri.')
  info=json.loads(os.environ['FCM_SERVICE_ACCOUNT_JSON'])
  if isinstance(info,dict):print('Missing required fields:',','.join(k for k in ('type','project_id','client_email','private_key','token_uri') if not isinstance(info.get(k),str) or not info.get(k)))
  raise RuntimeError('Invalid FCM key schema') from None
 previous=restore_state();epoch=int(time.time())
 try:
  observed=get_devices(config['session'])
  if any(observed.get(device['id']) not in ('online','offline') for device in config['routers']):raise CloudError(-10001)
 except CloudError as error:pending,state=health_event(previous,error.code,epoch)
 except Exception:pending,state=health_event(previous,None,epoch)
 else:pending,state=events(config,observed,previous,epoch)
 print('Cloud check result:',state.get('health'),'Pending events:',len(pending))
 for event in pending:send_push(config,event)
 if os.getenv('SEND_TEST_PUSH')=='true':send_push(config,{'title':'Тест мониторинга роутеров','body':'GitHub Actions может отправлять уведомления на этот телефон.','id':'test-monitor'})
 save_state(state)
 print('Check completed. Notification count:',len(pending),'Health:',state.get('health'))

if __name__=='__main__':
 try:run()
 except Exception as error:
  # Never print exception text/traceback: URLs may contain cloud tokens.
  print('Monitor failed safely:',type(error).__name__);raise SystemExit(1)
