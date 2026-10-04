"""Aman GRC Nexus — local-first evidence workspace; rule-based review, not a certification engine."""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sqlite3, json, uuid, datetime, re, shutil, os, secrets, socket, ipaddress, urllib.parse, html
from fastapi.security import HTTPBasic, HTTPBasicCredentials
ROOT=Path(__file__).resolve().parent
UPLOAD=ROOT/'uploads'; UPLOAD.mkdir(exist_ok=True)
DB=ROOT/'workspace.sqlite3'
app=FastAPI(title='Aman GRC Nexus',version='4.0')
security=HTTPBasic(auto_error=False)
def admin(credentials:HTTPBasicCredentials=Depends(security)):
 password=os.environ.get('GRC_ADMIN_PASSWORD','')
 if not password or not credentials or not (secrets.compare_digest(credentials.username,'aman') and secrets.compare_digest(credentials.password,password)):
  raise HTTPException(401,'Owner authentication required; set GRC_ADMIN_PASSWORD',headers={'WWW-Authenticate':'Basic realm=GRC-Nexus-Owner'})
 return True
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
# Source documents are private; never mount confidential reports as public static assets.
FRAMEWORKS={
 'ISO 42001':[
 ('4','Context, interested parties and AIMS scope',['scope','interested parties','stakeholder','inventory','organizational context']),
 ('5','Leadership, accountability and AI policy',['ai policy','leadership','accountability','roles','responsibilities']),
 ('6','AI risk planning, assessment and treatment',['risk assessment','risk register','risk treatment','risk criteria','statement of applicability']),
 ('7','Resources, competence and documented information',['training','competence','awareness','document control','resources']),
 ('8','AI operations and impact assessment',['impact assessment','lifecycle','human oversight','operational controls','monitoring']),
 ('9','Performance evaluation and internal audit',['internal audit','management review','performance evaluation','metrics','kpi']),
 ('10','Nonconformity and continual improvement',['corrective action','nonconformity','continual improvement','capa','root cause']),
 ('Annex A','AI governance controls and applicability',['annex a','control objective','control mapping','soa','ai system lifecycle'])],
 'ISO 27001':[('4','ISMS organizational context and scope',['isms','scope','interested parties','information security']),('5','Leadership and information security policy',['security policy','leadership','roles','responsibilities']),('6','Information security risk planning',['risk assessment','risk treatment','risk criteria','statement of applicability']),('7','Support, competence and documented information',['competence','training','awareness','document control']),('8','Operational risk assessment and treatment',['operational','risk treatment','change management','controls']),('9','Monitoring, internal audit and management review',['internal audit','monitoring','management review','evaluation']),('10','Corrective action and improvement',['nonconformity','corrective action','continual improvement']),('Annex A','Organizational, people, physical and technological controls',['access control','asset management','supplier','incident','physical security'])],
 'NIST AI RMF':[
 ('GOVERN','Governance, culture, roles and policies',['govern','governance','policy','accountability','roles']),
 ('MAP','Context, categorization and affected stakeholders',['map','context','stakeholder','intended use','impact']),
 ('MEASURE','Testing, validation and evaluation',['measure','validation','evaluation','testing','bias','metrics']),
 ('MANAGE','Prioritize, respond and monitor AI risks',['manage','mitigation','risk treatment','incident','monitoring'])]}

def connect():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c

def init():
 with connect() as c:
  c.execute('CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,name TEXT,kind TEXT,added TEXT,summary TEXT,review TEXT,filename TEXT)')
  c.execute('CREATE TABLE IF NOT EXISTS risks(id TEXT PRIMARY KEY,title TEXT,category TEXT,likelihood INTEGER,impact INTEGER,status TEXT,owner TEXT,treatment TEXT,created TEXT)')
  c.execute('CREATE TABLE IF NOT EXISTS profile(key TEXT PRIMARY KEY,value TEXT)')
  c.execute('CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY,title TEXT,issuer TEXT,issued TEXT,description TEXT,filename TEXT,created TEXT)')
  if not c.execute('SELECT COUNT(*) FROM risks').fetchone()[0]:
   items=[('AI-01','Prompt injection against agent routing','AI Security',4,4,'Open','AI / Security','Validate tool authorization server-side'),('AI-02','Excessive SQL / Cypher agent privileges','Access Control',3,5,'Open','Engineering','Least-privilege read-only identities'),('AI-03','Untrusted document ingestion','Data Integrity',3,4,'Open','AI Engineering','Scan, isolate and validate retrieved context'),('AI-04','Hallucinated or misleading responses','AI Reliability',3,4,'Open','AI Owner','Grounding, evaluations and human review'),('AI-05','Sensitive data leakage via responses','Privacy',3,5,'Open','Data Owner','Output filters and tenant scoping'),('AI-06','Missing impact assessment evidence','Governance',4,3,'Open','GRC','Document AI system impact assessment'),('AI-07','Insufficient AI audit evidence','Assurance',3,3,'Open','GRC','Retain logs and independent verification'),('AI-08','Weak HTTP response hardening','AppSec',4,2,'Open','Engineering','CSP, HSTS, framing and nosniff retests')]
   c.executemany('INSERT INTO risks VALUES (?,?,?,?,?,?,?,?,?)',[(i,t,cat,l,im,s,o,tr,'2026-09-30') for i,t,cat,l,im,s,o,tr in items])
  if not c.execute('SELECT COUNT(*) FROM profile').fetchone()[0]:
   c.executemany('INSERT INTO profile VALUES (?,?)',[('headline','GRC & AI Governance | Security Engineering'),('bio','I connect software security engineering with auditable AI governance. My work spans ISO/IEC 42001 readiness, NIST AI RMF alignment, agentic-AI threat assessment, risk treatment, control mapping and evidence-led remediation.'),('email','aman20dev05@gmail.com'),('linkedin','https://linkedin.com/in/devad007'),('certifications',json.dumps(['Google Cybersecurity Professional Certificate','SailPoint Identity Security Leader','Securiti AI Security & Governance','Qualys Certified Specialist — PCI Compliance','Certified LLM Security Professional (CLLMSP)','ThinkCloudly IT Auditing & GRC Bootcamp']))])
init()

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def readpdf(path):
 try:
  import fitz
  doc=fitz.open(path)
  return '\n'.join(page.get_text() for page in list(doc)[:70])[:500000]
 except Exception:return ''

def assess(text):
 lower=re.sub(r'\s+',' ',text.lower()); total=[]
 for framework,sections in FRAMEWORKS.items():
  entries=[]
  for code,title,terms in sections:
   matched=[]; snippets=[]
   for term in terms:
    m=re.search(r'\b'+re.escape(term)+r'\b',lower)
    if m:
     matched.append(term)
     snippets.append(text[max(0,m.start()-65):min(len(text),m.end()+115)].replace('\n',' ')[:180])
   coverage=round(100*len(matched)/len(terms))
   entries.append({'code':code,'title':title,'coverage':coverage,'matched':matched,'missing':[x for x in terms if x not in matched],'excerpts':snippets[:2],'status':'Evidence mentioned' if coverage>=60 else ('Partial mention' if matched else 'Not evidenced'),'recommendation':('Request owner-approved operating evidence, effectiveness tests and approval records.' if matched else 'Add a documented process, accountable owner, implementation records and verifiable evidence.')})
  total.append({'framework':framework,'sections':entries,'coverage':round(sum(x['coverage'] for x in entries)/len(entries))})
 return {'frameworks':total,'disclaimer':'Keyword-based evidence discovery only. Mentioned terms are NOT proof of implementation, conformity, certification or operating effectiveness. Validate source, scope, owners, dates, artifacts and test results manually.'}

@app.get('/')
def index():return FileResponse(ROOT/'static'/'portfolio.html')
@app.get('/workspace')
def workspace():return FileResponse(ROOT/'static'/'index.html')
@app.get('/api/state')
def state():
 # Public demonstration only. Never expose private uploaded artifacts or actual workspace records.
 sample=[('DEMO-01','Prompt injection against agent routing','AI Security',4,4,'Open','AI / Security','Enforce server-side tool authorization'),('DEMO-02','Excessive database privileges','Access Control',3,5,'Open','Engineering','Use least-privilege database roles'),('DEMO-03','Untrusted document ingestion','Data Integrity',3,4,'Open','AI Engineering','Validate and isolate untrusted content'),('DEMO-04','Hallucinated AI responses','AI Reliability',3,4,'Open','AI Owner','Evaluate responses against trusted sources'),('DEMO-05','Sensitive data disclosure','Privacy',3,5,'Open','Data Owner','Enforce tenant-scoped access'),('DEMO-06','Missing AI impact assessment','Governance',4,3,'Open','GRC','Document impact assessments'),('DEMO-07','Insufficient audit evidence','Assurance',3,3,'Open','GRC','Maintain review and audit logs'),('DEMO-08','Weak HTTP response headers','AppSec',4,2,'Open','Engineering','Harden headers and retest')]
 return {'risks':[dict(zip(('id','title','category','likelihood','impact','status','owner','treatment'),row),created='2026-09-30') for row in sample], 'artifacts':[], 'profile':{'headline':'GRC & AI Governance | Security Engineering','bio':'Interactive public demonstration with synthetic data.','email':'','linkedin':'','certifications':'[]'},'sources':[]}

@app.post('/api/risks')
def add_risk(data:dict,_=Depends(admin)):
 title=str(data.get('title','')).strip();l=int(data.get('likelihood',1));i=int(data.get('impact',1))
 if not title or not(1<=l<=5 and 1<=i<=5):raise HTTPException(400,'Title and scores 1–5 required')
 rid='R-'+uuid.uuid4().hex[:7].upper()
 with connect() as c:c.execute('INSERT INTO risks VALUES (?,?,?,?,?,?,?,?,?)',(rid,title,str(data.get('category','AI Risk')),l,i,str(data.get('status','Open')),str(data.get('owner','Unassigned')),str(data.get('treatment','')),now()))
 return {'id':rid}
@app.patch('/api/risks/{rid}')
def update_risk(rid:str,data:dict,_=Depends(admin)):
 allowed={'title','category','likelihood','impact','status','owner','treatment'};fields={k:v for k,v in data.items() if k in allowed}
 if not fields:raise HTTPException(400,'No valid fields')
 for k in ('likelihood','impact'):
  if k in fields and not 1<=int(fields[k])<=5:raise HTTPException(400,'Score must be 1–5')
 with connect() as c:
  cur=c.execute('UPDATE risks SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',(*fields.values(),rid))
  if not cur.rowcount:raise HTTPException(404,'Risk not found')
 return {'ok':True}
@app.delete('/api/risks/{rid}')
def delete_risk(rid:str,_=Depends(admin)):
 with connect() as c:c.execute('DELETE FROM risks WHERE id=?',(rid,))
 return {'ok':True}
@app.post('/api/profile')
def update_profile(data:dict,_=Depends(admin)):
 with connect() as c:
  for k,v in data.items():
   if k in ('headline','bio','email','linkedin','certifications'):c.execute('INSERT OR REPLACE INTO profile VALUES (?,?)',(k,str(v)[:12000]))
 return {'ok':True}
@app.post('/api/upload')
async def upload(file:UploadFile=File(...),kind:str=Form('Assessment'),_=Depends(admin)):
 ext=Path(file.filename or '').suffix.lower()
 if ext not in ('.pdf','.txt','.md','.html','.json','.csv','.png','.jpg','.jpeg'):raise HTTPException(400,'Supported: PDF, TXT, MD, HTML, JSON, CSV, PNG, JPG')
 data=await file.read(15*1024*1024+1)
 if len(data)>15*1024*1024:raise HTTPException(413,'15 MB maximum')
 aid=uuid.uuid4().hex[:12];filename=aid+ext;path=UPLOAD/filename;path.write_bytes(data)
 text=readpdf(path) if ext=='.pdf' else (data.decode('utf-8','replace') if ext in ('.txt','.md','.html','.json','.csv') else '')
 result=assess(text) if text.strip() else {'frameworks':[],'disclaimer':'No machine-readable text extracted. Image/scanned documents need OCR or manual evidence review; no automated mapping was performed.'}
 summary=f'{len(text):,} extracted characters; '+('rule-based mapping available' if text.strip() else 'manual review required')
 with connect() as c:c.execute('INSERT INTO artifacts VALUES (?,?,?,?,?,?,?)',(aid,Path(file.filename).name[:220],kind,now(),summary,json.dumps(result),filename))
 return {'id':aid,'name':file.filename,'summary':summary,'review':result}
@app.get('/api/artifacts/{aid}/file')
def artifact_file(aid:str,_=Depends(admin)):
 with connect() as c:r=c.execute('SELECT * FROM artifacts WHERE id=?',(aid,)).fetchone()
 if not r:raise HTTPException(404,'Not found')
 return FileResponse(UPLOAD/r['filename'],filename=r['name'])
@app.delete('/api/artifacts/{aid}')
def delete_artifact(aid:str,_=Depends(admin)):
 with connect() as c:
  r=c.execute('SELECT filename FROM artifacts WHERE id=?',(aid,)).fetchone()
  c.execute('DELETE FROM artifacts WHERE id=?',(aid,))
 if r:(UPLOAD/r['filename']).unlink(missing_ok=True)
 return {'ok':True}
@app.get('/api/export')
def export(_=Depends(admin)):
 with connect() as c:
  return {'risks':[dict(r) for r in c.execute('SELECT * FROM risks')], 'artifacts':[dict(r) for r in c.execute('SELECT * FROM artifacts')]}


@app.get('/api/public')
def public():
 with connect() as c:
  certs=[dict(x) for x in c.execute('SELECT id,title,issuer,issued,description,filename FROM credentials ORDER BY created DESC')]
  bio=c.execute("SELECT value FROM profile WHERE key='bio'").fetchone()
  return {'certifications':[{**x,'url':'/api/certificates/'+x['id']+'/view' if x['filename'] else None} for x in certs], 'bio':bio['value'] if bio else ''}

@app.get('/api/certificates/{cid}/view')
def view_certificate(cid:str):
 with connect() as c:r=c.execute('SELECT filename FROM credentials WHERE id=?',(cid,)).fetchone()
 if not r or not r['filename']:raise HTTPException(404,'Not found')
 return FileResponse(ROOT/'certificates'/r['filename'],headers={'Content-Security-Policy':"default-src 'none'; sandbox",'X-Content-Type-Options':'nosniff'})

@app.post('/api/certificates')
async def add_certificate(title:str=Form(...),issuer:str=Form(...),issued:str=Form(''),description:str=Form(''),file:UploadFile=File(...),_=Depends(admin)):
 ext=Path(file.filename or '').suffix.lower()
 if ext not in ('.pdf','.png','.jpg','.jpeg','.webp'):raise HTTPException(400,'PDF and image certificates only')
 blob=await file.read(8*1024*1024+1)
 if len(blob)>8*1024*1024:raise HTTPException(413,'8MB limit')
 if ext=='.pdf' and not blob.startswith(b'%PDF-'):raise HTTPException(400,'Invalid PDF')
 if ext=='.png' and not blob.startswith(b'\x89PNG'):raise HTTPException(400,'Invalid PNG')
 if ext in ('.jpg','.jpeg') and not blob.startswith(b'\xff\xd8'):raise HTTPException(400,'Invalid JPEG')
 cid=uuid.uuid4().hex[:12]; name=cid+ext
 folder=ROOT/'certificates';folder.mkdir(exist_ok=True);(folder/name).write_bytes(blob)
 with connect() as c:c.execute('INSERT INTO credentials VALUES (?,?,?,?,?,?,?)',(cid,title[:160],issuer[:120],issued[:40],description[:500],name,now()))
 return {'id':cid,'url':'/api/certificates/'+cid+'/view'}

@app.delete('/api/certificates/{cid}')
def remove_certificate(cid:str,_=Depends(admin)):
 with connect() as c:
  row=c.execute('SELECT filename FROM credentials WHERE id=?',(cid,)).fetchone()
  if not row:raise HTTPException(404,'Not found')
  c.execute('DELETE FROM credentials WHERE id=?',(cid,))
 (ROOT/'certificates'/row['filename']).unlink(missing_ok=True)
 return {'ok':True}

@app.post('/api/assess-url')
def assess_url(data:dict,_=Depends(admin)):
 # Public HTTP(S) pages only; block loopback, RFC1918, metadata and DNS rebinding.
 import httpx
 url=str(data.get('url','')).strip();parsed=urllib.parse.urlsplit(url)
 if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:raise HTTPException(400,'Public HTTP(S) URL required')
 try:
  addresses=socket.getaddrinfo(parsed.hostname,None,type=socket.SOCK_STREAM)
  if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):raise ValueError('Non-public destination')
 except Exception:raise HTTPException(400,'Only publicly resolvable internet hosts are supported')
 # DNS resolution between validation and connect is a residual risk; use an isolated outbound proxy in production.
 try:
  with httpx.Client(timeout=8,follow_redirects=False,trust_env=False) as client:
   r=client.get(url,headers={'User-Agent':'GRC-Nexus-Document-Review/1.0','Accept':'text/html,text/plain'})
   r.raise_for_status()
   if 'text/html' not in r.headers.get('content-type','') and 'text/plain' not in r.headers.get('content-type',''):raise HTTPException(415,'HTML/text pages only; upload PDFs instead')
   if len(r.content)>1500000:raise HTTPException(413,'Page exceeds 1.5MB')
   body=r.text
 except HTTPException:raise
 except Exception as e:raise HTTPException(400,'Unable to retrieve public page')
 body=re.sub(r'(?is)<(script|style|noscript).*?</\1>',' ',body)
 body=re.sub(r'<[^>]*>',' ',body)
 body=html.unescape(body)
 result=assess(body[:250000]);result['source_url']=url
 result['website_note']='Public page content only. This is NOT a live security scan, audit, certification, or assessment of internal controls.'
 return result

@app.get('/owner')
def owner(_=Depends(admin)):
 return FileResponse(ROOT/'static'/'owner.html')
