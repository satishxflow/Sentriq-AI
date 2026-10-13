from __future__ import annotations
import re, json, ssl, socket, urllib.request, urllib.error, urllib.parse, html
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    impact: str
    recommendation: str
    confidence: str = "medium"
    source: str = "source"

class MarkupInventory(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=[]; self.links=[]; self.scripts=[]; self.inputs=[]; self._form=None
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag.lower()=='form':
            self._form={'action':a.get('action',''), 'method':a.get('method','GET').upper(), 'onsubmit':a.get('onsubmit',''), 'inputs':[]}; self.forms.append(self._form)
        elif tag.lower()=='input':
            item={'type':a.get('type','text').lower(),'name':a.get('name',''),'autocomplete':a.get('autocomplete','')}
            self.inputs.append(item)
            if self._form is not None:self._form['inputs'].append(item)
        elif tag.lower()=='a' and a.get('href'): self.links.append(a['href'])
        elif tag.lower()=='script' and a.get('src'): self.scripts.append(a['src'])
    def handle_endtag(self, tag):
        if tag.lower()=='form': self._form=None

def _add(out, sev, title, evidence, impact, fix, confidence='medium', source='source'):
    out.append(Finding(sev,title,evidence[:700],impact,fix,confidence,source))

def scan_source(text: str, filename='uploaded source') -> Dict[str, Any]:
    out=[]; low=text.lower()
    # Secret-like patterns: public browser keys are not treated as secrets by themselves.
    patterns=[
      ('critical','Private key material',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','A private key may have been shipped to clients.','Revoke/rotate it immediately and remove it from frontend/build history.'),
      ('critical','Supabase service-role key pattern',r'\b(?:service_role|sb_secret_[A-Za-z0-9_-]{12,})\b','Service-role/secret credentials must never be present in browser code.','Rotate the credential, remove it from client code, and use server-side secrets only.'),
      ('high','Hard-coded credential-like value',r'(?i)(?:password|passwd|api[_-]?secret|client[_-]?secret)\s*[:=]\s*[\'\"]([^\'\"]{8,})[\'\"]','A string near a credential label may be a hard-coded secret; review the evidence manually.','Move secrets to server-side environment variables and rotate any real credential.'),
      ('high','Potential private API token',r'\b(?:sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})\b','A recognizable private-token format may be embedded in client source.','Revoke/rotate the token and keep it server-side.'),
    ]
    for sev,title,pat,impact,fix in patterns:
        for m in list(re.finditer(pat,text))[:4]:
            snippet=text[max(0,m.start()-70):min(len(text),m.end()+70)].replace('\n',' ')
            _add(out,sev,title,snippet,impact,fix,'high')
    if re.search(r'createClient\s*\(\s*[\'\"]https://[^\'\"]+\.supabase\.co',text,re.I):
        if re.search(r'\b(?:service_role|sb_secret_)\b',text,re.I): pass
        else: _add(out,'info','Supabase browser client detected','A Supabase project URL and browser key are embedded in frontend code.','This is normal for a browser client when using a publishable/anon key; the database must enforce access with RLS and least-privilege grants.','Verify RLS is enabled on every exposed table, policies cover SELECT/INSERT/UPDATE/DELETE, and RPC functions validate the caller.','high')
    # XSS heuristic, intentionally not a proof of exploitability.
    sinks=list(re.finditer(r'\.innerHTML\s*=',text))
    if sinks:
        _add(out,'medium','HTML injection sinks require review',f'Found {len(sinks)} assignments to .innerHTML. Example: {text[max(0,sinks[0].start()-100):sinks[0].start()+180].replace(chr(10)," ")}', 'If untrusted user/database content reaches these sinks without context-safe escaping, stored or reflected XSS may be possible.','Prefer textContent/createElement; where HTML is necessary, use a maintained sanitizer and validate URL attributes. Trace data from products, coupons, profiles, and other database fields into each sink.','medium')
    if re.search(r'\beval\s*\(|new\s+Function\s*\(',text):
        _add(out,'high','Dynamic code execution API', 'Found eval(...) or new Function(...).','Dynamic code execution increases injection risk if input can influence the evaluated string.','Remove dynamic evaluation; use explicit parsers and fixed function dispatch.','high')
    if re.search(r'\*\s*\{\s*\}',text): pass
    # Browser-side role checks are UI only.
    role_hits=list(re.finditer(r'(?:isOwner|ownerAuthenticatedNow|ownerAuthenticated|role\s*===?\s*[\'\"]owner)',text,re.I))
    if role_hits:
        _add(out,'medium','Owner checks appear in frontend code',f'Found {len(role_hits)} frontend owner/role checks; these can hide UI but cannot enforce authorization.','If database tables or RPCs do not independently enforce owner-only access, a user may call the backend directly regardless of hidden buttons.','Enforce owner identity and permissions in Supabase RLS policies and SECURITY DEFINER RPCs; use auth.uid() and a server-controlled role mapping, never a client-provided role.','high')
    # Inline JS and no CSP visible in static file
    if re.search(r'<script(?![^>]*\bsrc\s*=)[^>]*>',text,re.I):
        _add(out,'low','Inline JavaScript detected','The page contains inline script blocks.','A strict Content-Security-Policy is harder to deploy with unrestricted inline scripts, reducing defense-in-depth against XSS.','Move scripts to files or use CSP nonces/hashes; deploy a tested CSP response header.','high')
    external=re.findall(r'<script[^>]+src=[\'\"](https?://[^\'\"]+)',text,re.I)
    unpinned=[u for u in external if re.search(r'/(?:@\d+|\d+\.\d+(?:\.\d+)?)(?:/|$)',u) is None]
    if unpinned:
        _add(out,'low','External script dependency without an obvious pinned version',', '.join(unpinned[:8]),'A moving dependency URL can change without a code deployment.','Pin exact dependency versions, use Subresource Integrity where supported, and review dependency updates.','medium')
    # Inventory forms without submitting them.
    inv=MarkupInventory()
    try: inv.feed(text)
    except Exception: pass
    if inv.forms:
        insecure=[]
        for f in inv.forms:
            if f['method']=='GET' and not re.search(r'return\s+false|preventDefault',f.get('onsubmit',''),re.I) and any(i['type']=='password' for i in f['inputs']): insecure.append(f)
        if insecure: _add(out,'high','Password field appears in a GET form','At least one GET form contains a password input.','GET may place credentials in URLs, browser history, logs, and referrers.','Use POST for authentication and submit over HTTPS.','high')
    return {'filename':filename,'bytes':len(text.encode('utf-8','replace')),'findings':[asdict(x) for x in out], 'inventory':{'forms':inv.forms,'links_count':len(inv.links),'external_scripts':external,'password_fields':sum(i['type']=='password' for i in inv.inputs)}}

class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__(); self.base=base; self.links=[]; self.forms=[]; self._form=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag.lower()=='a' and a.get('href'):
            u=urllib.parse.urljoin(self.base,a['href']); self.links.append(u)
        if tag.lower()=='form':
            self._form={'action':urllib.parse.urljoin(self.base,a.get('action','')),'method':a.get('method','GET').upper(),'has_password':False};self.forms.append(self._form)
        if tag.lower()=='input' and self._form is not None and a.get('type','').lower()=='password': self._form['has_password']=True
    def handle_endtag(self,tag):
        if tag.lower()=='form':self._form=None

def live_passive_scan(url: str, max_pages: int=12, timeout: int=10) -> Dict[str, Any]:
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme!='https' or not parsed.hostname: raise ValueError('Live scan requires a valid HTTPS URL.')
    origin=f'{parsed.scheme}://{parsed.netloc}'; host=parsed.hostname
    findings=[]; pages=[]; seen=set(); queue=[url]
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    def req(u):
        request=urllib.request.Request(u,headers={'User-Agent':'Pecuvea-Security-Agent/4.0 (authorized passive audit)','Accept':'text/html,application/xhtml+xml,*/*;q=0.8'},method='GET')
        opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirectHandler())
        try:
            with opener.open(request,timeout=timeout) as r:
                data=r.read(1_000_000); return r.status,dict(r.headers.items()),data,r.geturl()
        except urllib.error.HTTPError as e:
            # A 3xx response is reported, but is never followed to another host.
            return e.code,dict(e.headers.items()),e.read(200000),e.geturl()
    status,headers,body,final_url=req(url)
    hdr={k.lower():v for k,v in headers.items()}
    if not hdr.get('strict-transport-security'): _add(findings,'medium','HSTS header missing', 'The initial HTTPS response did not include Strict-Transport-Security.','Browsers may be more susceptible to downgrade paths before HTTPS is established.','After confirming all subdomains support HTTPS, set a suitable Strict-Transport-Security policy.','high','live')
    if not hdr.get('content-security-policy'): _add(findings,'medium','Content-Security-Policy header missing','No CSP response header was observed on the initial page.','CSP can reduce the impact of some injection vulnerabilities.','Deploy a report-only CSP first, then enforce a policy tailored to the site.','high','live')
    if not hdr.get('x-content-type-options'): _add(findings,'low','X-Content-Type-Options missing','No X-Content-Type-Options header was observed.','MIME sniffing can cause content to be interpreted unexpectedly in some contexts.','Set X-Content-Type-Options: nosniff.','high','live')
    if not hdr.get('referrer-policy'): _add(findings,'low','Referrer-Policy missing','No Referrer-Policy header was observed.','URLs may leak more referrer information than necessary.','Set a policy such as strict-origin-when-cross-origin, after reviewing product needs.','high','live')
    if not hdr.get('permissions-policy'): _add(findings,'info','Permissions-Policy missing','No Permissions-Policy header was observed.','Browser features are not explicitly restricted by this header.','Set a least-privilege Permissions-Policy appropriate to used browser features.','high','live')
    acao=hdr.get('access-control-allow-origin','')
    if acao=='*' and hdr.get('access-control-allow-credentials','').lower()=='true': _add(findings,'high','Potentially unsafe CORS header combination','Observed Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.','This combination is rejected by browsers for credentialed CORS, but may indicate misconfigured CORS handling elsewhere.','Use an explicit allowlist of trusted origins and verify responses for authenticated endpoints.','high','live')
    # Crawl same-origin GET pages only. No forms are submitted, no payloads are injected.
    while queue and len(seen)<max_pages:
        u=queue.pop(0)
        if u in seen: continue
        p=urllib.parse.urlparse(u)
        if p.scheme!='https' or p.netloc!=urllib.parse.urlparse(origin).netloc: continue
        if p.path.lower().endswith(('.png','.jpg','.jpeg','.gif','.svg','.webp','.pdf','.zip','.css','.js','.woff','.woff2')): continue
        seen.add(u)
        try:
            st,hs,b,fu=req(u); ctype=next((v for k,v in hs.items() if k.lower()=='content-type'),'')
            entry={'url':u,'status':st,'content_type':ctype,'bytes':len(b)}; pages.append(entry)
            if 'html' in ctype.lower() or b.lstrip().lower().startswith((b'<!doctype html',b'<html')):
                parser=PageParser(fu)
                parser.feed(b.decode('utf-8','replace'))
                for form in parser.forms:
                    if form['has_password'] and urllib.parse.urlparse(form['action']).scheme!='https':
                        _add(findings,'high','Password form action is not HTTPS',f"{u} submits a password field to {form['action']}",'Credentials may travel without transport encryption.','Ensure authentication forms post only to HTTPS endpoints.','medium','live')
                for link in parser.links:
                    lp=urllib.parse.urlparse(link)
                    if lp.scheme=='https' and lp.netloc==urllib.parse.urlparse(origin).netloc and link not in seen and len(queue)+len(seen)<max_pages*3: queue.append(link.split('#')[0])
        except Exception as e: pages.append({'url':u,'error':str(e)[:180]})
    # Deduplicate same finding title/evidence.
    uniq=[]; keys=set()
    for f in findings:
        k=(f.title,f.evidence)
        if k not in keys: uniq.append(asdict(f));keys.add(k)
    return {'target':url,'mode':'passive GET-only live scan','pages_checked':len(pages),'pages':pages,'findings':uniq,'note':'This passive mode did not submit forms or attempt SQLi, login bypasses, brute force, destructive actions, or database writes. Controlled read-only SQLi signals are available only in the separate opt-in active-tests tab.'}

def severity_counts(findings):
    c={x:0 for x in ['critical','high','medium','low','info']}
    for f in findings:c[f.get('severity','info').lower()]=c.get(f.get('severity','info').lower(),0)+1
    return c
