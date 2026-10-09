#!/usr/bin/env python3
"""Live WAF regression: only Discover's known highlight value passes to auth."""
import argparse,json,ssl,urllib.request,urllib.error

def main():
 p=argparse.ArgumentParser();p.add_argument('origin');args=p.parse_args()
 base=args.origin.rstrip('/');context=ssl._create_unverified_context()
 good={'params':{'body':{'highlight':{'fragment_size':2147483647}}}}
 cases=[
  ('/_kt88/wazuh/internal/search/opensearch-with-long-numerals',good,401),
  ('/_kt88/wazuh/internal/search/opensearch',good,401),
  ('/_kt88/wazuh/internal/search/opensearch-with-long-numerals',{'params':{'body':{'highlight':{'fragment_size':'1e309'}}}},403),
  ('/_kt88/api/not-a-search',good,403),
  ('/_kt88/wazuh/internal/search/opensearch-with-long-numerals',{**good,'q':'<script>alert(1)</script>'},403),
 ]
 for nesting in [('query',),('query','bool')]:
  for value,expected in [(2147483647,401),('1e309',403),(2147483648,403)]:
   body={'highlight':{'fragment_size':value}}
   for name in reversed(nesting):body={name:body}
   payload={'params':{'body':body}}
   for path in ('/_kt88/wazuh/internal/search/opensearch','/_kt88/wazuh/internal/search/opensearch-with-long-numerals'):
    cases.append((path,payload,expected))
   if expected==401:
    cases.append(('/_kt88/api/not-a-search',payload,403))
    cases.append(('/_kt88/wazuh/internal/search/opensearch',{**payload,'q':'<script>alert(1)</script>'},403))
 for path,payload,expected in cases:
  request=urllib.request.Request(base+path,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Origin':base,'osd-xsrf':'regression'},method='POST')
  try:
   with urllib.request.urlopen(request,context=context,timeout=15) as response:status=response.status
  except urllib.error.HTTPError as error:status=error.code
  if status!=expected:raise SystemExit(f'FAIL {path}: expected {expected}, got {status}')
 print('PASS: Discover INT_MAX reaches authentication; other values, paths and XSS remain blocked')
if __name__=='__main__':main()
