"""Enable native Wazuh archives without changing alert rules or credentials."""
import re


def enable_archive_logging(content):
    match=re.search(r'<global>.*?</global>',content,re.S)
    if not match:raise ValueError('Wazuh global configuration not found')
    section=match.group()
    if re.search(r'<logall_json>.*?</logall_json>',section,re.S):
        section=re.sub(r'<logall_json>.*?</logall_json>','<logall_json>yes</logall_json>',section,flags=re.S)
    else:section=section.replace('</global>','  <logall_json>yes</logall_json>\n</global>')
    return content[:match.start()]+section+content[match.end():]
