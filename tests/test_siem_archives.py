import subprocess
from pathlib import Path
import pytest
from scripts.siem_archives import enable_archive_logging
from scripts.setup_security_views import field_list


def test_archive_config_preserves_alerts_and_other_global_sections():
 original='<ossec_config><global><jsonout_output>yes</jsonout_output><logall>no</logall><logall_json>no</logall_json></global><localfile><location>/logs/eve.json</location></localfile></ossec_config><ossec_config><ruleset/></ossec_config>'
 updated=enable_archive_logging(original)
 assert updated==original.replace('<logall_json>no</logall_json>','<logall_json>yes</logall_json>')
 assert enable_archive_logging(updated)==updated
 assert '<logall_json>yes</logall_json>' in enable_archive_logging('<ossec_config><global></global></ossec_config>')
 with pytest.raises(ValueError):enable_archive_logging('<ossec_config/>')


def test_boot_hook_preserves_credentials_and_alerts_and_repeats_safely(tmp_path):
 path=tmp_path/'filebeat config.yml'
 original='output.elasticsearch:\n  password: "synthetic-password"\nfilebeat.modules:\n  - module: wazuh\n    alerts:\n      enabled: true\n    archives:\n      # Include regular events\n      enabled: false\n'
 path.write_text(original)
 script=Path(__file__).resolve().parents[1]/'security/filebeat-archives.sh'
 for _ in range(2):subprocess.run(['bash',str(script),str(path)],check=True)
 assert path.read_text()==original.replace('enabled: false','enabled: true')
 path.write_text('filebeat.modules: []\n')
 assert subprocess.run(['bash',str(script),str(path)]).returncode!=0


def test_discover_fields_require_native_timestamp_mapping():
 result=field_list({'fields':{'timestamp':{'date':{'searchable':True,'aggregatable':True}},'data.blocked_packets':{'long':{'searchable':True,'aggregatable':True}},'location':{'keyword':{'searchable':True,'aggregatable':True}},'full_log':{'text':{'searchable':True,'aggregatable':False}}}})
 assert next(f for f in result if f['name']=='data.blocked_packets')['type']=='number'
 assert not next(f for f in result if f['name']=='full_log')['aggregatable']
 with pytest.raises(RuntimeError):field_list({'fields':{}})
