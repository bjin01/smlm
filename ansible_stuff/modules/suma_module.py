import ssl
import six
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: suma_module

short_description: module for SUSE Manager API
description:
  - This module interacts with SUSE Manager (Uyuni) API to query scheduled jobs and status of the current running host.
options:
  suma_server:
    description: hostname of the SUSE Manager server.
    required: true
    type: str
  suma_api_username:
    description: username to login to SUSE Manager API
    required: true
    type: str
  suma_api_password:
    description: password to login to SUSE Manager API. The password should be encrypted using python ryptography.fernet
    required: true
    type: str
author:
  - Bo Jin (@bjin)
'''

EXAMPLES = r'''
- name: Example usage
  suma_module:
    suma_api_username: api_user
    suma_api_password: gAAAAABnwtd
    suma_server: suma.example.com
'''

RETURN = r'''
result:
  description: The result of the call
  type: dict
  returned: always
'''

def main():
    """ module_args = dict(
        action=dict(type="str", required=True, choices=["schedule_patch", "check_job", "schedule_package_refresh"]),
        system_name=dict(type="str", required=True),
        config_path=dict(type="str", required=False, default="suma_config.yaml"),
        key_path=dict(type="str", required=False, default="suma_key"),
    ) """

    module_args = dict(
        action=dict(type="str", required=True, choices=["schedule_patch", "check_job", "schedule_package_refresh"]),
        system_name=dict(type="str", required=True),
        suma_api_username=dict(type="str", required=True),
        suma_api_password=dict(type="str", required=True),
        suma_server=dict(type="str", required=True),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)
    params = module.params

    result = dict(
        changed=False,
        Failed=False,
        msg='',
        output=[]
    )

    try:
        context = ssl._create_unverified_context()
        client = six.moves.xmlrpc_client.ServerProxy(f"https://{params['suma_server']}/rpc/api", context=context)
        session_key = client.auth.login(params['suma_api_username'], params['suma_api_password'])

        system_id = 0
        if not params['system_name']:
                module.fail_json(msg="system_name is required for scheduling a patch.")
        else:
            getid_result = client.system.getId(session_key, params['system_name'])
            if len(getid_result) == 1:
                system_id = getid_result[0]['id']
            else:
                result['changed'] = True
                result['failed'] = True
                result['msg'] = f"Failed to find system_id for {params['system_name']} or found more than one matching system_id {len(getid_result)}."
                module.fail_json(**result)
                
        if params['action'] == 'schedule_patch' and system_id != 0:
            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now() + timedelta(minutes=3))
            list_system_ids = []
            list_system_ids.append(system_id)
            job_id = client.system.schedulePackageUpdate(session_key, list_system_ids, earliest_occurrence)
            result['changed'] = True
            result['message'] = "A package update job has been scheduled."
            result['output'] = f"Job ID: {str(job_id)}"

            module.exit_json(changed=True, job_id=job_id)
          
        elif params['action'] == 'schedule_package_refresh' and system_id != 0:
            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now())
            job_id = client.system.schedulePackageRefresh(session_key, system_id, earliest_occurrence)
            result['changed'] = True
            result['message'] = "A package refresh job has been scheduled."
            result['output'] = f"Job ID: {str(job_id)}"

            module.exit_json(changed=True, job_id=job_id)


        elif params['action'] == 'check_job' and system_id != 0:
            today_start_iso8601 = six.moves.xmlrpc_client.DateTime(datetime.combine(datetime.today(), datetime.min.time()))
            getEventHistory_result = client.system.getEventHistory(session_key, system_id, today_start_iso8601, 0, 10)
            
            # raise Exception(getEventHistory_result)
            status = []
            for event in getEventHistory_result:
                event_dict = {}
                event_dict[event['id']] = {"status": event['status'], "summary": event['summary']}
                """ if event['id'] == 294:
                    raise Exception(event) """
                if event['status'].lower() not in {"completed", "failed", "(n/a)"}:
                    # raise Exception(event['status'])
                    result['changed'] = True
                    result['failed'] = True
                    module.fail_json(msg="Job is still running", output=f"{event['id']}: {event['summary']} {event['status']}")
                    
                status.append(event_dict) 

            result['msg'] = "Even History."
            result['output'] = f"Jobs {status}" 
            module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e))
    
    finally:
        client.auth.logout(session_key)

if __name__ == "__main__":
    main()
