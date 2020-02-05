#!/usr/bin/env python
#
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_manager_cluster_vip
short_description: 'Set manager cluster VIP'
description: "Sets the cluster virtual IP address. Note, all nodes in the management
              cluster must be in the same subnet. If not, a 409 CONFLICT status is
              returned."
version_added: '2.9.3'
author: 'Dave Ahr'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: str
    ip_address:
        description: 'Cluster vip IP'
        no_log: 'False'
        required: true
        type: str
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true   
'''

EXAMPLES = '''
- name: Manager cluster cert update
    nsxt_manager_cluster_cert:
        hostname: "{{hostname}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: False
        ip_address: "192.168.110.41"
        state: "present"
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_cluster_vip_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def read_cluster_vip(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url + '/cluster/api-virtual-ip', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing certificate. Error [%s]' % (to_native(err)))

    return resp

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, vip_params):
    existing_vip = read_cluster_vip(module, manager_url, mgr_username, mgr_password, validate_certs)
    if existing_vip is None:
        return False
    if existing_vip['ip_address'] == vip_params['ip_address']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(ip_address=dict(required=True, type='str', no_log=False),
                    state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  cert_params = get_cluster_vip_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'
  request_data = json.dumps(cert_params)

  if state == 'present':
    # add the certificate
    if check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, cert_params):
        module.exit_json(changed=False, msg="VIP with IP %s already exist."% module.params['ip_address'])
    if module.check_mode:
       module.exit_json(changed=True, debug_out=str(request_data), id=module.params['certificate_id'])
    try:
        (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=' + module.params['ip_address'], headers=headers, method='POST',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg="Failed to set cluster VIP. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, result=resp, message="Certificate with id %s created." % module.params['ip_address'])

  elif state == 'absent':
    # delete the certificate
    id = module.params['ip_address']
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(request_data), id=id)
    try:
       (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=' + id, method='POST',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to delete certificate with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="VIP with IP %s deleted." % id)


if __name__ == '__main__':
    main()
