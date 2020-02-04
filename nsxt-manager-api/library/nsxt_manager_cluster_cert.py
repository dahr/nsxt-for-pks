#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
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
module: nsxt_licenses
short_description: 'Add a new license key'
description: "This will add a license key to the system.
              The API supports adding only one license key for each license edition
              type - Standard, Advanced or Enterprise. If a new license key is tried
              to add for an edition for which the license key already exists,
              then this API will return an error."
version_added: '2.7'
author: 'Rahul Raghuvanshi'
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
    license_key:
        description: 'license key'
        no_log: 'True'
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
- name: Add license
  nsxt_licenses:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      license_key: "11111-22222-33333-44444-55555"
      state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_cert_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def get_cluster_cert(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
      (rc, resp) = request(manager_url + '/cluster/api-certificate', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg='Error accessing certificate. Error [%s]' % (to_native(err)))

    return resp

def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, cert_params):
    existing_cert = get_cluster_cert(module, manager_url, mgr_username, mgr_password, validate_certs)
    if existing_cert is None:
        return False
    if existing_cert['certificate_id'] == cert_params['certificate_id']:
        return True
    return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(certificate_id=dict(required=True, type='str', no_log=False),
                    state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  cert_params = get_cert_params(module.params.copy())
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
        module.exit_json(changed=False, msg="Certificate with id %s already exist."% module.params['certificate_id'])
    if module.check_mode:
       module.exit_json(changed=True, debug_out=str(request_data), id=module.params['certificate_id'])
    try:
        (rc, resp) = request(manager_url+ '/cluster/api-certificate?action=set_cluster_certificate&certificate_id=' + module.params['certificate_id'], headers=headers, method='POST',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
        module.fail_json(msg="Failed to add certificate. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, result=resp, message="Certificate with id %s created." % module.params['certificate_id'])

  elif state == 'absent':
    # delete the license key
    id = module.params['certificate_id']
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(request_data), id=id)
    try:
       (rc, resp) = request(manager_url+ '/cluster/api-certificate?action=clear_cluster_certificate&certificate_id=' + id, method='POST',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to delete certificate with id %s. Error[%s]." % (id, to_native(err)))

    time.sleep(5)
    module.exit_json(changed=True, object_name=id, message="Certificate with id %s deleted." % id)


if __name__ == '__main__':
    main()
