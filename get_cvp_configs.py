#!/usr/bin/env python
# Author: Casey Blair
# Python 3.8.0
# This script is used to capture the switch running configurations from CVP.
# This material and information contained in this file is for general
# information purposes only. Please use at your own risk.
# Arista CVP version 2020.1.0


import requests
import json
requests.urllib3.disable_warnings()
# The variables below are for access to the DMF controller. Eample:
# CVP_HOST = '10.1.1.1'
# CVP_USER = 'admin'
# CVP_PWD = 'pa55word'


CVP_HOST = " "
CVP_USER = " "
CVP_PWD = " "


class CVPAPI():
    def __init__(self, cvp_host, username, password):
        '''inputs the ip address of the cvp server to create the api_root var.

        '''
        self.api_root = 'https://{0}:/cvpservice'.format(cvp_host)
        self.username = username
        self.password = password
        self.cookies = self._authenticate()
        self.switch_hn_mac = {}

    def _authenticate(self):
        '''uses the request module to post authentication credentials and
        Returns:
           session key for further api calls.
        '''
        auth_data = json.dumps({'userId': self.username, 'password': self.password})
        auth_url = self.api_root + "/login/authenticate.do"
        auth_response = requests.post(auth_url, data=auth_data, verify=False)
        assert auth_response.ok
        return auth_response.cookies

    def cvp_logout(self):
        '''used to log out of CVP to clear session
        Returns:
           None
        '''
        logout_url = self.api_root + "/login/logout.do"
        logout = requests.post(logout_url, cookies=self.cookies, verify=False)
        assert logout.ok

    def get_swx_info(self):
        '''used to capture hosname and system MAC address
        Returns:
           an updated dictionary with hostname and MAC adress
        '''
        tasks_url = self.api_root + "/inventory/devices"
        cvp_inventory_response = requests.get(tasks_url, cookies=self.cookies, verify=False)
        assert cvp_inventory_response.ok
        inventory_json = cvp_inventory_response.json()
        for z in range(len(inventory_json)):
            self.switch_hn_mac.update({inventory_json[z]['hostname']: inventory_json[z]['systemMacAddress']})
        # print(self.switch_hn_mac)

    def get_full_config(self):
        '''used to capture the switch configuration form CVP.
        Returns:
           creates / overwirtes a file with the hostname as the file name.
           the configuration string is recorded in the file.
        '''
        for hn, mac in self.switch_hn_mac.items():
            mac_addr = ('netElementId=' + str(mac))
            tasks_url = self.api_root + "/inventory/device/config"
            cvp_inventory_response = requests.get(tasks_url, params=mac_addr, cookies=self.cookies, verify=False)
            assert cvp_inventory_response.ok
            switch_json = cvp_inventory_response.json()
            switch_config = switch_json['output']
            with open(hn, 'w') as config_data:
                config_data.writelines(switch_config)
                config_data.close()


def main():
    api = CVPAPI(CVP_HOST, CVP_USER, CVP_PWD)
    api.get_swx_info()
    api.get_full_config()
    api.cvp_logout()


if __name__ == '__main__':
    main()
