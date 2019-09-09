#################################################################################################
# Nutanix network function/service chain creation script
#
# By: Keith Olsen - keith.olsen@nutanix.com
#
# This script creates and configureS a network function / service chain for use in Flow micro-segmentation
# security policies.
#
# It requires the network function VM already be created. Please do so before executing this script.
#
# It was developed in accordance with the document "Configuring Service Chains and Network Functions"
# by Jason Burns - Thanks Jason, it is a most excellent document!!!
#
# Available at: https://docs.google.com/document/d/1_Y_1D1gV1EWjd5CTQIyYWvaGl6Zg1WMajQM-6JDeb3M/edit?usp=sharing
#
# For a better understanding of what this script does, please reference the above document.
#
# Any questions or comments, please feel free to contact me.
#
# PLEASE NOTE - this script has not been audited for any security vulnerabilities.
# Please review and understand what it does, and how this may impact your environment.
#
# THIS CARRIES NO WARRANTY - EXPRESSED NOR IMPLIED AND IS FOR USE STRICTLY AT YOUR OWN RISK.
#
####################################################################################################

import requests
import time
import json
import paramiko
import re
from http.client import HTTPSConnection
from base64 import b64encode

requests.packages.urllib3.disable_warnings()


print("****************** Please create the network function VM (NFVM) prior to running this script ******************")
print("●	                Use recommended vCPU and Memory as mentioned in vendor documentation")
print("●	            Add a single Normal NIC to the VM. This is the management interface of the VM")
print("●	DO NOT POWER ON THE VM YET. This script will be performing actions on the VM that require it to be off")
print()


# # Gather cluster & prism central information

clusterName = input("Enter the target cluster name: ")
print()
clusterIP = input("Enter the target cluster IP: ")
print()
cvmUserID = input("Enter cluster administrator ID: ")
print()
cvmPassword = input(" Enter cluster administrator password: ")
print()
prisCentIP = input("Enter Prism Central IP: ")
print()
pcUserID = input("Enter Prism Central administrator ID: ")
print()
pcPassword = input("Enter Prism Central administrator password: ")
print()
#This sets up the https connection

c = HTTPSConnection(prisCentIP)


# # Creates encoded Authorization value

userpass = (pcUserID) + ":" + (pcPassword)
buserAndPass = b64encode(userpass.encode("ascii"))
authKey = (buserAndPass.decode("ascii"))

headers = {
    'Content-Type': "application/json",
    'Authorization': "Basic " + authKey,
    'cache-control': "no-cache"
    }

# # Defines base url for API calls

baseurl = "https://" + prisCentIP + ":9440/api/nutanix/v3/"

# # Gather network function VM information

nfvmName = input("Enter the name for the NFVM: ")
print()

# # # Get info for all VMs, filter for NFVM determine VMs power state

allntnxvmUrl = baseurl + "vms/list"
allntnxvmsPayload = {'kind': 'vm'}
json_allntnxvmsPayload = json.dumps(allntnxvmsPayload)

allntnxvmsRsp = requests.request("POST", allntnxvmUrl, data=json_allntnxvmsPayload, headers=headers, verify=False)\
    .json()

for each in allntnxvmsRsp['entities']:
    if each['spec']['name'] == nfvmName:
        powerSt = each['status']['resources']['power_state']

if powerSt == 'ON':
    print(nfvmName + " is currently powered on, please shut it down before proceeding.")
    print()

# nvfmPower = input("Is " + nfvmName + " off (Y/N)? ")
#
# if nvfmPower == 'N':
#     (print("Please ensure it is powered off before proceeding"))
# print()
# add in automatic check for power state of VM and alert user if VM is powered on/advise to power off

nfpVendor = input("Enter the vendor name of the appliance: ")
print()

# # Get cluster UUID for use in network function chain creation

clusterUrl = baseurl + "clusters/list"
clusterPayload = {
    'kind': 'cluster'
    }
json_clusterPayload = json.dumps(clusterPayload)

clusterList = requests.request("POST", clusterUrl, data=json_clusterPayload, headers=headers, verify=False).json()

for each in clusterList['entities']:
    if (each['spec']['name']) == clusterName:
        clusterUuid = (each['metadata']['uuid'])


# # Create Network Function Provider (nfp) category

nfpUrl = baseurl + "categories/network_function_provider"
nfpPayload = {
    'name': 'network_function_provider',
    'description': 'For Flow network function service chaining'
}
json_nfpPayload = json.dumps(nfpPayload)

nfpCreateRsp = requests.request("PUT", nfpUrl, data=json_nfpPayload, headers=headers, verify=False).json()


# # Create network function provider (nfp) values - using network function application vendor (nfpVendor)

nfpVendUrl = baseurl + "categories/network_function_provider/" + nfpVendor + ""
nfpVendorPayload = {
    'value': nfpVendor
    }
json_nfpVendorPayload = json.dumps(nfpVendorPayload)

nfpVendRsp = requests.request("PUT", nfpVendUrl, data=json_nfpVendorPayload, headers=headers, verify=False).json()

nfpVendListUrl = baseurl + "categories/network_function_provider/list"
nfpVendListPayload = {'kind': 'category'}
json_nfpVendListPayload = json.dumps(nfpVendListPayload)

nfpVendListRsp = requests.request("POST", nfpVendListUrl, data=json_nfpVendListPayload, headers=headers, verify=False)\
    .json()


# # Create network function chain (nfc)

nfChain = input("Enter name for this network function chain: ")
print()
nfType = input("Is this chain type INLINE (firewall) or TAP (sniffer): ").upper()
print()

if nfType == 'TAP':
    hostIP = input("Enter the IP address of the host this NFVM will be bound to: ")
## need to add validation that IP provided exists in cluster
else:
    hostIP = 'X.X.X.X'
print()

nfcUrl = baseurl + "network_function_chains"
nfcPayload = {
    'spec':
        {'name': nfChain, 'resources': {'network_function_list': [{'network_function_type': nfType,
'category_filter': {'type': 'CATEGORIES_MATCH_ANY', 'params': {'network_function_provider': [nfpVendor]}}}]},
'cluster_reference': {'kind': 'cluster', 'name': clusterName, 'uuid': clusterUuid}}, 'api_version': '3.1.0',
'metadata': {'kind': 'network_function_chain'}}
json_nfcPayload = json.dumps(nfcPayload)

nfcRsp = requests.request("POST", nfcUrl, data=json_nfcPayload, headers=headers, verify=False).json()

print("Creating service chain, please wait....")
print()
time.sleep(10)  # needed delay so next step would pull current/valid data

nfcListUrl = nfcUrl + "/list"
nfcListPayload = {'kind': 'network_function_chain'}
json_nfcListPayload = json.dumps(nfcListPayload)

nfcListRsp = requests.request("POST", nfcListUrl, data=json_nfcListPayload, headers=headers, verify=False).json()

for each in nfcListRsp['entities']:
    if (each['spec']['name']) == nfChain:
        print("Successfully created network function chain: " + each['spec']['name'] + " with type " + each['status']
        ['resources']['network_function_list'][0]['network_function_type'])
print()

# # Modify VM - create network function NICs, set agent VM, set host affinity(if applicable)

print('Modifying NFVM (adding service NICs, setting agent VM flag)')
print()

nbytes = 4096
port = 22
username = cvmUserID
password = cvmPassword
cfgInline = 'acli vm.nic_create ' + nfvmName + ' type=kNetworkFunctionNic network_function_nic_type=kIngress && ' \
            'sleep 5 &&' \
            'acli vm.nic_create ' + nfvmName + ' type=kNetworkFunctionNic network_function_nic_type=kEgress && ' \
            'sleep 5 &&' \
            'acli vm.update ' + nfvmName + ' agent_vm=true extra_flags=is_system_vm=true'

cfgTap = 'acli vm.nic_create ' + nfvmName + ' type=kNetworkFunctionNic network_function_nic_type=kTap && ' \
        'sleep 5 &&' \
         'acli vm.update ' + nfvmName + ' agent_vm=true extra_flags=is_system_vm=true && ' \
        'sleep 5 &&' \
         'acli vm.affinity_set ' + nfvmName + ' host_list=' + hostIP + ''

if nfType == 'INLINE':
        command = cfgInline
else:
        command = cfgTap

client = paramiko.Transport((clusterIP, port))
client.connect(username=username, password=password)

stdout_data = []
stderr_data = []
session = client.open_channel(kind='session')
session.exec_command(command)


while True:
    if session.recv_ready():
        stdout_data.append(session.recv(nbytes))
    if session.recv_stderr_ready():
        stderr_data.append(session.recv_stderr(nbytes))
    if session.exit_status_ready():
        break

#print "exit status: "#, session.recv_exit_status()
print(stdout_data)
print(stderr_data)

session.close()
client.close()

# # # Get info for all VMs, filter for NFVM get vm uuid and extract spec details to update VM category

allntnxvmUrl = baseurl + "vms/list"
allntnxvmsPayload = {'kind': 'vm'}
json_allntnxvmsPayload = json.dumps(allntnxvmsPayload)

allntnxvmsRsp = requests.request("POST", allntnxvmUrl, data=json_allntnxvmsPayload, headers=headers, verify=False)\
    .json()

for each in allntnxvmsRsp['entities']:
    if each['spec']['name'] == nfvmName:
        vmUuid = each['metadata']['uuid']
        json_spec = json.dumps(each['spec'])
        json_metadata = json.dumps(each['metadata'])
        json_CatMetadata = re.sub('"categories": {}', '"categories": {"network_function_provider" : ' '"' + nfpVendor +
                                  '" }}', json_metadata)
        json_vmCatUpdatePayload = '{ "spec": ' + json_spec + ', "metadata": ' + json_CatMetadata

# # # Set VM category

vmCatUpdateUrl = baseurl + "vms/" + (vmUuid)
vmCatUpdateRsp = requests.request("PUT", vmCatUpdateUrl, data=json_vmCatUpdatePayload, headers=headers, verify=False)

print(vmCatUpdateRsp)  # If response code is 202 - everything worked as it should

# need to add a better statement of successful completion.
