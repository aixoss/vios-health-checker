#!/usr/bin/python
#
# Copyright 2017, International Business Machines Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

######################################################################

from datetime import datetime
import os, sys, getopt
import fileinput
import re
import pycurl
import xml.etree.cElementTree as ET

#######################################################
# Initialize variables
#######################################################
# Target HMC
hmc_ip = ""

# HMC Rest API Login Credentials
user_id = ""
password = ""
session_key = ""

# Dual VIOS pair2
vios1_uuid = ""
vios2_uuid = ""
managed_system_uuid = ""

# Flags & Counters used by program
hc_fail = 0
verbose = 0
num_hc_fail = 0
num_hc_pass = 0
total_hc = 0

###################
# Check to make sure tmp path exists
if not os.path.exists('tmp'):
    os.makedirs('tmp')

# Establish a log file for this running
# log file format is vio_maint_mm_dd_YYYY_HH_MM_SS.log
# currently unused
today = datetime.now()
logfile = "vios_maint_%02d_%02d_%d_%02d_%02d_%02d.log" %(today.day, today.month, today.year, today.hour, today.minute, today.second)


#######################################################
# Define functions
#######################################################
### File manipulation functions ###

# Create file under tmp directory
def touch(path):
    with open(path, 'a'):
        os.utime(path, None)

# Remove file under tmp directory
def remove(path):
    os.remove(path)

# Verbose output
def write(filename, txt):
    if (verbose == 0):
        os.write(filename, txt)
    else:
        print txt

### Interfacing functions ###

# Takes in XML file of managed systems, parsing it and
# retrieving Managed system and VIOS UUIDs and Machine SerialNumber
# Input: XML file of managed systems, session key, and hmc ip
# Output: dict of mapped managed systems to thier SerialNumbers and VIOS
def managed_system_discovery(xml_file, session_key, hmc_ip):
    vios_arr = [] # list of all vios UUIDs
    m = {} # managed system to vios mapping
    managed_system = "" # string to hold current managed system being searched

    tree = ET.ElementTree(file=xml_file)

    # Map managed system UUIDs to serial numbers
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == "entry"):
            elem_child = elem.getchildren()
            for child in elem_child:
                if ( re.sub(r'{[^>]*}', "", child.tag) == "id"):
                    if child.text in m:
                        continue
                    else:
                        m[child.text] = []
                        managed_system = child.text
        # Retreiving the current Managed System Serial
        if ( re.sub(r'{[^>]*}', "", elem.tag) == "MachineTypeModelAndSerialNumber"):
            # string to append to the managed system dict
            serial_string = ""
            elem_child = elem.getchildren()
            for serial_child in elem_child:
                if re.sub(r'{[^>]*}', "", serial_child.tag) == "MachineType":
                    serial_string += serial_child.text + "-"
                if re.sub(r'{[^>]*}', "", serial_child.tag) == "Model":
                    serial_string += serial_child.text + "*"
                if re.sub(r'{[^>]*}', "", serial_child.tag) == "SerialNumber":
                    serial_string += serial_child.text
            # Adding the serial to the current Managed System
            m[managed_system].append([serial_string])
    # Retrieve the VIOS UUIDs
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == "AssociatedVirtualIOServers"):
            elem_child = elem.getchildren()
            for child in elem_child:
                if re.sub(r'{[^>]*}', "", child.tag) == "link":
                    # The VIOS UUIDs are in the "link" attribute
                    link_str = str(child.attrib)
                    vios_arr.append(link_str.strip().split("/"))
    # Get rid of excess info and place in dict
    for line in vios_arr:
        s = line[line.index("VirtualIOServer")+1]
        s = re.sub(r'\'[^>]*}', "", s)
        # Check if key already exists
        if line[line.index("ManagedSystem")+1] in m:
            m[line[line.index("ManagedSystem")+1]].append(s)

    uuid_arr = []
    for key, values in m.iteritems():
        for uuid in values[1:]:
            uuid_arr.append(uuid)

    # Get PartitionIDs
    vios_part = {} 
    i = 0
    for uuid in uuid_arr:
        filename = "vios%s.xml" %(i)
        i += 1
        touch(filename)
        get_client_info(session_key, hmc_ip, uuid, filename)
        # TODO for every file vios(n) get the partion id
        # Parse file for partition IDs
        tree = ET.ElementTree(file=filename)
        iter_ = tree.getiterator()
        for elem in iter_:
            if ( re.sub(r'{[^>]*}', "", elem.tag) == "PartitionID"):
                vios_part[uuid] = elem.text
                break

    # Clean up
    i = 0
    for uuid in uuid_arr:
        filename = "vios%s.xml" %(i)
        i += 1
        remove(filename)

    return m, vios_part

# Inputs: HMC IP address, user ID, password
# Output: session key
def get_session_key (hmc_ip, user_id, password):
    s_key = ""
    with open('sessionkey.xml', 'wb') as f:
        url = "https://%s:12443/rest/api/web/Logon" %(hmc_ip)
        fields = '<LogonRequest schemaVersion=\"V1_0\" xmlns=\"http://www.ibm.com/xmlns/systems/power/firmware/web/mc/2012_10/\"  xmlns:mc=\"http://www.ibm.com/xmlns/systems/power/firmware/web/mc/2012_10/\"> <UserID>%s</UserID> <Password>%s</Password></LogonRequest>' %(user_id, password)
        hdrs = ['Content-Type: application/vnd.ibm.powervm.web+xml; type=LogonRequest']

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.CUSTOMREQUEST, "PUT")
        c.setopt(c.POST, 1)
        c.setopt(c.POSTFIELDS, fields)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

    # Isolate session key
    with open('sessionkey.xml', 'r') as f:
        for line in f:
            if (re.search('<X-API-Session', line) != None):
                s_key = re.sub(r'<[^>]*>', "", line)
    return s_key.strip()

# Given a corresponding flag, it will print out managed system
# and vios UUIDs
# Input: HMC IP address, user id, password, argument flag
# Output: None
def print_uuid(hmc_ip, user_id, password, arg):
    # Check for necessary flags
    if (hmc_ip == "" or user_id == "" or password == ""):
        print "Please include [-i hmc_ip_address] [-u user_id] [-p password]"
        sys.exit(2)
    sess_key = get_session_key(hmc_ip, user_id, password)

    with open('systems.xml', 'wb') as file:
        url = "https://%s:12443/rest/api/uom/ManagedSystem" %(hmc_ip)
        hdrs = ["X-API-Session:%s" %(sess_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, file)
        c.perform()

    # Mapped managed systems
    m, vios_part = managed_system_discovery('systems.xml', sess_key, hmc_ip)

    if (arg == 'm'):
        # Print only managed systems
        print "\nManaged Systems UUIDs                   Serial"
        print "-" * 37 + "\t" + "-"*22
        for key, values in m.iteritems():
            print key + "\t" + ''.join(values[0]) + "\n"

    elif ( arg == 'a'):
        print "\nManaged Systems UUIDs                   Serial"
        print "-" * 37 + "\t" + "-"*22
        for key, values in m.iteritems():
            print key + "\t" + ''.join(values[0]) + "\n"
            print"\tVIOS                                    Partition ID"
            print "\t" + "-" * 37 + "\t" + "-" * 14
            for v in values[1:]:
                print "\t" + v + "\t" + vios_part[v]
            print "\n"
    else:
        print "Invalid option. \nUsage: [-l m | -l a]"
    remove('systems.xml')
    exit()


### Parsing functions ###

# Parse through xml to find tag value
# Inputs: file name, tag
# Output: value
def grep (filename, tag):
    tree = ET.ElementTree(file=filename)
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == tag):
            return elem.text
    return ""

# Parse through xml file to create list of tag values
# Inputs: file name, tag
# Output: array of values corresponding to given tag
def grep_array(filename, tag):
    arr = []
    tree = ET.ElementTree(file=filename)
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == tag):
            arr.append(elem.text)
    return arr

# Checks for existence of tag in file
# Inputs: file name, tag
# Output: True if tag exists, False otherwise
def grep_check (filename, tag):
    found = False
    tree = ET.ElementTree(file=filename)
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == tag):
            found = True
    return found

# Parse through specific sections of xml file to create a list of tag values
# Inputs: file name, outer tag, inner tag
# Output: array of values corresponding to given tags
def awk (filename, tag1, tag2):
    arr = []
    tree = ET.ElementTree(file=filename)
    iter_ = tree.getiterator()
    for elem in iter_:
        if ( re.sub(r'{[^>]*}', "", elem.tag) == tag1):
            elem_child = elem.getchildren()
            for child in elem_child:
                if ( re.sub(r'{[^>]*}', "", child.tag) == tag2):
                    arr.append(child.text)
    return arr


### Pycurl ###

# Find clients of a VIOS
# Inputs: session key, HMC IP address, VIOS UUID, file name
# No output, writes data to file
def get_client_info (session_key, hmc_ip, vios_uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s" %(hmc_ip, vios_uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

# Get VIOS UUID and ID info
# Inputs: session key, HMC IP address, file name
# No output, writes data to file
def get_vios_info (session_key, hmc_ip, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/VirtualIOServer" %(hmc_ip)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

# Find LPARs of a managed system
# Inputs: session key, HMC IP address, managed system UUID, file name
# No output, writes data to file
def get_managed_system_lpar (session_key, hmc_ip, managed_system_uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/ManagedSystem/%s/LogicalPartition" %(hmc_ip, managed_system_uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

# Get VSCSI info
# Inputs: session key, HMC IP address, VIOS UUID, file name
# No output, writes data to file
def get_vscsi_info (session_key, hmc_ip, vios_uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping" %(hmc_ip, vios_uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

# Get fibre channel mapping for VIOS
# Inputs: session key, HMC IP address, VIOS UUID, file name
# No output, writes data to file
def get_fc_mapping_vios (session_key, hmc_ip, vios_uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosFCMapping" %(hmc_ip, vios_uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

# Get info about LPAR to see network connections
# Inputs: session key, HMC IP address, LPAR, file name
# No output, writes data to file
def get_lpar_info (session_key, hmc_ip, lpar, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/LogicalPartition/%s/VirtualFibreChannelClientAdapter" %(hmc_ip, lpar)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

def get_network_info (session_key, hmc_ip, vios_uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosNetwork" %(hmc_ip, vios_uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()

def get_vnic_info (session_key, hmc_ip, uuid, filename):
    with open(filename, 'wb') as f:
        url = "https://%s:12443/rest/api/uom/LogicalPartition/%s/VirtualNICDedicated" %(hmc_ip, uuid)
        hdrs = ["X-API-Session:%s" %(session_key)]

        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()


#######################################################
# Get command line options
#######################################################
os.chdir('tmp')
# Get options
def usage():
    print """
        Usage: vioshc [-i hmc_ip_address] [-u user_id] [-p password] [-U vios_uuid] [-m managed_system] [-v] [-l list]

                -i          :hmc ip address
                -u          :hmc user ID
                -p          :hmc password
                -U          :vios UUID, use flag twice for two UUIDs
                -m          :managed system UUID
                -v          :verbose
                -l          :list managed system information
                                [-l a] list managed system and vios UUIDs
                                [-l m] list managed system UUIDs

            """

try:
    opts, args = getopt.getopt(sys.argv[1:], 'i:u:p:U:m:v:l:', ['HMC IP=', 'User ID=', 'Password=', 'VIOS UUID=', 'Managed System UUID=', 'Verbose', 'List'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-i'):
        hmc_ip = arg
    elif opt in ('-u'):
        user_id = arg
    elif opt in ('-p'):
        password = arg
    elif opt in ('-U'):
        # Check if vios UUID is valid
        if re.match("^[a-zA-Z0-9-]*$", arg):
            if vios1_uuid == "":
                vios1_uuid = arg
            elif vios2_uuid == "":
                vios2_uuid = arg
        else:
            print "Invalid UUID. Please try again.\n"
            sys.exit(2)
    elif opt in ('-m'):
        # Check if managed system UUID is valid
        if re.match("^[a-zA-Z0-9-]*$", arg):
            managed_system_uuid = arg
        else:
            print "Invalid UUID. Please try again.\n"
    elif opt in ('-v'):
        verbose = 1
        silent = 0
        sys.stdout = sys.stderr
    elif opt in ('-l'):
        print_uuid(hmc_ip, user_id, password, arg)
    else:
        usage()
        sys.exit(2)

    session_key = get_session_key(hmc_ip, user_id, password)

# If verbose-output not requested, write to fd
fd = os.open('f1.txt', os.O_RDWR|os.O_CREAT)


#######################################################
# Check for curl on the system
#######################################################
# Return status is 0 if successful, else failed
os.system('command -v curl >/dev/null 2>&1 || { echo "ERROR: Curl not installed on this system. Exiting now." >&2; exit 2; }')


#######################################################
# REST Call to /rest/api/uom/VirtualIOServer
# Get name and partition ID of each VIOS then filter
# the ones of interest
#######################################################
# Find clients of VIOS1, write data to vios1_only.xml
try:
    get_client_info(session_key, hmc_ip, vios1_uuid, 'vios1_only.xml')
except:
    print "ERROR: Request to https://$%s:12443/rest/api/uom/VirtualIOServer/%s failed." %(hmc_ip, vios1_uuid)
    sys.exit(3)

# Find clients of VIOS2, write data to vios2_only.xml
try:
    get_client_info(session_key, hmc_ip, vios2_uuid, 'vios2_only.xml')
except:
    print "ERROR: Request to https://$%s:12443/rest/api/uom/VirtualIOServer/%s failed." %(hmc_ip, vios2_uuid)
    sys.exit(3)

# Find UUID and IP addresses of VIOSes, write data to vios_info.xml
try:
    get_vios_info(session_key, hmc_ip, 'vios_info.xml')
except:
    print "ERROR: Request to https://$%s:12443/rest/api/uom/VirtualIOServer failed." %(hmc_ip)
    sys.exit(3)


# Grab all UUIDs, names, and partition IDs from xml doc and map the names in
# order to get UUID to name mapping as well as partition ID
vios_uuid_list = []
vios_name_list = []
vios_partitionid_list = []
vios_ip_list = []
vios_partition_state_list = []
vios_control_state_list = []

# Create list of partition UUIDs
vios_uuid_list = grep_array('vios_info.xml', 'PartitionUUID')
if (len(vios_uuid_list) == 0):
    print "ERROR: Unable to detect any VIOS partition UUIDs. Exiting Now."
    sys.exit(2)

# Create list of partition names
# NOTE: some VIOSes do not return PartitionName elements
name_list = []
name_list = grep_array('vios_info.xml', 'PartitionName')
for name in name_list:
    if name not in vios_name_list:
        vios_name_list.append(name)
if (len(vios_name_list) == 0):
    write(fd, "WARNING: Unable to detect any VIOS partition names. This may affect the the output of this program.")

# Create a list of partition IDs
part_id = False
tree = ET.ElementTree(file='vios_info.xml')
iter_ = tree.getiterator()
for elem in iter_:
    if part_id and ( re.sub(r'{[^>]*}', "", elem.tag) == 'PartitionID'):
        vios_partitionid_list.append(elem.text)
        part_id = False
    if ( re.sub(r'{[^>]*}', "", elem.tag) == 'PartitionCapabilities'):
        part_id = True
if (len(vios_partitionid_list) == 0):
    write(fd, "WARNING: Unable to detect any VIOS partition IDs. This may affect the the output of this program.")

# Create list of IP addresses
vios_ip_list = grep_array('vios_info.xml', 'ResourceMonitoringIPAddress')
if (len(vios_ip_list) == 0):
    print "ERROR: Unable to detect any VIOS partition IP addresses. Exiting Now."
    sys.exit(2)

# Create list of partition states
vios_partition_state_list = grep_array('vios_info.xml', 'PartitionState')
if (len(vios_partition_state_list) == 0):
    print "ERROR: Unable to detect partition states. Exiting Now."
    sys.exit(2)

# Create list of resource monitoring control states
vios_control_state_list = grep_array('vios_info.xml', 'ResourceMonitoringControlState')
if (len(vios_control_state_list) == 0):
    print "ERROR: Unable to detect partition control states. Exiting Now."
    sys.exit(2)


# Create new lists with just the info we want - since we have to query all
# the VIOS in the HMC for the REST API, there is a lot of unnecessary info
found_vios1 = 0
found_vios2 = 0
i = 0
ip_idx = 0
state_idx = 0
control_state_idx = 0

primary_header = "\nPrimary VIOS Name         IP Address      ID         UUID                "
backup_header = "Backup VIOS Name          IP Address      ID         UUID                "
divider= "-------------------------------------------------------------------------------------------------\n"
format = "%-25s %-15s %-10s %-40s \n\n"

for vios in vios_uuid_list:
    # If Resource Monitoring Control State is inactive, it will throw off our UUID/IP pairing
    if ((vios_control_state_list[control_state_idx] == "inactive") and (vios_partition_state_list[state_idx] == "not")):
        i += 1
        state_idx += 2
        control_state_idx += 1
        continue

    if ((vios_control_state_list[control_state_idx] == "inactive") and (vios_partition_state_list[state_idx] == "running")):
        i += 1
        state_idx += 1
        control_state_idx += 1
        continue

    # If VIOS is not running, skip it otherwise it will throw off our UUID/IP pairing
    if (vios_partition_state_list[state_idx] == "not"):
        i += 1
        state_idx += 2
        continue

    # Get VIOS1 info (original VIOS)
    if (vios == vios1_uuid):
        found_vios1 = 1
        print primary_header
        print divider
        print format %(vios_name_list[i], vios_ip_list[ip_idx], vios_partitionid_list[i], vios_uuid_list[i])
        vios1_name = vios_name_list[i]
        vios1_partitionid = vios_partitionid_list[i]
        vios1_ip = vios_ip_list[ip_idx]

    # Get VIOS2 info (VIOS to take on new clients)
    if (vios == vios2_uuid):
        found_vios2 = 1
        print backup_header
        print divider
        print format %(vios_name_list[i], vios_ip_list[ip_idx], vios_partitionid_list[i], vios_uuid_list[i])
        vios2_name = vios_name_list[i]
        vios2_partitionid = vios_partitionid_list[i]
        vios2_ip = vios_ip_list[ip_idx]

    control_state_idx += 1
    state_idx += 1
    ip_idx += 1
    i += 1

error = 0
if (found_vios1 != 1):
    print "ERROR: Unable to find VIOS with UUID %s" %(vios1_uuid)
    error = 1
if (found_vios2 != 1):
    print "ERROR: Unable to find VIOS with UUID %s" %(vios2_uuid)
    error = 1

if (error == 1):
    sys.exit(2)

remove('vios_info.xml')


#######################################################
# Get UUIDs of all LPARs that belong to the managed
# system that we are interested in
# i.e., they are specified in vios1_xml and vios2_xml
#######################################################
# Get managed system LPAR info, write data to lpar_info.xml
try:
    get_managed_system_lpar(session_key, hmc_ip, managed_system_uuid, 'lpar_info.xml')
except:
    print "ERROR: Request to https://$%s:12443/rest/api/uom/ManagedSystem/$%s/LogicalPartition failed." %(hmc_ip, managed_system_uuid)
    sys.exit(3)


lpar_id = []
lpar_name = []
lpar_uuid = []

# Check for error response in lpar_info.xml
if grep_check('lpar_info.xml', 'HttpErrorResponse'):
    print "ERROR: Request to https://%s:12443/rest/api/uom/ManagedSystem/%s/LogicalPartition returned Error Response." %(hmc_ip, managed_system_uuid)
    print "Unable to detect LPAR information"

# Create list of LPAR partition IDs
lpar_id = grep_array('lpar_info.xml', 'PartitionID')
# Create list of LPAR partition names
lpar_name = grep_array('lpar_info.xml', 'PartitionName')
# Create list of LPAR UUIDs
# skip first element because first <id> tag not relevant
lpar_uuid = grep_array('lpar_info.xml', 'id')
lpar_uuid.pop(0)

# Associative array to map LPAR UUID to its partition name
uuid_to_partname = {}
# Associative array to map LPAR ID to its UUID
id_to_uuid = {}
# Associative array to map LPAR ID to its partition name
id_to_name = {}

write(fd, "\nLPAR information belonging to managed system with UUID %s:\n" %(managed_system_uuid))

# Create associative arrays
i = 0
for lpar in lpar_id:
    uuid_to_partname[lpar_uuid[i]] = lpar_name[i]
    id_to_uuid[lpar_id[i]] = lpar_uuid[i]
    id_to_name[lpar_id[i]] = lpar_name[i]
    i += 1

######################
active_client_id_1 = []
active_client_id_2 = []
active_client_uuid = []
active_client_name = []
diff_clients = []

# Find configured clients of VIOS1
active_client_id_1 = awk('vios1_only.xml', 'ServerAdapter', 'ConnectingPartitionID')
# Find configured clients of VIOS2
active_client_id_2 = awk('vios2_only.xml', 'ServerAdapter', 'ConnectingPartitionID')

# Check that both VIOSes have the same clients
# if they do not, all health-checks will fail and we cannot continue the program
for id in active_client_id_1:
    if (id not in active_client_id_2) and (id not in diff_clients):
        diff_clients.append(id)
diff_clients.sort()

# Check for error response in lpar_info.xml
if grep_check('lpar_info.xml', 'HttpErrorResponse'):
    print "FAIL: Unable to detect active clients"
    num_hc_fail += 1
    hc_fail = 1
elif (len(diff_clients) == 0):
    write(fd, "PASS: Active client lists are the same for both VIOSes")
    active_client_id = active_client_id_1
    num_hc_pass += 1
else:
    print "WARNING: Active client lists are not the same for VIOS1 and VIOS2, check these clients:"
    print diff_clients
    num_hc_fail += 1
    hc_fail = 1

for id in active_client_id:
    active_client_uuid.append(id_to_uuid[id])
    active_client_name.append(id_to_name[id])


header = "LPAR                      ID         UUID                            "
divider = "-------------------------------------------------------------------\n"
format = "%-25s %-10s %-40s"

write(fd, "\nClient Information:\n")
write(fd, header)
write(fd, divider)

# Print active clients, IDs, and UUIDs
for i in range(len(active_client_id)):
    write(fd, format %(active_client_name[i], active_client_id[i], active_client_uuid[i]))
write(fd, "\n")

remove('vios1_only.xml')
remove('vios2_only.xml')
remove('lpar_info.xml')


#######################################################
# VSCSI Mapping for VIOS1
#######################################################
# Create msg.txt
touch('msg.txt')

write(fd, "\nVSCSI MAPPINGS FOR %s:\n" %(vios1_name))

# Get VSCSI info, write data to 'vscsi_mapping.xml'
get_vscsi_info(session_key, hmc_ip, vios1_uuid, 'vscsi_mapping.xml')

# Check for error response in vscsi_mapping.xml
if grep_check('vscsi_mapping.xml', 'HttpErrorResponse'):
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping returned Error Response." %(hmc_ip, vios1_uuid)
    print "ERROR: Unable to detect VSCSI Information"


local_partition_vscsi = []
remote_partition_vscsi = []
local_slot_vscsi = []
remote_slot_vscsi = []
backing_device_vscsi = []

backing_device_type_vscsi = []
backing_device_res_vscsi = []
backing_device_id_vscsi = []

available_disks_1 = []
available_disks_2 = []

disk_info = []

# Grab local partition IDs
local_partition_vscsi = grep_array('vscsi_mapping.xml', 'LocalPartitionID')
# Grab remote partition IDs
remote_partition_vscsi = grep_array('vscsi_mapping.xml', 'RemoteLogicalPartitionID')
# Grab local slot number
local_slot_vscsi= grep_array('vscsi_mapping.xml', 'VirtualSlotNumber')
# Grab remote slot number
remote_slot_vscsi = grep_array('vscsi_mapping.xml', 'RemoteSlotNumber')
# Grab the backup device name
backing_device_vscsi = grep_array('vscsi_mapping.xml', 'BackingDeviceName')

print "Test output: "
print "Local partition VSCSI: %s" %(local_partition_vscsi)
print "Remote partition VSCSI: %s" %(remote_partition_vscsi)
print "Local slot VSCSI: %s" %(local_slot_vscsi)
print "Remote slot VSCSI: %s" %(remote_slot_vscsi)
print "Backing device VSCSI: %s\n" %(backing_device_vscsi)

# Parse for backup device info
tree = ET.ElementTree(file='vscsi_mapping.xml')
iter_ = tree.getiterator()
for elem in iter_:
    if ( re.sub(r'{[^>]*}', "", elem.tag) == 'Storage'):
        elem_child = elem.getchildren()
        for child in elem_child:
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'PhysicalVolume'):
                disk_type = "PhysicalVolume"
                print disk_type
                disk_info.append(disk_type)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'VirtualDisk'):
                disk_type = "LogicalVolume"
                print disk_type
                res_pol = "None"
                print res_pol
                disk_info.append(disk_type)
                disk_info.append(res_pol)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'ReservePolicy'):
                res_pol = re.sub(r'<[^>]*>', "", child.text)
                print res_pol
                disk_info.append(res_pol)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'UniqueDeviceID'):
                udid = re.sub(r'<[^>]*>', "", child.text)
                print udid
                disk_info.append(udid)

# Backing device vscsi attributes
i = 0
while (i < len(disk_info)):
    backing_device_type_vscsi.append(disk_info[i])
    backing_device_res_vscsi.append(disk_info[i+1])
    backing_device_id_vscsi.append(disk_info[i+2])
    i += 3

if (len(backing_device_id_vscsi) == 0):
    print "WARNING: no disks configured with this system\n"

i = 0 # index for looping through all partition mappings
j = 0 # index for looping through backing devices

vscsi_header = "Device Name     UDID                                                                    Disk Type           Reserve Policy      "
divider = "---------------------------------------------------------------------------------------------------------------------------\n"
format = "%-15s %-75s %-20s %-20s \n"
write(fd, vscsi_header)
write(fd, divider)


msg_txt = open('msg.txt', 'w+')
for partition in local_partition_vscsi:
    if (partition == vios1_partitionid):
        # ssh into VIOS1 to make sure we can open disk
        try:
            cmd = "ssh padmin@%s \"print '< /dev/%s' | oem_setup_env\"" %(vios1_ip, backing_device_vscsi[j])
            os.popen(cmd)
        except:
            print "ERROR: health check failed, cannot open disk"

        if (backing_device_res_vscsi[j] == "SinglePath"):
            msg = "WARNING: You have single path for %s on VIOS %s which is likely an issue" %(backing_device_vscsi[j], vios1_name)
            print msg
            msg_txt.write(msg)
        elif (backing_device_type_vscsi[j] == "Other"):
            msg = "WARNING: %s is not supported by both VIOSes because it is of type %s" %(backing_device_vscsi[j], backing_device_type_vscsi[j])
            print msg
            msg_txt.write(msg)
        elif (backing_device_type_vscsi[j] == "LogicalVolume"):
            msg = "WARNING: This program cannot guarantee that the data in this %s is accessible via both VIOSes" %(backing_device_vscsi[j])
            print msg
            msg_txt.write(msg)
        else:
            available_disks_1.append(backing_device_id_vscsi[j])
        write(fd, format %(backing_device_vscsi[j], backing_device_id_vscsi[j], backing_device_type_vscsi[j], backing_device_res_vscsi[j]))
        j += 1
    i += 1

msg_txt = open('msg.txt', 'r')
print msg_txt.read()

remove('vscsi_mapping.xml')
remove('msg.txt')


#######################################################
# VSCSI Mapping for VIOS2
#######################################################
# Clear arrays before using again
del local_partition_vscsi[:]
del remote_partition_vscsi[:]
del local_slot_vscsi[:]
del remote_slot_vscsi[:]
del backing_device_vscsi[:]

del backing_device_type_vscsi[:]
del backing_device_res_vscsi[:]
del backing_device_id_vscsi[:]

del disk_info[:]

diff_disks = []

# Create msg.txt
touch('msg.txt')

write(fd, "\nVSCSI MAPPINGS FOR %s:" %(vios2_name))

# Get VSCSI info, write data to 'vscsi_mapping.xml'
get_vscsi_info(session_key, hmc_ip, vios2_uuid, 'vscsi_mapping.xml')

# Check for error response
if grep_check('vscsi_mapping.xml', 'HttpErrorResponse'):
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping returned Error Response." %(hmc_ip, vios1_uuid)
    print "Unable to detect VSCSI Information"

# Grab local partition IDs
local_partition_vscsi = grep_array('vscsi_mapping.xml', 'LocalPartitionID')
# Grab remote partition IDs
remote_partition_vscsi = grep_array('vscsi_mapping.xml', 'RemoteLogicalPartitionID')
# Grab local slot number
local_slot_vscsi= grep_array('vscsi_mapping.xml', 'VirtualSlotNumber')
# Grab remote slot number
remote_slot_vscsi = grep_array('vscsi_mapping.xml', 'RemoteSlotNumber')
# Grab the backup device name
backing_device_vscsi = grep_array('vscsi_mapping.xml', 'BackingDeviceName')

print "Local partition VSCSI: %s" %(local_partition_vscsi)
print "Remote partition VSCSI: %s" %(remote_partition_vscsi)
print "Local slot VSCSI: %s" %(local_slot_vscsi)
print "Remote slot VSCSI: %s" %(remote_slot_vscsi)
print "Backing device VSCSI: %s\n" %(backing_device_vscsi)

# Parse for backup device info
tree = ET.ElementTree(file='vscsi_mapping.xml')
iter_ = tree.getiterator()
for elem in iter_:
    if ( re.sub(r'{[^>]*}', "", elem.tag) == 'Storage'):
        elem_child = elem.getchildren()
        for child in elem_child:
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'PhysicalVolume'):
                disk_type = "PhysicalVolume"
                print disk_type
                disk_info.append(disk_type)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'VirtualDisk'):
                disk_type = "LogicalVolume"
                print disk_type
                res_pol = "None"
                print res_pol
                disk_info.append(disk_type)
                disk_info.append(res_pol)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'ReservePolicy'):
                res_pol = re.sub(r'<[^>]*>', "", child.text)
                print res_pol
                disk_info.append(res_pol)
            if ( re.sub(r'{[^>]*}', "", child.tag) == 'UniqueDeviceID'):
                udid = re.sub(r'<[^>]*>', "", child.text)
                print udid
                disk_info.append(udid)

# Backing device vscsi attributes
i = 0

while (i < len(disk_info)):
    backing_device_type_vscsi.append(disk_info[i])
    backing_device_res_vscsi.append(disk_info[i+1])
    backing_device_id_vscsi.append(disk_info[i+2])
    i += 3

if (len(backing_device_id_vscsi) == 0):
    print "WARNING: no disks configured with this system\n"

i = 0 # index for looping through all partition mappings
j = 0 # index for looping through backing devices

vscsi_header = "Device Name     UDID                                                                    Disk Type           Reserve Policy      "
divider = "---------------------------------------------------------------------------------------------------------------------------\n"
format = "%-15s %-75s %-20s %-20s \n"
write(fd, vscsi_header)
write(fd, divider)


msg_txt = open('msg.txt', 'w+')
for partition in local_partition_vscsi:
    if (partition == vios2_partitionid):
        # ssh into VIOS2 to make sure we can open disk
        try:
            cmd = "ssh padmin@%s \"print '< /dev/%s' | oem_setup_env\"" %(vios2_ip, backing_device_vscsi[j])
            os.popen(cmd)
        except:
            print "ERROR: health check failed, cannot open disk"

        if (backing_device_res_vscsi[j] == "SinglePath"):
            msg = "WARNING: You have single path for %s on VIOS %s which is likely an issue" %(backing_device_vscsi[j], vios1_name)
            print msg
            msg_txt.write(msg)
        elif (backing_device_type_vscsi[j] == "Other"):
            msg = "WARNING: %s is not supported by both VIOSes because it is of type %s" %(backing_device_vscsi[j], backing_device_type_vscsi[j])
            print msg
            msg_txt.write(msg)
        elif (backing_device_type_vscsi[j] == "LogicalVolume"):
            msg = "WARNING: This program cannot guarantee that the data in this %s is accessible via both VIOSes" %(backing_device_vscsi[j])
            print msg
            msg_txt.write(msg)
        else:
            available_disks_2.append(backing_device_id_vscsi[j])
        write(fd, format %(backing_device_vscsi[j], backing_device_id_vscsi[j], backing_device_type_vscsi[j], backing_device_res_vscsi[j]))
        j += 1
    i += 1

msg_txt = open('msg.txt', 'r')
print msg_txt.read()

#Check to see if any disks are different
for disk in available_disks_1:
    if (disk not in available_disks_2) and (disk not in diff_disks):
        diff_disks.append(disk)
diff_disks.sort()

###########
if (len(diff_disks) == 0):
    write(fd, "\nVSCSI VALIDATION")
    write(fd, "PASS: same configuration")
    num_hc_pass += 1
else:
    print "FAIL: configurations are not the same, check these disks:"
    print diff_disks
    num_hc_fail += 1
    hc_fail = 1

remove('vscsi_mapping.xml')
remove('msg.txt')


#######################################################
# Fibre Channel Mapping for VIOS1
#######################################################
write(fd, "\nFC MAPPINGS for %s:\n" %(vios1_name))

# Find VIOS fibre channel mappings, write data to fc_mapping.xml
try:
    get_fc_mapping_vios(session_key, hmc_ip, vios1_uuid, 'fc_mapping.xml')
except:
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosFCMapping failed." %(hmc_ip, vios1_uuid)
    sys.exit(3)


local_partition_fc = []
remote_partition_fc = []
local_slot_fc = []
remote_slot_fc = []

# Get local partition IDs
local_partition_fc = grep_array('fc_mapping.xml', 'LocalPartitionID')
# Get remote partition IDs
remote_partition_fc = grep_array('fc_mapping.xml', 'ConnectingPartitionID')
# Get local slot number
local_slot_fc = grep_array('fc_mapping.xml', 'VirtualSlotNumber')
# Get remote slot number
remote_slot_fc = grep_array('fc_mapping.xml', 'ConnectingVirtualSlotNumber')

i = 0 # index for looping through all partition mappings

fc_header="VIOS Name            Slot       Client              "
divider="-------------------------------------------------\n"
format="%-20s %-10s %-20s "
write(fd, fc_header)
write(fd, divider)

for partition in local_partition_fc:
    if (partition == vios1_partitionid):
        write(fd, format %(vios1_name, local_slot_fc[i], id_to_name[remote_partition_fc[i]]))
    i += 1
write(fd, "\n")

remove('fc_mapping.xml')


#######################################################
# Fibre Channel Mapping for VIOS2
#######################################################
write(fd, "\nFC MAPPINGS for %s:\n" %(vios2_name))

# Find VIOS fibre channel mappings, write data to fc_mapping.xml
try:
    get_fc_mapping_vios(session_key, hmc_ip, vios2_uuid, 'fc_mapping.xml')
except:
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosFCMapping failed." %(hmc_ip, vios2_uuid)
    sys.exit(3)

# Clear arrays before using again
del local_partition_fc[:]
del remote_partition_fc[:]
del local_slot_fc[:]
del remote_slot_fc[:]

# Get local partition IDs
local_partition_fc = grep_array('fc_mapping.xml', 'LocalPartitionID')
# Get remote partition IDs
remote_partition_fc = grep_array('fc_mapping.xml', 'ConnectingPartitionID')
# Get local slot number
local_slot_fc = grep_array('fc_mapping.xml', 'VirtualSlotNumber')
# Get remote slot number
remote_slot_fc = grep_array('fc_mapping.xml', 'ConnectingVirtualSlotNumber')


i = 0 # index for looping through all partition mappings

fc_header="VIOS Name            Slot       Client              "
divider="-------------------------------------------------\n"
format="%-20s %-10s %-20s "
write(fd, fc_header)
write(fd, divider)

for partition in local_partition_fc:
    if (partition == vios2_partitionid):
        write(fd, format %(vios2_name, local_slot_fc[i], id_to_name[remote_partition_fc[i]]))
    i += 1
write(fd, "\n")

remove('fc_mapping.xml')


#######################################################
#NPIV PATH VALIDATION
#######################################################
# In order to do this step, we need to generate a pair of authentication keys to
# allow for automatic login without having to sign in to other vios
# path validation

###########
# cannot get data for fc_mapping2
# 204 no content response
###########

fc_ids = []
drc_list = []
WWPN_list = []

write(fd, "\nNPIV Path Validation:\n")

for lpar in active_client_uuid:
    # Get LPAR info, write data to fc_mapping2.xml
    try:
        get_lpar_info(session_key, hmc_ip, lpar, 'fc_mapping2.xml')
    except:
        print "ERROR: Request to https://%s:12443/rest/api/uom/LogicalPartition/%s/VirtualFibreChannelClientAdapter failed." %(hmc_ip, lpar)
        sys.exit(3)

    #Create a list of fibre channel IDs
    fc_ids = grep_array('fc_mapping2.xml', 'LocalPartitionID')
    #Create a list of dynamic reconfiguration connectors
    drc_list = grep_array('fc_mapping2.xml', 'DynamicReconfigurationConnectorName')
    # Create a list of WWPN
    WWPN_list = grep_array('fc_mapping2.xml', 'WWPN')

    # Process two at a time, so i and j are both counters
    j = 0

    notzoned_value1 = ""
    notzoned_value2 = ""

    # Check for path validation by running mig_vscsi to check for notzoned tag
    touch('adapter_info1.xml')
    touch('adapter_info2.xml')

    # Cannot get mig_vscsi to stdout so need to use another file to get info
    for partition_id in fc_ids:
        adapter1_xml = open('adapter_info1.xml', 'r')
        adapter2_xml = open('adapter_info2.xml', 'r')

        if (vios1_partitionid == partition_id):
            lower_WWPN = WWPN_list[j]
            j += 1  # get the higher WWPN
            higher_WWPN = WWPN_list[j]
            DRC = drc_list[j]
            j += 1 # one more increment bc we skip clients, and drc_list repeats itself twice

            # ssh to both, get notzoned info, check to see if false
            cmd = 'ssh padmin@%s "echo /usr/lib/methods/mig_vscsi -f get_adapter -t vscsi -s %s -a ACTIVE_LPM -c RPA  -M 1 -d 5 -W 0x%s -w 0x%s -F %s | ioscli oem_setup_env " 1>/dev/null 2>&1' %(vios1_ip, DRC, lower_WWPN, higher_WWPN, adapter1_xml)
            os.system(cmd)
            cmd = 'ssh padmin@%s "cat %s" > /tmp/adapter1.xml' %(vios1_ip, adapter1_xml)
            os.system(cmd)

            if os.path.exists('adapter1.xml'):
                notzoned_value1 = grep('adapter1.xml', 'notZoned')

        if (vios2_partitionid == partition_id):
            lower_WWPN = WWPN_list[j]
            j += 1 # get the higher WWPN
            higher_WWPN = WWPN_list[j]
            DRC = drc_list[j]
            j += 1 # one more increment bc we skip clients, and drc_list repeats itself twice
            # ssh to both, get notzoned info, check to see if false
            cmd = 'ssh padmin@%s "echo /usr/lib/methods/mig_vscsi -f get_adapter -t vscsi -s %s -a ACTIVE_LPM -c RPA  -M 1 -d 5 -W 0x%s -w 0x%s -F %s | ioscli oem_setup_env" 1>/dev/null 2>&1' %(vios2_ip, DRC, lower_WWPN, higher_WWPN, adapter2_xml)
            os.system(cmd)
            cmd = 'ssh padmin@%s "cat %s" > /tmp/adapter2.xml' %(vios2_ip, adapter2_xml)
            os.system(cmd)

            if os.path.exists('adapter2.xml'):
                notzoned_value1 = grep('adapter1.xml', 'notZoned')

        if ((notzoned_value1 == "false") and (notzoned_value2 == "false")):
            print "PASS: %s has a path through both VIOSes" %(uuid_to_partname[lpar])
            num_hc_pass += 1
        else:
            print "FAIL: %s doesn't have a path through both VIOSes" %(uuid_to_partname[lpar])
            hc_fail = 1
            num_hc_fail += 1

        adapter1_xml.close()
        adapter2_xml.close()


#######################################################
# Checking if SEA is configured for VIOSes
#######################################################
write(fd, "\nSEA VALIDATION: \n")

# Check each VIOS UUID and see if we can grab the <SharedEthernetAdapters tag
# this means that SEA is configured
write(fd, "Checking to see if SEA is configured for VIOS:\n")

# Get network info for VIOS1, write to network1.xml
try:
    get_network_info(session_key, hmc_ip, vios1_uuid, 'network1.xml')
except:
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosNetwork failed." %(hmc_ip, vios1_uuid)
    sys.exit(3)

# Check VIOS1 for SEA
if grep_check('network1.xml', 'SharedEthernetAdapters'):
    write(fd, "PASS: SEA is configured for %s" %(vios1_name))
    num_hc_pass += 1
else:
    print "FAIL: SEA is not configured for %s" %vios1_name
    num_hc_fail += 1
    hc_fail = 1


# Get network info for VIOS2, write to network2.xml
try:
    get_network_info(session_key, hmc_ip, vios2_uuid, 'network2.xml')
except:
    print "ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosNetwork failed." %(hmc_ip, vios2_uuid)
    sys.exit(3)

# Check VIOS2 for SEA
if grep_check('network2.xml', 'SharedEthernetAdapters'):
    write(fd, "PASS: SEA is configured for %s\n" %(vios2_name))
    num_hc_pass += 1
else:
    print "FAIL: SEA is not configured for %s\n" %vios2_name
    num_hc_fail += 1
    hc_fail = 1


#######################################################
# SEA Validation
#######################################################
vios1_state = ""
vios2_state = ""

header = "Name                      High Availability Mode           "
divider = "------------------------------------------------\n"
format = "%-25s %-25s "

write(fd, header)
write(fd, divider)

# Check for high availability mode for each vios
vios1_ha = grep('network1.xml', 'HighAvailabilityMode')
if (vios1_ha == ""):
    print "FAIL: Unable to detect High Availability Mode for VIOS %s" %(vios1_name)
    hc_fail = 1
    num_hc_fail += 1
else:
    write(fd, format %(vios1_name, vios1_ha))

vios2_ha = grep('network2.xml', 'HighAvailabilityMode')
if (vios2_ha == ""):
    print "FAIL: Unable to detect High Availability Mode for VIOS %s" %(vios2_name)
    hc_fail = 1
    num_hc_fail += 1
else:
    write(fd, format %(vios2_name, vios2_ha))
write(fd, "\n")

# Get the SEA device names for the VIOS
tree = ET.ElementTree(file='network1.xml')
iter_ = tree.getiterator()
for elem in iter_:
    if ( re.sub(r'{[^>]*}', "", elem.tag) == 'DeviceName'):
        if ((elem.get('kxe') == "false") and (elem.get('kb') == "CUD")):
            vios1_SEA = elem.text
tree = ET.ElementTree(file='network2.xml')
iter_ = tree.getiterator()
for elem in iter_:
    if ( re.sub(r'{[^>]*}', "", elem.tag) == 'DeviceName'):
        if ((elem.get('kxe') == "false") and (elem.get('kb') == "CUD")):
            vios2_SEA = elem.text

# If ha_mode is auto we use entstat and grab the states
if (vios1_ha == "auto"):
    # ssh into vios1
    cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh %s.aus.stglabs.ibm.com \"/bin/entstat -d ent7\" | grep '    State:' | sed -e 's/  State://g' |  sed -e 's/ //g'" %(vios1_name)
    vios1_state = os.popen(cmd).read()
    write(fd, "VIOS1 %s state: %s" %(vios1_SEA, vios1_state))

if (vios2_ha == "auto"):
    # ssh into vios2
    cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh %s.aus.stglabs.ibm.com \"/bin/entstat -d ent7\" | grep '    State:' | sed -e 's/  State://g' |  sed -e 's/ //g'" %(vios2_name)
    vios2_state = os.popen(cmd).read()
    write(fd, "VIOS2 %s state: %s" %(vios2_SEA, vios2_state))


header = "VIOS                 SEA Device Name           State "
divider = "------------------------------------------------------\n"
format = "%-20s %-25s %-15s \n"

write(fd, header)
write(fd, divider)
write(fd, format %(vios1_name, vios1_SEA, vios1_state))
write(fd, format %(vios2_name, vios2_SEA, vios2_state))

if (vios1_state == "STANDBY"):
    print "WARNING: VIOS1 State should be BACKUP instead of STANDBY"
if (vios2_state == "STANDBY"):
    print "WARNING: VIOS2 State should be BACKUP instead of STANDBY"

# Pass conditions
if ((vios1_state == "PRIMARY") and (vios2_state == "BACKUP")):
    write(fd, "PASS: SEA is configured for failover")
    num_hc_pass += 1
elif ((vios2_state == "PRIMARY") and (vios1_state == "BACKUP")):
    write(fd, "PASS: SEA is configured for failover")
    num_hc_pass += 1
elif ((vios2_state == "PRIMARY") and (vios1_state == "STANDBY")):
    write(fd, "PASS: SEA is configured for failover")
    num_hc_pass += 1
elif ((vios1_state == "PRIMARY") and (vios2_state == "STANDBY")):
    write(fd, "PASS: SEA is configured for failover")
    num_hc_pass += 1

# Fail conditions
if ((vios1_state == "PRIMARY") and (vios2_state == "PRIMARY")):
    print "FAIL: SEA states for both VIOS cannot be PRIMARY, change one to BACKUP with the chdev command"
    hc_fail = 1
    num_hc_fail += 1

if ((vios1_state == "BACKUP") and (vios2_state == "BACKUP")):
    print "FAIL: SEA states for both VIOS cannot be BACKUP, change one to PRIMARY with the chdev command"
    hc_fail = 1
    num_hc_fail += 1

if ((vios1_state == "STANDBY") and (vios2_state == "STANDBY")):
    print "FAIL: SEA states for both VIOS cannot be STANDBY, change one to PRIMARY and the other to BACKUP with the chdev command"
    hc_fail = 1
    num_hc_fail += 1

remove('network1.xml')
remove('network2.xml')


#######################################################
# VNIC Validation with REST API
#######################################################

# Create vnic_fails.txt
touch('vnic_fails.txt')

# Create fail_msg and vnic_xml
vnic_fail_flag = 0
vnic_configured = 0

write(fd, "\nVNIC Validation:\n")

for uuid in active_client_uuid:
    # Get VNIC info, write data to vnic_info.xml
    get_vnic_info(session_key, hmc_ip, uuid, 'vnic_info.xml')

    # grep_devnull
    if grep_check('vnic_info.xml', '200 OK'):
        vnic_configured = 1
        break

# If a VNIC configuration is detected, perform the validation
if (vnic_configured == 1):
    header = "Client Name           Client ID       VIOS1 VNIC Server           VIOS2 VNIC Server"
    divider = "---------------------------------------------------------------------------------------\n"
    format = "%-20s %-15s %-27s %-27s \n"
    write(fd, header)
    write(fd, divider)

    i = 0
    for uuid in active_client_uuid:
        vios1_associated = "DISCONNECTED"
        vios2_associated = "DISCONNECTED"

        # Get VNIC info, write data to vnic_info.xml
        get_vnic_info(session_key, hmc_ip, uuid, 'vnic_info.xml')

        # Check to see if VNIC Server on VIOS1 is associated
        associated_vios = grep_array('vnic_info.xml', 'AssociatedVirtualIOServer')
        for vios in associated_vios:
            if vios1_uuid in vios:
                vios1_associated = "CONNECTED"
            if vios2_uuid in vios:
                vios2_associated = "CONNECTED"

        write(fd, format %(active_client_name[i], active_client_id[i], vios1_associated, vios2_associated))
        print "\n"
        if (vios1_associated == "DISCONNECTED"):
            print "FAIL: %s is not connected with VIOS1 VNIC Server" %(active_client_name[i])
            vnic_fail_flag = 1
            hc_fail = 1
            num_hc_fail += 1
        if (vios2_associated == "DISCONNECTED"):
            print "FAIL: %s is not connected with VIOS2 VNIC Server" %(active_client_name[i])
            vnic_fail_flag = 1
            hc_fail = 1
            num_hc_fail += 1

        vios1_associated = 0
        vios2_associated = 0
        i += 1

    if (vnic_fail_flag == 0):
        write(fd, "PASS: VNIC Configuration is Correct")
        num_hc_pass += 1
    else:
        fail_msg = open('vnic_fails.txt', 'r')
        content = fail_msg.read()
        print content

# VNIC not configured
else:
    print "VNIC Configuration Not Detected"

remove('vnic_fails.txt')
remove('vnic.xml')


#######################################################
# End of Health Checks
#######################################################

# Perform analysis on Pass and Fails
total_hc = num_hc_fail + num_hc_pass
pass_pct = num_hc_pass * 100 / total_hc
print "\n%d of %d Health Checks Passed\n" %(num_hc_pass, total_hc)
print "%d of %d Health Checks Failed\n" %(num_hc_fail, total_hc)
print "Pass rate of %d\%\n" %(pass_pct)

os.close(fd)

# Should exit 0 if all health checks pass, exit 1 if any health check fails
sys.exit(hc_fail)
