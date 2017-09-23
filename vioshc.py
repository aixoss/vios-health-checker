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
import subprocess
import fileinput
import re
import pycurl
import xml.etree.cElementTree as ET
import socket
import cStringIO


#######################################################
# Initialize variables
#######################################################
# Constants
LOG_DIR = "/tmp"
C_RSH = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh"

action = ""     # (user provided -l present?)
list_arg = ""   # (user provided -l)

# Target HMC
hmc_ip = ""         # (user provided)
hmc_user_id = ""    # (user provided -u or retrieved)
hmc_password = ""   # (user provided -p or retrieved)
hmc_info = {}

# Dual VIOS pair
vios_info = {}
vios1_name = ""
vios2_name = ""
vios_num = 0        # number of vios uuid provided (-U option)
vios1_uuid = ""     # (user provided -U)
vios2_uuid = ""     # (user provided -U)
managed_system_uuid = ""    # (user provided -m)

# Flags & Counters used by program
rc = 0
verbose = 0         # (user provided -v)
num_hc_fail = 0
num_hc_pass = 0
total_hc = 0

# File name
filename_session_key = 'sessionkey.xml'
filename_systems = 'systems.xml'
filename_vios1 = 'vios1_only.xml'   # check managed_system_discovery() if you change this
filename_vios2 = 'vios2_only.xml'   # check managed_system_discovery() if you change this
filename_lpar_info = 'lpar_info.xml'
filename_vscsi_mapping1 = 'vios1_vscsi_mapping.xml'
filename_vscsi_mapping2 = 'vios2_vscsi_mapping.xml'
filename_fc_mapping1 = 'vios1_fc_mapping.xml'
filename_fc_mapping2 = 'vios2_fc_mapping.xml'
filename_npiv_mapping = 'npiv_mapping.xml'
filename_adapter1 = 'adapter1_info.xml'
filename_adapter2 = 'adapter2_info.xml'
filename_network1 = 'network1.xml'
filename_network2 = 'network2.xml'
filename_sea1 = 'sea1.xml'
filename_sea2 = 'sea2.xml'
filename_vnic_info = 'vnic_info.xml'
filename_msg = 'msg.txt'

#######################################################
# Define functions
#######################################################
### File manipulation functions ###

# Create file
def touch(path):
    log("creating file: %s\n" %(path))
    try:
        open(path, 'a')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)
    os.utime(path, None)

# Log function
def log(txt):
    global log_file
    log_file.write(txt)

# Write txt into log file and if verbose into stdout
# set lvl to 0 to always print out: ERROR, WARNING, etc.
def write(txt, lvl=1):
    global verbose
    log(txt + "\n")
    if verbose >= lvl:
        print txt

# Remove file under tmp directory
def remove(path):
    try:
        log("removing file: %s\n" %(path))
        if os.path.exists(path):
            log("")
            #os.remove(path)
        else:
            log("file %s does not exists.\n" %(path))
    except OSError, e:
        write("ERROR: Failed to remove file %s: %s." %(e.filename, e.strerror), lvl=0)

# Remove extra headers from top of XML file
def format_xml_file(filename):
    try:
        log("reading file: %s\n" %(filename))
        f = open(filename, 'r+')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)
    lines = f.readlines()
    f.seek(0)
    start_writing = False
    for i in lines:
        if i[0] == '<':
            start_writing = True
        if start_writing:
            f.write(i)
    f.truncate()
    f.close()

### Remote command execution functions ###
def exec_cmd(cmd):
    """
    Execute the given command
    return
        - ret_code  (return code of the command)
        - output   stdout and stderr of the command
    """
    rc = 0
    output = ''
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT) 

    except subprocess.CalledProcessError as exc:
        output = exc.output
        rc = exc.returncode
        write('Command: {} failed: {}'.format(cmd, exc.output))

    except Exception as exc:
        output = exc.args
        rc = 1
        write('Command: {} failed: {}'.format(cmd, exc.args))

    # TBC - uncomment for debug
    log('command {} returned [rc:{} output:{}]\n'.format(cmd, rc, output))

    return (rc, output)

### Interfacing functions ###

# Takes in the hmc internet address and tries to
# retrieve the username and password
# Input: (str) hmc internet address
# Output: (str) username and password
def retrieve_usr_pass(hmc_info):
    if hmc_info is None or 'type' not in hmc_info or 'passwd_file' not in hmc_info:
        write("ERROR: Failed to retrieve user ID and password for %s" %(hmc_info['hostname']), lvl=0)
        return ("", "")

    decrypt_file = get_decrypt_file(hmc_info['passwd_file'],
                                    hmc_info['type'],
                                    hmc_info['hostname'])
    if decrypt_file != "":
        (user, passwd) = get_usr_passwd(decrypt_file)
        remove(decrypt_file)
    return (user, passwd)

# Return a hash with NIM info
# the associated value can be a list
def get_nim_info(obj_name):
    info = {}
    
    cmd = ["/usr/sbin/lsnim", "-l", obj_name]
    (rc, output) = exec_cmd(cmd)
    if rc != 0:
        write("ERROR: Failed to get %s NIM info: %s" %(obj_name, output), lvl=0)
        return None

    for line in output.split('\n'):
        match = re.match('^\s*(\S+)\s*=\s*(\S+)\s*$', line)
        if match:
            if match.group(1) not in info:
                info[match.group(1)] = match.group(2)
            else:
                info[match.group(1)] = [info[match.group(1)]]
                info[match.group(1)].append(match.group(2))
    return info

def get_nim_name(hostname):
    name = ""

    cmd =["lsnim", "-a", "if1"]
    (rc, output) = exec_cmd(cmd)
    if rc != 0:
        write("ERROR: Failed to get NIM name for %s: %s" %(hostname, output), lvl=0)
        return ""

    for line in output.split('\n'):
        match = re.match('^\s*(\S+)\s*:\s*$', line)
        if match:
            name = match.group(1)
            continue
        match = re.match('^\s*if1\s*=\s*\S+\s+(\S+).*$', line)
        if match and match.group(1) != hostname:
            name = ""
            continue
        else:
            break
    if name == "":
        write("ERROR: Failed to get NIM name for %s: Not Found" %(hostname), lvl=0)
    return name

# Return a triple (hostname, aliaslist, ipaddrlist) from either IP address
# or hostname.
# - hostname is the primary host name responding to the given ip_address,
# - aliaslist is a list of alternative host names for the same address (can be empty)
# - ipaddrlist is a list of IPv4 addresses for the same interface on the same host
def get_hostname(host):
    try:
        match_key = re.match('^\d+.*$', host)
        if match_key:
            return socket.gethostbyaddr(host)
        else:
            return socket.gethostbyname_ex(host)
    except OSError, e:
        write("ERROR: Failed to get hostname for %s: %d %s." %(host, e.errno, e.strerror), lvl=0)
        sys.exit(3)

# Takes in the encrypted password file and decrypts it
# Input: (str) password file, mananged type, managed hostname
# Output: (str) decrypted file
def get_decrypt_file(passwd_file, type, hostname):
    log("getting %s file for %s %s\n" %(passwd_file, type, hostname))
    path = ""

    cmd =["/usr/bin/dkeyexch", "-f", passwd_file, "-I", type, "-H", hostname, "-S"]
    (rc, output) = exec_cmd(cmd)
    if rc != 0:
        write("ERROR: Failed to get the encrypted password file path for %s: %s" %(hostname, output), lvl=0)
        return ""

    # dkeyexch output is like:
    # OpenSSH_6.0p1, OpenSSL 1.0.2h  3 May 2016
    # /var/ibm/sysmgt/dsm/tmp/dsm1608597933307771402.tmp
    return output.rstrip().split('\n')[1]

# Reads the decrypted file and returns the username and password
# Input: (str) decrypted file
# Output: (str) username and password
def get_usr_passwd(decrypt_file):
    try:
        log("reading file: %s\n" %(decrypt_file))
        f = open(decrypt_file, 'r')
    except IOError, e:
        write("ERROR: Failed to open file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)
    arr = f.read().split(' ')
    f.close()
    return arr

# Takes in XML file of managed systems, parsing it and
# retrieving Managed system and VIOS UUIDs and Machine SerialNumber
# Input: XML file of managed systems, hmc hash
# Output: dict of mapped managed systems to thier SerialNumbers and VIOS
def managed_system_discovery(xml_file, hmc_info):
    vios_arr = [] # list of all vios UUIDs
    m = {} # managed system to vios mapping
    managed_system = "" # string to hold current managed system being searched

    tree = ET.ElementTree(file=xml_file)

    # Map managed system UUIDs to serial numbers
    iter_ = tree.getiterator()
    for elem in iter_:
        # Retrieving the current Managed System
        if re.sub(r'{[^>]*}', "", elem.tag) == "entry":
            elem_child = elem.getchildren()
            for child in elem_child:
                if re.sub(r'{[^>]*}', "", child.tag) == "id":
                    if child.text in m:
                        continue
                    else:
                        m[child.text] = []
                        managed_system = child.text

        # Retrieving the current Managed System Serial
        if re.sub(r'{[^>]*}', "", elem.tag) == "MachineTypeModelAndSerialNumber":
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
        if re.sub(r'{[^>]*}', "", elem.tag) == "AssociatedVirtualIOServers":
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
        rc = get_vios_info(hmc_info, uuid, filename)
        if rc != 0:
            write("ERROR: Failed to get VIOS information %s: %s." %(filename, rc[1]), lvl=0)
            sys.exit(3)

        # Parse file for partition IDs
        tree = ET.ElementTree(file=filename)
        iter_ = tree.getiterator()
        for elem in iter_:
            vios_part[uuid] = "Not found"
            if re.sub(r'{[^>]*}', "", elem.tag) == "PartitionID":
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
def get_session_key(hmc_info, filename):
    s_key = ""
    try:
        log("writing file: %s\n" %(filename))
        f = open(filename, 'wb')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)

    url = "https://%s:12443/rest/api/web/Logon" %(hmc_info['hostname'])
    fields = '<LogonRequest schemaVersion=\"V1_0\" xmlns=\"http://www.ibm.com/xmlns/systems/power/firmware/web/mc/2012_10/\"  xmlns:mc=\"http://www.ibm.com/xmlns/systems/power/firmware/web/mc/2012_10/\"> <UserID>%s</UserID> <Password>%s</Password></LogonRequest>' %(hmc_info['user_id'], hmc_info['user_password'])
    hdrs = ['Content-Type: application/vnd.ibm.powervm.web+xml; type=LogonRequest']

    log("curl request on: %s\n" %(url))
    try:
        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.CUSTOMREQUEST, "PUT")
        c.setopt(c.POST, 1)
        c.setopt(c.POSTFIELDS, fields)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.perform()
    except pycurl.error, (errno, strerror):
        write("ERROR: Curl request failed: %s" %(strerror), lvl=0)
        return ""

    # Reopen the file in text mode
    f.close()
    try:
        log("reading file: %s\n" %(filename))
        f = open(filename, 'r')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)

    # Isolate session key
    for line in f:
        if re.search('<X-API-Session', line) != None:
            s_key = re.sub(r'<[^>]*>', "", line)

    return s_key.strip()

# Given a corresponding flag, it will print out managed system
# and vios UUIDs
# Input: HMC IP address, session key, argument flag
# Output: None
def print_uuid(hmc_info, arg, filename):

    log("print_uuid: arg=%s\n" %(arg))
    rc = 0

    url = "https://%s:12443/rest/api/uom/ManagedSystem" %(hmc_info['hostname'])
    rc = curl_request(hmc_info['session_key'], url, filename)
    if rc != 0:
        write("ERROR: Cannot get session key for '%s': %s" %(hmc_info['hostname'], rc[1]), lvl=0)
        remove(filename)
        return rc[0]


    # Mapped managed systems
    m, vios_part = managed_system_discovery(filename, sess_key, hmc_info)

    if arg == 'm':
        # Print only managed systems
        write("\nManaged Systems UUIDs                   Serial", lvl=0)
        write("-" * 37 + "\t" + "-"*22, lvl=0)
        for key, values in m.iteritems():
            write(key + "\t" + ''.join(values[0]) + "\n", lvl=0)

    elif arg == 'a':
        write("\nManaged Systems UUIDs                   Serial", lvl=0)
        write("-" * 37 + "\t" + "-"*22, lvl=0)
        for key, values in m.iteritems():
            write(key + "\t" + ''.join(values[0]) + "\n", lvl=0)
            write("\tVIOS                                    Partition ID", lvl=0)
            write("\t" + "-" * 37 + "\t" + "-" * 14, lvl=0)
            for v in values[1:]:
                write("\t" + v + "\t" + vios_part[v], lvl=0)
            write("\n", lvl=0)

    else:
        # should never happen as checked in main
        write("ERROR: Invalid argument '%s' for print_uuid." %(arg), lvl=0)
        rc = 2

    # Clean up
    remove(filename)

    return rc


### Parsing functions ###

# Parse through xml to find tag value
# Inputs: file name, tag
# Output: value
def grep(filename, tag):
    format_xml_file(filename)
    tree = ET.ElementTree(file=filename)
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == tag:
            return elem.text
    return ""

# Parse through xml file to create list of tag values
# Inputs: file name, tag
# Output: array of values corresponding to given tag
def grep_array(filename, tag):
    format_xml_file(filename)
    arr = []
    try:
        tree = ET.ElementTree(file=filename)
    except:
        return arr
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == tag:
            arr.append(elem.text)
    return arr

# Checks for existence of tag in file
# Inputs: file name, tag
# Output: True if tag exists, False otherwise
def grep_check(filename, tag):
    #format_xml_file(filename)
    found = False
    try:
        tree = ET.ElementTree(file=filename)
    except:
        return found
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == tag:
            found = True
    return found

# Parse through specific sections of xml file to create a list of tag values
# Inputs: file name, outer tag, inner tag
# Output: array of values corresponding to given tags
def awk(filename, tag1, tag2):
    arr = []
    try:
        tree = ET.ElementTree(file=filename)
    except:
        write("Cannot read file %s" %(filename), lvl=0)
        return arr
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == tag1:
            elem_child = elem.getchildren()
            for child in elem_child:
                if re.sub(r'{[^>]*}', "", child.tag) == tag2:
                    arr.append(child.text)
    return arr

# Parse VirtualIOServer XML file to build the vios_info hash
# Inputs: vios hash, file name, vios uuid
# Output: vios name use in hash if success,
#         prints error message and exit upon error
def build_vios_info(vios_info, filename, vios_uuid):
    ns = { 'Atom': 'http://www.w3.org/2005/Atom', \
           'vios': 'http://www.ibm.com/xmlns/systems/power/firmware/uom/mc/2012_10/' }
    try:
        e_tree = ET.parse(filename)
    except IOError, e:
        write("ERROR: Failed to parse %s for %s: %s." %(e.filename, vios_uuid, e.strerror), lvl=0)
        remove(filename)
        sys.exit(3)
    except ElementTree.ParseError, e:
        write("ERROR: Failed to parse %s for %s: %s" %(filename, vios_uuid, e), lvl=0)
        remove(filename)
        sys.exit(3)
    e_root = e_tree.getroot()

    #NOTE: Some VIOSes do not return PartitionName element
    #      so in that case we use the short hostname as hash
    #      key and replace partition name by this short hostname

    # Get element: ResourceMonitoringIPAddress
    e_RMIPAddress = e_root.find("Atom:content/vios:VirtualIOServer/vios:ResourceMonitoringIPAddress", ns)
    if e_RMIPAddress is None:
        write("ERROR: ResourceMonitoringIPAddress element not found in file %s" %(filename, vios_uuid), lvl=0)
        sys.exit(3)

    # Get the hostname 
    (hostname, aliases, ip_list) = get_hostname(e_RMIPAddress.text)
    vios_name = hostname.split(".")[0]

    vios_info[vios_name] = {}
    vios_info[vios_name]['uuid'] = vios_uuid
    vios_info[vios_name]['hostname'] = hostname
    vios_info[vios_name]['ip'] = e_RMIPAddress.text
    
    # Get element: PartitionName
    e_PartionName = e_root.find("Atom:content/vios:VirtualIOServer/vios:PartitionName", ns)
    if e_PartionName is None:
        write("ERROR: PartitionName element not found in file %s" %(filename, vios_uuid), lvl=0)
        sys.exit(3)
    vios_info[vios_name]['partition_name'] = e_PartionName.text

    # Get element: PartitionID
    e_PartionID = e_root.find("Atom:content/vios:VirtualIOServer/vios:PartitionID", ns)
    if e_PartionID is None:
        write("ERROR: PartitionID element not found in file %s" %(filename, vios_uuid), lvl=0)
        sys.exit(3)
    vios_info[vios_name]['id'] = e_PartionID.text

    # Get element: PartitionState
    e_PartitionState = e_root.find("Atom:content/vios:VirtualIOServer/vios:PartitionState", ns)
    if e_PartitionState is None:
        write("ERROR: PartitionState element not found in file %s" %(filename, vios_uuid), lvl=0)
        sys.exit(3)
    vios_info[vios_name]['partition_state'] = e_PartitionState.text

    # Get element: ResourceMonitoringControlState
    e_RMCState = e_root.find("Atom:content/vios:VirtualIOServer/vios:ResourceMonitoringControlState", ns)
    if e_RMCState is None:
        write("ERROR: ResourceMonitoringControlState element not found in file %s" %(filename, vios_uuid), lvl=0)
        sys.exit(3)
    vios_info[vios_name]['control_state'] = e_RMCState.text

    return vios_name


### c_rsh functions ###

def get_vios_sea_state(vios_name, vios_sea):
    global vios_info
    state = ""

    # file to get all SEA info (debug)
    filename = "%s_%s.txt" %(vios_name, vios_sea)
    log("writing file: %s\n" %(filename))
    try:
        f = open(filename, 'w+')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        f = None

    # ssh into vios1
    cmd = [C_RSH, vios_info[vios_name]['hostname'],
            "LANG=C /bin/entstat -d %s" %(vios_sea)]
    (rc, output) = exec_cmd(cmd)
    if rc != 0:
        write("ERROR: Failed to get the state of the %s SEA adapter on %s: %s" %(vios_SEA, vios_name, output), lvl=0)
        return (1, "")

    found_stat = False
    found_packet = False
    for line in output.rstrip().split('\n'):
        # file to get all SEA info (debug)
        if not (f is None):
            f.write("%s\n" %(line))

        if not found_stat:
            # Statistics for adapters in the Shared Ethernet Adapter entX
            match_key = re.match(r"^Statistics for adapters in the Shared Ethernet Adapter %s" %(vios_sea), line)
            if match_key:
                found_stat = True
                continue

        if not found_packet:
            # Type of Packets Received:
            match_key = re.match(r"^Type of Packets Received(.*)$", line)
            if match_key:
                found_packet = True
                continue

        if found_packet:
            # State: PRIMARY | BACKUP | STANDBY
            match_key = re.match(r"^\s+State\s*:\s+(.*)$", line)
            if match_key:
                found_packet = True
                state = match_key.group(1)
                continue

    log("VIOS: %s adapter: %s state: %s" %(vios_name, vios_sea, state))

    if state == "":
        write("ERROR: Failed to get the state of the %s SEA adapter on %s: State field not found." %(vios_sea, vios_name), lvl=0)
        return (1, "")
    return (0, state)


### Pycurl ###

def curl_request(sess_key, url, filename):
    log("Curl request, file: %s, url: %s\n" %(filename, url))
    try:
        log("writing file: %s\n" %(filename))
        f = open(filename, 'wb')
    except IOError, e:
        write("ERROR: Failed to create file %s: %s." %(e.filename, e.strerror), lvl=0)
        sys.exit(3)

    hdrs = ["X-API-Session:%s" %(sess_key)]
    hdr = cStringIO.StringIO()

    try:
        c = pycurl.Curl()
        c.setopt(c.HTTPHEADER, hdrs)
        c.setopt(c.URL, url)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.WRITEDATA, f)
        c.setopt(pycurl.HEADERFUNCTION, hdr.write)
        c.perform()
    except pycurl.error, (errno, strerror):
        write("ERROR: Request to %s failed: %s." %(url, strerror), lvl=0)
        f.close()
        return 1, strerror

    f.close()
    # TBC - uncomment the 2 following lines for debug
    #f = open(filename, 'r')
    #log("\n### File %s content ###%s### End of file %s ###\n" %(filename, f.read(), filename))

    # Get the http code and message to precise the error
    status_line = hdr.getvalue().splitlines()[0]
    m = re.match(r'HTTP\/\S*\s*(\d+)\s*(.*)\s*$', status_line)
    if m:
        http_code = str(m.group(1))
        http_message = " %s" %(str(m.group(2)))
    else:
        http_code = c.getinfo(pycurl.HTTP_CODE)
        http_message = ""

    if http_code != "200":
        log("Curl retuned '%s%s' for request '%s'\n" %(http_code, http_message, url))
        return http_code, http_message

    return 0

# Find clients of a VIOS
# No output, writes data to file
def get_vios_info(hmc_info, vios_uuid, filename):
    url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s" %(hmc_info['hostname'], vios_uuid)
    return curl_request(hmc_info['session_key'], url, filename)

# Find LPARs of a managed system
def get_managed_system_lpar(hmc_info, managed_system_uuid, filename):
    url = "https://%s:12443/rest/api/uom/ManagedSystem/%s/LogicalPartition" %(hmc_info['hostname'], managed_system_uuid)
    return curl_request(hmc_info['session_key'], url, filename)

# Get VSCSI info
def get_vscsi_info(hmc_info, vios_uuid, filename):
    url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping" %(hmc_info['hostname'], vios_uuid)
    return curl_request(hmc_info['session_key'], url, filename)

# Get fibre channel mapping for VIOS
def get_fc_mapping_vios(hmc_info, vios_uuid, filename):
    url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosFCMapping" %(hmc_info['hostname'], vios_uuid)
    return curl_request(hmc_info['session_key'], url, filename)

# Get info about LPAR to see network connections
def get_vfc_client_adapter(hmc_info, lpar, filename):
    url = "https://%s:12443/rest/api/uom/LogicalPartition/%s/VirtualFibreChannelClientAdapter" %(hmc_info['hostname'], lpar)
    return curl_request(hmc_info['session_key'], url, filename)

# Get info about VIOS Network connections 
def get_network_info(hmc_info, vios_uuid, filename):
    url = "https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosNetwork" %(hmc_info['hostname'], vios_uuid)
    return curl_request(hmc_info['session_key'], url, filename)

# Get info about VIOS Virtual NIC Dedicated adapter
def get_vnic_info(hmc_info, uuid, filename):
    url = "https://%s:12443/rest/api/uom/LogicalPartition/%s/VirtualNICDedicated" %(hmc_info['hostname'], uuid)
    return curl_request(hmc_info['session_key'], url, filename)


#===============================================================================
# MAIN
#===============================================================================

def usage():
    write("""
Usage: vioshc -h
       vioshc [-u id] [-p pwd] -i hmc_ip_addr -l {a | m} [-v] 
       vioshc [-u id] [-p pwd] -i hmc_ip_addr -m managed_system -U vios_uuid [-U vios_uuid] [-v]

        -h    :display this help message
        -i    :hmc ip address or hostname
        -u    :hmc user ID
        -p    :hmc user password
        -U    :vios UUID, use flag twice for two UUIDs
        -m    :managed system UUID
        -v    :verbose
        -l    :list managed system information
                  a :list managed system and vios UUIDs
                  m :list managed system UUIDs
    """, lvl=0)


# TBC - handle log name and location after discussion
# Establish a log file
today = datetime.now()
log_dir = "%s/vios_maint" %(LOG_DIR)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
os.chdir(log_dir)
log_path = "%s/vios_maint.log" %(log_dir)
# log file format is vios_maint_YY_mm_dd_HH_MM_SS.log
#log_path = "%s/vios_maint_%02d_%02d_%d_%02d_%02d_%02d.log" \
#            %(log_dir, today.year, today.month, today.day, today.hour, today.minute, today.second)
try:
    log_file = open(log_path, 'a+', 1)
except IOError, e:
    print("ERROR: Failed to create log file %s: %s." %(e.filename, e.strerror))
    sys.exit(3)
log("################################################################################\n")
log("vioshc log file for command:\n%s\n" %(sys.argv[0:]))
log("################################################################################\n")


#######################################################
# Parse command line arguments & Curl requirement 
#######################################################
log("\nParsing command line arguments\n")
action = "check"
try:
    opts, args = getopt.getopt(sys.argv[1:], 'hi:u:p:U:m:vl:', ["help", 'HMC IP=', 'User ID=', 'Password=', 'VIOS UUID=', 'Managed System UUID=', 'Verbose', 'List'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-h', "--help"):
        usage()
        sys.exit(0)
    elif opt in ('-i'):
        hmc_ip = arg
    elif opt in ('-u'):
        hmc_user_id = arg
    elif opt in ('-p'):
        hmc_password = arg
    elif opt in ('-U'):
        # Check if vios UUID is valid
        if re.match("^[a-zA-Z0-9-]*$", arg):
            if vios1_uuid == "":
                vios1_uuid = arg
            elif vios2_uuid == "":
                vios2_uuid = arg
            else:
                write("Warning: more than 2 UUID specified. They will be ignored.", lvl=0)
            vios_num += 1
        else:
            write("Invalid UUID. Please try again.", lvl=0)
            sys.exit(2)
    elif opt in ('-m'):
        # Check if managed system UUID is valid
        if re.match("^[a-zA-Z0-9-]*$", arg):
            managed_system_uuid = arg
        else:
            write("Invalid UUID format. Please try again.", lvl=0)
            sys.exit(2)
    elif opt in ('-v'):
        verbose += 1
        sys.stdout = sys.stderr
    elif opt in ('-l'):
        action = "list"
        list_arg = arg
    else:
        usage()
        sys.exit(2)

# Check mandatory arguments
log("\nChecking mandatory arguments\n")
rc = 0
if hmc_ip == "":
    write("Missing HMC information.", lvl=0)
    rc += 1
if action == "check":
    if vios1_uuid == "":
        write("Missing VIOS UUID.", lvl=0)
        rc += 1
    if managed_system_uuid == "":
        write("Missing Managed System UUID.", lvl=0)
        rc += 1
elif action == "list":
    if list_arg != 'a' and list_arg != 'm':
        write("Invalid argument '%s' for list flag." %(list_arg), lvl=0)
        rc += 1
else:
    write("ERROR: Unknown action." %(action), lvl=0)
    rc += 1
if rc != 0:
    usage()
    sys.exit(2)

# Check for curl on the system: return status is 0 if successful, else failed
os.system('command -v curl >/dev/null 2>&1 || { echo "ERROR: Curl not installed on this system. Exiting now." >&2; exit 2; }')


#######################################################
# Get HMC credentials
#######################################################
write("Getting HMC %s info" %(hmc_ip))
# Get the HMC hostname in case user provided the short name or an IP address
(hostname, aliases, ip_list) = get_hostname(hmc_ip)
log("hmc %s hostname: %s\n" %(hmc_ip, hostname))

# Retrieve the NIM object name matching the hostname
nim_name = get_nim_name(hostname)
log("hmc %s nim_name: %s\n" %(hostname, nim_name))
if nim_name == "":
    sys.exit(3)

# Get all NIM attributes
hmc_info = get_nim_info(nim_name)
if hmc_info is None:
    write("ERROR: Failed to retrieve HMC info: %s.", lvl=0)
    sys.exit(3)
hmc_info['nim_name'] = nim_name
hmc_info['hostname'] = hostname
hmc_info['ip'] = ip_list[0]

for key in hmc_info.keys():
    log("hmc_info: %s, %-13s = %s\n" %(nim_name, key, hmc_info[key]))

write("Getting HMC credentials")
# If either username or password are empty, try to retrieve them
if (hmc_password == "") or (user_id == ""):
    write("Retrieving HMC user id and password")
    (hmc_user_id, hmc_password) = retrieve_usr_pass(hmc_info)
if (hmc_user_id != ""):
    hmc_info['user_id'] = hmc_user_id
if (hmc_password != ""):
    hmc_info['user_password'] = hmc_password

write("Getting HMC seesion key")
session_key = get_session_key(hmc_info, filename_session_key)
if session_key == "":
    write("ERROR: Failed to get %s session key." %(hmc_ip), lvl=0)
    sys.exit(3)
hmc_info['session_key'] = session_key


#######################################################
# List UUIDs
#######################################################
if action == "list":
    log("\nListing UUIDs\n")
    rc = print_uuid(hmc_info, list_arg, filename_systems)
    sys.exit(rc)


#######################################################
# REST Call to /rest/api/uom/VirtualIOServer
# Get name and partition ID of each VIOS then filter
# the ones of interest
#######################################################
write("Find VIOS(es) Name, IP Address, ID, UUID")

# Find clients of VIOS1, write data to file
write("Collect info on clients of VIOS1: %s" %(vios1_uuid))
rc1 = get_vios_info(hmc_info, vios1_uuid, filename_vios1)
if rc1 != 0:
    write("ERROR: Failed to collect vios %s info: %s" %(vios1_uuid, rc1[1]), lvl=0)
    rc = rc1[0]

if vios_num > 1:
    # Find clients of VIOS2, write data to file
    write("Collect info on clients of VIOS2: %s" %(vios2_uuid))
    rc1 = get_vios_info(hmc_info, vios2_uuid, filename_vios2)
    if rc1 != 0:
        write("ERROR: Failed to collect vios %s info: %s" %(vios1_uuid, rc1[1]), lvl=0)
        rc = rc1[0]
if rc != 0:
    sys.exit(2)

# Parse vios xml file and build the hash, exit upon error
vios1_name = build_vios_info(vios_info, filename_vios1, vios1_uuid)
vios_info[vios1_name]['role'] = 'primary'
vios2_name = build_vios_info(vios_info, filename_vios2, vios2_uuid)
vios_info[vios2_name]['role'] = 'secondary'

# Log VIOS information
for vios in vios_info.keys():
    log("vios: %s, %s\n" %(vios, str(vios_info[vios])))

primary_header = "\nPrimary VIOS Name         IP Address      ID         UUID                "
backup_header = "\nBackup VIOS Name          IP Address      ID         UUID                "
divider= "-------------------------------------------------------------------------------------------------"
format = "%-25s %-15s %-10s %-40s "

for vios in vios_info.keys():
    # If Resource Monitoring Control State is inactive, it will throw off our UUID/IP pairing
    if (vios_info[vios]['control_state'] == "inactive"):
        continue

    # If VIOS is not running, skip it otherwise it will throw off our UUID/IP pairing
    if vios_info[vios]['partition_state'] == "not running":
        continue

    # Get VIOS1 info (original VIOS)
    if vios_info[vios]['role'] == "primary":
        write(primary_header, lvl=0)
    else:
        write(backup_header, lvl=0)

    write(divider, lvl=0)
    write(format %(vios_info[vios]['partition_name'], \
                   vios_info[vios]['ip'], \
                   vios_info[vios]['id'], \
                   vios_info[vios]['uuid']), lvl=0)


#######################################################
# Get UUIDs of all LPARs that belong to the managed
# system that we are interested in
#######################################################
# Get managed system LPAR info, write data to file
write("Getting managed system LPAR info")
get_managed_system_lpar(hmc_info, managed_system_uuid, filename_lpar_info)

# Check for error response in file
if grep_check(filename_lpar_info, 'HttpErrorResponse'):
    write("ERROR: Request to https://%s:12443/rest/api/uom/ManagedSystem/%s/LogicalPartition returned Error Response." %(hmc_ip, managed_system_uuid), lvl=0)
    write("Unable to detect LPAR information.", lvl=0)

# Create list of LPAR partition IDs
lpar_id = grep_array(filename_lpar_info, 'PartitionID')
# Create list of LPAR partition names
lpar_name = grep_array(filename_lpar_info, 'PartitionName')
# Create list of LPAR UUIDs
# skip first element because first <id> tag not relevant
lpar_uuid = grep_array(filename_lpar_info, 'id')
lpar_uuid.pop(0)

# Associative array to map LPAR ID to its partition name & UUID
lpar_info = {}

write("LPAR information belonging to managed system with UUID %s:" %(managed_system_uuid))

# Build lpar_info
log("lpar_id: %s\nlpar_name: %s\nlpar_uuid: %s\n" %(lpar_id, lpar_name, lpar_uuid))
i = 0
for id in lpar_id:
    lpar_info[id] = {}
    lpar_info[id]['name'] = lpar_name[i]
    lpar_info[id]['uuid'] = lpar_uuid[i]
    i += 1

#######################################################
# Check active client are the same for VIOS1 and VIOS2
#######################################################
write("Check active client(s):")
active_client_id = []
active_client = {}
diff_clients = []

# Find configured clients of VIOS1
# TBC - ConnectingPartitionID is present in VirtualFibreChannelMapping elem
active_client['vios1'] = awk(filename_vios1, 'ServerAdapter', 'ConnectingPartitionID')
log("active_client['vios1']: " + str(active_client['vios1']) + "\n")

if vios_num > 1:
    # Find configured clients of VIOS2
    active_client['vios2'] = awk(filename_vios2, 'ServerAdapter', 'ConnectingPartitionID')
    log("active_client['vios2']: " + str(active_client['vios2']) + "\n")

    # Check that both VIOSes have the same clients
    # if they do not, all health-checks will fail and we cannot continue the program
    for id in active_client['vios1']:
        if (id not in active_client['vios2']) and (id not in diff_clients):
            diff_clients.append(id)
    diff_clients.sort()
    log("diff_clients: " + str(diff_clients) + "\n")

# Check for error response in file
if grep_check(filename_lpar_info, 'HttpErrorResponse'):
    write("FAIL: Unable to detect active clients", lvl=0)
    num_hc_fail += 1
elif len(diff_clients) == 0:
    if vios_num > 1:
        write("PASS: Active client lists are the same for both VIOSes")
    active_client_id = active_client['vios1']
    num_hc_pass += 1
else:
    write("FAIL: Active client lists are not the same for VIOS1 and VIOS2, check these clients:", lvl=0)
    write(diff_clients, lvl=0)
    num_hc_fail += 1

write("\nActive Client Information:")

header = "LPAR                      ID         UUID                            "
divider = "-------------------------------------------------------------------"
format = "%-25s %-10s %-40s "
write(header)
write(divider)

# Print active clients, IDs, and UUIDs
for id in active_client_id:
    write(format %(lpar_info[id]['name'], id, lpar_info[id]['uuid']))

remove(filename_vios1)
if vios_num > 1:
    remove(filename_vios2)
remove(filename_lpar_info)


#######################################################
# VSCSI Mapping for VIOS1
#######################################################
touch(filename_msg)

write("\nvSCSI Mapping info for %s:" %(vios1_name))

# Get VSCSI info, write data to file
get_vscsi_info(hmc_info, vios1_uuid, filename_vscsi_mapping1)

# Check for error response in file
if grep_check(filename_vscsi_mapping1, 'HttpErrorResponse'):
    write("ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping returned Error Response." %(hmc_ip, vios1_uuid), lvl=0)
    write("ERROR: Unable to detect VSCSI Information", lvl=0)

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
local_partition_vscsi = grep_array(filename_vscsi_mapping1, 'LocalPartitionID')
# Grab remote partition IDs
remote_partition_vscsi = grep_array(filename_vscsi_mapping1, 'RemoteLogicalPartitionID')
# Grab local slot number
local_slot_vscsi= grep_array(filename_vscsi_mapping1, 'VirtualSlotNumber')
# Grab remote slot number
remote_slot_vscsi = grep_array(filename_vscsi_mapping1, 'RemoteSlotNumber')
# Grab the backup device name
backing_device_vscsi = grep_array(filename_vscsi_mapping1, 'BackingDeviceName')

log("Local  partition VSCSI: %s\n" %(local_partition_vscsi))
log("Remote partition VSCSI: %s\n" %(remote_partition_vscsi))
log("Local  slot VSCSI     : %s\n" %(local_slot_vscsi))
log("Remote slot VSCSI     : %s\n" %(remote_slot_vscsi))
log("Backing device VSCSI  : %s\n" %(backing_device_vscsi))

# Parse for backup device info
try:
    tree = ET.ElementTree(file=filename_vscsi_mapping1)
except:
    write("Cannot read %s file." %(filename_vscsi_mapping1), lvl=0)
    sys.exit(2)
iter_ = tree.getiterator()
for elem in iter_:
    if re.sub(r'{[^>]*}', "", elem.tag) == 'Storage':
        elem_child = elem.getchildren()
        for child in elem_child:
            if re.sub(r'{[^>]*}', "", child.tag) == 'PhysicalVolume':
                disk_type = "PhysicalVolume"
                write(disk_type, lvl=0)
                disk_info.append(disk_type)
            if re.sub(r'{[^>]*}', "", child.tag) == 'VirtualDisk':
                disk_type = "LogicalVolume"
                write(disk_type, lvl=0)
                res_pol = "None"
                write(res_pol, lvl=0)
                disk_info.append(disk_type)
                disk_info.append(res_pol)
            if re.sub(r'{[^>]*}', "", child.tag) == 'ReservePolicy':
                res_pol = re.sub(r'<[^>]*>', "", child.text)
                write(res_pol, lvl=0)
                disk_info.append(res_pol)
            if re.sub(r'{[^>]*}', "", child.tag) == 'UniqueDeviceID':
                udid = re.sub(r'<[^>]*>', "", child.text)
                write(udid, lvl=0)
                disk_info.append(udid)

# Backing device vscsi attributes
i = 0
while i < len(disk_info):
    backing_device_type_vscsi.append(disk_info[i])
    backing_device_res_vscsi.append(disk_info[i+1])
    backing_device_id_vscsi.append(disk_info[i+2])
    i += 3
if len(backing_device_id_vscsi) == 0:
    write("WARNING: no VSCSI disks configured on %s." %(vios1_name))

i = 0 # index for looping through all partition mappings
j = 0 # index for looping through backing devices

vscsi_header = "Device Name     UDID                                                                    Disk Type           Reserve Policy      "
divider = "---------------------------------------------------------------------------------------------------------------------------"
format = "%-15s %-75s %-20s %-20s "
write(vscsi_header)
write(divider)
# TODO - Currently the storage info is not available (BackingDeviceName in the XML)
if len(backing_device_vscsi) == 0:
    write("Not yet implemented")
else:
    msg_txt = open(filename_msg, 'w+')
    for partition in local_partition_vscsi:
        if partition == vios_info[vios2_name]['id']:
            cmd = [C_RSH, vios_info[vios1_name]['hostname'],
                    "< /dev/%s" %(backing_device_vscsi[j])]
            (rc, output) = exec_cmd(cmd)
            if rc != 0 or output.rstrip() != "":
                write("ERROR: Cannot open disk %s on %s" %(backing_device_vscsi[j], vios_info[vios1_name]['hostname']), lvl=0)
                log("/dev/%s device open failure: %s\n" %(backing_device_vscsi[j], output.rstrip()))
            else:
                if backing_device_res_vscsi[j] == "SinglePath":
                    msg = "WARNING: You have single path for %s on VIOS %s which is likely an issue" %(backing_device_vscsi[j], vios1_name)
                    write(msg, lvl=0)
                    msg_txt.write(msg)
                elif backing_device_type_vscsi[j] == "Other":
                    msg = "WARNING: %s is not supported by both VIOSes because it is of type %s" %(backing_device_vscsi[j], backing_device_type_vscsi[j])
                    write(msg, lvl=0)
                    msg_txt.write(msg)
                elif backing_device_type_vscsi[j] == "LogicalVolume":
                    msg = "WARNING: This program cannot guarantee that the data in this %s is accessible via both VIOSes" %(backing_device_vscsi[j])
                    write(msg, lvl=0)
                    msg_txt.write(msg)
                else:
                    available_disks_1.append(backing_device_id_vscsi[j])
                    write(format %(backing_device_vscsi[j], backing_device_id_vscsi[j], backing_device_type_vscsi[j], backing_device_res_vscsi[j]))
            j += 1
        i += 1
    msg_txt = open(filename_msg, 'r')
    print msg_txt.read()    # do not use write as it's already logged

remove(filename_vscsi_mapping1)
remove(filename_msg)


if vios_num > 1:
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
    
    touch(filename_msg)
    
    write("\nvSCSI Mapping info for %s:" %(vios2_name))
    
    # Get VSCSI info, write data to file
    get_vscsi_info(hmc_info, vios2_uuid, filename_vscsi_mapping2)
    
    # Check for error response
    if grep_check(filename_vscsi_mapping2, 'HttpErrorResponse'):
        write("ERROR: Request to https://%s:12443/rest/api/uom/VirtualIOServer/%s?group=ViosSCSIMapping returned Error Response." %(hmc_ip, vios1_uuid), lvl=0)
        write("Unable to detect VSCSI Information.", lvl=0)
    
    # Grab local partition IDs
    local_partition_vscsi = grep_array(filename_vscsi_mapping2, 'LocalPartitionID')
    # Grab remote partition IDs
    remote_partition_vscsi = grep_array(filename_vscsi_mapping2, 'RemoteLogicalPartitionID')
    # Grab local slot number
    local_slot_vscsi= grep_array(filename_vscsi_mapping2, 'VirtualSlotNumber')
    # Grab remote slot number
    remote_slot_vscsi = grep_array(filename_vscsi_mapping2, 'RemoteSlotNumber')
    # Grab the backup device name
    backing_device_vscsi = grep_array(filename_vscsi_mapping2, 'BackingDeviceName')
    
    # Parse for backup device info
    try:
        tree = ET.ElementTree(file=filename_vscsi_mapping2)
    except:
        write("ERROR: Cannot read file filename_vscsi_mapping2.", lvl=0)
        sys.exit(2)
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == 'Storage':
            elem_child = elem.getchildren()
            for child in elem_child:
                if re.sub(r'{[^>]*}', "", child.tag) == 'PhysicalVolume':
                    disk_type = "PhysicalVolume"
                    write(disk_type, lvl=0)
                    disk_info.append(disk_type)
                if re.sub(r'{[^>]*}', "", child.tag) == 'VirtualDisk':
                    disk_type = "LogicalVolume"
                    write(disk_type, lvl=0)
                    res_pol = "None"
                    write(res_pol, lvl=0)
                    disk_info.append(disk_type)
                    disk_info.append(res_pol)
                if re.sub(r'{[^>]*}', "", child.tag) == 'ReservePolicy':
                    res_pol = re.sub(r'<[^>]*>', "", child.text)
                    write(res_pol, lvl=0)
                    disk_info.append(res_pol)
                if re.sub(r'{[^>]*}', "", child.tag) == 'UniqueDeviceID':
                    udid = re.sub(r'<[^>]*>', "", child.text)
                    write(udid, lvl=0)
                    disk_info.append(udid)
    
    # Backing device vscsi attributes
    i = 0
    while i < len(disk_info):
        backing_device_type_vscsi.append(disk_info[i])
        backing_device_res_vscsi.append(disk_info[i+1])
        backing_device_id_vscsi.append(disk_info[i+2])
        i += 3
    
    if len(backing_device_id_vscsi) == 0:
        write("WARNING: no VSCSI disks configured on %s." %(vios2_name))
    
    i = 0 # index for looping through all partition mappings
    j = 0 # index for looping through backing devices
    
    vscsi_header = "Device Name     UDID                                                                    Disk Type           Reserve Policy      "
    divider = "---------------------------------------------------------------------------------------------------------------------------"
    format = "%-15s %-75s %-20s %-20s "
    write(vscsi_header)
    write(divider)
    
    # TODO - Currently the storage info is not available (BackingDeviceName in the XML)
    if len(backing_device_vscsi) == 0:
        write("Not yet implemented")
    else:
        msg_txt = open(filename_msg, 'w+')
        for partition in local_partition_vscsi:
            if partition == vios_info[vios2_name]['id']:
                cmd = [C_RSH, vios_info[vios2_name]['hostname'],
                        "< /dev/%s" %(backing_device_vscsi[j])]
                (rc, output) = exec_cmd(cmd)
                if rc != 0 or output.rstrip() != "":
                    write("ERROR: Cannot open disk %s on %s" %(backing_device_vscsi[j], vios_info[vios2_name]['hostname']), lvl=0)
                    log("/dev/%s device open failure: %s\n" %(backing_device_vscsi[j], output.rstrip()))
                else:
                    if backing_device_res_vscsi[j] == "SinglePath":
                        msg = "WARNING: You have single path for %s on VIOS %s which is likely an issue" %(backing_device_vscsi[j], vios2_name)
                        write(msg, lvl=0)
                        msg_txt.write(msg)
                    elif backing_device_type_vscsi[j] == "Other":
                        msg = "WARNING: %s is not supported by both VIOSes because it is of type %s" %(backing_device_vscsi[j], backing_device_type_vscsi[j])
                        write(msg, lvl=0)
                        msg_txt.write(msg)
                    elif backing_device_type_vscsi[j] == "LogicalVolume":
                        msg = "WARNING: This program cannot guarantee that the data in this %s is accessible via both VIOSes" %(backing_device_vscsi[j])
                        write(msg, lvl=0)
                        msg_txt.write(msg)
                    else:
                        available_disks_2.append(backing_device_id_vscsi[j])
                        write(format %(backing_device_vscsi[j], backing_device_id_vscsi[j], backing_device_type_vscsi[j], backing_device_res_vscsi[j]))
                j += 1
            i += 1
    
        msg_txt = open(filename_msg, 'r')
        print msg_txt.read()    # do not use write as it's already logged

    remove(filename_vscsi_mapping2)
    remove(filename_msg)
    
    ###########
    write("\nvSCSI Validation:")

    # Check to see if any disks are different
    for disk in available_disks_1:
        if (disk not in available_disks_2) and (disk not in diff_disks):
            diff_disks.append(disk)
    diff_disks.sort()
    
    if len(diff_disks) == 0:
        write("PASS: same configuration.")
        num_hc_pass += 1
    else:
        write("FAIL: configurations are not the same, check these disks:", lvl=0)
        write(diff_disks, lvl=0)
        num_hc_fail += 1


#######################################################
# Fibre Channel Mapping for VIOS1
#######################################################
write("\nFC Mapping ifo for %s:" %(vios1_name))

# Find VIOS fibre channel mappings, write data to file
get_fc_mapping_vios(hmc_info, vios1_uuid, filename_fc_mapping1)

local_partition_fc = []
remote_partition_fc = []
local_slot_fc = []
remote_slot_fc = []

# Get local partition IDs
local_partition_fc = grep_array(filename_fc_mapping1, 'LocalPartitionID')
# Get remote partition IDs
remote_partition_fc = grep_array(filename_fc_mapping1, 'ConnectingPartitionID')
# Get local slot number
local_slot_fc = grep_array(filename_fc_mapping1, 'VirtualSlotNumber')
# Get remote slot number
remote_slot_fc = grep_array(filename_fc_mapping1, 'ConnectingVirtualSlotNumber')

log("local_partition_fc: " + str(local_partition_fc) +"\n")
log("local_slot_fc: " + str(local_slot_fc) +"\n")
log("remote_partition_fc: " + str(remote_partition_fc) +"\n")
log("remote_slot_fc: " + str(remote_slot_fc) +"\n")

fc_header="VIOS Name            Slot       Client              "
divider="-------------------------------------------------"
format="%-20s %-10s %-20s "
write(fc_header)
write(divider)

i = 0 # index for looping through all partition mappings
for partition in local_partition_fc:
    if partition == vios_info[vios1_name]['id']:
        write(format %(vios1_name, local_slot_fc[i], lpar_info[remote_partition_fc[i]]['name']))
    i += 1

remove(filename_fc_mapping1)
 

if vios_num > 1:
    #######################################################
    # Fibre Channel Mapping for VIOS2
    #######################################################
    write("\nFC MAPPINGS for %s:" %(vios2_name))
    
    # Find VIOS fibre channel mappings, write data to file
    get_fc_mapping_vios(hmc_info, vios2_uuid, filename_fc_mapping2)
    
    # Clear arrays before using again
    del local_partition_fc[:]
    del remote_partition_fc[:]
    del local_slot_fc[:]
    del remote_slot_fc[:]
    
    # Get local partition IDs
    local_partition_fc = grep_array(filename_fc_mapping2, 'LocalPartitionID')
    # Get remote partition IDs
    remote_partition_fc = grep_array(filename_fc_mapping2, 'ConnectingPartitionID')
    # Get local slot number
    local_slot_fc = grep_array(filename_fc_mapping2, 'VirtualSlotNumber')
    # Get remote slot number
    remote_slot_fc = grep_array(filename_fc_mapping2, 'ConnectingVirtualSlotNumber')
    
    
    i = 0 # index for looping through all partition mappings
    
    fc_header="VIOS Name            Slot       Client              "
    divider="-------------------------------------------------"
    format="%-20s %-10s %-20s "
    write(fc_header)
    write(divider)
    
    for partition in local_partition_fc:
        if partition == vios_info[vios2_name]['id']:
            write(format %(vios2_name, local_slot_fc[i], lpar_info[remote_partition_fc[i]]['name']))
        i += 1
    
    remove(filename_fc_mapping2)


#######################################################
# NPIV PATH VALIDATION
# TODO - The REST API does not send data for this request,
# the response is: 204 no content 
#######################################################

fc_ids = []
drc_list = []
WWPN_list = []

write("\nNPIV Path Validation:")

# Check for path validation by running mig_vscsi to check for notzoned tag
# for each active partition, get notzoned info for both vios and check if false
for id in active_client_id:
    # Get LPAR info, write data to xml file
    get_vfc_client_adapter(hmc_info, lpar_info[id]['uuid'], filename_npiv_mapping)
    # TBC - uncomment the 2 following lines for debug
    #f = open(filename_npiv_mapping, 'r')
    #log("\n### File %s content ###%s### End of file %s ###\n" %(filename_npiv_mapping, f.read(), filename_npiv_mapping))

    # Create a list of fibre channel IDs
    fc_ids = grep_array(filename_npiv_mapping, 'LocalPartitionID')
    if len(fc_ids) == 0:
        write("No vFC client adapter ID for lpar: %s (%s)" %(lpar_info[id]['name'], lpar_info[id]['uuid']))
        continue
    
    # Create a list of dynamic reconfiguration connectors
    drc_list = grep_array(filename_npiv_mapping, 'DynamicReconfigurationConnectorName')
    # Create a list of WWPN
    WWPN_list = grep_array(filename_npiv_mapping, 'WWPN')

    touch(filename_adapter1)
    touch(filename_adapter2)

    # Cannot get mig_vscsi to stdout so need to use another file to get info
    j = 0
    for partition_id in fc_ids:
        if vios_info[vios1_name]['id'] == partition_id:
            lower_WWPN = WWPN_list[j]
            j += 1  # get the higher WWPN
            higher_WWPN = WWPN_list[j]
            DRC = drc_list[j]
            j += 1 # one more increment bc we skip clients, and drc_list repeats itself twice

            cmd = [C_RSH, vios_info[vios1_name]['hostname'],
                    "LANG=C /usr/lib/methods/mig_vscsi -f get_adapter -t vscsi -s %s -a ACTIVE_LPM -c RPA  -M 1 -d 5 -W 0x%s -w 0x%s -F %s" \
                    %(DRC, lower_WWPN, higher_WWPN, filename_adapter1)]
            (rc, output) = exec_cmd(cmd)
            if rc != 0 or re.match('.*ERROR.*', output.rstrip()):
                write("ERROR: Cannot get vSCSI adapter info on %s, mig_vscsi command: %s" %(vios1_name, output.rstrip()), lvl=0)
                num_hc_fail += 1
                continue

            if os.path.exists(filename_adapter1):
                notzoned_value = grep(filename_adapter1, 'notZoned')
                notzoned = re.match('.*false.*', notzoned_value)

        if vios_info[vios2_name]['id'] == partition_id:
            lower_WWPN = WWPN_list[j]
            j += 1 # get the higher WWPN
            higher_WWPN = WWPN_list[j]
            DRC = drc_list[j]
            j += 1 # one more increment bc we skip clients, and drc_list repeats itself twice

            cmd = [C_RSH, vios_info[vios2_name]['hostname'],
                    "LANG=C /usr/lib/methods/mig_vscsi -f get_adapter -t vscsi -s %s -a ACTIVE_LPM -c RPA  -M 1 -d 5 -W 0x%s -w 0x%s -F %s" \
                    %(DRC, lower_WWPN, higher_WWPN, filename_adapter2)]
            (rc, output) = exec_cmd(cmd)
            if rc != 0 or re.match('.*ERROR.*', output.rstrip()):
                write("ERROR: Cannot get vSCSI adapter info on %s, mig_vscsi command: %s" %(vios2_name, output.rstrip()), lvl=0)
                num_hc_fail += 1
                continue

            if os.path.exists(filename_adapter2):
                notzoned_value = grep(filename_adapter2, 'notZoned')
                notzoned = notzoned and re.match('.*false.*', notzoned_value)

        if notzoned:
            write("PASS: %s has a path through both VIOSes." %(lpar_info[id]['name']))
            num_hc_pass += 1
        else:
            write("FAIL: %s doesn't have a path through both VIOSes." %(lpar_info[id]['name']), lvl=0)
            num_hc_fail += 1

    remove(filename_adapter1)
    remove(filename_adapter2)


#######################################################
# Checking if SEA is configured for VIOSes
#######################################################
write("\nSEA Validation:")

# Check each VIOS UUID and see if we can grab the <SharedEthernetAdapters tag
# this means that SEA is configured
write("Checking to see if SEA is configured for %s:" %(vios1_name))

# Get network info for VIOS1, write to file
get_network_info(hmc_info, vios1_uuid, filename_network1)

# Check VIOS1 for SEA
if grep_check(filename_network1, 'SharedEthernetAdapters'):
    write("PASS: SEA is configured for %s." %(vios1_name))
    num_hc_pass += 1
else:
    write("FAIL: SEA is not configured for %s." %vios1_name, lvl=0)
    num_hc_fail += 1


if vios_num > 1:
    write("Checking to see if SEA is configured for %s:" %(vios2_name))
    # Get network info for VIOS2, write to file
    get_network_info(hmc_info, vios2_uuid, filename_network2)

    # Check VIOS2 for SEA
    if grep_check(filename_network2, 'SharedEthernetAdapters'):
        write("PASS: SEA is configured for %s." %(vios2_name))
        num_hc_pass += 1
    else:
        write("FAIL: SEA is not configured for %s." %vios2_name, lvl=0)
        num_hc_fail += 1


#######################################################
# SEA Validation
#######################################################
vios1_state = ""
vios2_state = ""

header = "Name                      High Availability Mode           "
divider = "------------------------------------------------"
format = "%-25s %-25s "

write(header)
write(divider)

# Check for high availability mode for each vios
vios1_ha = grep(filename_network1, 'HighAvailabilityMode')
if vios1_ha == "":
    write("FAIL: Unable to detect High Availability Mode for VIOS %s." %(vios1_name), lvl=0)
    num_hc_fail += 1
else:
    write(format %(vios1_name, vios1_ha))

if vios_num > 1:
    vios2_ha = grep(filename_network2, 'HighAvailabilityMode')
    if vios2_ha == "":
        write("FAIL: Unable to detect High Availability Mode for VIOS %s." %(vios2_name), lvl=0)
        num_hc_fail += 1
    else:
        write(format %(vios2_name, vios2_ha))

# Get the SEA device names for the VIOS
tree = ET.ElementTree(file=filename_network1)
iter_ = tree.getiterator()
for elem in iter_:
    if re.sub(r'{[^>]*}', "", elem.tag) == 'DeviceName':
        if (elem.get('kxe') == "false") and (elem.get('kb') == "CUD"):
            vios1_SEA = elem.text
if vios_num > 1:
    tree = ET.ElementTree(file=filename_network2)
    iter_ = tree.getiterator()
    for elem in iter_:
        if re.sub(r'{[^>]*}', "", elem.tag) == 'DeviceName':
            if (elem.get('kxe') == "false") and (elem.get('kb') == "CUD"):
                vios2_SEA = elem.text

# If ha_mode is auto we use entstat and grab the states
if vios1_ha == "auto":
    (rc, vios1_state) = get_vios_sea_state(vios1_name, vios1_SEA)
if vios_num > 1:
    if vios2_ha == "auto":
        (rc, vios2_state) = get_vios_sea_state(vios2_name, vios2_SEA)

header = "VIOS                 SEA Device Name           State  "
divider = "------------------------------------------------------"
format = "%-20s %-25s %-15s "

write(header)
write(divider)
write(format %(vios1_name, vios1_SEA, vios1_state))
if vios_num > 1:
    write(format %(vios2_name, vios2_SEA, vios2_state))

if vios1_state == "STANDBY":
    write("WARNING: VIOS1 %s State should be BACKUP instead of STANDBY." %(vios1_name), lvl=0)
if vios_num > 1:
    if vios2_state == "STANDBY":
        write("WARNING: VIOS2 %s State should be BACKUP instead of STANDBY." %(vios2_name), lvl=0)

# Pass conditions
# TBC - how to handle this for only one VIOS?
if (vios1_state == "PRIMARY") and (vios2_state == "BACKUP"):
    write("PASS: SEA is configured for failover.")
    num_hc_pass += 1
elif (vios2_state == "PRIMARY") and (vios1_state == "BACKUP"):
    write("PASS: SEA is configured for failover.")
    num_hc_pass += 1
elif (vios2_state == "PRIMARY") and (vios1_state == "STANDBY"):
    write("PASS: SEA is configured for failover.")
    num_hc_pass += 1
elif (vios1_state == "PRIMARY") and (vios2_state == "STANDBY"):
    write("PASS: SEA is configured for failover.")
    num_hc_pass += 1

# Fail conditions
if (vios1_state == "") and (vios2_state == ""):
    write("FAIL: SEA states for both VIOS are empty.", lvl=0)
    num_hc_fail += 1

if (vios1_state == "PRIMARY") and (vios2_state == "PRIMARY"):
    write("FAIL: SEA states for both VIOS cannot be PRIMARY, change one to BACKUP with the chdev command.", lvl=0)
    num_hc_fail += 1

if (vios1_state == "BACKUP") and (vios2_state == "BACKUP"):
    write("FAIL: SEA states for both VIOS cannot be BACKUP, change one to PRIMARY with the chdev command.", lvl=0)
    num_hc_fail += 1

if (vios1_state == "STANDBY") and (vios2_state == "STANDBY"):
    write("FAIL: SEA states for both VIOS cannot be STANDBY, change one to PRIMARY and the other to BACKUP with the chdev command.", lvl=0)
    num_hc_fail += 1

remove(filename_network1)
if vios_num > 1:
    remove(filename_network2)


#######################################################
# VNIC Validation with REST API
#######################################################

vnic_fail_flag = 0
vnic_configured = 0

write("\nVNIC Validation:")

for id in active_client_id:
    # Get VNIC info, write data to file
    get_vnic_info(hmc_info, lpar_info[id]['uuid'], filename_vnic_info)

    # grep_devnull
    if grep_check(filename_vnic_info, '200 OK'):
        vnic_configured = 1
        break

# If a VNIC configuration is detected, perform the validation
if vnic_configured == 0:
    write("No VNIC Configuration Detected.")
else:
    header = "Client Name           Client ID       VIOS1 VNIC Server           VIOS2 VNIC Server    "
    divider = "---------------------------------------------------------------------------------------"
    format = "%-20s %-15s %-27s %-27s "
    write(header)
    write(divider)

    i = 0
    for id in active_client_id:
        vios1_associated = "DISCONNECTED"
        vios2_associated = "DISCONNECTED"

        # Get VNIC info, write data to vnic_info.xml
        get_vnic_info(hmc_info, lpar_info[id]['uuid'], filename_vnic_info)

        # Check to see if VNIC Server on VIOS1 is associated
        associated_vios = grep_array(filename_vnic_info, 'AssociatedVirtualIOServer')
        for vios in associated_vios:
            if vios1_uuid in vios:
                vios1_associated = "CONNECTED"
            if vios2_uuid in vios:
                vios2_associated = "CONNECTED"

        write(format %(lpar_info[id]['name'], active_client_id[i], vios1_associated, vios2_associated))
        write("\n")
        if vios1_associated == "DISCONNECTED":
            write("FAIL: %s is not connected with VIOS1 VNIC Server." %(lpar_info[id]['name']), lvl=0)
            vnic_fail_flag = 1
            num_hc_fail += 1
        if vios2_associated == "DISCONNECTED":
            write("FAIL: %s is not connected with VIOS2 VNIC Server." %(lpar_info[id]['name']), lvl=0)
            vnic_fail_flag = 1
            num_hc_fail += 1

        vios1_associated = 0
        vios2_associated = 0
        i += 1

    if vnic_fail_flag == 0:
        write("PASS: VNIC Configuration is Correct.")
        num_hc_pass += 1

remove(filename_vnic_info)


#######################################################
# End of Health Checks
#######################################################

# Perform analysis on Pass and Fails
total_hc = num_hc_fail + num_hc_pass
pass_pct = num_hc_pass * 100 / total_hc
write("\n\n%d of %d Health Checks Passed" %(num_hc_pass, total_hc), lvl=0)
write("%d of %d Health Checks Failed" %(num_hc_fail, total_hc), lvl=0)
write("Pass rate of %d%%\n" %(pass_pct), lvl=0)

log_file.close()

# Should exit 0 if all health checks pass, exit 1 if any health check fails
if (num_hc_pass == total_hc):
    sys.exit(0)
else:
    sys.exit(1)

