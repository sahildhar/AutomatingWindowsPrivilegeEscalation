#!/usr/bin/env python

__Author__='Sahil Dhar'

import wmi
from subprocess import PIPE,Popen
import os.path
from os import system

raw_permission_data = ""
exe_paths = set()
unquoted_service_paths = {}

def Exec(cmd):
	out =  Popen(cmd,shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)
	return str(out.stdout.read()+out.stderr.read())


def match(l):
	permatch = []
	permatch.append("BUILTIN\Users:(I)(F)")
	permatch.append("BUILTIN\Users:(F)")
	permatch.append("Everyone:(CI)(F)")

	for i in l:
		if i in permatch:
			return True
			break

def find_paths(lines):
	files_data = {}
	find = {}
	for line in lines.split('\n'):
		if len(line.split('\\')) > 2:
			if '.exe ' in line:
				executable = line.split('.exe ')[0]+'.exe'
				files_data[executable] = []
				files_data[executable].append(line.split('.exe ')[1])
		if not 'successfully' in line.lower() and not '.exe' in line and line.strip() != '':
			files_data[executable].append(line.strip())

	for x,v in files_data.iteritems():
		if match(v):
			find[x] = v
	if len(find) > 0:
		print "[+] Following executables have weak access permissions"
		for x,v in find.iteritems():
			print '\n\t[--> %s %s' %(x,v)
		print "\n\t[INFO] Replace above executables with one of your own executable to get shell :)\n"
	else:
		print "[!] No misconfigured permissions for service executables were found"

from _winreg import *
def reg_lookup():
	msi_installer_config_path = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
	try:
		key1 = OpenKey(HKEY_LOCAL_MACHINE,msi_installer_config_path,0,KEY_READ)
		key2 = OpenKey(HKEY_CURRENT_USER,msi_installer_config_path,0,KEY_READ)
		keyinfo1 = EnumValue(key1,0) # 0 indicates Enum First key Value except default ones
		keyinfo2 = EnumValue(key2,0)

		name1,value1,v_type1 = keyinfo1
		name2,value2,v_type2 = keyinfo2
		if value1 + value1 == 2:
			return True
	except Exception,ex:
		if ex.winerror == 2:
			print '\n[!] No misconfigured MSI registry entry found'

def get_service_info():
    global exe_paths
    global unquoted_service_paths
    wmi_obj = wmi.WMI()
    wql = "SELECT * from Win32_Service"
    for s in wmi_obj.query(wql):
        service_path = s.wmi_property("PathName").value
        if service_path != None:
            service_path = service_path.lower()
            exe_path = service_path.split('.exe')[0].lstrip('"')+'.exe'
            base_path = service_path.split('.exe')[0].lstrip('"').split('\\')
            if "system32" not in service_path:
                exe_paths.add(exe_path)
            if base_path[1].lower() != "windows"  and '"' not in service_path:
                unquoted_service_paths[s.wmi_property("DisplayName").value] = service_path


if __name__=='__main__':
    system('cls')
    get_service_info()

    for exe_path in exe_paths:
        raw_permission_data += Exec('icacls "%s"' %(exe_path))

    find_paths(raw_permission_data)


    if len(unquoted_service_paths.keys()) > 0:
        print "\n[+] Found %d Unquoted Service Path Issues" %(len(unquoted_service_paths.keys()))
        for key,value in unquoted_service_paths.iteritems():
            print '\n'+'_'*30
            print '[+] Service Name: %s' %key
            print '\t[--> Service Path: %s' %value

    else:
        print "\n[!] No Unquoted Service Path Issues were found"

    if reg_lookup():
        print "\n[+] Found misconfigured MSI registry entries"
        print "\t[--> Use msiexec /quiet /qn /i <shell.msi> to execute commands with elevated privileges"
