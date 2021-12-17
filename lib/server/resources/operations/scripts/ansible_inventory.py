#!/usr/bin/env python3

import os
import sys
import argparse
import yaml
import re
try:
    import json
except ImportError:
    import simplejson as json

DISPLAY_ERROR = False
DS            = os.sep
CURRENT_DIR   = os.path.dirname(os.path.realpath(__file__))+DS
INVENTORY_EXT = '.yml'

class SafescaleInventory():

    def __init__(self):

        parser = argparse.ArgumentParser(description='Return merged ansible inventories (require '+INVENTORY_EXT+' files)', usage='%(prog)s [options] [host|group]')
        parser.add_argument('--list' , action='store_true', help='Return all inventories')
        parser.add_argument('--host' , type=ascii, metavar='<hostname>', help='Return selected host')
        args = parser.parse_args(sys.argv[1:len(sys.argv)]).__dict__
        
        if args['list'] and args['host']!=None or args['list']==False and args['host']==None:
            self.fatal("Require one argument in (--host, --list)")
            return
        
        # Identify command line
        if args['list']==True:
            self.success(self.load_inventory_data())
            return            
        
        if args['host']!=None:
            self.success(self.load_inventory_data_host(args['host']))
            return

        self.success(self.load_empty_data())
        return        

    ##### COMMAND LINES FUNCS #####

    # ./all.py --list
    def load_inventory_data(self) -> dict:
        return self.inventory_format(
            {'all': {'children': 
                self.merge_groups(
                    self.load_safescale_embed_inventories_groups_data(), 
                    self.load_files_inventories_groups_data(CURRENT_DIR)
                )
            }}, 
            {}, 
            0
        )

    # ./all.py --host <hostname>
    def load_inventory_data_host(self, host: str) -> dict:
        host = self.trim(host, '\s\t\r\n\'\"')
        data = self.load_inventory_data()
        if host in data['_meta']['hostvars']:
            return data['_meta']['hostvars'][host]
        else:
            return {}
       
    ##### DATA LOADING #####
       
    # Load YAML data from current file (docstring), and extract groups (no keep "all")
    def load_safescale_embed_inventories_groups_data(self) -> dict:
        f = open(__file__,"r")
        status = 0
        lines = f.readlines()
        data = []
        for line in lines:
            line = line.replace("\n","")
            if line=='"""':
                status = status + 1
            if status==1:
                data.append(line)
        data = "\n".join(data[1:len(data)])
        
        try:
            data = self.inventory_groups(yaml.safe_load(data))
        except yaml.YAMLError as exc:
            self.error("Fail to parse embed data", exc)
            data = {}
            
        return data

    # Load YAML data from files in current directory, merge it, and extract groups (no keep "all")
    def load_files_inventories_groups_data(self, path: str) -> dict:
        scriptfile  = os.path.abspath(__file__)
        files       = self.listfile(path)
        merge       = {}
        for file in files:
            if file != scriptfile:
                try:
                    ext = file.rindex('.')
                    ext = file[ext:len(file)]
                    if ext == INVENTORY_EXT:
                        try:
                            f = open(file, "r")
                            data = f.read()                        
                            data = self.inventory_groups(yaml.safe_load(data))
                            merge.update(data)
                        except yaml.YAMLError as exc:
                            self.error("Ignore "+file+": parse fail", exc)
                    else:
                        self.error("Ignore "+file+": not "+INVENTORY_EXT)
                except ValueError:
                    self.error("Ignore "+file+": not "+INVENTORY_EXT)
        return merge
       
    # Extract groups from inventory, keep "vars" from group "all" before remove that group
    def inventory_groups(self, inventory: dict) -> dict:
        groups = {}
        if 'all' in inventory:
            gvars = {}
            if 'vars' in inventory['all']:
                gvars = inventory['all']['vars']
            if 'children' in inventory['all']:
                inventory = inventory['all']['children']
                for group in inventory:
                    if not 'vars' in inventory[group]:
                        inventory[group]['vars'] = {}
                    inventory[group]['vars'] = self.merge(gvars, inventory[group]['vars'])
        return inventory      

    ##### DATA FORMATING #####

    # Create empty inventory data for ansible expect
    def load_empty_data(self) -> dict:
        return {
            '_meta'    : { 'hostvars': {} },
            'all'      : { 'children': ['ungrouped'] },
            'ungrouped': { 'children': [] }
        }

    # Format inventory data for ansible expect
    def inventory_format(self, groups: dict, parent_vars: dict, level: int) -> list:
        data = {
            '_meta'    : { 'hostvars': {} },
            'all'      : { 'children': [] },
        }
        # Recursive formating
        for groupname in groups:
        
            # Vars heritance
            if not 'vars' in groups[groupname]:
                current_vars = parent_vars
            else: 
                current_vars = self.merge(parent_vars, groups[groupname]['vars'])
            if groupname!= 'all':
                data['all']['children'].append(groupname)
            if not groupname in data:
                data[groupname] = { 'hosts': [], 'children': [] }
                
            # Manage hosts
            if 'hosts' in groups[groupname]:
                for hostname in groups[groupname]['hosts']:
                    data[groupname]['hosts'].append(hostname)
                    data['_meta']['hostvars'][hostname] = self.merge(current_vars, groups[groupname]['hosts'][hostname]);
                    
            # Manage children by recursion
            if 'children' in groups[groupname]:
                sub = self.inventory_format(groups[groupname]['children'], current_vars, level + 1)
                data['_meta']['hostvars'] = self.merge_hostvars(data['_meta']['hostvars'], sub['_meta']['hostvars'].copy())
                for subgroupname in sub:
                    if subgroupname!= '_meta':
                        if subgroupname in data['all']['children']:
                            self.error('Group "'+subgroupname+'" already exists, merge rejected')
                        else:
                            if subgroupname != 'all':
                                data['all']['children'].append(subgroupname)
                                data[subgroupname] = sub[subgroupname]
        
            # Clean up
            if groupname!= 'all':
                if len(data[groupname]['hosts'])==0:
                    del data[groupname]['hosts']
                if len(data[groupname]['children'])==0:
                    del data[groupname]['children']
                
        if level==0:
            data['ungrouped'] = { 'children': [] }
            data['all']['children'].append('ungrouped')
            
        return data

    ##### DATA MERGES #####
    
    # Regular dictionnary merge, with overload
    def merge(self, a: dict, b: dict) -> dict:
        merged = a.copy()
        merged.update(b)
        return merged

    # Merge for group, no overload allowed
    def merge_groups(self, groups1: dict, groups2: dict) -> dict:
        for group in groups2:
            if group in groups1:
                self.error("Group \""+group+"\" already exists, merge rejected")
            else:
               groups1[group] = groups2[group]
        return groups1

    # Merge for hosts, no overload allowed
    def merge_hostvars(self, hostvars1: dict, hostvars2: dict) -> dict:
        for hostname in hostvars2:
            if hostname in hostvars1:
                self.error("Host \""+hostname+"\ already exists, merge rejected")
            else:
               hostvars1[hostname] = hostvars2[hostname]
        return hostvars1

    ##### UTILS #####

    # Trim
    def trim(self, source: str, trimChars: str) -> str:
        return re.sub('^['+trimChars+']+', '',
               re.sub('['+trimChars+']+$', '', source))
      
    # Recursive list files in directory
    def listfile(self, path: str) -> list:
        files = list()
        directories = []
        for file in os.listdir(path):
            filepath = path+file
            if os.path.isfile(filepath):
                files.append(filepath)
            if os.path.isdir(filepath):
                directories.append(filepath+DS)
        for directory in directories:
            files = files + self.listfile(directory)
        return files

    ##### OUTPUTS #####

    # -- Return data with json format and process exit (0)
    def success(self, data: dict) -> None:
        print(json.dumps(data, indent=2))
        sys.exit(0)
        return         

    # -- Throw error and exit process (1)
    def fatal(self, message: str, *argv) -> None:
        print(message, file=sys.stderr)
        for message in argv:
            print('    ', message, file=sys.stderr)
        sys.exit(1)
        return

    # -- Throw error in strerr (if DISPLAY_ERROR = True)
    def error(self, message: str, *argv) -> None:
        if DISPLAY_ERROR:
            print(message, file=sys.stderr)
            for message in argv:
                print('    ', message, file=sys.stderr)

# Let's start !
SafescaleInventory()

"""
---
gateways:
  hosts: 
    {{ .PrimaryGatewayName }}:
      ansible_host: {{ .PrimaryGatewayIP }}{{ if .PrimaryGatewayPort }}
      ansible_port: {{ .PrimaryGatewayPort }}{{ end }}{{ if .SecondaryGatewayIP }}
      alias:
        - "primary_gateway"
      alias_loopback: False
    {{ .SecondaryGatewayName }}:
      ansible_host: {{ .SecondaryGatewayIP }}{{ if .SecondaryGatewayPort }}
      ansible_port: {{ .SecondaryGatewayPort }}{{ end }}{{ end }}
      alias:
        - "secondary_gateway"
      alias_loopback: False
  vars :
    ansible_user: {{ .ClusterAdminUsername }}
    ansible_ssh_private_key_file: /home/{{ .ClusterAdminUsername }}/.ssh/id_rsa
    ansible_ssh_common_args: -q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no
    ansible_python_interpreter: /usr/bin/python3
masters:
  hosts:{{- range .ClusterMasters }}
    {{ .Name }}:
      ansible_host: {{ .PrivateIP }}{{- end }}
  vars :
    ansible_user: {{ .ClusterAdminUsername }}
    ansible_ssh_private_key_file: /home/{{ .ClusterAdminUsername }}/.ssh/id_rsa
    ansible_ssh_common_args: -q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no
    ansible_python_interpreter: /usr/bin/python3
{{ if .ClusterNodes }}nodes: 
  hosts:{{- range .ClusterNodes }}
    {{ .Name }}:
      ansible_host: {{ .PrivateIP }}{{- end }}
  vars :
    ansible_user: {{ .ClusterAdminUsername }}
    ansible_ssh_private_key_file: /home/{{ .ClusterAdminUsername }}/.ssh/id_rsa
    ansible_ssh_common_args: -q -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no
    ansible_python_interpreter: /usr/bin/python3
{{ end }}"""
