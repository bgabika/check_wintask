#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# COREX Windows Scheduled Task check plugin for Icinga 2
# Copyright (C) 2019-2022, Gabor Borsos <bg@corex.bg>
# 
# v1.1 built on 2022.12.14.
# usage: check_wintask.py --help
#
# For bugs and feature requests mailto bg@corex.bg
# 
# ---------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# Test it in test environment to stay safe and sensible before 
# using in production!
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# ---------------------------------------------------------------
# changelog:
# 2022.12.14. v1.1  - Hungarian codepage fix
# 2022.12.11. v1.0  - First release

import io
import sys

try:
    from enum import Enum
    import argparse
    import paramiko
    import re
    import textwrap

except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)


class CheckState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckWinTask:

    def __init__(self):

        self.pluginname = "check_wintask.py"
        self.result_list = []
        self.parse_args()


    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.pluginname, 
            add_help=True, 
            formatter_class=argparse.RawTextHelpFormatter,
            description = textwrap.dedent("""
            PLUGIN DESCRIPTION: Windows Scheduled Task check plugin for ICINGA 2.
            This plugin checks Microsoft Windows OS scheduled tasks over SSH. Plugin works from Microsoft Documentation error codes. For error code details check Microsoft sources.
            This plugin checks standard output result codes (cli: LastTaskResult, GUI: Last Run Result) of scheduled task and if task does not have any trigger.
            Trigger checks take a lot of time (1-2 sec per task) so trigger check works only with 'include-taskname' option."""),
            epilog = textwrap.dedent(f"""
            Examples:
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey /home/john.doe/mykey
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey /home/john.doe/mykey --ignore-resultcode 0x41303
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey /home/john.doe/mykey --ignore-resultcode 0x41303 --ignore-nextruntime --ignore-taskname 'my taskname'
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey /home/john.doe/mykey --include-taskname 'my taskname 1' --include-taskname 'my taskname 2'"""))
        
        ssh_connect_opt = parser.add_argument_group('SSH connection arguments', 'hostname, sshuser, sshport, sshkey')

        ssh_connect_opt.add_argument('--hostname', dest="hostname", type=str, required=True, help="host FQDN or IP")
        ssh_connect_opt.add_argument('--sshport', type=int, required=False, help="ssh port, default port: 22", default=22)
        ssh_connect_opt.add_argument('--sshuser', type=str, required=True, help="ssh user")
        ssh_connect_opt.add_argument('--sshkey', type=str, required=True, help="ssh key file")


        check_procedure_opt = parser.add_argument_group('Task arguments', 'ignore-taskname, include-taskname, ignore-resultcode, ignore-nextruntime')
        
        check_procedure_opt.add_argument('--ignore-taskname', dest='ignore_taskname', action='append', metavar='"MY TASKNAME"',
                                        help='Ignore task from checking, --ignore-taskname "taskname 1" --ignore-taskname "taskname 2" ...etc', default=[])

        check_procedure_opt.add_argument('--include-taskname', dest='include_taskname', action='append', metavar='"MY TASKNAME"',
                                        help='Include task for checking, --include-taskname "taskname 1" --ignore-taskname "taskname 2" ...etc', default=[])
        
        check_procedure_opt.add_argument('--ignore-resultcode', dest='ignore_resultcode', action='append', metavar='"0x123456"',
                                        help='Ignore tasks with "Last Run Result" code, --ignore-resultcode "0x41301" --ignore-resultcode "0x41303" ...etc', default=[])
        
        check_procedure_opt.add_argument('--ignore-nextruntime', dest='ignore_nextruntime', action='store_true', required=False, help="Ignore task check if task is not scheduled or no trigger.")

        self.options = parser.parse_args()



    def main(self):
        
        task_dict_list = self.get_windows_task(self.options.hostname, self.options.sshport, self.options.sshuser, self.options.sshkey)
        self.check_task_details(task_dict_list)
        self.check_exitcodes(self.result_list)
    


    @staticmethod
    def check_ssh(hostname, port, username, keyfile):
        keyfile = paramiko.RSAKey.from_private_key_file(keyfile)
        ssh = paramiko.SSHClient()
        
        try:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port, username, pkey=keyfile, allow_agent=False, look_for_keys=False, timeout=30, banner_timeout=30, auth_timeout=30)
            status = 0
            ssh.close()
            return status
        except:
            print(f"\tCould not connect to {hostname}!")
            sys.exit(1)
            

    @staticmethod
    def clean_string(mystring):
        return re.sub('\s+',' ',mystring)



    @staticmethod
    def result_code_hex_converter(decimal_code):
        return hex(decimal_code)



    @staticmethod
    def check_task_result_string(task_hex_code):
        
        if task_hex_code == "0x0":
            return "The task did run properly."
        
        elif task_hex_code == "0x1":
            return "The task did not run properly."
        
        elif task_hex_code == "0x2":
            return "File not found."

        elif task_hex_code == "0xa":
            return "The environment is incorrect."

        elif task_hex_code == "0x103":
            return "No more data is available."

        elif task_hex_code == "0x41301":
            return "The task is currently running."

        elif task_hex_code == "0x41302":
            return "The task will not run at the scheduled times because it has been disabled."

        elif task_hex_code == "0x41303":
            return "The task has not yet run."
        
        elif task_hex_code == "0x41305":
            return "One or more of the properties that are needed to run this task on a schedule have not been set."
        
        elif task_hex_code == "0x41306":
            return "The last run of the task was terminated by the user."

        elif task_hex_code == "0x41307":
            return "Either the task has no triggers or the existing triggers are disabled or not set."

        elif task_hex_code == "0x420":
            return "An instance of the service is already running."

        elif task_hex_code == "0x800710e0":
            return "The operator or administrator has refused the request."

        elif task_hex_code == "0x800700b7":
            return "Cannot create a file when that file already exists."
        
        elif task_hex_code == "0x8007042b":
            return "The process terminated unexpectedly."

        elif task_hex_code == "0x40010004":
            return "Debugger terminated the process."
        
        elif task_hex_code == "0x80004003":
            return "Invalid pointer."

        elif task_hex_code == "0x80004005":
            return "Unspecified error."

        elif task_hex_code == "0x80090030":
            return "The device that is required by this cryptographic provider is not ready for use."

        elif task_hex_code == "0x10000000":
            return "Task has a special error, see: https://devblogs.microsoft.com/oldnewthing/20121227-00/?p=5713"

        elif task_hex_code == "0x8000000a":
            return "The data necessary to complete this operation is not yet available."

        elif task_hex_code == "0x800710e0":
            return "The operator or administrator has refused the request."

        else:
            return "UNKNOWN error code!"



    def run_ssh_command(self, command, hostname, sshport, sshuser, keyfile, email_rcpt=""):
        
        ssh_status = self.check_ssh(hostname, sshport, sshuser, keyfile)
        keyfile = paramiko.RSAKey.from_private_key_file(keyfile)
        if ssh_status == 0:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port=sshport, username=sshuser, pkey=keyfile, allow_agent=False, look_for_keys=False, timeout=30, banner_timeout=30, auth_timeout=30)
            stdin, stdout, stderr = ssh.exec_command(command)
            stdin.flush()

            stdout = io.TextIOWrapper(stdout, encoding='852', errors='replace')
            output = (''.join(stdout.readlines()))
        else:
            self.output(CheckState.WARNING, f"Cannot run remote command ({command}) on {hostname}, please check ssh connection!")
            
        return output



    def get_windows_task(self, hostname, sshport, sshuser, sshkey):

        self.include_taskname_list = [x.strip() for x in self.options.include_taskname]
        
        if len(self.include_taskname_list) > 0:
            ps_array = ','.join(map("'{0}'".format, self.include_taskname_list))
            wincommand = """powershell "$task_array = (ps_array); foreach ($i in $task_array) {(Get-ScheduledTask -TaskName $i | Get-ScheduledTaskInfo) | select LastRunTime, LastTaskResult, NextRunTime, NumberOfMissedRuns, TaskName, TaskPath; if ($i -gt 1) {$triggerarray = (Get-ScheduledTask -TaskName $i.trim()).Triggers; if ($triggerarray.count -gt 0) {(Get-ScheduledTask -TaskName $i).Triggers[0] | select Enabled} else {echo "Enabled:False"}}}\""""
            wincommand = wincommand.replace("ps_array", ps_array)
        else:
            wincommand = """powershell "Get-ScheduledTask | Get-ScheduledTaskInfo | Sort-Object\""""
        
        perfdata = self.run_ssh_command(wincommand, hostname, sshport, sshuser, sshkey)
        perfdata_list = perfdata.splitlines()
        perfdata_list = list(filter(None, perfdata_list))
        element_index_list =  []
        full_task_list = []
        counter = 0
        for element in perfdata_list:
            if "LastRunTime" in element:
                element_index_list.append(counter)
            counter += 1

        for index_number in element_index_list:
            single_tasklist = perfdata_list[index_number:index_number+7]
            full_task_list.append(single_tasklist)


        full_task_dict_list = []
        for task_details_list in full_task_list:
            task_dict = {}
            for single_task_detail in task_details_list:
                task_preference_list = single_task_detail.split(":", 1)
                try:
                    task_dict[task_preference_list[0].strip()] = task_preference_list[1].strip()
                except:
                    task_dict[task_preference_list[0].strip()] = task_preference_list[1]

            full_task_dict_list.append(task_dict)
        
        return full_task_dict_list



    def check_task_details(self, task_dict_list):

        def internal_task_check(task_include):
            task_location = task_detail_dict["TaskPath"]
            task_nextruntime = task_detail_dict["NextRunTime"]
            task_result_code = int(task_detail_dict["LastTaskResult"])
            
            try:
                task_trigger = task_detail_dict["Enabled"]
            except:
                task_trigger = "True"

            task_hex_code = self.result_code_hex_converter(task_result_code)
            
            if task_hex_code not in self.options.ignore_resultcode:
                task_result_string = self.check_task_result_string(task_hex_code)
                output_message = f"'{task_name}': {task_result_string} Task location: {task_location}. Result code: {task_hex_code}"

                if task_detail_dict["LastTaskResult"] != "0":
                    self.result_list.append(f"WARNING - {output_message}")
                else:
                    if self.options.ignore_nextruntime == False:
                        if task_nextruntime == "" or task_trigger == "False":
                            self.result_list.append(f"WARNING - '{task_name}' is not scheduled or no trigger. Task location: {task_location}.")
                        else:
                            if task_include == True:
                                self.result_list.append(f"OK - {output_message}")
                    else:
                        if task_include == True:
                                self.result_list.append(f"OK - {output_message}")

        taskname_list = []
        for task_detail_dict in task_dict_list:
            taskname_list.append(task_detail_dict['TaskName'])

        different_list = list(set(self.include_taskname_list) - set(taskname_list))
        
        if len(different_list) > 0:
            for missing_taskname in different_list:
                self.result_list.append(f"WARNING - '{missing_taskname}' task can not be found. Please check task name!")

        for task_detail_dict in task_dict_list:
            task_name = task_detail_dict['TaskName']
            if len(self.include_taskname_list) > 0:
                task_include = True
                if task_name in self.include_taskname_list:
                    internal_task_check(task_include)
            else:
                task_include = False
                if task_name not in self.options.ignore_taskname:
                    internal_task_check(task_include)
                


    def check_exitcodes(self, result_list):

        if any("CRITICAL" in x for x in result_list):
            [print(x) for x in result_list if re.search("CRITICAL", x)]
        if any("WARNING" in x for x in result_list):
            [print(x) for x in result_list if re.search("WARNING", x)]
        if any("OK -" in x for x in result_list):
            [print(x) for x in result_list if re.search("OK -", x)]
        
    
        if any("CRITICAL" in x for x in result_list):
            sys.exit(2)
        if any("WARNING" in x for x in result_list):
            sys.exit(1)
        
        sys.exit(0)
        


check_win = CheckWinTask()
check_win.main()
