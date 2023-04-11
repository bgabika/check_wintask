
# check_wintask

COREX Windows Scheduled Task check plugin for Icinga 2
 
### Features
 - checks Windows Tasks output codes over SSH
 - Plugin works from Microsoft Documentation error codes. For error code details check Microsoft sources.
 - This plugin checks standard output result codes (cli: LastTaskResult, GUI: Last Run Result) of scheduled task and if task does not have any trigger.
   Trigger checks take a lot of time (1-2 sec per task) so trigger check works only with 'include-taskname' option.
 - for more details run check_wintask.py --help

### Usage

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_wintask.py --hostname mywin.mydomain.com --sshuser john.doe --sshkey /var/lib/nagios/.ssh/id_rsa --include-taskname "SAP Booking Data" --include-taskname "Daily report"
WARNING - 'Daily report': The task did not run properly. Task location: \. Result code: 0x1
OK - 'SAP Booking Data': The task did run properly. Task location: \. Result code: 0x0

</code></pre>


### Version

 - v1.11

### ToDo

 - waiting for bugs or feature requests (-:

## Changelog
 - version 1.11 Add new exit code
 - [initial release] version 1.1

