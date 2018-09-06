"""
[Details]:
This script is intended to be executed locally on a Linux box to enumerate basic system info and
search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
passwords and applicable exploits.
------------------------------------------------------------------------------------------------------------
[Warning]:
This script comes as-is with no promise of functionality or accuracy.
For example, the function that links packages to running processes is based on keywords and will
not always be accurate.

Based on the linux enumeration script published by Mike Czumak (T_v3rn1x) -- @SecuritySift

Released under the MIT license
Copyright (c) 2018, Brutal

@author     Brutal
@license    http://opensource.org/licenses/MIT
"""
from __future__ import print_function

try:
    import subprocess as sub

    compatibility = False
except ImportError:
    sub = False
    compatibility = True
    # older versions of python, need to use os instead
    import os

__version__ = "2.0.0 alpha"


def exec_cmd(command_dictionary):
    """loop through dictionary, execute the commands, call print function to send to screen"""
    if not compatibility:
        for command in command_dictionary:
            _cmd = command_dictionary[command]["cmd"]
            out, error = sub.Popen(_cmd, stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            r = filter(None, out.split('\n'))
            command_dictionary[command]["results"] = r

        output_results(command_dictionary)

    else:
        for command in command_dictionary:
            _cmd = command_dictionary[command]["cmd"]
            echo_stdout = os.popen(_cmd, 'r')
            r = filter(None, echo_stdout.read().split('\n'))
            command_dictionary[command]["results"] = r


def output_results(command_dictionary):
    """print results for each previously executed command, no return value"""
    for command in command_dictionary:
        msg = command_dictionary[command]["msg"]
        results = command_dictionary[command]["results"]
        print("    [+] " + msg)
        for r in results:
            if r:
                print("        {0}".format(r))


def identify_related_packages(processes, packages, super_users):
    process_dict = {}  # dictionary to hold the processes running as super users

    for proc in processes:
        related_packages = []
        for user in super_users:
            if user and user in proc:
                procname = proc.split(" ")[4]

                if "/" in procname:
                    split_name = procname.split("/")
                    procname = split_name[len(split_name) - 1]

                for package in packages:
                    if not len(procname) < 3:
                        if procname in package:
                            if procname in process_dict:
                                related_packages = process_dict[proc]
                            if package not in related_packages:
                                related_packages.append(package)
                process_dict[proc] = related_packages

    for key in process_dict:
        print("    {0}".format(key))
        try:
            if process_dict[key][0]:
                print("         Possible Related Packages:")
                for entry in process_dict[key]:
                    print("        {0}".format(entry))
        except IndexError:
            pass


def write_header():
    big_line = "================================================================================================="
    print(big_line)
    print("LINUX PRIVILEGE ESCALATION CHECKER {0}".format(__version__))
    print(big_line)


def main():
    sys_info = {
        "OS": {
            "cmd": "cat /etc/issue",
            "msg": "Operating System",
            "results": []
        },
        "KERNEL": {
            "cmd": "cat /proc/version",
            "msg": "Kernel",
            "results": []
        },
        "HOSTNAME": {
            "cmd": "hostname",
            "msg": "Hostname",
            "results": []
        }
    }

    network_info = {
        "NETINFO": {
            "cmd": "/sbin/ifconfig -a",
            "msg": "Interfaces",
            "results": []
        },
        "ROUTE": {
            "cmd": "route",
            "msg": "Route",
            "results": []
        },
        "NETSTAT": {
            "cmd": "netstat -antup | grep -v 'TIME_WAIT'",
            "msg": "Netstat",
            "results": []
        }
    }

    drive_info = {
        "MOUNT": {
            "cmd": "mount",
            "msg": "Mount results",
            "results": []
        },
        "FSTAB": {
            "cmd": "cat /etc/fstab 2>/dev/null",
            "msg": "fstab entries",
            "results": []
        }
    }

    cron_info = {
        "CRON": {
            "cmd": "ls -la /etc/cron* 2>/dev/null",
            "msg": "Scheduled cron jobs",
            "results": []
        },
        "CRONW": {
            "cmd": "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null",
            "msg": "Writable cron dirs",
            "results": []
        }
    }

    user_info = {
        "WHOAMI": {
            "cmd": "whoami",
            "msg": "Current User",
            "results": []
        },
        "ID": {
            "cmd": "id",
            "msg": "Current User ID",
            "results": []
        },
        "ALLUSERS": {
            "cmd": "cat /etc/passwd",
            "msg": "All users",
            "results": []
        },
        "SUPUSERS": {
            "cmd": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'",
            "msg": "Super Users Found:",
            "results": []
        },
        "HISTORY": {
            "cmd": "ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null",
            "msg": "Root and current user history (depends on privs)",
            "results": []
        },
        "ENV": {
            "cmd": "env 2>/dev/null | grep -v 'LS_COLORS'",
            "msg": "Environment",
            "results": []
        },
        "SUDOERS": {
            "cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null",
            "msg": "Sudoers (privileged)",
            "results": []
        },
        "LOGGEDIN": {
            "cmd": "w 2>/dev/null",
            "msg": "Logged in User Activity",
            "results": []
        }
    }

    # noinspection PyPep8,PyPep8,PyPep8
    file_directory_perms = {
        "WWDIRSROOT": {
            "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root",
            "msg": "World Writeable Directories for User/Group 'Root'",
            "results": []
        },
        "WWDIRS": {
            "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root",
            "msg": "World Writeable Directories for Users other than Root",
            "results": []
        },
        "WWFILES": {
            "cmd": "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null",
            "msg": "World Writable Files",
            "results": []
        },
        "SUID": {
            "cmd": "find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null",
            "msg": "SUID/SGID Files and Directories",
            "results": []
        },
        "ROOTHOME": {
            "cmd": "ls -ahlR /root 2>/dev/null",
            "msg": "Checking if root's home folder is accessible",
            "results": []
        }
    }

    password_files = {
        "LOGPWDS": {
            "cmd": "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
            "msg": "Logs containing keyword 'password'",
            "results": []
        },
        "CONFPWDS": {
            "cmd": "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
            "msg": "Config files containing keyword 'password'",
            "results": []
        },
        "SHADOW": {
            "cmd": "cat /etc/shadow 2>/dev/null",
            "msg": "Shadow File (Privileged)",
            "results": []
        }
    }

    apps_and_proc = {
        "PROCS": {
            "cmd": "ps aux | awk '{print $1,$2,$9,$10,$11}'",
            "msg": "Current processes",
            "results": []
        },
        "PKGS": {
            "cmd": "",
            "msg": "Installed Packages",
            "results": []
        }
    }

    # noinspection PyPep8
    other_apps = {
        "SUDO": {
            "cmd": "sudo -V | grep version 2>/dev/null",
            "msg": "Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)",
            "results": []
        },
        "APACHE": {
            "cmd": "apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null",
            "msg": "Apache Version and Modules",
            "results": []
        },
        "APACHECONF": {
            "cmd": "cat /etc/apache2/apache2.conf 2>/dev/null",
            "msg": "Apache Config File",
            "results": []
        }
    }

    development_tools = {
        "TOOLS": {
            "cmd": "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp less 2>/dev/null",
            "msg": "Installed Tools",
            "results": []
        }
    }

    escape_strings = {
        "vi": [
            ":!bash",
            ":set shell=/bin/bash:shell"
        ],
        "awk": [
            "awk 'BEGIN {system(\"/bin/bash\")}'"
        ],
        "perl": [
            "perl -e 'exec \"/bin/bash\";'"
        ],
        "find": [
            "find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"
        ],
        "nmap": [
            "--interactive"
        ],
        "less": [
            "!/bin/sh"
        ]
    }

    write_header()

    print("\n[*] GETTING BASIC SYSTEM INFO...")
    exec_cmd(sys_info)

    print("\n\n[*] GETTING NETWORKING INFO...")
    exec_cmd(network_info)

    print("\n\n[*] GETTING FILESYSTEM INFO...")
    exec_cmd(drive_info)
    exec_cmd(cron_info)

    print("\n\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...")
    exec_cmd(user_info)
    # noinspection PyTypeChecker
    if "root" in user_info["ID"]["results"][0]:
        print("    [!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?")

    print("\n\n[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...")
    exec_cmd(file_directory_perms)
    exec_cmd(password_files)

    print("\n\n[*] ENUMERATING PROCESSES AND APPLICATIONS...")
    debian_distro = ['debian', 'ubuntu', 'kali']
    # noinspection PyTypeChecker
    if [s for s in debian_distro if s in sys_info["KERNEL"]["results"][0]]:
        apps_and_proc['PKGS']['cmd'] = "dpkg -l | awk '{$1=$4=\"\"; print $0}'"
    else:
        apps_and_proc['PKGS']['cmd'] = "rpm -qa | sort -u"
    exec_cmd(apps_and_proc)
    exec_cmd(other_apps)

    print("\n\n[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...")
    identify_related_packages(apps_and_proc["PROCS"]["results"],
                              apps_and_proc["PKGS"]["results"],
                              user_info["SUPUSERS"]["results"])

    print("\n\n[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR PRIVESC OR EXPLOIT BUILDING...\n")
    exec_cmd(development_tools)

    print("\n\n[+] Related Shell Escape Sequences...")
    for cmd in escape_strings:
        for result in development_tools["TOOLS"]["results"]:
            if cmd in result:
                for item in escape_strings[cmd]:
                    print("    {0}-->\t{1}".format(cmd, item))

    print("\n\nFinished")


if __name__ == "__main__":
    main()
