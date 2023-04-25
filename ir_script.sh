#!/bin/bash

# Instructions:
# 1. Ensure the script is executable, run "chmod +x <script_name>"
# 2. Run with Sudo privileges, "sudo ./<script_name>"
# 3. The tools folder needs to be place in the same directory as the script.

# The purpose of this scirpt is to gather information in an incident reponse case. 
# It was tested on Rocky 8 and Rocky 9. 
# It collects:
# - Volatile data in the order of volatility [NIST]:
#	1.	(optional) Memory image
# 	2.	Network connections & configurations
#	3.	Login sessions
#	4.	Contents of memory
#	5.	Running processes
#	6.	Open files
#	7.	Operating system information
# Additionally it collects following non-volatile data:
# 	8. Cron files
# 	9. User and group lists
# 	10. /var/logs
#	11. Suspicious and Keyfiles
#	12. (optional) Compromise scanning with Thor-lite
#   13. (optional) SLURM jobs executed on the node

# The script uses local binaries and additionally following tools provided with the script:
# (Binaries need to be provided manually)
# - AVML: Memory collection
# - Unhide: Lists hidden processes / ports
# - Thor-lite: Compromise assessment tool

# Please make sure that the file system under / is mounted with the option `noatime`. 
# If this is not the case, please execute the command 
# `mount -o remount,noatime /dev/sdX /` where X is the filesystem 
# under /. This ensures that no timestamps are modified during investigation.
# Note that `noatime` option has no effect on NFS mounts.

# Please create an own license if you intend to use the thor-lite scanner.
# A license can be created under "https://www.nextron-systems.com/thor-lite/".
# Afterwards place it in the tools/thor-lite folder.




[[ $UID == 0 || $EUID == 0 ]] || (
	echo "Must be root!"s
	exit 1
	) || exit 1


echo "Please make sure that the filesystem under / is mounted with 'noatime'."
echo "If not, please remount file system with 'mount -o remount,noatime /dev/sdX'."

# Saving 
if ! [[ -n $OUT_PATH ]]; then
  echo -n "Directory to store data: "
  read OUT_PATH
  [[ -d $OUT_PATH ]] || `mkdir -p "$OUT_PATH"` || (
    echo "Not a valid directory."
    exit 1
    ) || exit 1
fi

# Binary location
bin="$(pwd)/tools"
[[ -d $bin ]] || ( 
  echo "Linux IR binaries cannot be found."
  echo "This script must be run inside its own directory."
  exit 1
  ) || exit 1

host="$(hostname)-$(date +%Y.%m.%d-%H.%M.%S)"
saveto="$OUT_PATH/$host"
mkdir -p "$saveto"
logfile="$saveto/log.txt"

# Creating output directory structure
chmod 600 $saveto
mkdir $saveto/network
mkdir $saveto/login_sessions
mkdir $saveto/memory
mkdir $saveto/process
mkdir $saveto/open_files
mkdir $saveto/persistence # Cron
mkdir $saveto/system
mkdir $saveto/users_groups
mkdir $saveto/logs
mkdir $saveto/files


log() {
	echo "$(date +"%b %d %H:%M:%S") $(hostname) irscript: $1" | tee -a "$logfile"
}

# Outputs every content in cron.* files
get_cron() {
	FILE_DIR="/etc/cron.*"
	for FILES in $FILE_DIR; do
	  if [[ $(ls $FILES | wc -l) -gt 0 ]]; then
	    DIR="$FILES/*"
	    for f in $DIR; do
	      DIR_PATH="${f%/*}"
	      mkdir -p $saveto/persistence/cron/$DIR_PATH
	      BASEPATH="${f##*/}"
	      cat $f | tee -a $saveto/persistence/cron/$DIR_PATH/$BASEPATH.txt
	    done
	  fi
	done
}

cat_dir() {
  DIR=$1
  for f in $DIR; do
  echo $f
  cat $f
  echo ""
done
}

create_memory() {
	# NOTE: If the kernel feature kernel_lockdown is enabled, AVML will not be able to acquire memory.
	log "$bin/avml $host.mem > $saveto/memory/$host.mem"
	$bin/avml $saveto/memory/$host.mem 2>&1
	log "Computing hash of collected avml memory file"
	md5sum $saveto/memory/$host.mem | tee -a $saveto/memory/$host.mem.md5
	sha1sum $saveto/memory/$host.mem | tee -a $saveto/memory/$host.mem.sha1
	sha256sum $saveto/memory/$host.mem | tee -a $saveto/memory/$host.mem.sha256
}

get_thor() {
  FILE="$bin/thor_lite/*.lic"
  if [ -f $FILE ]; then
    echo "License file exists."
    log "# Starting thor-lite scan. > $saveto/thor"
    log "# $bin/thor-lite/thor-lite-linux --quick --allreasons -e $saveto/thor"
    mkdir -p $saveto/thor
    echo "Do you wish to update the thor signatures? (Needs internet connection)"
    select yn in "Yes" "No"; do
      case $yn in
          Yes ) $bin/thor_lite/thor-lite-util update; break;;
          No ) echo "No updates applied."; break 2;;
      esac
    done
    echo "Creating report."
    $bin/thor_lite/thor-lite-linux --quick --allreasons -e $saveto/thor

  else
    echo "Please create a license and place it under $bin/thor_lite."
  fi
}

get_slurm() {
	mkdir -p $saveto/slurm
	echo -n "Enter the username who started the jobs: "
	read USERNAME

	echo -n "Enter the start date for the search period (YYYY-MM-DD): "
	read STARTDATE


	echo -n "Enter the end date for the search period (YYYY-MM-DD): "
	read ENDDATE

	log "# sacct -X --user=$USERNAME -S $STARTDATE -E $ENDDATE --format=jobid,jobname,partition,account,alloccpus,state,exitcode,start,end,nodelist > $saveto/slurm/slurm_jobs.txt"
	sacct -X --user=$USERNAME -S $STARTDATE -E $ENDDATE --format=jobid,jobname,partition,account,alloccpus,state,exitcode,start,end,nodelist | tee -a $saveto/slurm/slurm_jobs.txt
}


# Start the log.
echo -n > "$logfile"
log "# Incident response volatile data collection script."
log "# Starting data collection..."


# Memory acquisition
echo "======================================================================================" >> $logfile
log "# Collecting memory image."

echo "It is adviced to create a memory image before starting the script as some timestamps will be modified by commands that are used."
echo "Do you wish to create a memory image?"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) create_memory; break;;
        No ) echo "Continuing with script."; break;;
    esac
done

log "# Collecting memory image done."
echo "======================================================================================" >> $logfile


# Network information
echo "======================================================================================" >> $logfile
log "# Collecting network information."

log "# ifconfig -a > $saveto/network/ifconfig.txt"
echo "List of network devices:" | tee -a $saveto/network/ifconfig.txt
echo "ifconfig -a:" | tee -a $saveto/network/ifconfig.txth
ifconfig -a | tee -a $saveto/network/ifconfig.txt 2>&1

log "# iptables -L -n -v --line-numbers > $saveto/network/iptables.txt"
echo "List of iptables:" | tee -a $saveto/network/iptables.txt
echo "iptables -L -n -v --line-numbers:" | tee -a $saveto/network/iptables.txt
iptables -L -n -v --line-numbers | tee -a $saveto/network/iptables.txt 2>&1

# ss will replace netstat in later releases
if ss -anepo &>/dev/null; then
	log "# ss -anepo > $saveto/network/connections.txt"
	echo "List of network connections:" | tee -a $saveto/network/connections.txt
	echo "ss -anepo:" | tee -a $saveto/network/connections.txt
	ss -anepo | tee -a $saveto/network/connections.txt 2>&1
else 
	log "# netstat -nalpo > $saveto/network/connections.txt"
	echo "List of network connections:" | tee -a $saveto/network/connections.txt
	echo "netstat -nalpo:" | tee -a $saveto/network/connections.txt
	netstat -nalpo | tee -a $saveto/network/connections.txt 2>&1
fi

log "# netstat -i > $saveto/network/interfaces.txt"
echo "List of interfaces:" | tee -a $saveto/network/interfaces.txt
echo "netstat -i:" | tee -a $saveto/network/interfaces.txt
netstat -i | tee -a $saveto/network/interfaces.txt 2>&1

log "# netstat -r > $saveto/network/routing_table.txt"
echo "List of kernel network routing table:" | tee -a $saveto/network/routing_table.txt
echo "netstat -r:" | tee -a $saveto/network/routing_table.txt
netstat -r | tee -a $saveto/network/routing_table.txt 2>&1

log "# netstat -plant > $saveto/network/netstat_plant.txt"
echo "List of Network Connections:" | tee -a $saveto/network/netstat_plant.txt
echo "netstat -plant:" | tee -a $saveto/network/netstat_plant.txt
netstat -plant | tee -a $saveto/network/netstat_plant.txt 2>&1

log "# arp -a > $saveto/network/arp_cache.txt"
echo "List of the ARP table cache (Address Resolution Protocol):" | tee -a $saveto/network/arp_cache.txt
echo "arp -a:" | tee -a $saveto/network/arp_cache.txt
arp -a | tee -a $saveto/network/arp_cache.txt 2>&1

log "# ip route > $saveto/network/routing.txt"
echo "List routing table:" | tee -a $saveto/network/routing.txt
echo "ip route:" | tee -a $saveto/network/routing.txt
ip route | tee -a $saveto/network/routing.txt 2>&1

# If it takes too long, insert "s" as argument for quick scanning
log "# unhide-tcp -lv > $saveto/network/hidden_ports.txt"
echo "List hidden ports:" | tee -a $saveto/network/hidden_ports.txt
echo "unhide-tcp -lv:" | tee -a $saveto/network/hidden_ports.txt
$bin/Unhide/unhide-tcp -lv | tee -a $saveto/network/hidden_ports.txt 2>&1

log "# Collecting network information done."
echo "======================================================================================" >> $logfile


# Login sessions
echo "======================================================================================" >> $logfile
log "# Collecting login session information."

log "# find /var/log -maxdepth 1 -type f -name "btmp*" -exec last -Faiwx -f {} \; > $saveto/login_sessions/bad_login.txt"
echo "List failed logins:" | tee -a $saveto/login_sessions/bad_loging.txt
echo "find /var/log -maxdepth 1 -type f -name "btmp*" -exec last -Faiwx -f {} \;:" | tee -a $saveto/login_sessions/bad_loging.txt
find /var/log -maxdepth 1 -type f -name "btmp*" -exec last -Faiwx -f {} \; | tee -a $saveto/login_sessions/bad_loging.txt 2>&1

log "# who -H > $saveto/login_sessions/users_logged_on.txt"
echo "List of users currently logged on:" | tee -a $saveto/login_sessions/users_logged_on.txt
echo "who -H:" | tee -a $saveto/login_sessions/users_logged_on.txt
who -H | tee -a $saveto/login_sessions/users_logged_on.txt 2>&1

log "# find / -maxdepth 2 -type f -name "utmp*" -exec last -Faiwx -f {} \; > $saveto/login_sessions/active_loging.txt"
echo "List active logon information (utmp):" | tee -a $saveto/login_sessions/active_login.txt
echo "find / -maxdepth 2 -type f -name "utmp*" -exec last -Faiwx -f {} \;:" | tee -a $saveto/login_sessions/active_login.txt
find / -maxdepth 2 -type f -name "utmp*" -exec last -Faiwx -f {} \; | tee -a $saveto/login_sessions/active_login.txt 2>&1

log "# lastlog  > $saveto/login_sessions/lastlog.txt"
echo "List lastlog:" | tee -a $saveto/login_sessions/lastlog.txt
echo "lastlog :" | tee -a $saveto/login_sessions/lastlog.txt
lastlog | tee -a $saveto/login_sessions/lastlog.txt 2>&1

log "# find /var/log -maxdepth 1 -type f -name "wtmp*" -exec last -Faiwx -f {} \; > $saveto/login_sessions/wtmp.txt"
echo "List historic logon information:" | tee -a $saveto/login_sessions/wtmp.txt
echo "find /var/log -maxdepth 1 -type f -name "wtmp*" -exec last -Faiwx -f {} \;:" | tee -a $saveto/login_sessions/wtmp.txt
find /var/log -maxdepth 1 -type f -name "wtmp*" -exec last -Faiwx -f {} \; | tee -a $saveto/login_sessions/wtmp.txt 2>&1

log "# last > $saveto/login_sessions/last.txt"
echo "List of last logged in users:" | tee -a $saveto/login_sessions/last.txt
echo "last :" | tee -a $saveto/login_sessions/last.txt
last | tee -a $saveto/login_sessions/last.txt 2>&1

log "# cat /var/log/auth.log > $saveto/login_sessions/authlog.txt"
echo "Listing auth log:" | tee -a $saveto/login_sessions/authlog.txt
echo "cat /var/log/auth.log :" | tee -a $saveto/login_sessions/authlog.txt
cat /var/log/auth.log | tee -a $saveto/login_sessions/authlog.txt 2>&1

log "# cat /etc/ssh/ssh_config > $saveto/login_sessions/ssh_config.txt"
echo "Listing ssh config:" | tee -a $saveto/login_sessions/ssh_config.txt
echo "cat /etc/ssh/ssh_config :" | tee -a $saveto/login_sessions/ssh_config.txt
cat /etc/ssh/ssh_config | tee -a $saveto/login_sessions/ssh_config.txt 2>&1

log "# cat /etc/ssh/sshd_config > $saveto/login_sessions/sshd_config.txt"
echo "Listing sshd config:" | tee -a $saveto/login_sessions/sshd_config.txt
echo "cat /etc/ssh/sshd_config :" | tee -a $saveto/login_sessions/sshd_config.txt
cat /etc/ssh/sshd_config | tee -a $saveto/login_sessions/sshd_config.txt 2>&1

log "# Collecting login session information done."
echo "======================================================================================" >> $logfile


# Memory info
echo "======================================================================================" >> $logfile
log "# Collecting memory information."

log "# free > $saveto/memory/free.txt"
echo "List of system memory information:" | tee -a $saveto/system/free.txt
echo "free:" | tee -a $saveto/system/free.txt
free | tee -a $saveto/system/free.txt 2>&1

log "# cat /proc/meminfo > $saveto/memory/meminfo.txt"
echo "List of system memory information:" | tee -a $saveto/memory/meminfo.txt
echo "cat /proc/meminfo:" | tee -a $saveto/memory/meminfo.txt
cat /proc/meminfo | tee -a $saveto/memory/meminfo.txt 2>&1

log "# vmstat -aS M > $saveto/memory/vmstat.txt"
echo "List memory statistics:" | tee -a $saveto/memory/vmstat.txt
echo "vmstat -aS M:" | tee -a $saveto/memory/vmstat.txt
vmstat -aS M | tee -a $saveto/memory/vmstat.txt 2>&1

log "# vmstat -d > $saveto/memory/vmstat_disk.txt"
echo "List memory statistics:" | tee -a $saveto/memory/vmstat_disk.txt
echo "vmstat -d:" | tee -a $saveto/memory/vmstat_disk.txt
vmstat -d | tee -a $saveto/memory/vmstat_disk.txt 2>&1

log "# Collecting memory information done."
echo "======================================================================================" >> $logfile


# Process info
echo "======================================================================================" >> $logfile
log "# Collecting process information."

log "# pstree -pn> $saveto/process/pstree.txt"
echo "List running processes with PID and numerically sorted:" | tee -a $saveto/process/pstree.txt
echo "pstree -pn:" | tee -a $saveto/process/pstree.txt
pstree -pn | tee -a $saveto/process/pstree.txt 2>&1

log "# ps -aux > $saveto/process/ps_aux.txt"
echo "List running processes: " | tee -a $saveto/process/ps_aux.txt
echo "ps -aux:" | tee -a $saveto/process/ps_aux.txt
ps -aux | tee -a $saveto/process/ps_aux.txt 2>&1

log "# ls -alR /proc/*/cwd 2> /dev/null | grep -E \"tmp|dev\" > $saveto/process/process_dev_tmp.txt"
echo "List all processes running from /tmp or /dev directory " | tee -a $saveto/process/process_dev_tmp.txt
echo "ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev":" | tee -a $saveto/process/process_dev_tmp.txt
ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev" | tee -a $saveto/process/process_dev_tmp.txt 2>&1

# Exe directory contains the Link to the executable of this process with the process identification
log "# find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $saveto/process/process_symlink.txt"
echo "Get process symbolic links: " | tee -a $saveto/process/process_symlink.txt
echo "find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null: " | tee -a $saveto/process/process_symlink.txt
find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null | tee -a $saveto/process/process_symlink.txt 2>&1

log "# lsof 2> /dev/null | grep deleted > $saveto/process/deleted_binary.txt"
echo "List of deleted binaries still running: " | tee -a $saveto/process/deleted_binary.txt
echo "lsof 2> /dev/null | grep deleted:" | tee -a $saveto/process/deleted_binary.txt
lsof 2> /dev/null | grep deleted | tee -a $saveto/process/deleted_binary.txt 2>&1

log "# find /proc/[0-9]*/fd -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $saveto/process/process_fd.txt"
echo "List of process fd links: " | tee -a $saveto/process/process_fd.txt
echo "find /proc/[0-9]*/fd -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null:" | tee -a $saveto/process/process_fd.txt
find /proc/[0-9]*/fd -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null | tee -a $saveto/process/process_fd.txt 2>&1

log "# find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > $saveto/process/process_cmdline.txt"
echo "List of process cmdline: " | tee -a $saveto/process/process_cmdline.txt
echo "find /proc/[0-9]*/cmdline | xargs head 2>/dev/null:" | tee -a $saveto/process/process_cmdline.txt
find /proc/[0-9]*/cmdline | xargs head 2>/dev/null| tee -a $saveto/process/process_cmdline.txt 2>&1

log "# find /proc/[0-9]*/environ | xargs head 2>/dev/null > $saveto/process/process_env_var.txt"
echo "List of process environment variables: " | tee -a $saveto/process/process_env_var.txt
echo "find /proc/[0-9]*/environ | xargs head 2>/dev/null:" | tee -a $saveto/process/process_env_var.txt
find /proc/[0-9]*/environ | xargs head 2>/dev/null | tee -a $saveto/process/process_env_var.txt 2>&1

log "# $bin/Unhide/unhide-linux -v quick reverse checksysinfo > $saveto/process/hidden_process.txt"
echo "List of hidden process : " | tee -a $saveto/process/hidden_process.txt
echo "$bin/Unhide/unhide-linux -v quick reverse checksysinfo:" | tee -a $saveto/process/hidden_process.txt
$bin/Unhide/unhide-linux -v quick reverse checksysinfo | tee -a $saveto/process/hidden_process.txt 2>&1

log "# Collecting process information done."
echo "======================================================================================" >> $logfile


# Open files information
echo "======================================================================================" >> $logfile
log "# Collecting open files information."

log "# lsof -l> $saveto/network/lsof.txt"
echo "List open files" | tee -a $saveto/network/lsof.txt
echo "lsof -l:" | tee -a $saveto/network/lsof.txt
lsof -l | tee -a $saveto/network/lsof.txt 2>&1

log "# Collecting open files information done."
echo "======================================================================================" >> $logfile


# General host information
echo "======================================================================================" >> $logfile
log "# Collecting system information."

log "# hostnamectl > $saveto/system/hostnamectl.txt"
echo "hostnamectl:" | tee -a $saveto/system/hostnamectl.txt
hostnamectl | tee -a  $saveto/system/hostnamectl.txt 2>&1

log "# uname -a > $saveto/system/uname.txt"
echo "Linux version and kernel information:" | tee -a $saveto/system/uname.txt
echo "uname -a:" | tee -a $saveto/system/uname.txt
uname -a | tee -a $saveto/system/uname.txt 2>&1

log "# cat /proc/version > $saveto/system/kernel_version.txt"
echo "Kernel version:" | tee -a $saveto/system/kernel_version.txt
echo "cat /proc/version:" | tee -a $saveto/system/kernel_version.txt
cat /proc/version | tee -a $saveto/system/kernel_version.txt 2>&1

log "# /sbin/sysctl -a > $saveto/system/kernel_params.txt"
echo "Kernel parameters:" | tee -a $saveto/system/kernel_params.txt
echo "/sbin/sysctl -a:" | tee -a $saveto/system/kernel_params.txt
/sbin/sysctl -a | tee -a $saveto/system/kernel_params.txt 2>&1


log "# find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat > $saveto/system/kernel_release.txt"
echo "Collecting kernel release:" | tee -a $saveto/system/kernel_release.txt
echo "find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat:" | tee -a $saveto/system/kernel_release.txt
find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat | tee -a $saveto/system/kernel_release.txt 2>$1

log "# timedatectl > $saveto/system/timedatectl.txt"
echo "List of system date/time/timezone:" | tee -a $saveto/system/timedatectl.txt
echo "timedatectl:" | tee -a $saveto/system/timedatectl.txt
timedatectl | tee -a $saveto/system/timedatectl.txt 2>&1

log "# cat $PATH > $saveto/system/path.txt"
echo "List $PATH: " | tee -a $saveto/system/path.txt
echo "cat $PATH:" | tee -a $saveto/system/path.txt
cat $PATH | tee -a $saveto/system/path.txt 2>&1

log "# uptime > $saveto/system/uptime.txt"
echo "List uptime of machine: " | tee -a $saveto/system/uptime.txt
echo "uptime:" | tee -a $saveto/system/uptime.txt
uptime | tee -a $saveto/system/uptime.txt 2>&1

log "# last reboot > $saveto/system/last_reboot.txt"
echo "Last reboot time:" | tee -a $saveto/system/last_reboot.txt
echo "last reboot:" | tee -a $saveto/system/last_reboot.txt
last reboot | tee -a $saveto/system/last_reboot.txt 2>&1

log "# last system boot > $saveto/system/last_boot.txt"
echo "Last system boot time:" | tee -a $saveto/system/last_boot.txt
echo "who -b:" | tee -a $saveto/system/last_boot.txt
who -b | tee -a $saveto/system/last_boot.txt 2>&1

log "# systemctl status *timer > $saveto/system/systemd_timers.txt"
echo "List of systemd timers:" | tee -a $saveto/system/systemd_timers.txt
echo "systemctl status *timer:" | tee -a $saveto/system/systemd_timers.txt
systemctl status *timer | tee -a $saveto/system/systemd_timers.txt 2>&1

log "# lscpu > $saveto/system/cpu_prop.txt"
echo "List of CPU's properties and architecture as reported by OS:" | tee -a $saveto/system/cpu_prop.txt
echo "lscpu:" | tee -a $saveto/system/cpu_prop.txt
lscpu | tee -a $saveto/system/cpu_prop.txt 2>&1

log "# lsblk -a > $saveto/system/block_device.txt"
echo "List of all block devices:" | tee -a $saveto/system/block_device.txt
echo "lsblk -a:" | tee -a $saveto/system/block_device.txt
lsblk -a | tee -a $saveto/system/block_device.txt 2>&1

log "# fdisk -l > $saveto/system/fdisk.txt"
echo "List of hard drives and properties:" | tee -a $saveto/system/fdisk.txt
echo "fdisk -l:" | tee -a $saveto/system/fdisk.txt
fdisk -l | tee -a $saveto/system/fdisk.txt 2>&1

log "# df -Th > $saveto/system/mounted_filesystems.txt"
echo "List of mounted file systems:" | tee -a $saveto/system/mounted_filesystems.txt
echo "df -Th:" | tee -a $saveto/system/mounted_filesystems.txt
df -Th | tee -a $saveto/system/mounted_filesystems.txt 2>&1

log "# mount > $saveto/system/mount.txt"
echo "List of mounted file systems:" | tee -a $saveto/system/mount.txt
echo "mount:" | tee -a $saveto/system/mount.txt
mount | tee -a $saveto/system/mount.txt 2>&1

log "# cat /proc/mounts > $saveto/system/proc_mount.txt"
echo "List of all mount points on the machine:" | tee -a $saveto/system/proc_mount.txt
echo "cat /proc/mounts:" | tee -a $saveto/system/proc_mount.txt
cat /proc/mounts | tee -a $saveto/system/proc_mount.txt 2>&1

log "# exportfs -v > $saveto/system/exportfs.txt"
echo "List of NFS shares and versions:" | tee -a $saveto/system/exportfs.txt
echo "exportfs -v:" | tee -a $saveto/system/exportfs.txt
exportfs -v | tee -a $saveto/system/exportfs.txt 2>&1

log "# lsmod > $saveto/system/lsmod.txt"
echo "List lsmod:" | tee -a $saveto/system/lsmod.txt
echo "lsmod :" | tee -a $saveto/system/lsmod.txt
lsmod  | tee -a $saveto/system/lsmod.txt 2>&1

log $'# for i in lsmod | awk \'{print $1}\' | sed \'/Module/d\'`; do echo -e "\\nModule: $i"; modinfo $i ; done  > $saveto/system/modinfo.txt'
echo "List modinfo:" | tee -a $saveto/system/modinfo.txt
echo $'# for i in lsmod | awk \'{print $1}\' | sed \'/Module/d\'`; do echo -e "\\nModule: $i"; modinfo $i ; done  > $saveto/system/modinfo.txt'| tee -a $saveto/system/modinfo.txt
for i in $(lsmod | awk '{print $1}' | sed '/Module/d'); do 
	echo -e "\nModule: $i"
	modinfo $i 
done | tee -a $saveto/system/modinfo.txt 2>&1

log $'# for i in `lsmod | awk \'{print $1}\' | sed \'/Module/d\'`; do modinfo $i | grep "filename:" | awk \'{print $2}\' | xargs -I{} sha1sum {} ; done  > $saveto/system/loaded_modules.sha1'
for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do 
	modinfo $i | grep "filename:" | awk '{print $2}' | xargs -I{} sha1sum {}
done | tee -a $saveto/system/loaded_modules.sha1 2>&1

log "# cat /proc/modules > $saveto/system/proc_modules.txt"
echo "List /proc/modules:" | tee -a $saveto/system/proc_modules.txt
echo "cat /proc/modules :" | tee -a $saveto/system/proc_modules.txt
cat /proc/modules  | tee -a $saveto/system/proc_modules.txt 2>&1

log "# find /usr/lib/modules/$(uname -r)/kernel/ -name *.ko > $saveto/system/ko_modules.txt"
echo "List *.ko modules:" | tee -a $saveto/system/ko_modules.txt
echo "find /usr/lib/modules/$(uname -r)/kernel/ -name *.ko :" | tee -a $saveto/system/ko_modules.txt
find /usr/lib/modules/$(uname -r)/kernel/ -name *.ko | tee -a $saveto/system/ko_modules.txt 2>&1

log "# cat /etc/modules > $saveto/system/etc_modules.txt"
echo "List modules at startup:" | tee -a $saveto/system/etc_modules.txt
echo "cat /etc/modules :" | tee -a $saveto/system/etc_modules.txt
cat /etc/modules | tee -a $saveto/system/etc_modules.txt 2>&1

log "# dmesg -T > $saveto/system/dmesg.txt"
echo "List dmesg:" | tee -a $saveto/system/dmesg.txt
echo "dmesg -T :" | tee -a $saveto/system/dmesg.txt
dmesg -T | tee -a $saveto/system/dmesg.txt 2>&1

log "# rpm -qa > $saveto/system/installed_packages.txt"
echo "List installed_packages:" | tee -a $saveto/system/installed_packages.txt
echo "rpm -qa :" | tee -a $saveto/system/installed_packages.txt
rpm -qa | tee -a $saveto/system/installed_packages.txt 2>&1
# dpkg --list for Debian

log "# cat /etc/hosts > $saveto/system/hosts.txt"
echo "List hosts:" | tee -a $saveto/system/hosts.txt
echo "cat /etc/hosts :" | tee -a $saveto/system/hosts.txt
cat /etc/hosts | tee -a $saveto/system/hosts.txt 2>&1

log "# cat /etc/fstab > $saveto/system/fstab.txt"
echo "List fstab:" | tee -a $saveto/system/fstab.txt
echo "cat /etc/fstab :" | tee -a $saveto/system/fstab.txt
cat /etc/fstab | tee -a $saveto/system/fstab.txt 2>&1

log "# Collecting system information done."
echo "======================================================================================" >> $logfile


# Persistence
echo "======================================================================================" >> $logfile
log "# Collecting persistence information."

log "# cat /etc/crontab > $saveto/persistence/crontab.txt"
echo "List of all scheduled jobs:" | tee -a $saveto/persistence/crontab.txt
echo "cat /etc/crontab:" | tee -a $saveto/persistence/crontab.txt
cat /etc/crontab | tee -a $saveto/persistence/crontab.txt 2>&1

log "# cat /etc/cron.*/ > $saveto/persistence/cron_dir.txt"
echo "List of all scheduled jobs:" | tee -a $saveto/persistence/cron_dir.txt
echo "cat /etc/cron.*/:" | tee -a $saveto/persistence/cron_dir.txt
cat /etc/cron.*/ | tee -a $saveto/persistence/cron_dir.txt 2>&1

log "# cat /etc/*.d > $saveto/persistence/etc_dotd_files.txt"
echo "List of all scheduled jobs:" | tee -a $saveto/persistence/etc_dotd_files.txt
echo "cat /etc/*.d:" | tee -a $saveto/persistence/etc_dotd_files.txt
cat /etc/*.d | tee -a $saveto/persistence/etc_dotd_files.txt 2>&1

log "# get_cron > $saveto/persistence/cron/"
echo "get_cron: "
get_cron

log "# systemctl list-unit-files --type=service > $saveto/persistence/startup_services.txt"
echo "List of startup services at boot:" | tee -a $saveto/persistence/startup_services.txt
echo "systemctl list-unit-files --type=service: " | tee -a $saveto/persistence/startup_services.txt
systemctl list-unit-files --type=service | tee -a $saveto/persistence/startup_services.txt 2>&1

log "# service --status-all > $saveto/persistence/service_status.txt"
echo "List of services and their status:" | tee -a $saveto/persistence/service_status.txt
echo "service --status-all:" | tee -a $saveto/persistence/service_status.txt
service --status-all | tee -a $saveto/persistence/service_status.txt 2>&1

log "# cat_dir '/etc/modules-load.d/*' > $saveto/persistence/modules_load.txt"
echo "Auto-start modules:" | tee -a $saveto/persistence/modules_load.txt
echo "cat_dir '/etc/modules-load.d/*': " | tee -a $saveto/persistence/modules_load.txt
cat_dir "/etc/modules-load.d/*" | tee -a $saveto/persistence/modules_load.txt 2>&1

log "# cat_dir '/etc/modprobe.d/*' > $saveto/persistence/modprobe.txt"
echo "Auto-start modules:" | tee -a $saveto/persistence/modprobe.txt
echo "cat_dir '/etc/modprobe.d/*': " | tee -a $saveto/persistence/modprobe.txt
cat_dir "/etc/modprobe.d/*" | tee -a $saveto/persistence/modprobe.txt 2>&1

log "# Collecting persistence information done."
echo "======================================================================================" >> $logfile


# Logs
echo "======================================================================================" >> $logfile
log "# Collecting logs information."

log "# grep [[:cntrl:]] /var/log/*.log > $saveto/logs/binary_code_logs.txt"
echo "List ALL log files that contain binary code inside:" | tee -a $saveto/logs/binary_code_logs.txt
echo "grep [[:cntrl:]] /var/log/*.log:" | tee -a $saveto/logs/binary_code_logs.txt
grep [[:cntrl:]] /var/log/*.log | tee -a $saveto/logs/binary_code_logs.txt 2>&1

log "# cat /var/log/syslog > $saveto/logs/syslog.txt"
echo "Getting Syslog:" | tee -a $saveto/logs/syslog.txt
echo "cat /var/log/syslog" | tee -a $saveto/logs/syslog.txt
cat /var/log/syslog | tee -a $saveto/logs/syslog.txt 2>&1

log "# Collecting /var/log folder > $saveto/logs/var_logs_files.tar.gz"
tar -czvf $saveto/logs/var_logs_files.tar.gz --dereference --hard-dereference --sparse /var/log | tee -a $saveto/logs/var_list.txt

log "# Collecting logs information done."
echo "======================================================================================" >> $logfile


# Users and Groups
echo "======================================================================================" >> $logfile
log "# Collecting user and group information."

log "# grep -Po '^sudo.+:\K.*$' /etc/group > $saveto/users_groups/superusers.txt"
echo "List of superusers:" | tee -a $saveto/users_groups/superusers.txt
echo "grep -Po '^sudo.+:\K.*$' /etc/group:" | tee -a $saveto/users_groups/superusers.txt
cgrep -Po '^sudo.+:\K.*$' /etc/group | tee -a $saveto/users_groups/superusers.txt 2>&1

log "# cat /etc/passwd > $saveto/users_groups/passwd.txt"
echo "List passwd file" | tee -a $saveto/users_groups/passwd.txt
echo "cat /etc/passwd" | tee -a $saveto/users_groups/passwd.txt
cat /etc/passwd | tee -a $saveto/users_groups/passwd.txt 2>&1

log "# cat /etc/shaddow > $saveto/users_groups/shaddow.txt"
echo "List shadow file" | tee -a $saveto/users_groups/shaddow.txt
echo "cat /etc/shaddow" | tee -a $saveto/users_groups/shaddow.txt
cat /etc/shaddow | tee -a $saveto/users_groups/shaddow.txt 2>&1

log "# cat /etc/sudoers > $saveto/users_groups/sudoers.txt"
echo "Sudoers config file and list of users with sudo access:" | tee -a $saveto/users_groups/sudoers.txt
echo "cat /etc/sudoers" | tee -a $saveto/users_groups/sudoers.txt
cat /etc/sudoers | tee -a $saveto/users_groups/sudoers.txt 2>&1

log "# pwck -r > $saveto/users_groups/passwd_integrity.txt"
echo "passwd file integrity" | tee -a $saveto/users_groups/passwd_integrity.txt
echo "pwck -r" | tee -a $saveto/users_groups/passwd_integrity.txt
pwck -r | tee -a $saveto/users_groups/passwd_integrity.txt 2>&1

log "# Collecting user and group information done."
echo "======================================================================================" >> $logfile


# File information
echo "======================================================================================" >> $logfile
log "# Collecting file information."

log "# ls -l -h -A -R / > $saveto/files/all_files.txt"
echo "Full directory listing of all file:" | tee -a $saveto/files/all_files.txt
echo "ls -l -h -A -R /:" | tee -a $saveto/files/all_files.txt
ls -l -h -A -R / | tee -a $saveto/files/all_files.txt 2>&1

log "# find / -type d -name '\.*' > $saveto/files/hidden_dir.txt"
echo "Find hidden directories" | tee -a $saveto/files/hidden_dir.txt
echo "find / -type d -name '\.*':" | tee -a $saveto/files/hidden_dir.txt
find / -type d -name '\.*' | tee -a $saveto/files/hidden_dir.txt 2>&1

log "# find /tmp /dev /var/tmp -type f -name '\.*' > $saveto/files/hidden_files_specific.txt"
echo "Find hidden directories" | tee -a $saveto/files/hidden_files_specific.txt
echo "find /tmp /dev /var/tmp -type f -name '\.*':" | tee -a $saveto/files/hidden_files_specific.txt
find /tmp /dev /var/tmp -type f -name '\.*' | tee -a $saveto/files/hidden_files_specific.txt 2>&1

log "# find / -type f -name '\.*' > $saveto/files/hidden_files.txt"
echo "Find hidden files" | tee -a $saveto/files/hidden_files.txt
echo "find / -type f -name '\.*':" | tee -a $saveto/files/hidden_files.txt
find / -type f -name '\.*' | tee -a $saveto/files/hidden_files.txt 2>&1

log "# find / -name '.. ' > $saveto/files/hidden_files.txt"
echo "find / -name '.. ':" | tee -a $saveto/files/hidden_files.txt
find / -type f -name ".. " | tee -a $saveto/files/hidden_files.txt 2>&1

log "# find / -type f -name '...' > $saveto/files/hidden_files.txt"
echo "find / -type f -name '...':" | tee -a $saveto/files/hidden_files.txt
find / -type f -name "..." | tee -a $saveto/files/hidden_files.txt 2>&1

log "# find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null > $saveto/files/no_user_groups.txt"
echo "List of files/directories with no user/group name" | tee -a $saveto/files/no_user_groups.txt
echo "find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null:" | tee -a $saveto/files/no_user_groups.txt
find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null | tee -a $saveto/files/no_user_groups.txt 2>&1

log "# find / -xdev -type f -perm -o+rx -print0 | xargs -0 sha1sum  > $saveto/system/executabels.sha1"
echo "List hash of all executables:" | tee -a $saveto/system/execuables.sha1
echo "find / -xdev -type f -perm -o+rx -print0 | xargs -0 sha1sum :" | tee -a $saveto/system/execuables.sha1
find / -xdev -type f -perm -o+rx -print0 | xargs -0 sha1sum | tee -a $saveto/system/execuables.sha1 2>&1

files="( ( -iname yum* -o -iname apt* -o -iname hosts* -o -iname passwd \
	-o -iname sudoers* -o -iname cron* -o -iname ssh* -o -iname rc* -o -iname systemd* -o -iname anacron  \
	-o -iname inittab -o -iname init.d -o -iname profile* -o -iname bash* ) -a ( -type f -o -type d ) )"

log "# find /etc/ $files -print0 | xargs -0 tar -czvf keyfiles.tar.gz --dereference --hard-dereference --sparse > $saveto/files/keyfiles.tar.gz"
echo "Gathering /etc directory" | tee -a $saveto/files/keyfiles_list.txt
find /etc/ $files -print0 | xargs -0 tar -czvf $saveto/files/keyfiles.tar.gz --dereference --hard-dereference --sparse 2>/dev/null > $saveto/files/keyfiles_list.txt

log "# find /etc/ -mtime -90 -print0 | xargs -0 tar -czvf $saveto/files/modified.tar.gz --dereference --hard-dereference --sparse > $saveto/files/modified_etc.tar.gz"
echo "Find modified files in /etc in last 90 days" | tee -a $saveto/files/modified_etc.txt
echo "find /etc/ -mtime -90 -print0 | xargs -0 tar -czvf --dereference --hard-dereference --sparse:" | tee -a $saveto/files/modified_etc.txt
find /etc/ -mtime -90 -print0 | xargs -0 tar -czvf  $saveto/files/modified.tar.gz --dereference --hard-dereference --sparse 2>/dev/null >> $saveto/files/modified_etc.txt

log "# find /usr/bin/ -mtime -90 > $saveto/files/modified_bin.tar.gz"
echo "Find modified files in /usr/bin in last 90 days" | tee -a $saveto/files/modified_bin.txt
echo "find /usr/bin/ -mtime -90 :" | tee -a $saveto/files/modified_bin.txt
find /usr/bin/ -mtime -90  | tee -a $saveto/files/modified_bin.txt

log "# find / -xdev -type d -name .ssh -print0 | xargs -0 tar -czvf --dereference --hard-dereference --sparse > $saveto/files/ssh_folder.tar.gz"
find / -xdev -type d -name .ssh -print0 | xargs -0 tar -czvf $saveto/files/ssh_folder.tar.gz --dereference --hard-dereference --sparse | tee -a $saveto/files/ssh_folder.txt

log "# find /dev/ -type f -print0 | xargs -0 file 2>/dev/null > $saveto/files/dev_dir.txt"
echo "Find files in dev (not common)" | tee -a $saveto/files/dev_dir.txt
echo "find /dev/ -type f -print0 | xargs -0 file 2>/dev/null: " | tee -a $saveto/files/dev_dir.txt
find /dev/ -type f -print0 | xargs -0 file 2>/dev/null | tee -a $saveto/files/dev_dir.txt 2>&1

log "# find / -xdev -name sysctl* -print0 | xargs -0 tar -czvf $saveto/files/sysctl.tar.gz --dereference --hard-dereference --sparse > $saveto/files/sysctl.tar.gz"
find / -xdev -name sysctl* -print0 | xargs -0 tar -czvf $saveto/files/sysctl.tar.gz --dereference --hard-dereference --sparse | tee -a $saveto/files/sysctl.txt

log "# find /etc -xdev -name init* -print0 | xargs -0 tar -czvf $saveto/files/init.tar.gz --dereference --hard-dereference --sparse > $saveto/files/init.tar.gz"
find /etc -xdev -name init* -print0 | xargs -0 tar -czvf $saveto/files/init.tar.gz --dereference --hard-dereference --sparse | tee -a $saveto/files/init.txt

# find / -user <username> -perm -4000 -print to find fro specific user
log "# find / -perm -4000 -print > $saveto/files/setuid_files.txt"
echo "Find setuid files" | tee -a $saveto/files/setuid_files.txt
echo "find / -perm -4000 -print:" | tee -a $saveto/files/setuid_files.txt
find / -perm -4000 -print | tee -a $saveto/files/setuid_files.txt 2>&1

log "# find / -perm -2000 -print > $saveto/files/setgid_kmem_files.txt"
echo "Find setgid files" | tee -a $saveto/files/setgid_kmem_files.txt
echo "find / -perm -2000 -print:" | tee -a $saveto/files/setgid_kmem_files.txt
find / -perm -2000 -print | tee -a $saveto/files/setgid_kmem_files.txt 2>&1


log "# Collecting file information done."
echo "======================================================================================" >> $logfile


echo "Do you wish to additionally scan the system with a compromise assessment tool? May take a long time."
select yn in "Yes" "No"; do
    case $yn in
        Yes ) get_thor; break;;
        No ) echo "Continuing with script."; break;;
    esac
done

echo "Do you wish to additionally gather SLRUM jobs executed on this node?"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) get_slurm; break;;
        No ) echo "Continuing with script."; break;;
    esac
done


log "# Creating checksums (sha1sum) for all files"
log "# find $saveto/* -type f -exec sha1sum {} \; > $saveto/sha1sums.txt"
find $saveto/* -type f -exec sha1sum {} \; > $saveto/sha1sums.txt

log "# All tasks completed. Exiting."

