# HPC_IR
Incident Reponse Script for High Performance Computing Clusters. This script was developed during the High-Performance-Computing System Administration seminar (https://hps.vi4io.org/teaching/autumn_term_2022/hpcsa).

# Instructions:
1. Ensure the script is executable, run "chmod +x <script_name>"
2. Run with Sudo privileges, "sudo ./<script_name>"
3. The tools folder needs to be place in the same directory as the script.

The purpose of this scirpt is to gather information in an incident reponse case. 
It was tested on Rocky 8 and Rocky 9. 
It collects:
- Volatile data in the order of volatility [NIST]:
  1.	(optional) Memory image
  2.	Network connections & configurations
  3.	Login sessions
  4.	Contents of memory
  5.	Running processes
  6.	Open files
  7.	Operating system information
Additionally it collects following non-volatile data:
  8. Cron files
  9. User and group lists
 	10. /var/logs
	11. Suspicious and Keyfiles
	12. (optional) Compromise scanning with Thor-lite
  13. (optional) SLURM jobs executed on the node

The script uses local binaries and additionally following tools provided with the script:
(Binaries need to be provided manually)
 - AVML: Memory collection
 - Unhide: Lists hidden processes / ports
 - Thor-lite: Compromise assessment tool

Please make sure that the file system under / is mounted with the option `noatime`. 
If this is not the case, please execute the command 
`mount -o remount,noatime /dev/sdX /` where X is the filesystem 
under /. This ensures that no timestamps are modified during investigation.
Note that `noatime` option has no effect on NFS mounts.

Please create an own license if you intend to use the thor-lite scanner.
A license can be created under "https://www.nextron-systems.com/thor-lite/".
Afterwards place it in the tools/thor-lite folder.

