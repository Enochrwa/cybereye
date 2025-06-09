@echo off
echo Running Nmap scans for testing...
nmap -sn 192.168.1.0/24
nmap -sS 192.168.1.1
nmap -p 22,80,443 192.168.1.1
nmap -A 192.168.1.1
echo Scan tests completed!