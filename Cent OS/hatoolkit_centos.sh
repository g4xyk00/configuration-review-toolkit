#!/bin/bash
#Host Assessment Toolkit to assess on Cent OS configuration 
#Usage: sh hatoolkit_centos.sh
echo -e "\e[33mHost Assessment Tooklit (Cent OS) By Axcel Security v1.0\e[0m"
echo "Author: g4xyk00"
echo "Website: www.axcelsec.com"
echo ""
echo "[*] Collecting information..."
echo "Date: " `date` > hatreport
echo "System Identification:" `uname -a` >> hatreport
echo "A2.1 Ensure the following services are disabled" >> hatreport
systemctl list-unit-files | grep "enabled" | grep "autofs\|xinetd\|avahi-daemon\|cups\|dhcpd\|slapd\|nfs\|named\|vsftpd\|httpd\|dovecot\|smb\|squid\|snmpd\|ypserv\|rsh.socket\|rlogin.socket\|rexec.socket\|telnet.socket\|tftp.socket\|rsyncd\|ntalk" >> hatreport
echo "" >> hatreport
echo "A2.2 Ensure the following services and service client are not installed." >> hatreport
rpm -qa | grep "xorg-x11\|ypbind\|rsh\|talk\|telnet\|openldap-clients\|prelink\|setroubleshoot\|mcstrans" >> hatreport
echo "" >> hatreport
echo "A2.3 Ensure the following services are in use." >> hatreport
systemctl list-unit-files | grep "enabled" | grep "auditd\|rsyslog\|syslog-ng\|crond" >> hatreport
echo "" >> hatreport
rpm -qa | grep "ntp\|chrony\|tcp_wrappers\|AIDE, SELinux, iptables, rsyslog, syslog-ng" >> hatreport
echo "" >> hatreport
echo "A2.4 SMTP" >> hatreport
cat /etc/postfix/main.cf | grep "smtpd_banner" >> hatreport
echo "" >> hatreport
echo "A3. Network Configuration" >> hatreport
echo "A3.1 Network Parameters" >> hatreport
sysctl -a | grep "net.ipv4.ip_forward\|net.ipv4.conf.all.send_redirects\|net.ipv4.conf.default.send_redirects\|net.ipv4.conf.all.accept_source_route\|net.ipv4.conf.default.accept_source_route\|net.ipv4.conf.all.accept_redirects\|net.ipv4.conf.default.accept_redirects\|net.ipv4.conf.all.secure_redirects\|net.ipv4.conf.default.secure_redirects\|net.ipv4.conf.all.log_martians\|net.ipv4.conf.default.log_martians\|net.ipv4.icmp_echo_ignore_broadcasts\|net.ipv4.icmp_ignore_bogus_error_responses\|net.ipv4.conf.all.rp_filter\|net.ipv4.conf.default.rp_filter\|net.ipv4.tcp_syncookies\|net.ipv6.conf.all.disable_ipv6" >> hatreport
echo "" >> hatreport
echo "A3.2 Uncommon Network Protocols" >> hatreport
modprobe -n -v -a dccp sctp rds tipc >> hatreport
echo "" >> hatreport
echo "A4. Logging and Auditing" >> hatreport
echo "A4.1 Ensure logging is configured" >> hatreport
ls -l /var/log/ >> hatreport
echo "A4.2 Configure System Accounting" >> hatreport
cat /etc/audit/auditd.conf | grep "max_log_file\|space_left_action\|action_mail_acct\|admin_space_left_action\|max_log_file_action" >> hatreport
echo "" >> hatreport
echo "A4.3 Ensure sufficient events information are collected" >> hatreport
cat /etc/audit/audit.rules | grep "time-change\|identity\|system-locale\|MAC-policy\|logins\|session\|perm_mod\|access\|mounts\|delete\|scope\|actions\|modules" >> hatreport
echo "" >> hatreport
echo "A5. Access, Authentication and Authorization" >> hatreport
echo "A5.1 Configure cron" >> hatreport
ls -l /etc/ | grep "crontab\|cron.hourly\|cron.daily\|cron.weekly\|cron.monthly\|cron.d\|cron.deny\|cron.allow\|at.allow\|at.deny" >> hatreport
echo "" >> hatreport
echo "A5.2 SSH Server Configuration" >> hatreport
ls -l /etc/ssh/sshd_config >> hatreport
echo "" >> hatreport
cat /etc/ssh/sshd_config | grep "Protocol\|LogLevel\|X11Forwarding\|MaxAuthTries\|IgnoreRhosts\|HostbasedAuthentication\|PermitRootLogin\|PermitEmptyPasswords\|PermitUserEnvironment\|Ciphers\|MACs\|ClientAliveInterval\|ClientAliveCountMax\|LoginGraceTime\|AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups\|Banner" >> hatreport
echo "" >> hatreport
echo "A5.3 Ensure password creation requirements are configured" >> hatreport
cat /etc/pam.d/system-auth | grep "pam_pwquality.so\|pam_unix.so\|pam_faillock.so" >> hatreport
echo "" >> hatreport
cat /etc/pam.d/password-auth | grep "pam_pwquality.so\|pam_unix.so\|pam_faillock.so" >> hatreport
echo "" >> hatreport
cat /etc/security/pwquality.conf | grep "minlen\|dcredit\|lcredit\|ocredit\|ucredit" >> hatreport
echo "" >> hatreport
echo "A5.4 Set Shadow Password Suite Parameters" >> hatreport
cat /etc/login.defs | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE" >> hatreport
echo "A5.5 Ensure default user umask is 027 or more restrictive" >> hatreport
cat /etc/bashrc | grep "umask" >> hatreport
echo "" >> hatreport
cat /etc/profile | grep "umask" >> hatreport
echo "" >> hatreport
echo "A6. System Maintenance" >> hatreport
echo "A6.1 System File Permissions" >> hatreport
ls -l /etc/ | grep "passwd\|shadow\|group\|gshadow" >> hatreport
echo "" >> hatreport
echo -e "\e[32m[+] Report generated at "`pwd`/hatreport"\e[0m"
