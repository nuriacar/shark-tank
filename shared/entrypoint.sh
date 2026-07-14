#!/bin/sh
FTP_USER="${FTP_USER:-ftpuser}"
FTP_PASS="${FTP_PASS:-ftppass123}"

echo "${FTP_USER}:${FTP_PASS}" | chpasswd

exec vsftpd -olisten=YES -obackground=NO /etc/vsftpd/vsftpd.conf
