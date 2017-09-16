#!/usr/bin/python

import socket

SIEM_ADDR = "192.168.1.2"
SIEM_PORT = 514

data = """Jan 1 11:11:11 192.168.1.1 AgentDevice=WindowsLog	AgentLogFile=Security	PluginVersion=1.0.14	Source=Microsoft-Windows-Security-Auditing	Computer=main_dc	User= 	Domain= 	EventID=4776	EventIDCode=4776	EventType=8	EventCategory=14336	RecordNumber=1089190650	TimeGenerated=111111111111	TimeWritten=111111111111	Message=The computer attempted to validate the credentials for an account.  Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: admin Source Workstation: main_dc Error Code: 0x0""""

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = sock.sendto(data, (SIEM_ADDR, SIEM_PORT))
except socket.error, e:
    sys.stderr.write("Error: %s.\n" % str(e))
    sys.exit()
finally:
    sock.close()
    sys.stdout.write("Done.\n")
