#!/usr/bin/python

from scapy.all import *

SIEM_ADDR = "192.168.1.2"
SIEM_PORT = 514

DC_ADDR = "192.168.1.100"
DC_PORT = 9191

data = """Jan 1 11:11:11 192.168.1.1 AgentDevice=WindowsLog\tAgentLogFile=Security\tPluginVersion=1.0.14\tSource=Microsoft-Windows-Security-Auditing\tComputer=main_dc\tUser= \tDomain= \tEventID=4776\tEventIDCode=4776\tEventType=8\tEventCategory=14336\tRecordNumber=1089190650\tTimeGenerated=111111111111\tTimeWritten=111111111111\tMessage=The computer attempted to validate the credentials for an account.  Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: admin Source Workstation: main_dc Error Code: 0x0""""

ip = IP(dst=SIEM_ADDR, src=DC_ADDR)
udp = ip/UDP(dport=SIEM_PORT, sport=DC_PORT)
final = udp/Raw(load=data)
send(final)
