#!/usr/bin/python

import sys
import time
import random
import socket
import logging
import datetime

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Globals
SIEM_IP = "192.168.1.1"
SIEM_UDP_PORT = 514


def _FormPacketPayload(source_ip, source_hostname, kind, user, port=123, original_host="Scarry!"):
    months_arr = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    now = datetime.now()
    day = "%02d" % (now.day,)
    month = "%02d" % (now.month,)
    hour = "%02d" % (now.hour,)
    minute = "%02d" % (now.minute,)
    second = "%02d" % (now.second,)
    date_formatted = "%s-%s-%s" % (now.year, month, day)
    time_formatted = "%s:%s:%s" % (hour, minute, second)
    epoch_time = str(int(time.time()))
    month_name_short = months_arr[int(month)]

    # Test Params
    user_name = user
    event_id = str(4776)

    raw_test = "<13>%s %s %s %s AgentDevice=WindowsLog\tAgentLogFile=Security\tPluginVersion=1.0.14\tSource=Microsoft-Windows-Security-Auditing\tComputer=%s\tUser= \tDomain= \tEventID=4776\tEventIDCode=4776\tEventType=8\tEventCategory=14336\tRecordNumber=357588878\tTimeGenerated=%s\tTimeWritten=%s\tMessage=The computer attempted to validate the credentials for an account.  Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: %s Source Workstation: %s Error Code: 0x0 " % (month_name_short, day, time_formatted,  source_hostname[1], source_hostname[0], epoch_time, epoch_time, user_name, original_host)

    return raw_test

def _buildIP(src, dst):
    a = IP(
        src=src,
        dst=dst
    )
    return a

def _UDP(ip, dst_port, src_port=0):
    if src_port == 0:
        src_port = random.randint(5000,50000)
    b = ip/UDP(sport=src_port, dport=dst_port)
    return b

def _AddPayload(packet, payload):
    return packet / Raw(load=payload)

def _Send(packet, times, delay):
    for i in range(0,times):
        send(packet)
        time.sleep(delay)

if __name__ == "__main__":
    DELIVERING_SERVER = ("main_dc.local", "192.168.1.100")
    SOURCE_IP = DELIVERING_SERVER[1]

    counter = 1

    user = "goodall"

    # Create a payload for user authentication success
    src_port = 1234
    payload = _FormPacketPayload(   source_ip=SOURCE_IP,
                                    source_hostname=DELIVERING_SERVER,
                                    kind=4,
                                    port=src_port,
                                    user=user,
                                    original_host=DELIVERING_SERVER[0]
                                )

    pcket = _buildIP(src=SOURCE_IP, dst=SIEM_IP)
    udp = _UDP(ip=pcket, dst_port=SIEM_UDP_PORT, src_port=src_port)
    last = _AddPayload(packet=udp, payload=payload)
    _Send(last, times=counter, delay=0.2)
