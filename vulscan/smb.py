# -*- coding: utf-8 -*-
# @File  : netbios.py
# @Date  : 2019/12/10
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf


import struct
from socket import AF_INET, SOCK_STREAM

from gevent import socket

from lib.config import logger

# Negotiate Protocol Request
packetms17010 = "\x00\x00\x00\x54"
packetms17010 += "\xff\x53\x4d\x42"
packetms17010 += "\x72"
packetms17010 += "\x00"
packetms17010 += "\x00"
packetms17010 += "\x00\x00"
packetms17010 += "\x18"
packetms17010 += "\x01\x28"
packetms17010 += "\x00\x00"
packetms17010 += "\x00\x00\x00\x00\x00\x00\x00\x00"
packetms17010 += "\x00\x00"
packetms17010 += "\x00\x00"
packetms17010 += "\x44\x6d"
packetms17010 += "\x00\x00"
packetms17010 += "\x42\xc1"
packetms17010 += "\x00"
packetms17010 += "\x31\x00"
packetms17010 += "\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
packetms17010 += "\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"
packetms17010 += "\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00"
packetms17010 += "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"


def handle(data, iptarget):
    ## SMB Command: Session Setup AndX Request, User: .\
    if data[8:10] == "\x72\x00":
        packetsession = "\xff\x53\x4d\x42"  # Server Component: SMB
        packetsession += "\x73"  # SMB Command: Session Setup AndX (0x73)
        packetsession += "\x00"  # Error Class: Success (0x00)
        packetsession += "\x00"  # Reserved
        packetsession += "\x00\x00"  # Error Code: No Error
        packetsession += "\x18"  # Flags
        packetsession += "\x01\x28"  # Flags 2
        packetsession += "\x00\x00"  # Process ID High 0
        packetsession += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        packetsession += "\x00\x00"  # Reserved
        packetsession += data[28:34]  # TID+PID+UID
        packetsession += "\x42\xc1"  # Multiplex ID 49474
        packetsession += "\x0d"  # WCT 0
        packetsession += "\xff"  # AndXCommand: No further commands (0xff)
        packetsession += "\x00"  # Reserved 00
        packetsession += "\x00\x00"  # AndXOffset: 0
        packetsession += "\xdf\xff"  # Max Buffer: 65503
        packetsession += "\x02\x00"  # Max Mpx Count: 2
        packetsession += "\x01\x00"  # VC Number: 1
        packetsession += "\x00\x00\x00\x00"  # Session Key: 0x00000000
        packetsession += "\x00\x00"  # ANSI Password Length: 0
        packetsession += "\x00\x00"  # Unicode Password Length: 0
        packetsession += "\x00\x00\x00\x00"  # Reserved: 00000000
        packetsession += "\x40\x00\x00\x00"  # Capabilities: 0x00000040, NT Status Codes
        packetsession += "\x26\x00"  # Byte Count (BCC): 38
        packetsession += "\x00"  # Account:
        packetsession += "\x2e\x00"  # Primary Domain: .
        packetsession += "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00"  # Native OS: Windows 2000 2195
        packetsession += "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00"  # Native LAN Manager: Windows 2000 5.0

        return struct.pack(">i", len(packetsession)) + packetsession

    ## Tree Connect AndX Request, Path: \\ip\IPC$
    if data[8:10] == "\x73\x00":
        share = "\xff\x53\x4d\x42"  # Server Component: SMB
        share += "\x75"  # SMB Command: Tree Connect AndX (0x75)
        share += "\x00"  # Error Class: Success (0x00)
        share += "\x00"  # Reserved
        share += "\x00\x00"  # Error Code: No Error
        share += "\x18"  # Flags
        share += "\x01\x28"  # Flags 2
        share += "\x00\x00"  # Process ID High 0
        share += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        share += "\x00\x00"  # Reserved
        share += data[28:34]  # TID+PID+UID
        share += "\x42\xc1"  # Multiplex ID 49474
        share += "\x04"  # WCT 4
        share += "\xff"  # AndXCommand: No further commands (0xff)
        share += "\x00"  # Reserved: 00
        share += "\x00\x00"  # AndXOffset: 0
        share += "\x00\x00"  # Flags: 0x0000
        share += "\x01\x00"  # Password Length: 1
        share += "\x19\x00"  # Byte Count (BCC): 25
        share += "\x00"  # Password: 00
        share += "\x5c\x5c" + iptarget + "\x5c\x49\x50\x43\x24\x00"  # Path: \\ip_target\IPC$
        share += "\x3f\x3f\x3f\x3f\x3f\x00"

        return struct.pack(">i", len(share)) + share

    ## PeekNamedPipe Request, FID: 0x0000
    if data[8:10] == "\x75\x00":
        smbpipefid0 = "\xff\x53\x4d\x42"  # Server Component: SMB
        smbpipefid0 += "\x25"  # SMB Command: Trans (0x25)
        smbpipefid0 += "\x00"  # Error Class: Success (0x00)
        smbpipefid0 += "\x00"  # Reserved
        smbpipefid0 += "\x00\x00"  # Error Code: No Error
        smbpipefid0 += "\x18"  # Flags
        smbpipefid0 += "\x01\x28"  # Flags 2
        smbpipefid0 += "\x00\x00"  # Process ID High 0
        smbpipefid0 += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        smbpipefid0 += "\x00\x00"  # Reserved
        smbpipefid0 += data[28:34]  # TID+PID+UID
        smbpipefid0 += "\x42\xc1"  # Multiplex ID 49474
        smbpipefid0 += "\x10"  # Word Count (WCT): 16
        smbpipefid0 += "\x00\x00"  # Total Parameter Count: 0
        smbpipefid0 += "\x00\x00"  # Total Data Count: 0
        smbpipefid0 += "\xff\xff"  # Max Parameter Count: 65535
        smbpipefid0 += "\xff\xff"  # Max Data Count: 65535
        smbpipefid0 += "\x00"  # Max Setup Count: 0
        smbpipefid0 += "\x00"  # Reserved: 00
        smbpipefid0 += "\x00\x00"  # Flags: 0x0000
        smbpipefid0 += "\x00\x00\x00\x00"  # Timeout: Return immediately (0)
        smbpipefid0 += "\x00\x00"  # Reserved: 0000
        smbpipefid0 += "\x00\x00"  # Parameter Count: 0
        smbpipefid0 += "\x4a\x00"  # Parameter Offset: 74
        smbpipefid0 += "\x00\x00"  # Data Count: 0
        smbpipefid0 += "\x4a\x00"  # Data Offset: 74
        smbpipefid0 += "\x02"  # Setup Count: 2
        smbpipefid0 += "\x00"  # Reserved: 00
        smbpipefid0 += "\x23\x00"  # Function: PeekNamedPipe (0x0023)
        smbpipefid0 += "\x00\x00"  # FID: 0x0000
        smbpipefid0 += "\x07\x00"  # Byte Count (BCC): 7
        smbpipefid0 += "\x5c\x50\x49\x50\x45\x5c\x00"  # Transaction Name: \PIPE\

        return struct.pack(">i", len(smbpipefid0)) + smbpipefid0


def ms17010scan(ipaddress, port=445, timeout=3):
    try:
        s = socket.socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((str(ipaddress), port))
        s.send(packetms17010)
        nativeos = ""
        try:
            while True:
                data = s.recv(1024)
                if data[8:10] == "\x73\x00":
                    nativeos = data[45:100].split(b'\x00' * 1)[0]
                if data[8:10] == "\x25\x05":
                    if data[9:13] == "\x05\x02\x00\xc0":
                        format_str = "{:<16}{:<7}{:<25}{}".format(ipaddress, port, "VULNERABLE to MS17-010", nativeos)
                        logger.warning(format_str)
                s.send(handle(data, str(ipaddress)))
        except Exception as E:
            pass
            s.close()
    except Exception as msg:
        # print("[+] Can't connecto to "+str(targets))
        try:
            s.close()
        except Exception as E:
            pass
