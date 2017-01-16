#!/usr/bin/python
#Gets the local ip address of this machine.
import socket

def getLocalIP():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 1))  # connecting to a UDP address doesn't send packets
	local_ip_address = s.getsockname()[0]
	return local_ip_address

#getLocalIP()
