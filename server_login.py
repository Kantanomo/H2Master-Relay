#!/usr/bin/python
#Fixed, now using Kantanomo's sql db.
#Active as the login server since Dec 2016.
import socket
import SocketServer
import struct
import sys
import random
import threading
import time
import requests
import hashlib
import base64
import thread
import datetime
from datetime import datetime as getdatetime
from random import randint
# from local project
import packet_pb2
import get_local_ip
import mtils
from common_sql import update_sql_ip_port
from common_sql import fetch_single_sql_result
from login_details import login_api_addr
from random_accounts import generate_accounts
from random_accounts import generate_random_account

def ip2int(addr):
	ret = struct.unpack("<L",socket.inet_aton(addr))[0]
	return ret

def int2ip(addr):
	ret = socket.inet_ntoa(struct.pack("<L",addr))
	return ret

player_data_lock = threading.Lock()
player_data = dict()

player_login = dict()

class XNADDR:
	port = 0
	addr = "0.0.0.0"
	abenet = ""
	abonline = ""

def pad_hex(text, length):
	text_len = len(text)
	pad_len = length - text_len
	return text + ("20"*(pad_len/2))

def get_id_from_xuid(xuid):
	return id - 1000000000000000
def get_xuid_from_id(id):
	return 1000000000000000 + id

def get_id_from_secure(secure):
	return int(secure[:-2], 16)
def get_secure_from_id(id):
	return int("%06X00" % id, 16)

def get_id_from_ab_hex(ab_hex):
	return int(ab_hex.decode('hex'))
def get_abenet_from_id(id):
	return pad_hex(str(id).encode('hex'), 12).lower()
def get_abonline_from_id(id):
	return pad_hex(str(id).encode('hex'), 40).lower()

class MyUDPHandler(SocketServer.BaseRequestHandler):
	HANDLERS = {
		packet_pb2.Packet.login_request: "lrequest",
		packet_pb2.Packet.secure_request: "srequest",
		packet_pb2.Packet.xnaddr_request: "xrequest"
	}
	
	def handle(self):
		s = self.request[1]
		data = self.request[0]
		packet = packet_pb2.Packet()
		packet.ParseFromString(data)
		hndlr = self.HANDLERS[packet.type]
		message = getattr(packet,hndlr,None)
		handler = getattr(self,'handle_{0}'.format(hndlr))
		
		return handler(message)
	
	def handle_lrequest(self,msg):
		s = self.request[1]
		ipaddr = self.client_address[0]
		
		token = msg.login_token
		xnport = msg.port
		
		if token is None or token == "":
			log_lvl(1, "[Log Req] Log Attempt "+ipaddr+":"+str(xnport)+" Token: NULL - FAILED" )
			return
		log_lvl(1, "[Log Req] Log Attempt "+ipaddr+":"+str(xnport)+" Token:"+token )
		
		user_data = None
		if generate_accounts():
			user_data = generate_random_account()
			log_lvl(1, "[Log Req] Login RANDOMLY generated!")
		else:
			resp = requests.get(login_api_addr() + token)
			user_data = resp.json()
		
		if user_data is None or str(user_data['status']) != "success":
			log_lvl(1, "[Log Req] FAILED" )
		else:
			
			username = str(user_data['username'])
			id = int(str(user_data['id']))
			xuid = get_xuid_from_id(id)
			secure = get_secure_from_id(id)
			abenet = get_abenet_from_id(id)
			abonline = get_abonline_from_id(id)
			
			packet = packet_pb2.Packet()
			packet.type = packet.login_reply
			
			xn = XNADDR()
			xn.addr = ip2int(ipaddr)
			xn.port = xnport
			xn.abenet = abenet
			xn.abonline = abonline
			
			packet.lreply.username = username
			packet.lreply.xuid = xuid
			packet.lreply.secure_addr = secure
			packet.lreply.xnaddr = xn.addr
			packet.lreply.port = xn.port
			packet.lreply.abEnet = abenet
			packet.lreply.abOnline = abonline
			
			log_lvl(1, "[Log Req] Login Success for id: %d, Player:\"%s\"" % (id, username))
			log_lvl(2, "[Log Req] Login Token:" + token )
			log_lvl(2, "[Log Req] secure: %08X, abEnet: %s, abOnline: %s" % (secure, abenet, abonline) )
			log_lvl(2, "[Log Req] xnaddr: %08X, port: %d" % (xn.addr, xn.port) )
			s.sendto(packet.SerializeToString(), self.client_address)
			log_lvl(2, "[Log Req]: Sent Success Packet to %s:%d." % self.client_address )
			
			player_login[username] = getdatetime.now()
			
			with player_data_lock:
				global player_data
				player_data[id] = xn
				
				#Others not needed anymore as srequest isn't even called right?
				#player_data[secure] = xn
				#on same pc with client, they send xn instead of secure for some unknown reason
				#this here doesn't work.
				#xn.addr = int(secure)
				#player_data[xn.addr] = xn
				player_data[abenet] = secure
			
			if not generate_accounts():
				update_sql_ip_port(log_lvl, "%s:%s" % (ipaddr, xnport), "id = %d" % id)
	
	
	def handle_xrequest(self, msg):
		s = self.request[1]
		id = get_id_from_secure("%08X" % msg.secure)
		log_lvl(1, "[xnaddr Req] From %s:%d with saddr: %08X, id: %d" % (self.client_address[0], self.client_address[1], msg.secure, id) )
		packet = packet_pb2.Packet()
		packet.type = packet.xnaddr_reply
		global player_data
		xn = player_data.get(id, None)
		#if xn is None:
		#	xn = player_data.get(msg.secure, None)
		if xn is None and not generate_accounts():
			load_user_from_sql_query_condition(log_lvl, "id = %d" % id)
			xn = player_data.get(id, None)
		if xn is None:
			#Send them 0.0.0.0 etc. on error as client appeared to once have handled it as obvious invalid data.
			log_lvl(1, "[xnaddr Req] ERROR - id not found in player_data or sql db: %d" % id )
			xn = XNADDR()
			xn.addr = ip2int(xn.addr)
		packet.xreply.xnaddr = xn.addr
		packet.xreply.port = xn.port
		packet.xreply.abEnet = xn.abenet
		packet.xreply.abOnline = xn.abonline
		
		log_lvl(2, "[xnaddr Req] secure: %08X, abEnet: %s, abOnline: %s" % (msg.secure, xn.abenet, xn.abonline) )
		log_lvl(2, "[xnaddr Req] xnaddr: %08X, port: %d" % (xn.addr, xn.port) )
		s.sendto(packet.SerializeToString(), self.client_address)
		log_lvl(2, "[xnaddr Req] Sent response to %s:%d." % self.client_address )
	
	
	#This is apparently never used by the client.
	def handle_srequest(self, msg):
		s = self.request[1]
		log_lvl(1, "[secure Req] From %s:%d with abenet: 0x%s." % (self.client_address[0], self.client_address[1], msg.abEnet.encode('hex')) )
		
		#Send them 0.0.0.0 etc. on error as client appeared to once have handled it as obvious invalid join data.
		global player_data
		secure = player_data.get(msg.abEnet.encode('hex'), None)
		if secure is None:
			load_user_from_sql_query_condition(log_lvl, "abEnet = 0x%s" % msg.abEnet.encode('hex'))
			secure = player_data.get(msg.abEnet.encode('hex'), None)
		xn = None
		if secure is not None:
			xn = player_data.get(int(secure), None)
		if secure is None:
			log_lvl(1, "[secure Req] ERROR - abenet not found in player_data or sql db: "+msg.abEnet.encode('hex') )
			secure = ip2int("0.0.0.0")
		if xn is None:
			log_lvl(1, "[secure Req] ERROR - secure not found in player_data: %08X" % secure )
			xn = XNADDR()
			xn.addr = ip2int(xn.addr)
		
		packet = packet_pb2.Packet()
		packet.type = packet.secure_reply
		packet.sreply.secure = secure
		packet.sreply.xnaddr = xn.addr
		packet.sreply.port = xn.port
		packet.sreply.abEnet = xn.abenet
		packet.sreply.abOnline = xn.abonline
		
		log_lvl(2, "[secure Req] responding to %s:%d." % self.client_address )
		log_lvl(2, "[secure Req] secure addr: %08X " % secure )
		log_lvl(2, "[secure Req] abEnet matched xn data:" )
		log_lvl(2, "[secure Req] abEnet: " + xn.abenet.encode('hex') )
		log_lvl(2, "[secure Req] abOnline: " + xn.abonline.encode('hex') )
		log_lvl(2, "[secure Req] xnaddr: %08X" % (xn.addr) )
		log_lvl(2, "[secure Req] port: %08X" % (xn.port) )
		
		s.sendto(packet.SerializeToString(), self.client_address)

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
	pass

def load_user_from_sql_query_condition(log_lvl, condition):
	user_data = fetch_single_sql_result(log_lvl, "SELECT id, username, ip_port FROM user WHERE %s" % (condition))
	if user_data is not None:
		log_lvl(2, "All user data: "+str(user_data) )
		id = int( user_data[0] )
		username = user_data[1]
		xn = XNADDR()
		if user_data[2] is not None:
			xn.addr, xn.port = user_data[2].split(":")
			xn.addr = ip2int(xn.addr)
			xn.port = int(xn.port)
			xn.abenet = get_abenet_from_id(id)
			xn.abonline = get_abonline_from_id(id)
			with player_data_lock:
				global player_data
				#player_data[xn.abenet.encode('hex')] = secure
				player_data[id] = xn
			log_lvl(3, "[SQL Query] Fetched user:\"%s\" id:%s." % (username, id) )
			return
		else:
			log_lvl(1, "[SQL Query] User has Null ip_port." )
	log_lvl(1, "[SQL ERROR] FAILED to fetch with query condition \"%s\"." % (condition) )

def init_master_server():
	HOST, PORT = get_local_ip.getLocalIP(), 27020
	log( "Binding to (Local) IP on Port: {}:{}".format(HOST, PORT) )
	server = ThreadedUDPServer((HOST,PORT), MyUDPHandler)
	server.serve_forever()

def knownCommands():
	log("help, (quit, q, exit, close, stop), logins [minutes] [display_players_bool], loglevel [level_num].")

def log(text):
	#print "%s> %s" % (getdatetime.strftime(getdatetime.now(), '%H:%M:%S').lower(), text)
	mtils.logger("%s> %s" % (getdatetime.strftime(getdatetime.now(), '%H:%M:%S').lower(), text))

log_level = [True,False,True]

def log_lvl(level, text):
	global log_level
	if level is None or level == 0:
		log(text)
	elif level > 0 and level <= len(log_level):
		if log_level[level-1]:
			log(text)
	else:
		log("INVALID LOG LEVEL: %d" % level)
		log(text)
		

def say(text):
	mtils.logger("%s>>%s" % (getdatetime.strftime(getdatetime.now(), '%H:%M:%S').lower(), text))

def quit():
	log("Exiting...")
	exit()

if __name__ == "__main__":
	#init_master_server()
	#try:
	#thread.start_new_thread( test_sql, () )
	thread.start_new_thread( init_master_server, () )
	#except:
	#	log("ERROR: Unable to start master server thread!")
	while True:
		inputCommand = mtils.get("Cmd: ")
		if inputCommand == "":
			continue
		elif inputCommand == -1:
			quit()
		say(inputCommand)
		cmd = inputCommand.split()
		if len(cmd) > 0 and cmd[0] != "":
			cmd[0] = cmd[0].lower()
			if cmd[0] == "quit" or cmd[0] == "q" or cmd[0] == "exit" or cmd[0] == "close" or cmd[0] == "stop":
				quit()
			elif cmd[0] == "help":
				knownCommands()
				continue
			elif cmd[0] == "logins":
				if len(cmd) >= 2:
					passed_minutes = 60
					try:
						passed_minutes = int(cmd[1])
					except ValueError:
						pass
					print_names = False
					if len(cmd) >= 3:
						print_names = True if cmd[2].lower() in ['true', '1', 't', 'y', 'yes'] else False
					numPlayers = 0
					namePlayers = ""
					for name,time in player_login.iteritems():
						if getdatetime.now() - time < datetime.timedelta(minutes=passed_minutes):
							numPlayers += 1
							if print_names:
								namePlayers += name+","
					log( "Number of logins from the past %d minutes: %d" % (passed_minutes, numPlayers) )
					if len(namePlayers) > 0:
						log( "Players: %s" % (namePlayers[:-1]) )
				else:
					log("Number of total logins: %d" % (len(player_login)))
				continue
			elif cmd[0] == "loglevel":
				if len(cmd) >= 2:
					loglvl = 0
					try:
						loglvl = int(cmd[1])
						if loglvl > len(log_level):
							loglvl = 0
					except ValueError:
						pass
					loglvl -= 1
					if loglvl < 0:
						for i in range(0,len(log_level)):
							log_level[i] = True
					else:
						log_level[loglvl] = not log_level[loglvl]
				log(str(log_level))
				continue
		log("Unknown Command")
		knownCommands();
	
