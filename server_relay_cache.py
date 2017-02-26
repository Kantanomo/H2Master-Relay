#!/usr/bin/python
#This version caches the lobby data and alters the packet to send valid replies to clients asking. This greatly reduces the load on the master as well as all game lobbies.
#This version also contains many commands and now allows Client whitelisting and blacklisting control.
#Active as the relay server since Jan 2017.
import SocketServer
import thread
import threading
import datetime
from datetime import datetime as getdatetime
import base64
import json
import os.path
import copy
# from local project
import get_local_ip
import mtils
from common_sql import load_static_dedi_server_ips

CLT_LAST_COMM = 0
CLT_ANNOYANCE_FACTOR = 1
CLT_IS_SERVER = 2
CLT_LOBBY_DATA = 3
CLT_TIMEOUT_FACTOR = 4
CLT_LAST_REQUEST = 5
CLT_DICT_LENGTH = 6

ip_data = dict()
clients = dict()
dict_lock = threading.Lock()

# IP: [Ports], Dedi, Blocked, Release Time, whitelist, blacklist
#ip_data["127.0.0.1"] = [[1001, 2001], True, False, getdatetime.now(), []]
IPD_PORTS = 0
IPD_IS_STATIC_DEDI = 1
IPD_BLOCKED = 2
IPD_BLOCKED_RELEASE = 3
IPD_LOBBY_WHITELIST = 4
IPD_LOBBY_BLACKLIST = 5
IPD_DICT_LENGTH = 6

CONST_BEFORE_BEGINNING_OF_TIME = getdatetime.now() - datetime.timedelta(seconds=360)
CONST_PORT_LIMIT = 50 #Any IP that exceeds this limit gets blocked (Spam/DDoS prevention)
CONST_BLOCKED_LENGTH = (0, 6, 0) #Days, Hours, Minutes
CONST_IDLE_SECONDS = 60 * 5 #Roughly time allowed to idle for in lobby list
CONST_REQ_FREQ = 5 #Lobby request frequency in seconds
CONST_RETRY_FREQ = 4 #Lobby request retry frequency in seconds
CONST_TIMEOUT_LEN = 20 #CONST_REQ_FREQ + CONST_RETRY_FREQ * THIS ~= Seconds till removal with active clients pinging.

def get_dict_lock_on_call(func, *args):
	with dict_lock:
		global ip_data
		global clients
		return func(ip_data, clients, *args)

def ensure_ip_data_exists_valid(ip_data, ip_addr, deep_check=False):
	if ip_data.get(ip_addr, None) == None or not type(ip_data[ip_addr]) == type([]) or len(ip_data[ip_addr]) <= 0:
		ip_data[ip_addr] = [[], False, False, CONST_BEFORE_BEGINNING_OF_TIME, [], []]
		return False
	if not deep_check and len(ip_data[ip_addr]) == IPD_DICT_LENGTH:
		return True
	ip_addr_len = len(ip_data[ip_addr])
	ports = []
	isDedi = False
	isBlocked = False
	blockedRelease = getdatetime.now() + datetime.timedelta(days=CONST_BLOCKED_LENGTH[0], hours=CONST_BLOCKED_LENGTH[1], minutes=CONST_BLOCKED_LENGTH[2] + 1)
	lobbyWhitelist = []
	lobbyBlacklist = []
	if ip_addr_len >= 1 and type(ip_data[ip_addr][IPD_PORTS]) == type([]):
		ports = ip_data[ip_addr][IPD_PORTS]
	if ip_addr_len >= 2 and type(ip_data[ip_addr][IPD_IS_STATIC_DEDI]) == type(True):
		isDedi = ip_data[ip_addr][IPD_IS_STATIC_DEDI]
	if ip_addr_len >= 3 and type(ip_data[ip_addr][IPD_BLOCKED]) == type(True):
		isBlocked = ip_data[ip_addr][IPD_BLOCKED]
	if ip_addr_len >= 4 and type(ip_data[ip_addr][IPD_BLOCKED_RELEASE]) == type(CONST_BEFORE_BEGINNING_OF_TIME):
		blockedRelease = ip_data[ip_addr][IPD_BLOCKED_RELEASE]
	elif ip_addr_len >= 4 and (type(ip_data[ip_addr][IPD_BLOCKED_RELEASE]) == type("str") or type(ip_data[ip_addr][IPD_BLOCKED_RELEASE]) == type(u"uni")):
		blockedRelease = datetime.datetime.strptime(ip_data[ip_addr][IPD_BLOCKED_RELEASE], "%Y-%m-%d %H:%M:%S.%f")
	if ip_addr_len >= 5:
		lobbyWhitelist = ip_data[ip_addr][IPD_LOBBY_WHITELIST]
	if ip_addr_len >= 6:
		lobbyBlacklist = ip_data[ip_addr][IPD_LOBBY_BLACKLIST]
	ip_data[ip_addr] = [ports, isDedi, isBlocked, blockedRelease, lobbyWhitelist, lobbyBlacklist]
	return True

def add_port_to_ip_data(ip_data, client):
	ensure_ip_data_exists_valid(ip_data, client[0])
	if client[1] not in ip_data[client[0]][IPD_PORTS]:
		ip_data[client[0]][IPD_PORTS].append(client[1])
		if len(ip_data[client[0]][IPD_PORTS]) >= CONST_PORT_LIMIT:
			block_ip(ip_data, client, client[0])

def block_ip(ip_data, client, ip, length_of_time=CONST_BLOCKED_LENGTH):
	blocked_length = length_of_time
	if type(blocked_length) == type(""):
		blt = blocked_length.split(':')
		if len(blt) == 3:
			try:
				blocked_length = (int(blt[0]), int(blt[1]), int(blt[2]))
			except:
				return False
		else:
			blocked_length = CONST_BLOCKED_LENGTH
	elif type(blocked_length) == type(()) and len(blocked_length) == 3 and type(blocked_length[0]) == type(0) and type(blocked_length[1]) == type(0) and type(blocked_length[2]) == type(0):
		pass
	else:
		blocked_length = CONST_BLOCKED_LENGTH
	ensure_ip_data_exists_valid(ip_data, ip, True)
	ip_data[ip][IPD_BLOCKED] = True
	ip_data[ip][IPD_BLOCKED_RELEASE] = getdatetime.now() + datetime.timedelta(days=blocked_length[0], hours=blocked_length[1], minutes=blocked_length[2] + 1)
	return True

def remove_client(ip_data, clients, client):
	if clients.get(client, None) != None:
		del clients[client]
	if ip_data.get(client[0], None) != None:
		if len(ip_data[client[0]][IPD_PORTS]) <= 1 and not ip_data[client[0]][IPD_BLOCKED]:
			del ip_data[client[0]]
		else:
			if client[1] in ip_data[client[0]][IPD_PORTS]:
				ip_data[client[0]][IPD_PORTS].remove(client[1])

class MyUDPHandler(SocketServer.BaseRequestHandler):

	def handle(self):
		s = self.request[1]
		pkt_data = self.request[0]
		
		if len(pkt_data) < 1:
			return

		with dict_lock:
			global clients
			global ip_data
			client = self.client_address
			
			if LOCAL_ADDRESS[0] == client[0] and LOCAL_ADDRESS[1] == client[1]:
				log("[WARNING] LOCAL ADDRESS PACKET RECEIVED!")
				log("Data: %s." % pkt_data.encode('hex'))
				return
			
			if ip_data.get(client[0], None) != None and ip_data[client[0]][IPD_BLOCKED]:
				td = ip_data[client[0]][IPD_BLOCKED_RELEASE] - getdatetime.now()
				if td < datetime.timedelta(minutes=1) and len(ip_data[client[0]][IPD_PORTS]) < CONST_PORT_LIMIT:
					ip_data[client[0]][IPD_BLOCKED] = False
				else:
					if td < datetime.timedelta(minutes=1):
						td = datetime.timedelta(minutes=0)
					log_lvl(1, "[BLOCKED]: %s:%d - Releases: %dD:%dH:%dM." % (client[0], client[1], td.days, td.seconds//3600, (td.seconds//60)%60 ) )
					return
			
			is_server = False
			lobbyData = None
			if pkt_data[0].encode('hex') == "07": # An active game lobby data packet
				is_server = True
				lobbyData = pkt_data
				log_lvl(1, "[Lobby Available]: %s:%d." % self.client_address )
			elif pkt_data[0].encode('hex') == "05": # Game lobby search
				pass
			elif pkt_data[0].encode('hex') == "00" and len(pkt_data) >= 3 and pkt_data[1].encode('hex') == "43": # Client Commands
				if pkt_data[2].encode('hex') not in ["01", "02"]:
					s.sendto("Unsupported Version!", (client[0],client[1]) )
					return
				if len(pkt_data) > 3:
					command = pkt_data[3:]
					log("[Client CMD](%s:%d): %s." % (client[0], client[1], command))
					cmdParts = command.split()
					if len(cmdParts) > 0 and cmdParts[0] != "":
						if cmdParts[0].lower() == "push":
							if len(cmdParts) >= 2:
								if cmdParts[1].lower() == "dedilobby" and len(cmdParts) == 3 and is_valid_port(cmdParts[2]):
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									add_port_to_ip_data(ip_data, (client[0], int(cmdParts[2])))
									if (client[0], int(cmdParts[2])) not in clients:
										clients[(client[0], int(cmdParts[2]))] = [getdatetime.now(), 0, False, None, 0, CONST_BEFORE_BEGINNING_OF_TIME]
									s.sendto("Push Successful.", (client[0],client[1]) )
									return
						if cmdParts[0].lower() == "add":
							if len(cmdParts) >= 2:
								if cmdParts[1].lower() == "lobby_whitelist" and len(cmdParts) == 3 and is_valid_ip(cmdParts[2]):
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									if cmdParts[2] not in ip_data[client[0]][IPD_LOBBY_WHITELIST]:
										ip_data[client[0]][IPD_LOBBY_WHITELIST].append(cmdParts[2])
									s.sendto("Lobby Whitelist Addition Successful.", (client[0],client[1]) )
									return
								elif cmdParts[1].lower() == "lobby_blacklist" and len(cmdParts) == 3 and is_valid_ip(cmdParts[2]):
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									if cmdParts[2] not in ip_data[client[0]][IPD_LOBBY_BLACKLIST]:
										ip_data[client[0]][IPD_LOBBY_BLACKLIST].append(cmdParts[2])
									s.sendto("Lobby Blacklist Addition Successful.", (client[0],client[1]) )
									return
						elif cmdParts[0].lower() == "show":
							if len(cmdParts) >= 2:
								if cmdParts[1].lower() == "lobby_whitelist":
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									build_reply = ""
									for ip_addr in ip_data[client[0]][IPD_LOBBY_WHITELIST]:
										build_reply = str(build_reply) + ",  " + ip_addr
									if len(build_reply) > 3:
										build_reply = "Whitelisted IPs: %s." % build_reply[3:]
									else:
										build_reply = "There are no Whitelisted IPs."
									s.sendto(build_reply, (client[0],client[1]) )
									return
								elif cmdParts[1].lower() == "lobby_blacklist":
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									build_reply = ""
									for ip_addr in ip_data[client[0]][IPD_LOBBY_BLACKLIST]:
										build_reply = str(build_reply) + ",  " + ip_addr
									if len(build_reply) > 3:
										build_reply = "Blacklisted IPs: %s." % build_reply[3:]
									else:
										build_reply = "There are no Blacklisted IPs."
									s.sendto(build_reply, (client[0],client[1]) )
									return
						elif cmdParts[0].lower() == "remove":
							if len(cmdParts) >= 2:
								if cmdParts[1].lower() == "lobby_whitelist" and len(cmdParts) == 3 and is_valid_ip(cmdParts[2]):
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									if cmdParts[2] in ip_data[client[0]][IPD_LOBBY_WHITELIST]:
										ip_data[client[0]][IPD_LOBBY_WHITELIST].remove(cmdParts[2])
									s.sendto("Lobby Whitelist Removal Successful.", (client[0],client[1]) )
									return
								elif cmdParts[1].lower() == "lobby_blacklist" and len(cmdParts) == 3 and is_valid_ip(cmdParts[2]):
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									if cmdParts[2] in ip_data[client[0]][IPD_LOBBY_BLACKLIST]:
										ip_data[client[0]][IPD_LOBBY_BLACKLIST].remove(cmdParts[2])
									s.sendto("Lobby Blacklist Removal Successful.", (client[0],client[1]) )
									return
						elif cmdParts[0].lower() == "clear":
							if len(cmdParts) >= 2:
								if cmdParts[1].lower() == "lobby_whitelist":
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									ip_data[client[0]][IPD_LOBBY_WHITELIST] = []
									s.sendto("Lobby Whitelist Successfully Cleared.", (client[0],client[1]) )
									return
								elif cmdParts[1].lower() == "lobby_blacklist":
									ensure_ip_data_exists_valid(ip_data, client[0], True)
									ip_data[client[0]][IPD_LOBBY_BLACKLIST] = []
									s.sendto("Lobby Blacklist Successfully Cleared.", (client[0],client[1]) )
									return
				s.sendto("CMD FAILED!", (client[0],client[1]) )
				log("[Client CMD FAILED](%s:%d)." % (client[0], client[1]))
				return
			else:
				pass
			
			lastComm = getdatetime.now()
			annoyanceFactor = 0
			
			add_port_to_ip_data(ip_data, client)
			
			if clients.get(client, None) != None and is_server == False:
				lastComm = clients[client][CLT_LAST_COMM]
				annoyanceFactor = clients[client][CLT_ANNOYANCE_FACTOR]
				if (getdatetime.now() - lastComm < datetime.timedelta(microseconds=900*1000)):
					annoyanceFactor += 10
				elif (getdatetime.now() - lastComm < datetime.timedelta(seconds=4)):
					annoyanceFactor += 1
				else:
					annoyanceFactor = 0
			
			clients[client] = [getdatetime.now(), annoyanceFactor, is_server, lobbyData, 0, CONST_BEFORE_BEGINNING_OF_TIME]
			
			if is_server == False:
				# Roughly seconds of idle time in search menu.
				if annoyanceFactor > CONST_IDLE_SECONDS:
					log_lvl(1, "[Ignore] Player Request(%d): %s:%d." % (annoyanceFactor, client[0], client[1]) )
				else:
					log_lvl(1, "[Lobby Search] Request(%d): %s:%d." % (annoyanceFactor, self.client_address[0], self.client_address[1]) )
					
					#clients[client][CLT_LAST_COMM] = getdatetime.now() - datetime.timedelta(seconds=(CONST_REQ_FREQ-3))
					
					sent_to_string = ""
					
					for dest in clients.keys():
						if dest == client:
							continue
						# Remove any invalid entries (if they ever occur)
						if ( clients.get(dest, None) == None or type(clients[dest]) != type([]) or len(clients[dest]) != CLT_DICT_LENGTH ):
							log_lvl(1, "[ERROR] There was an invalid entry %s." % str(dest) )
							remove_client(ip_data, clients, dest)
							continue
						if clients[dest][CLT_TIMEOUT_FACTOR] >= CONST_TIMEOUT_LEN and (ip_data.get(dest[0], None) == None or not ip_data[dest[0]][IPD_IS_STATIC_DEDI]):
							log_lvl(1, "[TIMEOUT] %s:%d." % dest )
							remove_client(ip_data, clients, dest)
							continue
						
						if len(ip_data[dest[0]][IPD_LOBBY_WHITELIST]) > 0:
							if client[0] not in ip_data[dest[0]][IPD_LOBBY_WHITELIST]:
								continue
						if len(ip_data[dest[0]][IPD_LOBBY_BLACKLIST]) > 0:
							if client[0] in ip_data[dest[0]][IPD_LOBBY_BLACKLIST]:
								continue
						
						if getdatetime.now() - clients[dest][CLT_LAST_COMM] < datetime.timedelta(seconds=CONST_REQ_FREQ*1.4):
							built_packet_reply = build_valid_packet_reply(pkt_data, clients[dest][CLT_LOBBY_DATA])
							if built_packet_reply == 0:
								#one of the packets were null
								pass
							elif type(built_packet_reply) == type(0):
								#unknown packet
								log_lvl(1, "[UNKNOWN PACKET] Err:%d - " % built_packet_reply)
								log_lvl(1, "0x05-Data: %s." % pkt_data.encode('hex'))
								log_lvl(1, "0x07-Data: %s." % clients[dest][CLT_LOBBY_DATA].encode('hex'))
							else:
								s.sendto(built_packet_reply, (client[0],client[1]) )
						
						#Made it a 3 second delay for the first time you ask for a p2p lobby.
						if getdatetime.now() - clients[dest][CLT_LAST_COMM] + (datetime.timedelta(seconds=(CONST_REQ_FREQ-3)) if not clients[dest][CLT_IS_SERVER] else datetime.timedelta(seconds=0)) > datetime.timedelta(seconds=CONST_REQ_FREQ):
							if getdatetime.now() - clients[dest][CLT_LAST_REQUEST] > datetime.timedelta(seconds=CONST_RETRY_FREQ):
								# Sends out search for hosts
								sent_to_string += "{}:{}, ".format(dest[0],dest[1])
								if ip_data.get(dest[0], None) != None and not ip_data[dest[0]][IPD_IS_STATIC_DEDI]:
									clients[dest][CLT_TIMEOUT_FACTOR] += 1
									if clients[dest][CLT_TIMEOUT_FACTOR] >= 2:
										log_lvl(2, "[Timing Out] (%d) %s:%d." % (clients[dest][CLT_TIMEOUT_FACTOR], dest[0], dest[1]))
								clients[dest][CLT_LAST_REQUEST] = getdatetime.now()
								s.sendto(pkt_data, (dest[0],dest[1]) )
					
					# Logs sent packets to terminal.
					if len(sent_to_string) >= 2:
						log_lvl(2, "[Lobby Search] Ask: %s." % sent_to_string[:-2] )
	
def build_valid_packet_reply(pkt_data_request, pkt_data_lobby):
	if pkt_data_request == None or pkt_data_lobby == None:
		return 0
	elif len(pkt_data_request) != 14:
		return 1
	elif len(pkt_data_lobby) < 14:
		return 2
	data_packet = pkt_data_lobby[:5].encode('hex') + pkt_data_request[5:13].encode('hex') + ("05" if pkt_data_request[13].encode('hex') == "01" else "04") + pkt_data_lobby[14:].encode('hex')
	return data_packet.decode('hex')

def add_dedi_servers(ip_data):
	ip_list = load_static_dedi_server_ips(log_lvl)
	if ip_list is not None:
		for ip_addr in ip_list:
			ensure_ip_data_exists_valid(ip_data, ip_addr, True)
			ip_data[ip_addr][IPD_IS_STATIC_DEDI] = True
		log_lvl(1, "[LOAD] Loaded static dedi server ip addrs." )
		return
	log_lvl(1, "[ERROR] FAILED to load static dedi server ip addrs." )

LOCAL_ADDRESS = (get_local_ip.getLocalIP(), 1001)

def init_relay_server():
	log( "Loading Dedi Servers..." )
	add_dedi_servers(ip_data)
	log( "Binding to (Local) IP on Port: %s:%d" % LOCAL_ADDRESS )
	server = SocketServer.UDPServer(LOCAL_ADDRESS, MyUDPHandler)
	server.serve_forever()

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

def write_dicts_to_file():
	with dict_lock:
		global ip_data
		log("Saving dicts...")
		file = open("ip_data.json", "w")
		ip_data_copy = copy.deepcopy(ip_data)
		for ip_addr in ip_data_copy.keys():
			ip_data_copy[ip_addr][IPD_BLOCKED_RELEASE] = str(ip_data_copy[ip_addr][IPD_BLOCKED_RELEASE])
		file.write( json.dumps(ip_data_copy).strip().replace("], \"", "], \n\"") )
			#IP: [Ports], Dedi, Blocked, Release Time
		#file.write( "%s:%d\n" % (ip_addr, ip_data[ip_addr][IPD_PORTS], ip_data[ip_addr][IPD_IS_STATIC_DEDI], ip_data[ip_addr][IPD_BLOCKED], ip_data[ip_addr][IPD_BLOCKED_RELEASE]) )
		file.close()
		log("Saved dicts.")

def load_old_clients_dict_from_file():
	if not os.path.exists("clients.txt"):
		log("Save file does not exist!")
		return
	with dict_lock:
		global clients
		global ip_data
		log("Loading old client dict...")
		file = open("clients.txt", "r")
		for line in file:
			if line is not None and line is not "":
				values = line.strip().split(':')
				try:
					client = (str(values[0]),int(values[1]))
					add_port_to_ip_data(ip_data, client)
					clients[client] = [CONST_BEFORE_BEGINNING_OF_TIME, 0, False, None, 0, CONST_BEFORE_BEGINNING_OF_TIME]
				except ValueError as e:
					log("ValueError: "+str(e))
		file.close()
		log("Loaded old client dict.")

def load_dicts_from_file():
	if not os.path.exists("ip_data.json"):
		log("Save file does not exist!")
		return
	with dict_lock:
		global clients
		global ip_data
		log("Loading dicts...")
		with open("ip_data.json", "r") as file:
			ip_data = json.loads(file.read())
			for ip_addr in ip_data:
				ensure_ip_data_exists_valid(ip_data, ip_addr, True)
		for ip_addr in ip_data.keys():
			for port in ip_data[ip_addr][IPD_PORTS]:
				clients[(ip_addr, port)] = [CONST_BEFORE_BEGINNING_OF_TIME, 0, False, None, 0, CONST_BEFORE_BEGINNING_OF_TIME]
		log("Loaded dicts.")

def clear_ip_data_dict():
	with dict_lock:
		global clients
		global ip_data
		ip_data = dict()
		add_dedi_servers(ip_data)
		for client in clients.keys():
			add_port_to_ip_data(ip_data, client)
		log("Cleared and restocked ip_data dict.")
		
def clear_clients_dict():
	with dict_lock:
		global clients
		global ip_data
		clients = dict()
		for ip_addr in ip_data.keys():
			if not ip_data[ip_addr][IPD_IS_STATIC_DEDI]:
				del ip_data[ip_addr]
		log("Cleared client dict.")

def clear_all_dict():
	with dict_lock:
		global clients
		clients = dict()
		global ip_data
		ip_data = dict()
		add_dedi_servers(ip_data)
		log("Cleared client and ip_data dict.")

def is_valid_port(port):
	if type(port) == type("") and len(port) > 0:
		for part in port:
			if not part.isdigit():
				return False
		if int(port) <= 0 or int(port) > 65535:
			return False
		return True
	return False
		
def is_valid_ip(ip):
	if type(ip) == type(""):
		ip_parts = ip.split(".")
		if len(ip_parts) == 4:
			rebuild = ""
			for part in ip_parts:
				if len(part) > 0 and len(part) <= 3 and part.isdigit():
					rebuild = rebuild + str(int(part)) + "."
				else:
					return False
			rebuild = rebuild[:-1]
			if rebuild == ip:
				firstDigit = int(ip_parts[0])
				if firstDigit != 0:
					if rebuild != "127.0.0.1":
						return True
	return False
		
def quit():
	log("Exiting...")
	exit()

def knownCommands():
	log("\nAvailable Commands:\
	\nhelp,\
	\n(quit, q, exit, close, stop) [save_bool=True],\
	\nsave,\
	\nload,\
	\nloadold,\
	\nadd [blocked [ip] (d:h:m) / [lobby_whitelist/lobby_blacklist] [lobby_ip] [ip]],\
	\nshow [blocked / [lobby_whitelist/lobby_blacklist] [lobby_ip]],\
	\nremove [blocked [ip] / [lobby_whitelist/lobby_blacklist] [lobby_ip] [ip]],\
	\nclear [all / client / dedicated / blocked / [lobby_whitelist/lobby_blacklist] [lobby_ip]],\
	\nloglevel [level_num].")

if __name__ == "__main__":
	#init_relay_server()
	#try:
	thread.start_new_thread( init_relay_server, () )
	#except:
	#	log("ERROR: Unable to start relay server thread!")
	
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
				if len(cmd) == 1 or (len(cmd) >= 2 and cmd[1].lower() in ['true', '1', 't', 'y', 'yes']):
					write_dicts_to_file()
				quit()
			elif cmd[0] == "help":
				knownCommands()
				continue
			elif cmd[0] == "save":
				write_dicts_to_file()
				continue
			elif cmd[0] == "loadold":
				load_old_clients_dict_from_file()
				continue
			elif cmd[0] == "load":
				load_dicts_from_file()
				continue
			elif cmd[0] == "add":
				if len(cmd) >= 2:
					if cmd[1].lower() == "blocked" and (len(cmd) == 3 or len(cmd) == 4) and is_valid_ip(cmd[2]):
						if len(cmd) == 3:
							if get_dict_lock_on_call(block_ip, cmd[2]):
								continue
						else:
							if get_dict_lock_on_call(block_ip, cmd[2], cmd[3]):
								continue
					elif cmd[1].lower() == "lobby_whitelist" and len(cmd) == 4 and is_valid_ip(cmd[2]) and is_valid_ip(cmd[3]):
						with dict_lock:
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory. Creating...")
								ensure_ip_data_exists_valid(ip_data, cmd[2])
							if cmd[3] not in ip_data[cmd[2]][IPD_LOBBY_WHITELIST]:
								ip_data[cmd[2]][IPD_LOBBY_WHITELIST].append(cmd[3])
							continue
					elif cmd[1].lower() == "lobby_blacklist" and len(cmd) == 4 and is_valid_ip(cmd[2]) and is_valid_ip(cmd[3]):
						with dict_lock:
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory. Creating...")
								ensure_ip_data_exists_valid(ip_data, cmd[2])
							if cmd[3] not in ip_data[cmd[2]][IPD_LOBBY_BLACKLIST]:
								ip_data[cmd[2]][IPD_LOBBY_BLACKLIST].append(cmd[3])
							continue
			elif cmd[0] == "show":
				if len(cmd) >= 2:
					if cmd[1].lower() == "blocked":
						build_blocked = ""
						with dict_lock:
							for ip_addr in ip_data.keys():
								if ip_data[ip_addr][IPD_BLOCKED]:
									build_blocked = str(build_blocked) + ",  " + ip_addr
						if len(build_blocked) > 3:
							log("Blocked IPs: %s." % build_blocked[3:])
						else:
							log("There are no Blocked IPs.")
						continue
					elif cmd[1].lower() == "lobby_whitelist" and len(cmd) == 3 and is_valid_ip(cmd[2]):
						with dict_lock:
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							build_blocked = ""
							for ip_addr in ip_data[cmd[2]][IPD_LOBBY_WHITELIST]:
								build_blocked = str(build_blocked) + ",  " + ip_addr
							if len(build_blocked) > 3:
								log("Whitelisted IPs: %s." % build_blocked[3:])
							else:
								log("There are no Whitelisted IPs.")
							continue
					elif cmd[1].lower() == "lobby_blacklist" and len(cmd) == 3 and is_valid_ip(cmd[2]):
						with dict_lock:
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							build_blocked = ""
							for ip_addr in ip_data[cmd[2]][IPD_LOBBY_BLACKLIST]:
								build_blocked = str(build_blocked) + ",  " + ip_addr
							if len(build_blocked) > 3:
								log("Blacklisted IPs: %s." % build_blocked[3:])
							else:
								log("There are no Blacklisted IPs.")
							continue
			elif cmd[0] == "remove":
				if len(cmd) >= 2:
					with dict_lock:
						if cmd[1].lower() == "blocked" and len(cmd) == 3 and is_valid_ip(cmd[2]):
							if cmd[2] in ip_data.keys():
								ip_data[cmd[2]][IPD_BLOCKED] = False
								continue
						elif cmd[1].lower() == "lobby_whitelist" and len(cmd) == 4 and is_valid_ip(cmd[2]) and is_valid_ip(cmd[3]):
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							if cmd[3] in ip_data[cmd[2]][IPD_LOBBY_WHITELIST]:
								ip_data[cmd[2]][IPD_LOBBY_WHITELIST].remove(cmd[3])
							continue
						elif cmd[1].lower() == "lobby_blacklist" and len(cmd) == 4 and is_valid_ip(cmd[2]) and is_valid_ip(cmd[3]):
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							if cmd[3] in ip_data[cmd[2]][IPD_LOBBY_BLACKLIST]:
								ip_data[cmd[2]][IPD_LOBBY_BLACKLIST].remove(cmd[3])
							continue
			elif cmd[0] == "clear":
				if len(cmd) >= 2:
					with dict_lock:
						if cmd[1].lower() == "all":
							clear_all_dict()
							continue
						elif cmd[1].lower() == "client":
							clear_clients_dict()
							continue
						elif cmd[1].lower() == "ip_data":
							clear_ip_data_dict()
							continue
						elif cmd[1].lower() == "blocked":
							for ip_addr in ip_data.keys():
								if ip_data[ip_addr][IPD_BLOCKED]:
									ip_data[ip_addr][IPD_BLOCKED] = False
							continue
						elif cmd[1].lower() == "lobby_whitelist" and len(cmd) == 3 and is_valid_ip(cmd[2]):
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							ip_data[cmd[2]][IPD_LOBBY_WHITELIST] = []
							continue
						elif cmd[1].lower() == "lobby_blacklist" and len(cmd) == 3 and is_valid_ip(cmd[2]):
							if cmd[2] not in ip_data.keys():
								log("That IP is not present in memory.")
								continue
							ip_data[cmd[2]][IPD_LOBBY_BLACKLIST] = []
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
	
	