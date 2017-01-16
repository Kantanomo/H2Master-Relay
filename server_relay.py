#!/usr/bin/python
#Nov 2016
import SocketServer
import thread
import threading
import datetime
from datetime import datetime as getdatetime
import base64
# from local project
import get_local_ip
import mtils

dedicatedGameServers = dict()

# Preset Dedicated Servers
#dedicatedGameServers[("000.000.000.000",1001)] = (getdatetime.now(),0)

dict_lock = threading.Lock()
clients = dedicatedGameServers.copy()


class MyUDPHandler(SocketServer.BaseRequestHandler):

	def handle(self):
		s = self.request[1]
		data = self.request[0]

		with dict_lock:
			global clients
			global dedicatedGameServers
			broadcast_search_type = 0 # The Game Server replies to indicate to all users that a lobby is available
			if (data[0].encode('hex') == "07"):
				log_lvl(1, "[Lobby Available]: %s:%d." % self.client_address )
			if (data[0].encode('hex') == "05"):
				broadcast_search_type = 1 # The Client requests a search to be run to find available lobbys
			
			player = self.client_address
			annoyedLast = getdatetime.now()
			annoyanceFactor = 0

			if (clients.get(player, None) != None and broadcast_search_type == 1):
				annoyedLast = clients[player][0]
				annoyanceFactor = clients[player][1]
				if (getdatetime.now() - annoyedLast < datetime.timedelta(seconds=4)):
					annoyanceFactor += 1
				else:
					annoyanceFactor = 0
			
			clients[player] = (getdatetime.now(), annoyanceFactor)
			
			# Roughly 60 seconds of idle time in search menu.
			if (annoyanceFactor > 60):
				log_lvl(1, "[Ignore] Player Request(%d): %s:%d." % (annoyanceFactor, player[0], player[1]) )
			else:
				# Now since it hasn't been ignored, log the action.
				if (broadcast_search_type == 1):
					log_lvl(1, "[Lobby Search] Request(%d): %s:%d." % (annoyanceFactor, self.client_address[0], self.client_address[1]) )
				
				sent_to_string = ""
				
				for dest in clients.keys():
					# Remove any invalid entries (if they ever occur)
					if ( clients.get(dest, None) == None or type(clients.get(dest, None)) != type(()) or len(clients.get(dest, None)) != 2 ):
						log_lvl(1, "[ERROR] There was an invalid entry %s" % str(dest) )
						del clients[dest]
						continue
					
					# Sends out search for hosts
					if (broadcast_search_type == 1):
						sent_to_string += "{}:{}, ".format(dest[0],dest[1])
						s.sendto(data, (dest[0],dest[1]) )
					# Sends replies to active listeners.
					elif (dest not in dedicatedGameServers and broadcast_search_type == 0 and getdatetime.now() - clients.get(dest, None)[0] < datetime.timedelta(seconds=5) ):
						sent_to_string += "{}:{}, ".format(dest[0],dest[1])
						s.sendto(data, (dest[0],dest[1]) )
					
					# Gets rid of those excess IP's that cant host and have idled.
					#if (dest[1] != 1001 and getdatetime.now() - clients.get(dest, 0)[0] > datetime.timedelta(minutes=1)):
					#	log( "Removing >1 minute old non-host entry: {}:{}".format(dest[0],dest[1]) )
					#	del clients[dest]
					#	continue
					
					if (dest not in dedicatedGameServers and broadcast_search_type == 1):
						# Removes inactive players from search list.
						if (getdatetime.now() - clients.get(dest, 0)[0] > datetime.timedelta(minutes=20)):
							log_lvl(1, "[REMOVE OLD] >20 minute old entry: %s:%d" % dest )
							del clients[dest]
							continue
				
				# Logs sent packets to terminal.
				if (broadcast_search_type == 1):
					if len(sent_to_string) >= 2:
						log_lvl(2, "[Lobby Search] Ask: %s." % sent_to_string[:-2] )
				elif (broadcast_search_type == 0):
					if len(sent_to_string) >= 2:
						log_lvl(2, "[Lobby Available] Tell: %s." % sent_to_string[:-2] )

def init_relay_server():
	HOST, PORT = get_local_ip.getLocalIP(), 1001
	log( "Binding to (Local) IP on Port: {}:{}".format(HOST, PORT) )
	server = SocketServer.UDPServer((HOST,PORT), MyUDPHandler)
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

def write_clients_dict_to_file():
	with dict_lock:
		global clients
		global dedicatedGameServers
		log("Saving client dict...")
		file = open("clients.txt", "w")
		for key in clients:
			if key not in dedicatedGameServers:
				file.write( "%s:%d\n" % (key[0], key[1]) )
		file.close()
		log("Saved client dict.")

def load_clients_dict_from_file():
	with dict_lock:
		global clients
		log("Loading client dict...")
		file = open("clients.txt", "r")
		for line in file:
			if line is not None and line is not "":
				values = line.strip().split(':')
				try:
					clients[(str(values[0]),int(values[1]))] = (getdatetime.now(),0)
				except ValueError as e:
					log("ValueError: "+str(e))
		file.close()
		log("Loaded client dict.")

def clear_dedi_dict():
	with dict_lock:
		global dedicatedGameServers
		dedicatedGameServers = dict()
		log("Cleared dedicated server dict.")
		
def clear_clients_dict():
	with dict_lock:
		global clients
		global dedicatedGameServers
		clients = dedicatedGameServers.copy()
		log("Cleared client dict.")

def clear_all_dict():
	with dict_lock:
		global clients
		global dedicatedGameServers
		dedicatedGameServers = dict()
		clients = dict()
		log("Cleared client and dedicated server dict.")
		
def quit():
	log("Exiting...")
	exit()

def knownCommands():
	log("help, (quit, q, exit, close, stop) [save_bool=True], save, load, clear [all/client/dedicated], loglevel [level_num].")

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
					write_clients_dict_to_file()
				quit()
			elif cmd[0] == "help":
				knownCommands()
				continue
			elif cmd[0] == "save":
				write_clients_dict_to_file()
				continue
			elif cmd[0] == "load":
				load_clients_dict_from_file()
				continue
			elif cmd[0] == "clear":
				if len(cmd) >= 2:
					if cmd[1].lower() == "all":
						clear_all_dict()
						continue
					elif cmd[1].lower() == "client":
						clear_clients_dict()
						continue
					elif cmd[1].lower() == "dedicated":
						clear_dedi_dict()
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
	
	
