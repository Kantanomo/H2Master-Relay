#!/usr/bin/python
#Latest sql relay server since Dec 2016.
import SocketServer
from datetime import datetime as getdatetime
from Crypto.Cipher import AES
import json
# from local project
import get_local_ip
import mtils
from common_sql import fetch_sql_result
from common_sql import commit_sql_query
import login_details as logins

class MyTCPHandler(SocketServer.BaseRequestHandler):

	def handle(self):
		# Decryption
		decryption_suite = AES.new(logins.encryption_key(), AES.MODE_CBC, logins.encryption_iv())
		data = decryption_suite.decrypt(self.request.recv(1024)).strip()
		reply = "e"
		
		log_lvl(1, "%s:%d - \"%s\"." % (self.client_address[0], self.client_address[1], data))
		if data[0] == "f":
			query_results = handle_sql_query(data[1:])
			if query_results != None:
				reply = "s"+query_results
		elif data[0] == "u":
			if commit_sql_query(log_lvl, data[1:]):
				reply = "s"
		else:
			log_lvl(1, "incorrect packet type: %s" % data[0] )
		# Encryption
		reply = reply + (" "*(16-(len(reply) % 16)))
		encryption_suite = AES.new(logins.encryption_key(), AES.MODE_CBC, logins.encryption_iv())
		cipher_text = encryption_suite.encrypt(reply)
		
		self.request.sendall(cipher_text)

def handle_sql_query(query):
	results = fetch_sql_result(log_lvl, query)
	if results == None or (type(results) == type(()) and len(results) == 0):
		log_lvl(1, "Returning NULL" )
		return None
	resultsAsString = json.dumps(results)
	return resultsAsString

def log(text):
	#print "%s> %s" % (getdatetime.strftime(getdatetime.now(), '%H:%M:%S').lower(), text)
	mtils.logger("%s> %s" % (getdatetime.strftime(getdatetime.now(), '%H:%M:%S').lower(), text))

log_level = [True,True,True]
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

def init_relay_server():
	HOST, PORT = get_local_ip.getLocalIP(), logins.login_relay()[1]
	log( "Binding to (Local) IP on Port: {}:{}".format(HOST, PORT) )
	server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
	server.serve_forever()

if __name__ == "__main__":
	init_relay_server()
