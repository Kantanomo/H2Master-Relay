#!/usr/bin/python
#Handles all sql query related code.
import MySQLdb
import socket
from Crypto.Cipher import AES
import json
# from local project
import get_local_ip
import login_details as logins

WHEN_FAIL_DISCONTINUE = False
FAILED_SQL = False
FAILED_QClient = True
QRELAY_IP = None

def comm_query_client(log_lvl, dest, query):
	global FAILED_QClient
	global QRELAY_IP
	if QRELAY_IP == None:
		QRELAY_IP = get_local_ip.getLocalIP()
		if QRELAY_IP == dest[0]:
			FAILED_QClient = True
			log_lvl(1, "[SQL Query Relay] Not allowed, this is the host!")
	if FAILED_QClient:
		log_lvl(1, "[SQL Query FAILURE] Services Offline.")
		return None
	
	received = None
	# Create a socket (SOCK_STREAM means a TCP socket)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		# Connect to server and send data
		sock.connect(dest)
		text = "f" + query
		if query[0].lower() == "u":
			text = "u" + query
		text = text + (" "*(16-(len(text) % 16)))
		# Encryption
		encryption_suite = AES.new(logins.encryption_key(), AES.MODE_CBC, logins.encryption_iv())
		cipher_text = encryption_suite.encrypt(text)
		sock.sendall(cipher_text)
		log_lvl(1, "[Query Relay] Sending query: \"%s\"." % query )

		# Receive data from the server
		#received = sock.recv(1024)
		decryption_suite = AES.new(logins.encryption_key(), AES.MODE_CBC, logins.encryption_iv())
		received = decryption_suite.decrypt(sock.recv(1024)).strip()
		if received[0] == "s":
			received = received[1:]
			try:
				received = json.loads(received)
			except Exception:
				log_lvl(3, "[Query Relay] Can't Decode Json." )
			log_lvl(3, "[Query Relay] Received reply: \"%s\"." % received )
		else:
			received = None
			if received[0] == "e":
				log_lvl(3, "[Query Relay] Received NULL reply." )
			else:
				log_lvl(1, "[Query Relay] ERROR Unknown reply! \"%s\"" % str(received) )
	except Exception as e:
		log_lvl(1, "[Query Relay] ERROR: %s" % str(e) )
		global WHEN_FAIL_DISCONTINUE
		if WHEN_FAIL_DISCONTINUE and len(str(e)) >= 13 and str(e)[:13] == "[Errno 10061]":
			FAILED_QClient = True
	finally:
		sock.close()
	return received

def get_sql_conn(log_lvl):
	global FAILED_SQL
	if FAILED_SQL:
		return 2003
	sql_conn = None
	try:
		sql_conn = MySQLdb.connect( **logins.login_sql() )
		#sql_conn = 2003
	except MySQLdb.Error as e:
		log_lvl(1, "[SQL Connect ERROR] "+str(e) )
		sql_conn = None
		global WHEN_FAIL_DISCONTINUE
		if WHEN_FAIL_DISCONTINUE and e[0] == 2003:
			FAILED_SQL = True
			sql_conn = 2003
	return sql_conn

def fetch_sql_result(log_lvl, query):
	sql_conn = get_sql_conn(log_lvl)
	results = None
	if sql_conn == 2003:
		results = comm_query_client(log_lvl, logins.login_relay(), query)
	elif sql_conn is not None:
		cursor = sql_conn.cursor()
		try:
			# Execute the SQL command
			cursor.execute(query)
			# Fetch all the rows in a list of lists.
			results = cursor.fetchall()
		except MySQLdb.Error as e:
			log_lvl(1, "[SQL ERROR] FAILED to fetch query: "+str(e) )
		
		sql_conn.close()
		
	return results

def commit_sql_query(log_lvl, query):
	sql_conn = get_sql_conn(log_lvl)
	if sql_conn == 2003:
		aaa= comm_query_client(log_lvl, logins.login_relay(), query)
		print str(aaa)
		if aaa == "":
			log_lvl(3, "[SQL Commit]: %s." % query )
			return True
	elif sql_conn is not None:
		cursor = sql_conn.cursor()
		try:
			# Execute the SQL command
			cursor.execute(query)
			# Commit your changes in the database
			sql_conn.commit()
			log_lvl(3, "[SQL Commit]: %s." % query )
			return True
		except MySQLdb.Error as e:
			# Rollback in case there is any error
			sql_conn.rollback()
			log_lvl(1, "[SQL ERROR] FAILED to commit query with error: "+str(e) )
		finally:
			sql_conn.close()
	log_lvl(1, "[SQL ERROR] FAILED to commit: \"%s\"." % (query) )
	return False

def update_sql_ip_port(log_lvl, ip_port, condition):
	query = "UPDATE user SET ip_port = '%s' WHERE %s" % (ip_port, condition)
	commit_sql_query(log_lvl, query)

def fetch_single_sql_result(log_lvl, condition):
	results = fetch_sql_result(log_lvl, condition)
	if results is not None and (type(results) == type([]) or type(results) == type(())) and len(results) > 0:
		return results[0]
	return None


def load_static_dedi_server_ips(log_lvl):
	ip_port_data = fetch_sql_result(log_lvl, "SELECT DISTINCT ip_port FROM user INNER JOIN dedi_servers ON user.username = dedi_servers.username WHERE ip_port IS NOT NULL")
	if ip_port_data is not None and len(ip_port_data) > 0:
		log_lvl(2, "All dedi ip_port data: "+str(ip_port_data) )
		ip_addr_list = []
		for client in ip_port_data:
			ip_addr = client[0].split(":")[0]
			if ip_addr not in ip_addr_list:
				ip_addr_list.append(ip_addr)
		return ip_addr_list
	log_lvl(1, "[SQL ERROR] FAILED to fetch dedi server IP addrs." )
	return None

def test_sql():
	log("test sql")
	#update_sql_ip_port("117.117.117.117:11117", "username = '%s'" % "Killer Chief")
	#load_user_from_sql_query_condition("saddr = %s" % str(12580352))
	#load_user_from_sql_query_condition("saddr = %d" % 12580352)
	#load_user_from_sql_query_condition("abEnet = %s" % "0xef589cbf0621")
	#load_user_from_sql_query_condition("abEnet = %s" % hex(0xef589cbf0621))
	#load_user_from_sql_query_condition("username = '%s'" % "Killer Chief")
	log("done testing sql")

