#!/usr/bin/python

#Do NOT Distribute!
#Security and login codes for h2master.

def login_sql():
	return {'host':"69.195.136.203", 'port':3306, 'user':"h2master204", 'passwd':"KotCwcHvoT7UUk0X", 'db':"H2Cartographer"}

def login_api_addr():
	return "http://69.195.136.203/H2Cartographer/api/new_api.php?launcher=0&token="


#For the server_sql_relay.py and accompanying client inside common_sql.py

def encryption_key():
	return "AwakeningMantle4"

def encryption_iv():
	return "71CrystalHaven74"

def login_relay():
	return ("149.56.81.89", 27021)
