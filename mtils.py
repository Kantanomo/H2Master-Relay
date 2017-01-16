#!/usr/bin/python
#mtils - multi-thread input and logger separator.
#By Killer Chief /aka/ Glitchy Scripts.
#Version 1.0
#Aimed to be compatible with Windows and Linux.

from __future__ import print_function
import thread
import threading
import sys
import math
#local project
import getch

def logger(text):
	_logger_core(1, text)

cmdBuffer = ""
inprogress = 0
loggerLock = threading.Lock()

def _logger_core(lvl, text):
	with loggerLock:
		global cmdBuffer
		global inprogress
		screenWidth = 72
		if lvl == 0:
			inprogress = 1
			formattedText = ""
			if text is not None:
				for i in range(0, int(math.ceil(len(text)/float(screenWidth)))):
					formattedText += text[i*screenWidth : (i*screenWidth)+screenWidth]+"\x0D"
				formattedText = formattedText[0 : -1]
			cmdBuffer = formattedText
			print("\x0D%s" % (formattedText), end="")
		elif lvl == 1:
			if inprogress == 1:
				print("\x0D%s\x0D" % (" "*len(cmdBuffer)), end="")
			print("%s\x0D" % (text) )
			if inprogress == 1:
				print("\x0D%s" % (cmdBuffer), end="")
		elif lvl == 3:
			print("\x0D%s\x0D" % (" "*len(cmdBuffer)), end="")
			inprogress = 0
		sys.stdout.flush()


cmdBuild = ""

def get(cmdLabel):
	global cmdBuild
	while 1:
		char = getch.getch()
		# ctrl+c or ctrl+d
		if char == "\x03" or char == "\x04":
			return -1
		# backspace or del
		elif char == "\x08" or char == "\x7F":
			if len(cmdBuild) > 0:
				cmdBuild = cmdBuild[0:-1]
			if len(cmdBuild) > 0:
				_logger_core(0, cmdLabel+cmdBuild+" \x08")
			else:
				_logger_core(3, None)
		# enter key
		elif char == "\x0D":
			_logger_core(3, None)
			rtntext = cmdBuild
			cmdBuild = ""
			return rtntext
		# Normal Chars
		elif ord(char) >= 30 and ord(char) <= 126:
			cmdBuild += char
			_logger_core(0, cmdLabel+cmdBuild)

