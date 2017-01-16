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

print is_valid_ip("")
print is_valid_ip("0.1.1.1")
print is_valid_ip("127.0.0.1")
print is_valid_ip("1.1.1.")
print is_valid_ip("1..1.1")
print is_valid_ip(".1.1.1")
print is_valid_ip("123.123.123.1234")
print is_valid_ip([])
print is_valid_ip(None)
print "Okay"
print is_valid_ip("123.123.123.123")