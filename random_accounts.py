#!/usr/bin/python
#Handles whether random account data should be generated in case of sql db downage.
import threading

playerNumberLock = threading.Lock()
playerNumber = 1

playerNames = ["Blarg", "Wort", "Cave Man", "Billy", "Bob", "Jimmy", "Match", "Nin", "Water", "Toasty", "Wet", "Dry", "Black", "Thorn", "Quad", "Bulb", "Pinky", "Earth", "Fire", "Avatar", "Air", "Bendy", "Dino", "Final", "Roll", "Twenty", "Eight", "Amber", "Lamar", "City", "School", "Flight", "Chief", "Medicated", "Epic", "Reply", "Double", "Screen", "Donut", "Penguin", "Stumpy", "Whicker", "Shadow", "Howard", "Wilshire", "Darling", "Disco", "Jack", "The Bear", "Sneak", "The Big L", "Whisp", "Wheezy", "Crazy", "Goat", "Pirate", "Saucy", "Hambone", "Butcher", "Walla Walla", "Snake", "Caboose", "Sleepy", "Killer", "Stompy", "Mopey", "Dopey", "Weasel", "Ghost", "Dasher", "Grumpy", "Hollywood", "Tooth", "Noodle", "King", "Cupid", "Prancer", "Rainbow", "Twilight", "Rarity", "Spike", "Apples", "Scootaloo", "Big Mac", "Gundam", "Costy", "Gear", "Favel", "Franchy", "Rich", "April", "Adam", "Brock", "Manual", "Endy", "Mark", "Jesus", "Mohammed", "Krishna", "Osama", "Khalid", "Fatality", "Bull", "Abdullah", "Steam", "Gonna", "Flutter", "Sweetie", "Bloom", "Cotton", "Mono", "Harm", "Laid", "Roger", "Agit", "Teamer", "Multi", "Fire", "Record", "Addi", "Skim", "Alkesh", "Zat", "Kel", "Kree", "Jaffa"]

#Should activate it without further actions elsewhere.
def generate_accounts():
	return False

def get_next_id():
	num = 0
	with playerNumberLock:
		global playerNumber
		num = playerNumber
		playerNumber += 1
	return num

def generate_random_account():
	playerNumber = get_next_id()
	
	user_data = dict()
	user_data["status"] = "success"
	user_data["username"] = str(playerNames[playerNumber % len(playerNames)] + " " + str(playerNumber))
	user_data["id"] = playerNumber

	return user_data