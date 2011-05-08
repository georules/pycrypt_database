#!/usr/bin/python
# LGPL 3.0 Geoffery L. Miller
# http://www.gnu.org/copyleft/lesser.html
import sys, getpass
from Crypto.Cipher import AES
from Crypto.Hash import MD5

def main(argv):
	if (len(argv) < 2):
		print "Usage: " + argv[0] + " [new/add/read] [databaseFile]"
		sys.exit(-1)
	operation = argv[1]
	file = argv[2]
	# Get the password and hash it
	password = getpass.getpass() # Invisible text entry
	hash = MD5.new()
	hash.update(password)
	hashpass = hash.digest()
	# Create a new database
	if (operation == "new"):
		cy = AES.new(hashpass, AES.MODE_CFB)
		# xxxx and yyyy are my arbitrary flags in the database
		# to indicate the hashpass is here
		cytext = cy.encrypt("xxxx"+hashpass+"yyyy")
		f = open(file, 'wb')
		f.write(cytext)
		f.close()
		sys.exit(0)

	# Check the password so that we don't add entrys with a 
	# different password or spit out garbage
	if (checkpass(file, hashpass) != 0):
		print "Incorrect password"
		sys.exit(-1)

	# Add a record to the database
	if (operation == "add"):
		f = open(file, 'rb')
		s_old = f.read()
		# Decypher the old database
		cy = AES.new(hashpass, AES.MODE_CFB)
		s_old = cy.decrypt(s_old)

		f = open(file, 'wb')
		s = raw_input("Enter a string: ")
		s = s + "\n"
		cy = AES.new(hashpass, AES.MODE_CFB)
		# Add the old database to the new record
		# and cypher again
		cytext = cy.encrypt(s_old + s)
		f.write(cytext)

	# Read the records from the database
	if (operation == "read"):
		f = open(file, 'rb')
		s = f.read()
		cy = AES.new(hashpass, AES.MODE_CFB)
		s = cy.decrypt(s)
		loc = s.find("yyyy") + 4
		sub = s[loc:len(s)-1] # Don't need to print the hashed password
		print sub

def checkpass(file,hashpass):
	# Checks the flagged hash password in the file
	# Even if this wasn't checked, the unencrypted text
	# with the wrong key would be garbage
	f = open(file, 'rb')
	s = f.read()
	cy = AES.new(hashpass, AES.MODE_CFB)
	s = cy.decrypt(s)
	loc1 = s.find("xxxx")+4
	loc2 = s.find("yyyy")
	sub = s[loc1:loc2]
	if sub == hashpass:
		return 0
	else:
		return -1

main(sys.argv)
