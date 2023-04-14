#!/usr/bin/env python3
from ntpath import expanduser
import sys
import time
import pyotp
import redis
import logging
from hashlib import sha256
import base64
from sendmail import sendMail

from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE, ALL_ATTRIBUTES, ALL

SERVER = ''
PORT = 389
USER_BASE_DN = ''
SECRET="###"

def authenticate_user(username, password):
   try:
      server = Server(SERVER, port=PORT, get_info=ALL)
      conn = Connection(server, auto_bind=AUTO_BIND_NO_TLS) 

      search_filter = '(samAccountName={})'.format(username)
      conn.search(USER_BASE_DN, search_filter, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
      conn = Connection(server, user=username, password=password)
      if conn.bind():
         return True
      return False
   except Exception as exp:
      print (exp)
      return False

def mfa_authentication(username):
   r = redis.Redis(host='localhost', port=6379, db=0)
   hashUsername = sha256(username.encode('utf-8')).hexdigest()
   clientSecret = SECRET+hashUsername
   secOTP = base64.b32encode(clientSecret.encode()).decode()
   totp = pyotp.TOTP(secOTP, interval=120)
   r.set(hashUsername, "pending")
   otpNow = totp.now()
   sendMail(username, hashUsername+str(otpNow))
   r.expire(hashUsername, 60)
   statusCheck = r.exists(hashUsername)
   while statusCheck == 1:
      value = r.get(hashUsername)
      print (value.decode())
      if value.decode() == "accepted":
         return True
      time.sleep(1)
      statusCheck = r.exists(hashUsername)
   return False

if __name__ == "__main__":
   logging.basicConfig(level=logging.DEBUG)
   tmpFile = open(sys.argv[1], 'r')
   lines = tmpFile.readlines()
   username = lines[0].strip()
   password = lines[1].strip().encode("utf-8")

   if authenticate_user(username, password):
      if mfa_authentication(username):
         sys.exit(0)
      else:
         sys.exit(1)
   else:
      sys.exit(1)