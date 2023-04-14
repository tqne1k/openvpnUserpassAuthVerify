#!/usr/bin/env python
# encoding: utf-8
import redis
import base64
import pyotp
from flask import Flask, request, jsonify, render_template

from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

SECRET=""

@app.route('/api/auth', methods=['GET'])
def query_records():
    key = request.args.get('key')
    requestOTP = key[-6:]
    hashUsername = key[:len(key)-6]
    r = redis.Redis(host='localhost', port=6379, db=0)
    clientSecret = SECRET+hashUsername
    secOTP = base64.b32encode(clientSecret.encode()).decode()
    totp = pyotp.TOTP(secOTP, interval=120)
    if totp.verify(requestOTP):
        r.set(hashUsername, "accepted")
        r.expire(hashUsername, 3)
        return render_template('success.html')
    else:
        return render_template("failed.html")
    
app.run(debug=True, host="0.0.0.0", port=3000)