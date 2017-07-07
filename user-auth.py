#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import sqlite3
import sys
from yubico_client import Yubico


from config import DB_PATH, HASH_ALGORITHM, YUBICO_CLIENT_ID, YUBICO_SECRET


yubi_client = Yubico(YUBICO_CLIENT_ID, YUBICO_SECRET)


hash_func = getattr(hashlib, HASH_ALGORITHM)
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

yubi_otp = os.environ['password'][-44:]
sent_password = os.environ['password'][:-44]

cursor.execute('SELECT username, password FROM users WHERE username = ? AND yubi_public_id = ?;', (os.environ['username'], yubi_otp[:12], ))
result = cursor.fetchone()
if result is None:
    sys.exit(1)
username, password = result
if hash_func(sent_password.encode("utf-8")).hexdigest() != password:
    sys.exit(1)

if not yubi_client.verify(yubi_otp):
    sys.exit(1)

sys.exit(0)
