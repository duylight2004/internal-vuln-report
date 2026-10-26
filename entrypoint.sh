#!/bin/bash
set -e

echo "[*] Waiting for MariaDB..."
python3 -c "
import time, pymysql, os
for i in range(30):
    try:
        conn = pymysql.connect(
            host=os.environ['DB_HOST'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASS'],
            database=os.environ['DB_NAME']
        )
        conn.close()
        print('[+] DB is ready!')
        break
    except Exception as e:
        time.sleep(1)
else:
    print('[-] DB not ready after 30s')
    exit(1)
"

echo "[*] Initializing schema..."
python3 -c "
import pymysql, os
from pymysql.constants import CLIENT

conn = pymysql.connect(
    host=os.environ['DB_HOST'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASS'],
    database=os.environ['DB_NAME'],
    client_flag=CLIENT.MULTI_STATEMENTS
)
with open('src/schema.sql', 'r', encoding='utf-8') as f:
    sql = f.read()

cur = conn.cursor()
cur.execute(sql)
conn.commit()
while cur.nextset():
    pass
conn.close()
print('[+] Schema and procedure initialized.')
"

echo "[*] Starting Internal Vulnerability Report System on port 5000..."
exec python3 src/app.py
