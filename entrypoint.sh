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
while cur.nextset():
    pass

proc_sql = '''
CREATE PROCEDURE GetTopReporter(IN sortCol VARCHAR(128))
BEGIN
  SET @query = CONCAT(
    'SELECT user_id, COUNT(*) as cnt FROM reports GROUP BY user_id ',
    sortCol
  );
  PREPARE stmt FROM @query;
  EXECUTE stmt;
  DEALLOCATE PREPARE stmt;
END
'''
cur.execute(proc_sql)
conn.commit()
conn.close()
print('[+] Schema and procedure initialized.')
"

echo "[*] Starting Internal Vulnerability Report System on port 5000..."
exec python3 src/app.py
