#!/bin/bash
set -euo pipefail

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-ctf_user}"
DB_PASS="${DB_PASS:-ctf_pass}"
DB_NAME="${DB_NAME:-vuln_report}"
PORT="${PORT:-5000}"
export DB_HOST DB_PORT DB_USER DB_PASS DB_NAME PORT

start_embedded_mariadb() {
    echo "[*] Starting embedded MariaDB ($(mariadbd --version))..."
    mkdir -p /run/mysqld
    chown mysql:mysql /run/mysqld

    if [ ! -d /var/lib/mysql/mysql ]; then
        echo "[*] Initializing MariaDB data directory..."
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql
    fi
    chown -R mysql:mysql /var/lib/mysql

    mariadbd \
        --user=mysql \
        --datadir=/var/lib/mysql \
        --bind-address=127.0.0.1 \
        --port="${DB_PORT}" \
        --socket=/run/mysqld/mysqld.sock \
        --pid-file=/run/mysqld/mysqld.pid \
        --innodb-buffer-pool-size=64M \
        --innodb-use-native-aio=0 \
        --performance-schema=OFF \
        --max-connections=50 \
        &

    MARIADB_PID=$!

    echo "[*] Waiting for MariaDB..."
    for _ in $(seq 1 60); do
        if mariadb-admin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1; then
            echo "[+] MariaDB is ready!"
            break
        fi
        if ! kill -0 "${MARIADB_PID}" 2>/dev/null; then
            MARIADB_STATUS=0
            wait "${MARIADB_PID}" 2>/dev/null || MARIADB_STATUS=$?
            echo "[-] MariaDB exited during startup (exit code ${MARIADB_STATUS})."
            ls -la /var/lib/mysql
            exit 1
        fi
        sleep 1
    done

    if ! mariadb-admin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1; then
        echo "[-] MariaDB did not become ready in time."
        exit 1
    fi

    echo "[*] Creating database and application user..."
    timeout 30 mariadb --socket=/run/mysqld/mysqld.sock -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
SQL

    echo "[+] Database and application user are ready."
}

wait_for_external_mariadb() {
    echo "[*] Waiting for external database at ${DB_HOST}:${DB_PORT}..."
    python3 - <<'PY'
import os
import sys
import time

import pymysql

for _ in range(60):
    try:
        conn = pymysql.connect(
            host=os.environ['DB_HOST'],
            port=int(os.environ['DB_PORT']),
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASS'],
            database=os.environ['DB_NAME'],
            connect_timeout=5,
        )
        conn.close()
        print('[+] DB is ready!')
        break
    except Exception:
        time.sleep(1)
else:
    print('[-] DB not ready after 60s')
    sys.exit(1)
PY
}

case "${DB_HOST}" in
    localhost|127.0.0.1|::1)
        start_embedded_mariadb
        ;;
    *)
        wait_for_external_mariadb
        ;;
esac

echo "[*] Initializing schema..."
python3 - <<'PY'
import os

import pymysql
from pymysql.constants import CLIENT

conn = pymysql.connect(
    host=os.environ['DB_HOST'],
    port=int(os.environ['DB_PORT']),
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASS'],
    database=os.environ['DB_NAME'],
    client_flag=CLIENT.MULTI_STATEMENTS,
    connect_timeout=10,
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
PY

echo "[*] Starting Internal Vulnerability Report System on port ${PORT}..."
exec gunicorn \
    --chdir src \
    --bind "0.0.0.0:${PORT}" \
    --workers "${WEB_CONCURRENCY:-2}" \
    --threads "${WEB_THREADS:-2}" \
    --timeout 60 \
    app:app
