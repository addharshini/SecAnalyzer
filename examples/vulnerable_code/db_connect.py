import sqlite3
from flask import request

def bad_login():
    conn = sqlite3.connect(':memory:')
    cur = conn.cursor()
    # SQL injection via concatenation
    query = "SELECT * FROM users WHERE id = '" + request.args.get('id') + "'"
    cur.execute(query)
    return cur.fetchall()
