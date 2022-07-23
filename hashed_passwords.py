import sqlite3
import hashlib

conn = sqlite3.connect('users.db')
cursor = conn.cursor().execute('''
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(16) PRIMARY KEY,
    password VARCHAR(64)
)
''')

def create_account(username, password):
    if len(password) < 8:
        raise Exception('Password too short')

    cursor = conn.cursor()
    cursor.execute('SELECT count(*) FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    if result[0] > 0:
        raise Exception('Username already taken')

    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
        (username, hash_password(password)))
    conn.commit()

def login(username, password):
    cursor = conn.cursor()
    hashed = hash_password(password)
    cursor.execute("SELECT password FROM users WHERE username=? AND password=?",
        (username,hashed))
    result = cursor.fetchone()
    if result == None:
        raise Exception('Invalid username or password')

def hash_password(password):
    return hashlib.sha256(bytes(password, 'utf-8')).hexdigest()

create_account('bob', 'password')
create_account('sally', 'password')
create_account('jim', 'superman')

try:
    login('jim', 'superman')
    print('Login succeeded')
except Exception as e:
    print('Login error: %s' % (e))
