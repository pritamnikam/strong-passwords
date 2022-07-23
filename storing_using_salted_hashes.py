import sqlite3
import hashlib
import secrets

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

    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, salted_hash(password)))
    conn.commit()

def salted_hash(password):
    salt = secrets.token_bytes(16)
    salted_password = salt + bytes(password, 'utf-8')
    return salt.hex() + '$' + hashlib.sha256(salted_password).hexdigest()

def login(username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    if result == None or not check_password(result[0], password):
        raise Exception('Invalid username or password')

def check_password(salted_hash, password):
    (hex_salt, correct) = salted_hash.split('$')
    salted_password = bytes.fromhex(hex_salt) + bytes(password, 'utf8')
    return hashlib.sha256(salted_password).hexdigest() == correct

create_account('jimbob', 'password')

try:
    login('jimbob', 'password')
    print('Login succeeded')
except Exception as e:
    print('Login error: %s' % (e))
