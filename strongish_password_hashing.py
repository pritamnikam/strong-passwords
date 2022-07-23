import sqlite3
import bcrypt

BCRYPT_ROUNDS = 14

conn = sqlite3.connect('users.db')
cursor = conn.cursor().execute('''
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(16) PRIMARY KEY,
    password VARCHAR(60)
)
''')

def create_account(username, password):
    if len(password) < 8:
        raise Exception('Password too short')

    if len(password) > 72:
        raise Exception('Password too long')

    cursor = conn.cursor()
    cursor.execute('SELECT count(*) FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    if result[0] > 0:
        raise Exception('Username already taken')

    hashed = bcrypt.hashpw(bytes(password, 'UTF-8'), bcrypt.gensalt(BCRYPT_ROUNDS))
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
    conn.commit()

def login(username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()

    if result == None:
        # User doesn't exist. Make sure the login is still slow.
        bcrypt.hashpw(b'', bcrypt.gensalt(BCRYPT_ROUNDS))
        raise Exception('Invalid username or password')

    hashed = result[0]
    if not bcrypt.checkpw(bytes(password, 'UTF-8'), hashed):
        raise Exception('Invalid username or password')

create_account('jim', 'password')

try:
    login('jim1', 'password')
    print('Login succeeded')
except Exception as e:
    print(f'login error: {e}')
