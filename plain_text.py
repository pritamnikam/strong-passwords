import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor().execute('''
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(16) PRIMARY KEY,
    password VARCHAR(16)
)
''')

def create_account(username, password):
    if len(password) < 8:
        raise Exception('Password too short')

    if len(password) > 16:
        raise Exception('Password too long')

    cursor = conn.cursor()
    cursor.execute('SELECT count(*) FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    if result[0] > 0:
        raise Exception('Username already taken')

    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()

def login(username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT count(*) FROM users WHERE username=? AND password=?', (username, password))
    result = cursor.fetchone()
    if result[0] == 0:
        raise Exception('Invalid username or password')

create_account('jim', 'a-password')
create_account('sue', 'another-password')

try:
    login('jim', 'bad-password')
except Exception as e:
    print('Login error: %s' % (e))

login('jim', 'a-password')
print('Login succeeded')
