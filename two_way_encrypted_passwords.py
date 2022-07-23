import sqlite3
import nacl.secret

conn = sqlite3.connect('users.db')
cursor = conn.cursor().execute('''
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(16) PRIMARY KEY,
    password VARCHAR(100)
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

    encrypted = encrypt_password(password)
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted))
    conn.commit()

def login(username, password):
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    if result == None:
        raise Exception('Invalid username or password')

    decrypted = decrypt_password(result[0])
    if decrypted != password:
        raise Exception('Invalid username or password')

key = b'this is a super-duper secret key'

def encrypt_password(plaintext):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(bytes(plaintext, 'utf-8')).hex()

def decrypt_password(ciphertext):
    box = nacl.secret.SecretBox(key)
    bc = bytes.fromhex(ciphertext)
    return box.decrypt(bc).decode('utf-8')

create_account('jim', 'a-password')
create_account('sue', 'another-password')

try:
    login('jim', 'a-password')
    print('Login succeeded')
except Exception as e:
    print('Login error: %s' % (e))
