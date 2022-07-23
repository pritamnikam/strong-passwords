import sqlite3
from nacl import pwhash, secret

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

print('before:')
for row in conn.cursor().execute('SELECT * FROM users'):
    print(row)

cursor.execute('ALTER TABLE users ADD COLUMN nacl_pwhash VARCHAR(100)')

box = secret.SecretBox(b'this is a super-duper secret key')

params = []
for row in cursor.execute('SELECT password, username FROM users WHERE password != ""'):
    decrypted = box.decrypt((bytes.fromhex(row[0])))
    params.append(
        (pwhash.str(decrypted), row[1]),
    )

cursor.executemany('UPDATE users SET nacl_pwhash=?, password="" WHERE username=?', params)
conn.commit()

print('after:')
for row in conn.cursor().execute('SELECT * FROM users'):
    print(row)
