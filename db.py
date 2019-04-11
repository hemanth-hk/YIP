from app import app
import sqlite3

conn = sqlite3.connect('database.db')
print ("Opened database successfully")
conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,user_name TEXT,user_email TEXT,user_password TEXT)')
print ("Table created successfully")
conn.close()
