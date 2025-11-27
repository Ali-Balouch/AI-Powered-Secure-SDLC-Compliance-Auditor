import sqlite3
import os

def login(username, password):
    # ❌ SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)
    
    result = cursor.fetchall()
    conn.close()
    return result

def read_file():
    # ❌ Path Traversal vulnerability
    filename = input("Enter file name: ")
    with open(filename, "r") as f:
        print(f.read())

def run_command():
    # ❌ Command Injection vulnerability
    cmd = input("Enter command: ")
    os.system(cmd)

login("admin", "1234")
read_file()
run_command()
