import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "bank.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS accounts;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'client'
        );

        CREATE TABLE accounts (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            owner   TEXT NOT NULL,
            iban    TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        );
        """
    )
    seed = [
        ("alice", "5f4dcc3b5aa765d61d8327deb882cf99", "client"),
        ("bob", "e10adc3949ba59abbe56e057f20f883e", "client"),
        ("admin", "21232f297a57a5a743894a0e4a801fc3", "admin"),
    ]
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", seed
    )
    conn.executemany(
        "INSERT INTO accounts (owner, iban, balance) VALUES (?, ?, ?)",
        [
            ("alice", "TN59 1000 6035 1234 5678 9012", 4210.55),
            ("bob", "TN59 1000 6035 9876 5432 1098", 980.00),
            ("admin", "TN59 1000 6035 0000 0000 0001", 150000.00),
        ],
    )
    conn.commit()
    conn.close()
