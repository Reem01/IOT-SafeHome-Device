import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",          #افضل تكون root
        password="Adminroot123",  # نفس الباس
        database="safehome"
    )
