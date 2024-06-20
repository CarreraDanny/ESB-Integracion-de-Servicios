import pyodbc

def get_sqlserver_connection():
    return pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=LAPTOP-FHJSEOP7\\SQLEXPRESS;'
        'DATABASE=PROYECTO SERVICIOS;'
        'Trusted_Connection=yes;'
    )
