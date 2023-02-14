import mysql.connector
import config

connection = mysql.connector.connect(
  host = config.host,
  user = config.user,
  password = config.password,
  database= config.database
)