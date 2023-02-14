import os
import sys
import smtplib
from email.mime.text import MIMEText
import time

import config
from db import connection

try:
    LOG_FILE = os.path.abspath(sys.argv[1])

except:
    print('Unexcpected error')
    sys.exit(1)

def notify(message):
    msg = MIMEText(message, _subtype='plain', _charset='UTF-8')
    msg['Subject'] = ""
    msg['From'] = config.sender
    msg['To'] = config.receiver

    s = smtplib.SMTP('localhost')
    s.sendmail(config.sender, [config.receiver], msg.as_string())
    s.quit()


def get_recent_entries(file, n):
    with open(file, "r") as f:

        f.seek (0, 2)
        fsize = f.tell()
        f.seek (max (fsize-1024, 0), 0)
        lines = f.readlines()

    lines = lines[-n:]

    return lines

query = connection.cursor()

def getUnautorizedMessage(s):
    user = s.split()[-7]

    query.execute('SELECT ssh_fingerprint FROM company_users WHERE ssh_user = %(name)s', { 'name': user })

    validUser = query.fetchone()

    if validUser is None:
        return 'Se ha detectado un acceso no autorizado al sistema, el usuario %s no es un usuario valido.' % user

    fingerprint = s.split()[-1]

    if validUser[0] != fingerprint:
        return 'Se ha detectado un acceso no autorizado al sistema, el fingerprint %s no pertenece al usuario %s.' % (fingerprint, user)

    return False

def getInvalidUserMessage(s):
    return 'Se ha detectado un intento de acceso no autorizado a través del usuario no registrado %s.' % s.split()[-5]

def getAttemptsExceededMessage(s):
    user = s.split()[-7]

    query.execute('SELECT * FROM company_users WHERE so_user = %(name)s', { 'name': user })

    validUser = query.fetchone()

    if validUser:
        return 'Se ha detectado un intento de acceso no autorizado a través del usuario registrado %s.' % user

    return 'Se ha detectado un intento de acceso no autorizado a través del usuario no registrado %s.' % user

mtime_last = 0

keysToSearch = {
    'accepted publickey': 'getUnautorizedMessage',
    'disconnected from invalid user': 'getInvalidUserMessage',
    'authentication attempts exceeded': 'getAttemptsExceededMessage'
}

while True:
    mtime_cur = os.path.getmtime(LOG_FILE)

    if mtime_cur != mtime_last:

        for i in get_recent_entries(LOG_FILE, 5):

            for key in keysToSearch:

                if key in i.lower():

                    msg = keysToSearch[key](i)

                    if msg:
                        
                        notify(msg)

    mtime_last = mtime_cur

    time.sleep(5)