import string
import random
import passwordmeter
import pyperclip
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import sys


# sep =':'.encode()
a = list(string.punctuation)
a.remove(':')
charset = string.ascii_lowercase + \
    string.ascii_uppercase + string.digits+''.join(a)
X = ''.join(list(set(charset)))


def makeKEY(passgiven):
    salt = b''
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passgiven))
    return key


def genPassword():
    m = ''
    passwordStrength = passwordmeter.test(m)[0]
    while passwordStrength < 0.9:
        for i in range(20):
            m = m+X[random.randint(0, len(X)-1)]
        passwordStrength = passwordmeter.test(m)[0]
    return m


def savePassword(fernetobj):
    forsite = input('Enter site name (Like facebook.com): ').encode()
    userid = input(f'Enter {forsite.decode()} userid: ').encode()
    setPassword = genPassword()
    data = f'{forsite}:{userid}:{setPassword}'.encode()
    if os.path.exists('userdata') == False:
        with open('userdata', 'wb') as ff:
            ff.write(fernetobj.encrypt(data)+'\n'.encode())
    else:
        with open('userdata', 'ab') as ff:
            ff.write(fernetobj.encrypt(data)+'\n'.encode())
    pyperclip.copy(setPassword)
    print('Your password is copied to the clipboard. Please go to the site and change your current password with this one.\n')


def viewPasswords(fernetobj):
    if os.path.exists('userdata') == False:
        print('No passwords are created yet.')
    else:
        with open('userdata', 'r') as ff:
            for i in ff.readlines():
                i = fernetobj.decrypt(i.encode())  # ERROR byte and str
                idecrypted = i.decode().strip('\n').split(':')
                print(
                    f'Password for site {str(idecrypted[0])[2:-1]} is {idecrypted[2]} with userid= {str(idecrypted[1])[2:-1]}')


def check_password_and_key(givenusername, originalusername, givenpassword, originalpassword, givenkey, originalkey):
    if givenpassword == originalpassword and givenkey == originalkey and givenusername == originalusername:
        return True
    return False


def make_user(username, password, key, fernetobj):
    with open('userinfo', 'wb') as userinfofile:
        data = f'PasswordManagerUser:{username}:{password}'.encode()
        userinfofile.write(fernetobj.encrypt(data))
    with open('keyfile.key', 'wb') as keyfile:
        keyfile.write(fernetobj.encrypt(key))
    print('User and key made successfully.')


username = input('Enter Username: ')
password = input('Enter Password: ')
key = makeKEY(password.encode())
fernetobj = Fernet(key)

if os.path.exists('userinfo') == True and os.path.exists('keyfile.key') == True:
    with open('userinfo', 'rb') as file:
        try:
            xx = fernetobj.decrypt(file.readline())
        except Exception as e:
            print('Invalid password entered. Exiting app')
            sys.exit()
        x = xx.decode().split(':')
    with open('keyfile.key', 'rb') as file2:
        k = file2.readline().decode().strip('\n')
    key2 = fernetobj.decrypt(k.encode())
    if check_password_and_key(username, x[1], password, x[2], key, key2):
        print(
            'What to do from here? \n1. Make a password\n2. View saved passwords\n3. Exit')
        choice = ' '
        while(choice != 3):
            choice = int(input('Enter choice(1, 2 or 3): '))
            if choice == 1:
                savePassword(fernetobj)
            elif choice == 2:
                viewPasswords(fernetobj)
            elif choice == 3:
                print('Exiting program')
    else:
        print('Wrong credentials entered. Enter the correct one and try again')
else:
    make_user(username, password, key, fernetobj)
    print('Please restart the app to continue.')
