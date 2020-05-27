# This is a single user password manager, which means that there can only be one user who can create multiple passwords and store them.
# AES is used for ENCRYPTION and DECRYPTION.
# A AES key is generated based on the password of the used which can be created at the starting of the application.
# If the user forgets the master passwords or these files get deleted then the passwords for the accounts can never be recovered.
# The user is adviced to keep all the files that this program generates in a secure position and avoid their loss at all costs.
# This app uses double encryption scheme which means only the user with correct password can decrypt the files.

import string  # For generting the characterset
import random
import base64
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import passwordmeter
import pyperclip

a = list(string.punctuation)
# Selecting ':' as the spl. character to separate different data items when stored
a.remove(':')
charset = string.ascii_lowercase + \
    string.ascii_uppercase + string.digits + \
    ''.join(a)  # making characterset to choose characters from
X = ''.join(list(set(charset)))  # jumble the words khel ra


def makeKEY(passgiven):  # Generating a AES Key according to the user provided password *inserts smart meme*
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


def genPassword():  # Generating a Strong password of length = 20
    m = ''
    passwordStrength = passwordmeter.test(m)[0]
    while passwordStrength < 0.9:
        for i in range(20):
            m = m+X[random.randint(0, len(X)-1)]
        passwordStrength = passwordmeter.test(m)[0]
    return m


def savePassword(fernetobj):
    forsite = input('Enter site name (Like facebook.com): ')
    userid = input(f'Enter {forsite} userid: ')
    setPassword = genPassword()  # Getting a random password
    data = f'{forsite}:{userid}:{setPassword}'.encode()
    if os.path.exists('userdata') == False:
        with open('userdata', 'wb') as ff:
            # Encrypting the string with the key
            ff.write(fernetobj.encrypt(data)+'\n'.encode())
    else:
        with open('userdata', 'ab') as ff:
            # Encrypting the string with the key
            ff.write(fernetobj.encrypt(data)+'\n'.encode())
    # To copy the password to the clipboard so that user can paste it easily
    pyperclip.copy(setPassword)
    print('Your password is copied to the clipboard. Please go to the site and change your current password with this one.\n')


# Fetch encrypted passwords -> Decrypt -> print ecrypted passswords
def viewPasswords(fernetobj):
    if os.path.exists('userdata') == False:
        print('No passwords are created yet.')
    else:
        with open('userdata', 'r') as ff:
            for i in ff.readlines():
                i = fernetobj.decrypt(i.encode())
                idecrypted = i.decode().strip('\n').split(':')
                print(
                    f'Password for {idecrypted[0]} is -->   {idecrypted[2]}   <-- with userid= {idecrypted[1]}')
            else:
                print('No passwords are created yet.')


def check_username(givenusername, originalusername):
    if givenusername != originalusername:  # Checking entered username
        return False
    return True  # If it passes all the tests


# Making user for the first time. This will only execute once for creating the user.
def make_user(username, password, key, fernetobj):
    with open('userinfo', 'wb') as userinfofile:
        # Using encode() as we are working with bytes
        data = f'PasswordManagerUser:{username}:{password}'.encode()
        userinfofile.write(fernetobj.encrypt(data))
    with open('keyfile.key', 'wb') as keyfile:
        keyfile.write(fernetobj.encrypt(key))
    print('User and key made successfully.')


username = input('Enter Username: ')  # Username
password = input('Enter Password: ')  # Master password

# making key from password entered to check the key in keyfile.key
key = makeKEY(password.encode())

# This object is used for encrypting as well as decrypting
fernetobj = Fernet(key)

os.system('cls')

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
    if check_username(username, x[1]):
        print('What to do? \n1. Make a password\n2. View saved passwords\n3. Exit')
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
