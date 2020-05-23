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

sep =':'.encode()
a=list(string.punctuation)
a.remove(':')
charset = string.ascii_lowercase + string.ascii_uppercase + string.digits+''.join(a)
X=''.join(list(set(charset)))

def makeKEY(passgiven):
    salt=b''
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
    m=''
    passwordStrength = passwordmeter.test(m)[0]
    while passwordStrength<0.9:
        for i in range(20):
            m=m+X[random.randint(0,len(X)-1)]
        passwordStrength = passwordmeter.test(m)[0]
    return m

def savePassword():
    f=Fernet(makeKEY(returnPassword()))
    forsite=input('Enter site name (Like facebook.com): ').encode()
    userid = input(f'Enter {forsite.decode()} userid: ').encode()
    setPassword=genPassword()
    if os.path.exists('userdata')==False:
        with open('userdata','wb') as ff:
            data=forsite+ sep + userid +sep + setPassword.encode()+'\n'.encode()
            ff.write(f.encrypt(data))
    else:
        with open('userdata','ab') as ff:
            data=forsite+ sep + userid +sep + setPassword.encode()+'\n'.encode()
            ff.write(f.encrypt(data))
    pyperclip.copy(setPassword)
    print('Your password is copied to the clipboard. Please go to the site and change your current password with this one.')

def viewPasswords():
    f=Fernet(makeKEY(returnPassword()))
    if os.path.exists('userdata')==False:
        print('No passwords are created yet.')
    else:
        with open('userdata','rb') as ff:
            for i in ff.readlines():
                i=f.decrypt(i)
                ii=i.decode().strip('\n').split(':')
                print(f'Password for site {ii[0]} is {ii[2]} with userid= {ii[1]}')
    

def greetuser():
    with open('userinfo','rb') as f2:
        username = f2.read().decode().strip('\n').split(':')[1]
        if len(username)==0:
            raise ValueError
        print(f'Hello, {username}')


def makeuser():
    print('Create an account to use the app.')
    username=input('Username: ').encode()
    print('Don\'t forget this password. Without this password you will be locked out of your account.')
    password=input('Password: ').encode()
    with open('userinfo','wb') as f:
        f.write('PasswordManagerUser'.encode()+sep+username+sep+password)
    with open('keyfile.key','wb') as k:
        k.write(makeKEY(password))

def check(userPassword):
    print('Checking password...')
    userKey=makeKEY(userPassword)
    with open('keyfile.key','rb') as k:
        theKey=k.readline()
    return userKey==theKey


def authenticateuser():
    print('Authenticating user')
    userPassword=input('Master password : ').encode()
    if check(userPassword) == False:
        print('Wrong password')
        return False
    return True

def returnPassword():
    with open('userinfo','rb') as fdata:
        x=fdata.readline().decode().split(':')
        passwd=x[2].encode()
    return passwd

if os.path.exists('userinfo') == False:
    makeuser()
else:
    try:
        greetuser()
    except Exception as e:
        makeuser()

if authenticateuser()==True:
    print('What to do from here? \n1. Make a password\n2. View saved passwords\n3. Exit')
    choice =' '
    while(choice!=3):
        try:
            choice =int(input('Enter choice: '))
        except ValueError as e:
            print('Wrong value')

        if choice == 1:
            savePassword()
        elif choice == 2:
            viewPasswords()
        elif choice == 3:
            print('Exiting program')
else:
    print('Exiting program')
