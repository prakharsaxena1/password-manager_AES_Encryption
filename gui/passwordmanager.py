import random
import base64
import os
import sys
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    import passwordmeter
    import pyperclip
except ModuleNotFoundError as e:
    print("Modules required to run the application are not found.")
    print("pip install cryptography")
    print("pip install passwordmeter")
    print("pip install pyperclip")
    sys.exit()


class PasswordManager():

    def genPassword(self):
        m = ''
        passwordStrength = 0
        while passwordStrength <= 0.8 and len(m)<17:
            for _ in range(16):
                m = m + self.X[random.randint(0, len(self.X)-1)]
            passwordStrength = passwordmeter.test(m)[0]
        return m

    def savePassword(self, fernetobj):
        forsite = input('Enter site name (Like facebook.com): ')
        userid = input(f'Enter {forsite} userid: ')
        setPassword = self.genPassword()
        
        data = f'{forsite}:{userid}:{setPassword}'.encode()
        with open(self.userdataPATH, 'ab') as ff:
            ff.write(fernetobj.encrypt(data)+'\n'.encode())
        pyperclip.copy(setPassword)
        print('Your password is copied to the clipboard. Please go to the site and change your current password with this one.\n')

    def viewPasswords(self, fernetobj):
        with open(self.userdataPATH, 'r') as ff:
            listPass = ff.readlines()
            if len(listPass) != 0:
                for i in listPass:
                    i = fernetobj.decrypt(i.encode())
                    idecrypted = i.decode().strip('\n').split(':')
                    print(
                        f'Password for {idecrypted[0]} is -->   {idecrypted[2]}   <-- with userid= {idecrypted[1]}')
            else:
                print('No passwords are created yet.')

    def make_user(self, username, password, key, fernetobj):
        with open(self.userinfoPATH, 'wb') as userinfofile:
            data = f'PasswordManagerUser:{username}:{password}'.encode()
            userinfofile.write(fernetobj.encrypt(data))
        with open(self.keyfilePATH, 'wb') as keyfile:
            keyfile.write(fernetobj.encrypt(key))
        print('User and key made successfully.')

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.userPATH = "Users/Data_" + self.username + "/"
        self.userdataPATH = "Users/Data_" + self.username + "/userdata"
        self.userinfoPATH = "Users/Data_" + self.username + "/userinfo"
        self.keyfilePATH = "Users/Data_" + self.username + "/keyfile.key"

        if os.path.exists(self.userdataPATH) == False:
            os.makedirs(self.userPATH)
            y = open(self.userdataPATH, 'wb')
            y.close()

        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./<=>?@[]^_{|}~"
        self.X = ''.join(set(list(charset)))
        # Making KEY
        self.salt = b''
        self.kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt, iterations=100000, backend=default_backend())
        self.key = base64.urlsafe_b64encode(
            self.kdf.derive(self.password.encode()))
        self.fernetobj = Fernet(self.key)
        self.make_user(self.username, self.password, self.key, self.fernetobj)
        self.userchoices()

    def userchoices(self):
        with open(self.userinfoPATH, 'rb') as file:
            try:
                xx = self.fernetobj.decrypt(file.readline())
            except Exception as e:
                print('Invalid password entered. Exiting app')
                sys.exit()
            x = xx.decode().split(':')
        if str(self.username) == x[1]:
            print('What to do? \n1. Make a password\n2. View saved passwords\n3. Exit')
            choice = ''
            while(choice != 3):
                choice = int(input('Enter choice(1, 2 or 3): '))
                if choice == 1:
                    self.savePassword(self.fernetobj)
                elif choice == 2:
                    self.viewPasswords(self.fernetobj)
                elif choice == 3:
                    print('Exiting program')
        else:
            print('Wrong credentials entered. Enter the correct one and try again')


hello = PasswordManager("prakhar", "prakhar")
