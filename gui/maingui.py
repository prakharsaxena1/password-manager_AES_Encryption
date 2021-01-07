# ALL IMPORTS

# Tkinter imports:
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Other Standard library imports:
import os
import datetime
import random
import base64
import hashlib
import shutil

# REQUIRED MODULES
try:
    from PIL import ImageTk, Image
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    import passwordmeter
    import pyperclip
    import webbrowser
except ModuleNotFoundError as e:
    print("Modules required to run the application are not found.")
    print("pip install pillow")
    print("pip install cryptography")
    print("pip install passwordmeter")
    print("pip install pyperclip")
    print("pip install webbrowser")


# GLOBAL VARIABLES

# =================== Font Configure
ALL_TEXT_FONT = ("Helvetica", 12, "bold italic")
ALL_TEXT_FONT_Password = ("Calibri", 25, "bold")
ALL_MENU_FONT = ("Helvetica", 10)

# =================== OTHER
# AutoLogin = True  # REMOVE AFTER DEVELOPMENT
APP_KEYWORD_CONST = "prakhar"  # Don't change it
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./<=>?@[]^_{|}~"
X = ''.join(set(list(charset)))
# Selecting ':' as the spl. character to separate different data items when stored


def makeKEY(passgiven):  # Generating a AES Key according to the user provided password *inserts smart meme*
    salt = b''
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passgiven))
    return key


def genPassword():  # Generating a Strong password of length = 16
    m = ''  # m is the password string
    passwordStrength = 0
    while passwordStrength <= 0.8 and len(m) < 16:
        for _ in range(16):
            m = m + X[random.randint(0, len(X)-1)]
        passwordStrength = passwordmeter.test(m)[0]
    return m


# Main container class

class ContainerWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resizable(0, 0)
        self.title("Password VAULT")
        self.iconbitmap("Assets/logo.ico")
        self.geometry("500x400")
        self.rowconfigure(index=0, weight=1)
        self.columnconfigure(index=0, weight=1)
        self.startFrame = LRWindow(self)
        self.startFrame.grid(row=0, column=0)

# Login / Register window Class


class LRWindow(tk.Frame):

    def __init__(self, parent):
        super().__init__(parent)
        self.goToNextWindow = False
        self.controller = parent

        # ========================================================== VARIABLES
        self.usernameVariable = tk.StringVar()
        self.passwordVariable = tk.StringVar()
        self.cbVar = tk.BooleanVar(value=False)
        self.radioVariable = tk.StringVar()
        self.statusVariable = tk.StringVar()

        # ========================================================== Constants and Setups
        self.radioVariable.set("Register")
        self.img = ImageTk.PhotoImage(Image.open("Assets/logo.png"))
        self.panel = ttk.Label(self, image=self.img)
        self.panel.grid(row=0, column=0, columnspan=2, padx=(5), pady=(5))

        # ========================================================== Layout
        # Login radio button
        self.loginRadio = ttk.Radiobutton(self, text="Login", variable=self.radioVariable, value="Login", command=self.setButtonText)
        self.loginRadio.grid(row=1, column=0, padx=(5), pady=(5))

        # Register radio button
        self.registerRadio = ttk.Radiobutton(self, text="Register", variable=self.radioVariable, value="Register", command=self.setButtonText)
        self.registerRadio.grid(row=1, column=1, padx=(5), pady=(5))

        # Username Label
        self.usernameLabel = ttk.Label(self, text="Username: ", font=ALL_TEXT_FONT)
        self.usernameLabel.grid(row=2, column=0, sticky="W", padx=(10, 5), pady=(5))

        # Password Label
        self.passwordLabel = ttk.Label(self, text="Password: ", font=ALL_TEXT_FONT)
        self.passwordLabel.grid(row=3, column=0, sticky="W", padx=(10, 5), pady=(5))

        # Username Entry
        self.usernameEntry = ttk.Entry(self, textvariable=self.usernameVariable, width="25")
        self.usernameEntry.grid(row=2, column=1, sticky="E", padx=(5, 10), pady=(5))

        # Password Entry
        self.passwordEntry = ttk.Entry(self, textvariable=self.passwordVariable, width="25", show="*")
        self.passwordEntry.grid(row=3, column=1, sticky="E", padx=(5, 10), pady=(5))

        # Show password show button
        self.checkbutton = ttk.Checkbutton(self, text="show password", variable=self.cbVar, onvalue=True, offvalue=False, command=self.toggleShowPassword)
        self.checkbutton.grid(row=4, column=0, columnspan=2, sticky="E", padx=(5), pady=(5))

        # Login / Register Button
        self.radioSelectButton = ttk.Button(self, text=str(self.radioVariable.get()), command=self.useFunction)
        self.radioSelectButton.grid(row=5, column=0, columnspan=2, padx=(5), pady=(5), ipadx=(5))

        # Status Label for user friendly message
        self.statusLabel = ttk.Label(self, text=" ", font=ALL_TEXT_FONT)
        self.statusLabel.grid(row=6, column=0, columnspan=2, padx=(5), pady=(5), ipadx=(5))

    def registerFunction(self, username, password):
        # Checking username and password entered by the user
        if len(username) <= 4:
            messagebox.showerror("Username Error", "Username used is invalid")
            return 0
        if len(password) <= 4:
            messagebox.showerror("Password Error", "Password used is too small")
            return 0

        # Calculateing MD5 HASH for the username
        usernameHash = hashlib.md5(username.encode()).hexdigest()
        # Setting Home directory for each user.
        userHOME = "Users/UsersInfo/"+str(usernameHash)

        with open("Users/users.file", "r") as f:  # Checking for username in users.file
            for i in f.readlines():  # if it does not exist crate a user else show "Username already exists"
                if i.strip("\n") == usernameHash:
                    self.statusLabel["text"] = "~- Username already exists -~"
                    return 0
            else:
                with open("Users/users.file", "a") as f2:
                    f2.write(str(usernameHash)+"\n")
                os.mkdir(userHOME)
                key = makeKEY(password.encode())
                fernetobj = Fernet(key)
                if os.path.exists(userHOME+'/userdata') == False:
                    y = open(userHOME+'/userdata', 'wb')
                    y.close()
                with open(userHOME+'/userinfo', 'wb') as userinfofile:
                    data = f'{usernameHash}:{username}:{password}'.encode()
                    userinfofile.write(fernetobj.encrypt(data))
                with open(userHOME+'/keyfile.key', 'wb') as keyfile:
                    keyfile.write(fernetobj.encrypt(key))
                self.statusLabel["text"] = "~- Successfully registered -~"

    def loginFunction(self, username, password):
        if len(username) <= 4:
            messagebox.showerror("Username Error", "Username used is invalid")
            return 0
        if len(password) <= 4:
            messagebox.showerror("Password Error", "Password used is too small")
            return 0
        usernameHash = hashlib.md5(username.encode()).hexdigest()
        userHOME = "Users/UsersInfo/"+str(usernameHash)
        key = makeKEY(password.encode())
        fernetobj = Fernet(key)
        userFound = False
        passMatch = True

        with open("Users/users.file","r") as f:
            for i in f.readlines():
                if i.strip("\n") == usernameHash:
                    userFound = True
                    break
        if userFound == False:
            self.statusLabel["text"] = "~- log-in FAILED -~"
            return 0

        with open(userHOME + "/userinfo","rb") as f:
            try:
                fernetobj.decrypt(f.readline())
            except Exception as e:
                passMatch = False
                messagebox.showerror("Password Error", "Password invalid")
        if passMatch == False:
            self.statusLabel["text"] = "~- log-in FAILED -~"
            return 0

        if userFound == True and passMatch == True:
            self.statusLabel["text"] = "~- Successfully logged-in -~"
            self.mainAppFrame = mainAppWindow(self.controller,username,password)
            self.mainAppFrame.grid(row=0, column=0, sticky="NESW")
            with open("Users/logs.log", "w") as f:
                f.write(f"{datetime.datetime.now()} Last logged in by: {usernameHash}")

    def useFunction(self):
        username = self.usernameVariable.get()
        password = self.passwordVariable.get()
        if self.radioVariable.get().lower() == "register":
            self.registerFunction(username, password)
        elif self.radioVariable.get().lower() == "login":
            self.loginFunction(username, password)
        else:
            print("Some error occured")

    def setButtonText(self):
        self.radioSelectButton["text"] = self.radioVariable.get()

    def toggleShowPassword(self):
        if self.cbVar.get():
            self.passwordEntry['show'] = ""
        else:
            self.passwordEntry['show'] = "*"

# Main Application Window class

class mainAppWindow(tk.Frame):
    def __init__(self, parent,username,password):
        # mainApp window (side stuff)
        super().__init__(parent)
        self.controller = parent
        self.columnconfigure(index=(0, 1, 2), weight=1)
        self.controller.geometry("500x300")
        self.controller.resizable(1, 1)

        # ========================================================== VARIABLES
        self.who = tk.StringVar(value=" ")
        self.who.set(value=username)

        self.username = username
        self.password = password

        self.usernameHash = hashlib.md5(self.username.encode()).hexdigest()
        self.userHOME = "Users/UsersInfo/"+str(self.usernameHash)
        self.key = makeKEY(self.password.encode())
        self.fernetobj = Fernet(self.key)

        # ============================MENU
        self.menu = tk.Menu(self.controller, tearoff=False)
        self.controller.config(menu=self.menu)
        self.fileMenu = tk.Menu(self.menu, tearoff=False, font=ALL_MENU_FONT)
        self.submenu = tk.Menu(self.fileMenu, tearoff=False, font=ALL_MENU_FONT)
        self.submenu.add_command(label="Chrome")
        self.submenu.add_separator()
        self.submenu.add_command(label="Firefox")
        self.fileMenu.add_cascade(label='Import passwords', menu=self.submenu, underline=0)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Backup for port", command=self.backupForPort)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=lambda: exit())
        self.menu.add_cascade(label="<-- File -->", menu=self.fileMenu)
        self.infoMenu = tk.Menu(self.menu, tearoff=False, font=ALL_MENU_FONT)
        self.infoMenu.add_command(label="Dev. info", command=self.devinfo)
        self.infoMenu.add_separator()
        self.infoMenu.add_command(label="Encryption used", command=lambda: webbrowser.open("http://gestyy.com/ethzyj"))
        self.infoMenu.add_separator()
        self.infoMenu.add_command(label="Help", command=lambda: webbrowser.open("http://gestyy.com/ethztf"))
        self.menu.add_cascade(label="<-- Info  -->", menu=self.infoMenu)

        # ======================================= LAYOUT SETUP

        # Logged-in Label
        self.loggedinLable = ttk.Label(self, text=f"Logged-in as: {self.who.get()}", font=ALL_TEXT_FONT, foreground="#F2FA00", background="black", padding=(5))
        self.loggedinLable.grid(row=0, column=0, columnspan=4, sticky="EW")

        # Generate password button
        self.genPassButton = ttk.Button(self, text="Generate password", command=self.generatePassword)
        self.genPassButton.grid(row=1, column=0, padx=(10), pady=(5), ipadx=(10), ipady=(5))

        # show Label
        self.showLabel = ttk.Label(self, text="\t\t", font=ALL_TEXT_FONT_Password)
        self.showLabel.grid(row=2, column=0, columnspan=3, padx=(10), pady=(5), ipadx=(10), ipady=(5))

        # Save password button
        self.saveButton = ttk.Button(self, text="Add new", command=self.savePasswordEntryWindow)
        self.saveButton.grid(row=1, column=1, padx=(10), pady=(5), ipadx=(10), ipady=(5))

        # View passwords button
        self.viewButton = ttk.Button(self, text="View passwords", command=self.viewPasswords)
        self.viewButton.grid(row=1, column=2, padx=(10), pady=(5), ipadx=(10), ipady=(5))

    def savePasswordEntryWindow(self):
        self.saveButton.grid_forget()
        self.genPassButton.grid_forget()
        self.viewButton.grid_forget()
        self.xFrame = SaveFieldWindow(self,self.username,self.password)
        self.xFrame.grid(row=2, column=0, columnspan=3, rowspan=3, sticky="NSEW")

    def viewPasswords(self):
        self.saveButton.grid_forget()
        self.genPassButton.grid_forget()
        self.viewButton.grid_forget()
        self.xFrame = ViewPasswordsWindow(self,self.username,self.password)
        self.xFrame.grid(row=2, column=0, columnspan=3, rowspan=3, sticky="NSEW")

    def generatePassword(self):
        # copy button
        self.copyButton = ttk.Button(self, text="Copy", command=lambda: pyperclip.copy(self.showLabel["text"]))
        self.copyButton.grid(row=3, column=0, columnspan=3, padx=(10), pady=(5), ipadx=(10), ipady=(5))

        passwd = genPassword()
        self.showLabel["text"] = passwd

    def backupForPort(self):
        shutil.make_archive("BKP_PORT_Users", 'zip', "Users")

    def devinfo(self):
        webbrowser.open("https://github.com/prakharsaxena1")
        webbrowser.open("https://twitter.com/_thunder_cs")


class SaveFieldWindow(ttk.Frame):
    def __init__(self, parent,username,password):
        super().__init__(parent)
        self.controller = parent
        self.columnconfigure(index=(0, 1), weight=1)
        self.rowconfigure(index=(0, 1, 2), weight=1)

        # ========================================================== VARIABLES
        self.websiteVariable = tk.StringVar()
        self.userIDVariable = tk.StringVar()
        self.sitePasswordVariable = tk.StringVar()

        self.username = username
        self.password = password

        usernameHash = hashlib.md5(username.encode()).hexdigest()
        userHOME = "Users/UsersInfo/"+str(usernameHash)
        key = makeKEY(password.encode())
        fernetobj = Fernet(key)

        # ========================================================== LAYOUT
        self.titleLabel = ttk.Label(self, text="~ ADD FIELD ~", font=ALL_TEXT_FONT)
        self.titleLabel.grid(row=0, column=0, columnspan=2, sticky="EW", padx=(25), pady=(10))

        self.websiteLabel = ttk.Label(self, text="Website: ", font=ALL_TEXT_FONT)
        self.websiteEntry = ttk.Entry(self, textvariable=self.websiteVariable, width="25")
        self.websiteLabel.grid(row=1, column=0, sticky="W", padx=(10, 5), pady=(5))
        self.websiteEntry.grid(row=1, column=1, sticky="E", padx=(5, 10), pady=(5))

        self.userIDLabel = ttk.Label(self, text="Login ID: ", font=ALL_TEXT_FONT)
        self.userIDEntry = ttk.Entry(self, textvariable=self.userIDVariable, width="25")
        self.userIDLabel.grid(row=2, column=0, sticky="W", padx=(10, 5), pady=(5))
        self.userIDEntry.grid(row=2, column=1, sticky="E", padx=(5, 10), pady=(5))

        self.passwordLabel = ttk.Label(self, text="Password: ", font=ALL_TEXT_FONT)
        self.passwordEntry = ttk.Entry(self, textvariable=self.sitePasswordVariable, width="25")
        self.passwordLabel.grid(row=3, column=0, sticky="W", padx=(10, 5), pady=(5))
        self.passwordEntry.grid(row=3, column=1, sticky="E", padx=(5, 10), pady=(5))

        self.backButton = ttk.Button(self, text="Go back", command=self.goBack)
        self.backButton.grid(row=4, column=0, padx=(5, 10), pady=(5))

        self.saveInfoButton = ttk.Button(self, text="Save", command=lambda: self.saveField(userHOME,fernetobj))
        self.saveInfoButton.grid(row=4, column=1, padx=(5, 10), pady=(5))

    def goBack(self):
        self.controller.saveButton.grid(row=1, column=1, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.controller.genPassButton.grid(row=1, column=0, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.controller.viewButton.grid(row=1, column=2, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.destroy()

    def saveField(self,userHOME,fernetobj):
        data = f"{self.websiteVariable.get()}:{self.userIDVariable.get()}:{self.sitePasswordVariable.get()}".encode()
        with open(userHOME+"/userdata","ab") as f:
            f.write(fernetobj.encrypt(data))
            f.write("\n".encode())
        self.goBack()


class ViewPasswordsWindow(ttk.Frame):
    def __init__(self, parent, username, password):
        super().__init__(parent)
        self.controller = parent

        # self.columnconfigure(index=(0,1), weight=1)
        # self.rowconfigure(index=(0,1,2), weight=1)

        # ========================================================== LAYOUT
        self.titleLabel = ttk.Label(self, text="~ VIEW PASSWORDS ~", font=ALL_TEXT_FONT)
        self.titleLabel.grid(row=0, column=0, columnspan=2, sticky="EW", padx=(25), pady=(10))

        usernameHash = hashlib.md5(username.encode()).hexdigest()
        userHOME = "Users/UsersInfo/"+str(usernameHash)
        key = makeKEY(password.encode())
        fernetobj = Fernet(key)

        with open(userHOME+"/userdata","rb") as f:
            x = f.readlines()
            for i in x:
                idecrypted = fernetobj.decrypt(i.replace(b"\n", b""))
                idecrypted = idecrypted.decode().split(":")
                print(f'Password for {idecrypted[0]} is -->   {idecrypted[2]}   <-- with userid= {idecrypted[1]}')


        self.backButton = ttk.Button(self, text="Go back", command=self.goBack)
        self.backButton.grid(row=4, column=0, padx=(5, 10), pady=(5))

    def goBack(self):
        self.controller.saveButton.grid(row=1, column=1, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.controller.genPassButton.grid(row=1, column=0, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.controller.viewButton.grid(row=1, column=2, padx=(10), pady=(5), ipadx=(10), ipady=(5))
        self.destroy()


# Check if folders exists or not
if not os.path.exists("Users/"):
    os.mkdir("Users/")
    os.mkdir("Users/Usersinfo/")
    temp = open("Users/users.file", 'w')
    temp.close()

app = ContainerWindow()
app.mainloop()
