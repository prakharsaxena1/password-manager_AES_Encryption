import webbrowser
import random
import base64

import sys
import tkinter as tk
from tkinter import ttk
from PIL import ImageTk, Image
# REQUIRED MODULES
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


def makeKEY(passgiven):  # Generating a AES Key according to the user provided password *inserts smart meme*
    salt = b''
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passgiven))
    return key


def genPassword():  # Generating a Strong password of length = 16
    m = ''  # m is the password string
    passwordStrength = 0
    while passwordStrength <= 0.8:
        for _ in range(16):
            m = m + X[random.randint(0, len(X)-1)]
        passwordStrength = passwordmeter.test(m)[0]
    return m


# making characterset to choose characters from
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./<=>?@[]^_{|}~"
X = ''.join(set(list(charset)))
# Main Code


# Container class

class MainWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.geometry("300x300")
        self.resizable(0, 0)
        self.title("Password VAULT")
        self.iconbitmap("logo.ico")
        self.firstFrame = firstWindow(self, self)
        self.firstFrame.grid(row=0, column=0, sticky="NESW")
        self.secondFrame = secondWindow(self, self)
        self.secondFrame.grid(row=0, column=0, sticky="NESW")

# Login window class


class firstWindow(tk.Frame):
    def registerFunction(self, username, password):
        print("IN REGISTER FUNCTION")
        self.statusLabel["text"] = "~- Successfully registered -~"

    def loginFunction(self, username, password):
        print("IN LOGIN FUNCTION")
        self.statusLabel["text"] = "~- Successfully logged-in -~"

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

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.usernameVariable = tk.StringVar()
        self.passwordVariable = tk.StringVar()
        self.cbVar = tk.BooleanVar(value=False)
        self.radioVariable = tk.StringVar()
        self.statusVariable = tk.StringVar()

        self.radioVariable.set("Register")
        self.img = ImageTk.PhotoImage(Image.open("logo.png"))
        self.panel = ttk.Label(self, image=self.img)
        self.panel.grid(row=0, column=0, columnspan=2, padx=(5), pady=(5))

        self.loginRadio = ttk.Radiobutton(
            self, text="Login", variable=self.radioVariable, value="Login", command=self.setButtonText)
        self.loginRadio.grid(row=1, column=0, padx=(5), pady=(5))

        self.registerRadio = ttk.Radiobutton(
            self, text="Register", variable=self.radioVariable, value="Register", command=self.setButtonText)
        self.registerRadio.grid(row=1, column=1, padx=(5), pady=(5))

        self.usernameLabel = ttk.Label(self, text="Username: ")
        self.usernameLabel.grid(
            row=2, column=0, sticky="W", padx=(5), pady=(5))

        self.passwordLabel = ttk.Label(self, text="Password: ")
        self.passwordLabel.grid(
            row=3, column=0, sticky="W", padx=(5), pady=(5))

        self.usernameEntry = ttk.Entry(
            self, textvariable=self.usernameVariable, width="25")
        self.usernameEntry.grid(
            row=2, column=1, sticky="E", padx=(5), pady=(5))

        self.passwordEntry = ttk.Entry(
            self, textvariable=self.passwordVariable, width="25", show="*")
        self.passwordEntry.grid(
            row=3, column=1, sticky="E", padx=(5), pady=(5))

        self.checkbutton = ttk.Checkbutton(
            self, text="show password", variable=self.cbVar, onvalue=True, offvalue=False, command=self.toggleShowPassword)
        self.checkbutton.grid(row=4, column=0, columnspan=2,
                              sticky="E", padx=(5), pady=(5))

        self.radioSelectButton = ttk.Button(self, text=str(
            self.radioVariable.get()), command=self.useFunction)
        self.radioSelectButton.grid(
            row=5, column=0, columnspan=2, padx=(5), pady=(5), ipadx=(5))

        self.statusLabel = ttk.Label(self, text=" ")
        self.statusLabel.grid(row=6, column=0, columnspan=2,
                              padx=(5), pady=(5), ipadx=(5))


class secondWindow(tk.Frame):
    def exitProgram(self):
        exit()

    def devinfo(self):
        webbrowser.open("https://github.com/prakharsaxena1")
        webbrowser.open("https://twitter.com/_thunder_cs")

    def encryptionused(self):
        webbrowser.open("https://en.wikipedia.org/wiki/Advanced_Encryption_Standard")

    def helpme(self):
        webbrowser.open("https://github.com/prakharsaxena1/password-manager_AES_Encryption")

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.master = parent
        self.controller = controller
        self.controller.geometry("500x400")
        self.who = tk.StringVar(value=" ")
        self.menu = tk.Menu(self.master, tearoff=False)
        self.master.config(menu=self.menu)

        self.fileMenu = tk.Menu(self.menu, tearoff=False)

        self.submenu = tk.Menu(self.fileMenu, tearoff=False)
        self.submenu.add_command(label="Chrome")
        self.submenu.add_separator()
        self.submenu.add_command(label="Firefox")
        self.fileMenu.add_cascade(label='Import passwords', menu=self.submenu, underline=0)

        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Backup for port")
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=self.exitProgram)
        self.menu.add_cascade(label="<-- File -->", menu=self.fileMenu)

        self.infoMenu = tk.Menu(self.menu, tearoff=False)
        self.infoMenu.add_command(label="Dev. info", command=self.devinfo)
        self.infoMenu.add_separator()
        self.infoMenu.add_command(label="Encryption used", command=self.encryptionused)
        self.infoMenu.add_separator()
        self.infoMenu.add_command(label="Help", command=self.helpme)
        self.menu.add_cascade(label="<-- Info  -->", menu=self.infoMenu)
        self.loggedinLable = ttk.Label(self, text=f"Logged-in as: {self.who.get()}")
        self.loggedinLable.grid(row=0,column=0,sticky="EW")
        
        


app = MainWindow()
app.mainloop()
