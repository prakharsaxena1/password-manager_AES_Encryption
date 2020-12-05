import tkinter as tk
from tkinter import ttk

class passwordAddGui(tk.Frame):
    def __init__(self,parent):
        super().__init__(parent)
        self.siteNameFrame = tk.Frame(self, bg="green",width=120,height=120)
        self.siteNameFrame.grid(row=0,column=0)
        self.initialLabel

        self.userInfoFrame = tk.Frame(self, bg="orange", width=340, height=120)
        self.userInfoFrame.grid(row=0,column=1)

        self.passwordFrame = tk.Frame(self, bg="red", width=140, height=120)
        self.passwordFrame.grid(row=0,column=2)

root = tk.Tk()
root.geometry("600x400")
root.resizable(1,1)
someframe = passwordAddGui(root)
someframe.grid(row=0,column=0)
root = tk.mainloop()
