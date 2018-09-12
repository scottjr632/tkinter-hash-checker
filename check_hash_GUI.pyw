import tkinter as tk
from tkinter import filedialog
import hashlib


BLOCKSIZE = 65536
HASHES = {'MD5', 'SHA256', 'SHA1', 'SHA512'}


def __pick_hash(hash) -> hashlib:
    switcher = {
        'MD5': hashlib.md5(),
        'SHA256': hashlib.sha256(),
        'SHA1': hashlib.sha1(),
        'SHA512': hashlib.sha512()
    }
    return switcher.get(hash, None)


def check_hash(file, hash, type) -> bool:
    hasher = __pick_hash(type)
    if hasher is None: return False
    with open(file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf):
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    if hasher.hexdigest() == hash:
        return True
    else: return False


class CreateAndShowGui(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master=master)
        self.filename = None
        self.tkvar = tk.StringVar()
        self.tkvar.set('MD5')

        self.bttn = tk.Button(text="Get File", command=self.check,width=20)
        self.hash = tk.Entry(width=50)
        self.lbl = tk.Label(text="Pick file...")
        self.op = tk.OptionMenu(master, self.tkvar, *HASHES)
        self.hash_lbl = tk.Label(text="Enter hash to check against", width=20,padx=10)

        self.hash.event_add('<<Paste>>', '<Control-v>')
        self.hash.grid(row=0, column=1)
        self.hash_lbl.grid(row=0,column=0)
        self.bttn.grid(row=1, column=1,sticky='ne')
        self.op.grid(row=1, column=1,sticky='n')
        self.lbl.grid(row=2, column=0,columnspan=2)

    def check(self):
        self.lbl.config(text="Checking... ")
        self.filename = filedialog.askopenfilename(initialdir = "/Downloads",title = "Select file",filetypes = (("all files","*.*"),("zip files","*.zip"),("jpeg files","*.jpg")))
        if self.filename is not None:
            if (check_hash(self.filename, self.hash.get(), self.tkvar.get())):
                self.lbl.config(text="Correct Hash!")
            else:
                self.lbl.config(text="Incorrect Hash...")


if __name__ == '__main__':
    root = tk.Tk()

    w = 500 # width for the Tk root
    h = 200 # height for the Tk root

    # get screen width and height
    ws = root.winfo_screenwidth() # width of the screen
    hs = root.winfo_screenheight() # height of the screen

    # calculate x and y coordinates for the Tk root window
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    # set the dimensions of the screen 
    # and where it is placed
    root.geometry('%dx%d+%d+%d' % (w, h, x, y))

    
    root.iconbitmap(r'C:\Users\scott.DESKTOP-E7DFR3U\Documents\Python\images.ico')
    root.title("Hash Checker")
    main = CreateAndShowGui(root)
    root.geometry("500x200")
    root.mainloop()
