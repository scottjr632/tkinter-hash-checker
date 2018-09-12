import hashlib, sys
from tkinter import filedialog


BLOCKSIZE = 65536

def pick_hash(hash) -> hashlib:
    switcher = {
        'MD5': hashlib.md5(),
        'SHA256': hashlib.sha256(),
        'SHA1': hashlib.sha1()
    }
    return switcher.get(hash, None)

def check_hash(file, hash, type) -> bool:
    hasher = pick_hash(type)
    if hasher is None: return False
    with open(file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf):
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    if hasher.hexdigest() == hash:
        return True
    else: return False

if __name__ == '__main__':
    if len(sys.argv) > 1 and len(sys.argv) < 4:
        arg1 = sys.argv[1]
        if arg1 == '-h' \
        or arg1 == '--help' \
        or arg1 == '/?':
            print("python hash_checker.py hash_type hash \n-m for list of hashes")
            sys.exit()
        if arg1 == '-m' or arg1 == '-M':
            print("List of hashes:\n\t\tMD5\n\t\tSHA256\n\t\tSHA1")
            sys.exit()

        filename = filedialog.askopenfilename(initialdir = "/Downloads",title = "Select file",filetypes = (("zip files","*.zip"),("jpeg files","*.jpg"),("all files","*.*")))
        if (check_hash(filename, sys.argv[2], sys.argv[1])):
            print("Hashes match!")
        else:
            print ("Hashes do not match...")
    else:
        print ("python hash_checker --help")
        sys.exit()