from os.path import join, dirname, basename
from sys import exit, stderr, argv, stdin
from os import listdir, remove
from base64 import b64decode

def getfilepath(filename):
    return join(dirname(__file__), basename(filename))

def read():
    if len(argv) != 3:
        print("USAGES: fileshare.py read <file>", file=stderr)
        return 1
    print(open(getfilepath(argv[2]), encoding="latin-1").read())
    return 0

def write():
    if len(argv) != 3:
        print("USAGES: fileshare.py write <file>", file=stderr)
        return 1
    open(getfilepath(argv[2]), "wb").write(b64decode(stdin.buffer.read()))
    return 0

def add():
    if len(argv) != 3:
        print("USAGES: fileshare.py add <file>", file=stderr)
        return 1
    open(getfilepath(argv[2]), "ab").write(b64decode(stdin.buffer.read()))
    return 0

def delete():
    if len(argv) != 3:
        print("USAGES: fileshare.py delete <file>", file=stderr)
        return 1
    remove(getfilepath(argv[2]))
    return 0

def list():
    for filename in listdir(getfilepath("")):
        if not filename.endswith(".py") and not filename.startswith("."):
            print(filename)
    return 0

if len(argv) < 2:
    print("USAGES: fileshare.py (list | [read|write|add|delete] [file])", file=stderr)
    exit(1)

try:
    exit(eval(argv[1])())
except:
    exit(127)