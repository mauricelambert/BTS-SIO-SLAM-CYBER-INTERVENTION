from os.path import basename, dirname, join
from base64 import b64encode, b64decode
from functools import partial
from sys import stdin, exit
from pickle import loads
from hashlib import md5

class Key:
    def __init__(self, password):
        self.key = md5(password.encode("utf-16-le")).digest()
        self.length = 16

class Reader:
    def __init__(self, position = None, username = None):
        self.position = position
        self.username = username
        self.filter = partial(lambda v, i, u, p, l, c: i == v, position) if position is not None else partial(lambda v, i, u, p, l, c: u == v, username)

    def get_password(self):
        with open(Credentials.filename) as file:
            for index, line in enumerate(file):
                if not line:
                    return
                line = [word.strip() for word in line.split(',', 3)]
                if self.filter(index, *line):
                    credentials = Credentials(*line)
                    credentials.password = credentials.uncipher()
                    return credentials

    def __reduce__(self):
        return (Reader, (self.position, self.username))

class Credentials:

    filename = join(dirname(__file__), basename(".credentials"))

    def __init__(self, username, password, url = "", comment = ""):
        self.username = username
        self.password = password.encode()
        self.url = url
        self.comment = comment

    def cipher(self):
        return b64encode(self._cipher()).decode()

    def uncipher(self):
        self.password = b64decode(self.password)
        return self._cipher().decode("latin-1")

    def _cipher(self):
        return bytes(char ^ key.key[i % key.length] for i, char in enumerate(self.password))

    def save(self):
        with open(self.filename, "a") as file:
            file.write(f"{self.username},{self.cipher()},{self.url},{self.comment}\n")

key = Key("")

# cred = Credentials('Admin', '', 'http://127.0.0.1:8000/web/auth/', 'Mot de passe du server WebScripts.')
# cred.save(); exit(0)

# from pickle import dump, load
# with open("Credentials.cred", 'wb') as file: dump(Credentials('Username', 'P455W0RD', 'http://example.com/', 'My password.'), file, protocol=0)
# exit(0)

# with open("Reader1.read", 'wb') as file: dump(Reader(0), file, protocol=0)
# with open("Reader2.read", 'wb') as file: dump(Reader(username="Username"), file, protocol=0)

# with open("Key.key", 'wb') as file: dump(Key("r00t"), file, protocol=0)

# with open("Reader1.read", 'rb') as file: load(file)
# with open("Reader2.read", 'rb') as file: load(file)
# with open("Credentials.cred", 'rb') as file: load(file)
# with open("Key.key", 'rb') as file: load(file)

for line in stdin.buffer.readlines():
    object_ = loads(b64decode(line))

    if object_.__class__.__name__ == "Key":
        key = object_
        print("The key is changed.")
    elif object_.__class__.__name__ == "Credentials":
        credentials = object_
        credentials.save()
        print("The credentials are saved.")
    elif object_.__class__.__name__ == "Reader":
        reader = object_
        credentials = reader.get_password()
        try:
            print(credentials.username, credentials.password, credentials.url, credentials.comment, sep="\n")
        except UnicodeEncodeError:
            print("Key is invalid.")
            exit(1)
        except AttributeError:
            print("Credentials not found.")
            exit(2)

exit(0)