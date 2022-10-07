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