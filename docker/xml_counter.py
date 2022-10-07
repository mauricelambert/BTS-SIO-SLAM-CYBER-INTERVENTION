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