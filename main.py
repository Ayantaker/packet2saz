from src.packet2saz import Packet2saz
import json

# Opening JSON file
f = open('testdata.json','r')
data = json.load(f)

sazname = 'testsaz'

p = Packet2saz(sazname,data)
p.convert()