import pdb
import json
import os
import shutil
import re
import subprocess


class Packet2saz:
	def __init__(self,name,packets={}):
		self.name = name
		self.packets = packets


	def text_files_from_packet(self):
		i = 1

		packet_hash = self.packets
		sazname = self.name

		for key in packet_hash.keys():

			rr = packet_hash[key]

			index = ((3-len(str(i)))*'0')+str(i)
			i+=1

			f = open(os.path.join(sazname,'raw',f"{index}_c.txt"),'w+')
			print(rr['request'],file=f)
			f.close()

			f = open(os.path.join(sazname,'raw',f"{index}_s.txt"),'w+')
			print(rr['response'],file=f)
			f.close()
	

	def setup(self):

		sazname = self.name

		## Check if old dir exists and delete
		if os.path.isdir(sazname):
			shutil.rmtree(sazname)

		os.mkdir(sazname)
		os.mkdir(os.path.join(sazname,'raw'))
		f = open(os.path.join(sazname,'[Content_Types].xml'),'w+')
		print("""<?xml version="1.0" encoding="utf-8" ?>
			<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
			<Default Extension="htm" ContentType="text/html" />
			<Default Extension="xml" ContentType="application/xml" />
			<Default Extension="txt" ContentType="text/plain" />
			</Types>""",file=f)


	def archive_and_saz(self):
		subprocess.call(f"zip -r {self.name}.saz ./*", cwd=r"./"+self.name,shell=True)
		
	def create_index_file(self):

		packet_hash = self.packets
		sazname = self.name

		f = open(os.path.join(sazname,"_index.htm"),'w+')

		packet_template = """
			<tr>
				<td><a href='raw\\##index##_c.txt'>C</a>&nbsp;<a href='raw\\##index##_s.txt'>S</a>&nbsp;<a href='raw\\##index##_m.xml'>M</a></td>
				<td>##index##</td>
				<td>##ServerReplyResult##</td>
				<td>HTTPS</td>
				<td>##Host##</td>
				<td>##URL##</td>
				<td>##ResponseContentLength##</td>
				<td>##Cache-Control;Expires##</td>
				<td>##Content-type##</td>
				<td>chrome:11684</td>
				<td></td>
				<td></td>
			</tr>
			"""

		rows = []
		index = 1

		for key in packet_hash.keys():

			rr = packet_hash[key]
			request = rr['request']
			response = rr['response']
			i = ((3-len(str(index)))*'0')+str(index)
			temp = packet_template.replace("##index##",str(i))
			index += 1

			host = re.findall("Host: (.*)",request)

			if len(host) == 0:
				print("No host found. Exiting")
				exit()
			elif len(host) != 1:
				print("Multiple host found. Exiting")
				exit()
			else:
				temp = temp.replace("##Host##",host[0])

			url = re.findall('(GET|POST|PUT|CONNECT) (.*) HTTP/\\d.\\d',request)

			if len(url) != 1:
				print('URL is not 1... Exiting')
				exit()
			else:
				temp = temp.replace("##URL##",url[0][1])


			response_code = re.findall("HTTP/\\d.\\d (\\d\\d\\d) \\w*",response)
			if len(response_code) != 1:
				print("Issue with response_code. Exiting")
				exit()
			else:
				temp = temp.replace("##ServerReplyResult##",response_code[0])


			cache = re.findall("Cache-Control: (.*)",response)
			expires = re.findall("(Expires: .*)",response)

			if len(expires) == 0:
				if len(cache) != 0:
					temp = temp.replace("##Cache-Control;Expires##",f"{cache[0]}")
				else:
					temp = temp.replace("##Cache-Control;Expires##","")
			else:
				temp = temp.replace("##Cache-Control;Expires##",f"{cache[0]}:{expires[0]}")

			contenttype = re.findall("Content-Type: (.*)",response)
			temp = temp.replace("##Content-type##",contenttype[0])
			
			response_length = re.findall('Content-Length: (\\d*)',response)
			if len(response_length) == 0:
				response_length = 0
			else:
				response_length = response_length[0]

			temp = temp.replace("##ResponseContentLength##",response_length)



			rows.append(temp)


		print("""<html><head><style>body,thead,td,a,p{font-family:verdana,sans-serif;font-size: 10px;}</style></head><body><table cols=12><thead><tr><th>&nbsp;</th><th>#</th><th>Result</th><th>Protocol</th><th>Host</th><th>URL</th><th>Body</th><th>Caching</th><th>Content-Type</th><th>Process</th><th>Comments</th><th>Custom</th></tr></thead><tbody>"""+''.join(rows)+"""</tbody></table></body></html>""",file=f)






	def convert(self):
		self.setup()
		self.text_files_from_packet()
		self.create_index_file()
		self.archive_and_saz()