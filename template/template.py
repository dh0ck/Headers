from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml
import sys
from docxtpl import DocxTemplate
from docxtpl import InlineImage
from docx.shared import Mm

f = open('info.txt')
infos = f.readlines()[7:]
f.close()
descriptions = []
solutions = []
for info in infos:
	descriptions.append(info.split('---')[0])
	solutions.append(info.split('---')[1])


vulns = [('Missing HTTP-Strict-Transport-Security-header','MEDIUM','6.5','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'), 
	('Missing Access-Control-Allow-Origin header', 'LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
	('Missing X-Frame-Options header','LOW','3.1','CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N'),
	('Missing Content-Security-Policy header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
	('Missing X-Content-Type-Options header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
	('Missing X-XSS-Protection header','MEDIUM','5.4','CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N')]
  
cvss_images={'3.1':r'C:\Users\allc\Documents\GitHub\Headers\template\3,1.png',
	'6.5':r'C:\Users\allc\Documents\GitHub\Headers\template\6,5.png',
	'0':r'C:\Users\allc\Documents\GitHub\Headers\template\0.png', 
	'5.4':r'C:\Users\allc\Documents\GitHub\Headers\template\5,4.png'}

doc = DocxTemplate("template.docx")

def build_item(IP,host,port,vuln,cvss):
	table = []
	table.append( ('Name',vulns[int(vuln)-1][0]) )
	table.append( ('Port',port) )
	table.append( ('Description', descriptions[int(vuln)-1]) )
	table.append( ('Protocol', 'TCP') )
	table.append( ('Severity', vulns[int(vuln)-1][1]) ) 
	table.append( ('Code', '') )
	table.append( ('Host', host) )
	table.append( ('IP', IP) )
	table.append( ('State', 'OPEN') )
	table.append( ('Solution', solutions[int(vuln)-1]) )
	table.append( ('CVSS',vulns[int(vuln)-1][3]) )
	table.append( ('CVSS_image', InlineImage(doc, cvss_images[cvss], width=Mm(160))) )
	return table
	


'''las access-control-allow-origin mirar si las ponian en el informe anterior si no estaban. si no las ponen, quitarlas de aqui, solo habria que ponerla si esta mal configurada, no si no esta (en principio)'''
f = open("headers.txt")
lines = f.readlines()[7:]
f.close()
k=0
headers = []
for line in lines:
	splitted = line.split(':')
	host = splitted[0]
	IP = splitted[1]
	ports = splitted[2]
	ports_splitted = ports.split(';')

	for port in ports_splitted:
		port_number = port.split('-')[0]
		port_vulns = port.split('-')[1].split(',')
		for vuln in port_vulns:
			print(host,IP,port_number,vuln)
			cvss = vulns[int(vuln)-1][2]
			k+=1
			headers.append(build_item(IP,host,port_number,vuln,cvss))
		

context = {
    "headers" : headers
}

doc.render(context)
colors = {"CRITICAL":"C857C9","HIGH":"FF0000","MEDIUM":"ffff00","LOW":"00B050"}
for table in doc.tables:
	severity = table.cell(1,3).text
	shading_elm_1 = parse_xml(r'<w:shd {0} w:fill="{1}"/>'.format(nsdecls('w'),colors[severity]))

	
	print(severity)
	table.rows[1].cells[3]._tc.get_or_add_tcPr().append(shading_elm_1)
doc.save('aaa.docx')

