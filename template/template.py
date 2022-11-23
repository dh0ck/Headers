from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml
import os, sys
from docxtpl import DocxTemplate
from docxtpl import InlineImage
from docx.shared import Mm

f = open('info.txt')
infos = f.readlines()
f.close()
descriptions = {}
solutions = []
# info.txt file cannot contain empty lines!!! all lines must be of the format:
# header ::: description --- solution
for info in infos:
	header = info.split(' ::: ')[0]
	contents = info.split(' ::: ')[1]
	descriptions[header] = {}
	descriptions[header]["description"] = contents.split('---')[0]
	descriptions[header]["solution"] = contents.split('---')[1]

#breakpoint()
vulns = [
		('Missing HTTP-Strict-Transport-Security header','Missing Security Header','MEDIUM','6.5','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'), 
		('Missing Cache-Control header','Missing Security Header', 'LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Missing X-Frame-Options header','Missing Security Header','LOW','3.1','CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N'),
		('Missing Content-Security-Policy header','Missing Security Header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Missing X-Content-Type-Options header','Missing Security Header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Missing X-XSS-Protection header','Missing Security Header','MEDIUM','5.4','CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'),
		('Missing Referrer-Policy header','Missing Security Header','MEDIUM','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Missing Cookie Secure flag','Cookies without flags','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Missing Cookie HttpOnly flag','Cookies without flags','LOW','3.1','CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Dangerous Server header','Dangerous header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Dangerous X-Powered-By header','Dangerous header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Potentially Dangerous Access-Control-Allow-Origin header','Potentially Dangerous Header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
		('Potentially Dangerous Access-Control-Allow-Credentials header','Potentially Dangerous Header','LOW','3.1','CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N')
	]


cvss_images={'3.1':'3,1.png','6.5':'6,5.png','0':'0.png','5.4':'5,4.png'}

def get_issues():
	""" Generates output dictionary form output file generated by burp extension
	in the order Host > Issue > Issue details > URL"""
	dic = {'Host':{}}
	def fill_dic(title, variable):
		if title not in dic['Host'][host]['Issue'].keys():
				dic['Host'][host]['Issue'][issue] = {title:{variable:[url]}}
		else:
			if variable not in dic['Host'][host]['Issue'][issue][title].keys():
				dic['Host'][host]['Issue'][issue][title][variable] = []
			dic['Host'][host]['Issue'][issue][title][variable].append(url)

	f = open('../output/selected_output.txt','r')
	for line in f.readlines():
		issue = line.split(';')[0].split(': ')[1]
		host = line.split(';')[1].split(': ')[1]
		url = line.split(';')[2].split('- URL: ')[1].split('- Port')[0]
		port = line.split(';')[2].split('- Port: ')[1].rstrip('\n')

		host = host + ' [' + port + ']'

		if host not in dic['Host'].keys():
			dic['Host'][host] = {'Issue':{}}

		if issue == "Missing Security Header":
			"""para missing securit headers usa la estructura del diccionario: 
			host -> issue -> missing header -> url"""
			missing_header = line.split(';')[2].split('Missing "')[1].split('" header')[0]
			fill_dic("Missing Security Header", missing_header)
		
		if issue == "Dangerous header":
			dangerous_header = line.split(';')[2].split('" header')[0].split('Detail: ')[1].lstrip('"')
			fill_dic("Dangerous header", dangerous_header)

		if issue == "Potentially Dangerous Header":
			potentially_dangerous_header = line.split(';')[2].split('" header')[0].split('Detail: ')[1].lstrip('"')
			fill_dic("Potentially Dangerous Header", potentially_dangerous_header)

		if issue == "Cookies without flags":
			missing_flag = line.split('Missing "')[1].split('" flag -')[0]
			fill_dic("Cookies without flags", missing_flag)
			
	f.close()
	return dic

fill_dic = get_issues()
doc = DocxTemplate("template.docx")

def build_item(IP,host,port,vuln,cvss,urls):
	dic = {
		"Name":vuln[0],
		"Port":port,
		"Protocol":"TCP",
		"Description":descriptions[vuln[0]]["description"],
		"Severity":vuln[2],
		"Code":'',
		"Host":host,
		"IP":IP,
		"State":"OPEN",
		"Solution":descriptions[vuln[0]]["solution"],
		"CVSS":vuln[3],
		"CVSS_image":InlineImage(doc, cvss_images[vuln[3]], width=Mm(160)),
		"URLs":urls
		}
	return dic

headers = []
headers1 = []
for host in fill_dic['Host'].keys():
	for issue in fill_dic['Host'][host]['Issue'].keys():
		for detail in fill_dic['Host'][host]['Issue'][issue][issue].keys():
			urls = fill_dic['Host'][host]['Issue'][issue][issue][detail]
			""" buscar forma de incluir IP si esta disponible"""
			IP = '-'
			# loop to retrieve the appropriate description and solution of a certain issue type
			for vuln in vulns:
				if detail.lower() in vuln[0].lower():  
					break	
			cvss = vuln[3]
			if IP != '-':
				IP = ' - (' + IP + ')'
			else:
				IP = ''
			to_append = build_item(IP,host.split(' [')[0],host.split(' [')[1].split(']')[0],vuln,cvss,urls)
			headers.append(to_append)
			headers1.append({"headers":to_append})#, "urls":urls})

'''las access-control-allow-origin mirar si las ponian en el informe anterior
 si no estaban. si no las ponen, quitarlas de aqui, solo habria que ponerla
  si esta mal configurada, no si no esta (en principio), puedo crearla pero poniendo
  un aviso de revisarla a mano'''

context1 = {
	"headers" : headers1
}
doc.render(context1)
# Add colors to severity cell
colors = {"CRITICAL":"C857C9","HIGH":"FF0000","MEDIUM":"ffff00","LOW":"00B050"}
for table in doc.tables:
	severity = table.cell(1,3).text
	shading_elm_1 = parse_xml(r'<w:shd {0} w:fill="{1}"/>'.format(nsdecls('w'),colors[severity]))

	
	table.rows[1].cells[3]._tc.get_or_add_tcPr().append(shading_elm_1)

if len(sys.argv) != 2:
	filename = "bbb.docx"
else:
	filename = sys.argv[1]
try:
	os.remove(filename)
except:
	pass
doc.save(filename)

