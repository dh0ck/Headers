import docx
import docxtpl
print("this is run from python3, external file")

x = 5
tpl=docxtpl.DocxTemplate('your_template.docx')
#doc = docx.Document('your_template.docx')
context = { 'x' : "World company",
'x':"goodby" }
tpl.render(context)



tpl.save("generated_doc.docx")