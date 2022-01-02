from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
import shutil, glob, re
from javax.swing import JFrame, JSplitPane, JTable, JScrollPane, JPanel, BoxLayout, WindowConstants, JLabel, JMenuItem, JTabbedPane, JButton, JTextField, JTextArea, SwingConstants, JEditorPane
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints, Point, Component, Color  # quitar los layout que no utilice
from java.util import List, ArrayList
from java.awt.event.MouseEvent import getPoint
from java.awt.event import MouseListener


burp_extender_instance = "" # variable global que sera el instance de bupr extender, para acceder a los valores de la instancia de IBurpExtender que burp crea, pero desde fuera, sobre todo para cambiar con clicks la tabla de endpoints
history1 = []
host_endpoint = [] #se rellena al darle a filter en la tab, pero habra que arreglar que no haya duplicados cuando cambian los valores de los query string  rameters (o puedo dejar que se repitan y ponerlos todos.) lo bueno seria poner tambien el index del history y en el text area poner los headers de la req  los de la resp, separados por una =========, etc
endpoint_table = []


# el extra info window lo defino aqui fuera para que exista desde un principio y al hacer doble click en las tablas solamente se haga visible, pero no se  ee un nuevo frame por cada doble click
extra_info = JFrame("Extended header info")
extra_info_panel = JPanel()
extra_info_panel.setLayout(BoxLayout(extra_info_panel, BoxLayout.Y_AXIS ) )
extra_info.setSize(400, 350)
extra_info.setLocation(840, 0)
extra_info.toFront()
extra_info.setAlwaysOnTop(True)

extra_info_label1 = JLabel("<html><b><font color='orange'>Header Name:</font></b></html>")
extra_info_label1.setAlignmentX(JLabel.LEFT_ALIGNMENT)
extra_info_textarea1 = JTextArea("Header Name", rows=1, editable=False)
extra_info_textarea1.setLineWrap(True)
scrollPane_1 = JScrollPane(extra_info_textarea1)
scrollPane_1.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

extra_info_label2 = JLabel("<html><b><font color='orange'>Header Description:</font></b></html>")
extra_info_label2.setAlignmentX(JLabel.LEFT_ALIGNMENT)
extra_info_textarea2 = JTextArea("Description",rows=5, editable=False)
extra_info_textarea2.setLineWrap(True)
scrollPane_2 = JScrollPane(extra_info_textarea2)
scrollPane_2.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

extra_info_label3 = JLabel("<html><b><font color='orange'>Usage example:</font></b></html>")
extra_info_label3.setAlignmentX(JLabel.LEFT_ALIGNMENT)
extra_info_textarea3 = JTextArea("Example",rows=3, editable=False)
extra_info_textarea3.setLineWrap(True)
scrollPane_3 = JScrollPane(extra_info_textarea3)
scrollPane_3.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

extra_info_label4 = JLabel("<html><b><font color='orange'>URL describing header:</font></b></html>")
extra_info_label4.setAlignmentX(JLabel.LEFT_ALIGNMENT)
extra_info_textarea4 = JTextArea("URL2",rows=2, editable=False)
extra_info_textarea4.setLineWrap(True)
scrollPane_4 = JScrollPane(extra_info_textarea4)
scrollPane_4.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

extra_info_label5 = JLabel("<html><b><font color='orange'>Potential risks associated with header:</font></b></html>")
extra_info_label5.setAlignmentX(JLabel.LEFT_ALIGNMENT)
extra_info_textarea5 = JTextArea("There are no potential risks associated with this header",rows=3, editable=False)
extra_info_textarea5.setLineWrap(True)
scrollPane_5 = JScrollPane(extra_info_textarea5)
scrollPane_5.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

for element in [extra_info_label1, scrollPane_1, extra_info_label2, scrollPane_2, extra_info_label3, scrollPane_3, extra_info_label4, scrollPane_4, extra_info_label5, scrollPane_5]:
  extra_info_panel.add(element)

extra_info.add(extra_info_panel)
dict_req_headers = {}
req_headers_description = open('request_headers.txt','r')
for line in req_headers_description.readlines():
  line_split = line.split('&&')
  header_name = line_split[0]

  header_description = line_split[1]
  if header_description.rstrip() == '':
    header_description = 'Description unavailable for header: ' + header_name

  header_example = line_split[2]
  if header_example.rstrip() == '':
    header_example = 'Example unavailable for header: ' + header_name

  header_url = line_split[3]
  if header_url.rstrip() == '':
    header_url = 'URL unavailable for header ' + header_name

  header_risk = line_split[4]
  if header_risk.rstrip() == '':
    header_risk = 'Potential risks information unavailable for header ' + header_name
  dict_req_headers[header_name] = (header_description, header_example, header_url, header_risk)
req_headers_description.close()

dict_resp_headers = {}
resp_headers_description = open('response_headers.txt','r')
for line in resp_headers_description.readlines():
  line_split = line.split('&&')
  header_name = line_split[0]

  header_description = line_split[1]
  if header_description.rstrip() == '':
    header_description = 'Description unavailable for header: ' + header_name

  header_example = line_split[2]
  if header_example.rstrip() == '':
    header_example = 'Example unavailable for header: ' + header_name

  header_url = line_split[3]
  if header_url.rstrip() == '':
    header_url = 'URL unavailable for header ' + header_name

  header_risk = line_split[4]
  if header_risk.rstrip() == '':
    header_risk = 'Potential risks information unavailable for header ' + header_name
  dict_resp_headers[header_name] = (header_description, header_example, header_url, header_risk)
resp_headers_description.close()


class IssueTableModel(DefaultTableModel):
    """Extends the DefaultTableModel to make it readonly (among other
    things)."""

    def __init__(self, data, headings):
        # call the DefaultTableModel constructor to populate the table
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, column):
        """Returns True if cells are editable."""
        canEdit = [False, False]
        return canEdit[column]


class IssueTableMouseListener(MouseListener):

  def getClickedIndex(self, event):
    """Returns the value of the first column of the table row that was
    clicked. This is not the same as the row index because the table
    can be sorted."""
    # get the event source, the table in this case.
    tbl = event.getSource()
    # get the clicked row
    row = tbl.getSelectedRow()
    # get the first value of clicked row
    return tbl.getValueAt(row, 0)
    # return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)

  def getClickedRow(self, event):
    """Returns the complete clicked row."""
    tbl = event.getSource()
    return [tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow()), tbl.getSelectedRow()]

  def mousePressed(self, event):
    pass

  def mouseReleased(self, event):
    pass

  # the following two are necessary, although they are empty, otherwise the extension crashes when the mouse cursor enters or exits the table
  def mouseEntered(self, event):
    pass

  def mouseExited(self, event):
    pass

class IssueTableMouseListener_Window(IssueTableMouseListener):
    def mouseClicked(self, event):
        if event.getClickCount() == 1:  # single click on table elements
            header = self.getClickedRow(event)[0]

            header = header[0].split('<font color="orange">')[1].split('</b></font>')[0] #debe haber mas abajo al reves el orden de las closing tabs b y font
            extra_info_textarea1.setText(header)
            if header in list(dict_req_headers.keys()) and header not in list(dict_resp_headers.keys()):
              extra_info_textarea2.setText(dict_req_headers[header][0])
              extra_info_textarea3.setText(dict_req_headers[header][1])
              extra_info_textarea4.setText(dict_req_headers[header][2])
              extra_info_textarea5.setText(dict_req_headers[header][3])
            if header not in (list(dict_req_headers.keys())) and header not in list(dict_resp_headers.keys()):
              extra_info_textarea2.setText('Description unavailable for header: ' + header)
              extra_info_textarea3.setText('Example unavailable for header: ' + header)
              extra_info_textarea4.setText('URL unavailable for header: ' + header)
              extra_info_textarea5.setText('Potential risks unavailable for header: ' + header)
            if header in list(dict_resp_headers.keys()):
              extra_info_textarea2.setText(dict_resp_headers[header][0])
              extra_info_textarea3.setText(dict_resp_headers[header][1])
              extra_info_textarea4.setText(dict_resp_headers[header][2])
              extra_info_textarea5.setText(dict_resp_headers[header][3])
        if event.getClickCount() == 2:  # double click to make extra info panel visible
            extra_info.setVisible(True)

class IssueTableMouseListener_Tab(IssueTableMouseListener):

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        clicked_value = ''
        if event.getClickCount() == 1:
            
            tbl = event.getSource()
            val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())
            
            header = val[0]
            clicked_host = val[1]
            k = tbl.getSelectedRow()
            if header == '':
              while header == '':
                k -= 1
                header = tbl.getModel().getDataVector().elementAt(k)[0]
        header_value = header.split('<font color="orange">')[1].split('</font>')[0]
        #hasta aqui ok, header_value es el header que se ha marcado (primera columna), creo que este solo lo uso para subrayado en el textarea

        global host_endpoint #[host, endpoint]
        global endpoint_table
        endpoint_table = []
        for (host, endpoint) in host_endpoint:
          
          if clicked_host == host:# and endpoint not in endpoint_table:
            endpoint_table.append([endpoint])
        
        global burp_extender_instance #variable global que representa la instancia de IBurpExtender que se crea al cargar la extension. se usa para acceder desde fuera (especialmente desde el mouse event handler para actualizar la endpoint_table) a propiedades y metodos de la instancia "principal" de la extension. el valor se lo doy dentro de la intancia, igualando esta variable a self
        burp_extender_instance.update_endpoints(endpoint_table)
        burp_extender_instance.selected_host = clicked_host
        burp_extender_instance.selected_header = header



class IssueTableMouseListener_Endpoints(IssueTableMouseListener):

    def mouseClicked(self, event):
            
        global burp_extender_instance 
        clicked_value = ''
        if event.getClickCount() == 1:
            tbl = event.getSource()
            val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())

        global history1
        buffer = "" 

        k = 0 # para las que no salen siempre, uso esto mas adelante para saber si es la primera que se encontro en el history, o las siguientes
        # en estos dos guardo los que se han ido encontrando hasta ahora, para poder comprobar si los nuevos no estaban en la primera del history que coincidia:
        req_head_list = []
        resp_head_list = []
        
        # matchea query string parameters:
        query_params = re.compile('=.*?&|=.*? ') #matchea lo que haya entre = y & o entre = y ' ', para el ultimo parametro de la linea
        # matchea numeros en la url tipo /asdf/1234/qwe/1234, matchearia los dos 1234 y secuencias de letras, numeros y guiones o puntos. igual algun caso raro se cuela, pero por lo que he visto pilla todo:
        number_between_forwardslash = re.compile('\/[a-zA-Z]*\d+[a-zA-Z0-9-_\.]*')

        print('--------------------------')
        print(history1[1].__repr__())
        print('--------------------------')
        for item in history1:
          request = burp_extender_instance._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
          req_headers = request.split('\r\n')
          endpoint = req_headers[0]
          


          # lo siguiente aplica las regex tambien a los elementos del history con los que se compara si el click se ha originado desde la tabla de unique, porque a los elementos que clickamos de ahi ya se les aplico la regex y hace falta para hacer bien la comparacion. a los de all no hay que hacerles esto porque no se les aplica nunca las regex
          if tbl == burp_extender_instance.table_unique_endpoints:
          
            matches = query_params.findall(endpoint.split('HTTP/')[0])
            for match in matches:
              try:
                endpoint = endpoint.replace(match[1:], '<*>' + match[-1])
              except:
                print('Error matching first regex when computing unique endpoints.')

            matches1 = number_between_forwardslash.findall(endpoint.split('HTTP/')[0])
            for match1 in matches1:
              try:
                endpoint = endpoint.replace(match1[1:],  '<*>' )
              except:
                print('Error matching second regex when computing unique endpoints.')



          if endpoint == val[0]: # si coincide un endpoint del history con el que hemos seleccionado
            
            for req_head in req_headers[1:]: # este for encuentra el Host header
              if 'Host: ' in req_head:
                host = req_head.split(': ')[1]
                break
            print('--------- ' + host) 

            clicked_header = burp_extender_instance.selected_header.split('<font color="orange">')[1].split('</font>')[0]
            if host == burp_extender_instance.selected_host: # si coincide el host del history con el que clickamos en la tabla de headers
              burp_extender_instance.header_summary.setText("")
              buffer += '<html><h2><font color="orange">Request headers:</h2>' + "\n"
              buffer += '<b>' + req_headers[0] + '</b>'
              buffer += '<ul padding-left=0>'
              for req_head in req_headers[1:]: # este for encuentra el Host header
                  print(req_head) 
                  #if k == 0:
                  req_head = req_head.replace('<','< ')
                  if req_head.split(": ")[0] != "Host" and req_head.split(": ")[0] == clicked_header:
                    buffer += '<li><b><font color="orange">' + req_head + "</font></b><br></li>"

                  elif req_head.split(": ")[0] == "Host":# and req_head.split(": ")[0] == clicked_header:
                    buffer += '<li><b><font color="white">' + req_head + "</font></b><br></li>"
                  else:
                    req_head_name = req_head.split(': ')[0]
                    req_head_value = req_head.split(': ')[1]
                    
                    buffer += '<li><b>' + req_head_name + ":</b> " + req_head_value + "<br></li>"
                  #req_head_list.append(req_head)

                  '''if k > 0 and req_head not in req_head_list:
                  buffer += '<li><b><font color="pink">' + req_head_name + ":</font></b> " + req_head_value + "<br></li>"
                  req_head_list.append(req_head)'''

                
              #print(req_head_list)

              buffer += "</ul><br>" * 2 + "<hr>" + "<br>" 
              buffer += '<h2><font color="orange">Response headers:</h2>' 
              buffer += '<ul padding-left=0>'

              response = burp_extender_instance._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
              resp_headers = response.split('\r\n')
              for resp_head in resp_headers[1:]:
                resp_head = resp_head.replace('<','< ') #este es porque algunos headers tenian links en html y se renderizaba en cosas raras
                if resp_head.split(":")[0] == clicked_header:
                  buffer += '<li><b><font color="orange">' + resp_head + "</font></b><br>"
                else:
                  resp_head_name = resp_head.split(': ')[0]
                  resp_head_value = resp_head.split(': ')[1]
                  buffer += "<li><b>" + resp_head_name + ":</b> " + resp_head_value + "<br></li>"
                #resp_head_list.append(resp_head)
              buffer += "</ul>"
              print('hey')
              burp_extender_instance.header_summary.setText(buffer + "</html>")

              #k += 1
              break
              ''' lo que queria hacer aqui es que como a veces en un mismo endpoint no se mandan todas las headers, queria iterar por todas las requests de un cierto endpoint y anadir en otro color los headers que no aparecen en la primera, para indicar que no siempre salen. en la prueba inical que hice iba mal, muy lento y se petaba, pero creo que algo hice mal. creo que ayudaria en general en las tablas estas poner en otra columna el index de la request, y ese index podria usarse para localizar mas facilmente las entradas en el history, y me evitaria loops de comparacioines, y tener que aplicar en esta funcion las regex otra vez. intentar hacer esto, creo que todo ira mas fluido'''

class IssueTable(JTable):

    def __init__(self, model, table_type):
        self.setModel(model)
        self.getTableHeader().setReorderingAllowed(False)
        if table_type == "tab":
          self.addMouseListener(IssueTableMouseListener_Tab())
        elif table_type == "window":
          self.addMouseListener(IssueTableMouseListener_Window())
        elif table_type == "endpoints":
          self.addMouseListener(IssueTableMouseListener_Endpoints())


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

  def __init__(self):
    selected_host = ""
    selected_header = ""

  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.helpers
    callbacks.setExtensionName("Headers")
    callbacks.registerContextMenuFactory(self)
    callbacks.addSuiteTab(self)
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.for_table = []
    self.for_req_table = []
    self.for_resp_table = []
    self.headers_already_in_table = []
    self.last_len = 0
    self.last_row = 0
    global history1 # variable global con el history de requests
    history1 = self._callbacks.getProxyHistory()
    global burp_extender_instance
    burp_extender_instance = self
    return
    

  def getTabCaption(self):
    return "Headers"

  '''def getToolTipText(self, event):
    tip = '';
    #p = getPoint(event);
    p = event.getPoint();
    rowIndex = Point.rowAtPoint(p);
    colIndex = Point.columnAtPoint(p);
    try:
      tip = getValueAt(rowIndex, colIndex).toString();
    except:
      tip = ""
    
    return tip'''

  def UpdateHeaders(self, event):
    from urllib2 import urlopen #importo aqui esto para que tarde menos en cargar la extension
    print("Backing up old header files...")
    try:
      req_header_files = glob.glob('request_headers.txt*')
      resp_header_files = glob.glob('response_headers.txt*')
      for req_header_file in req_header_files:
        shutil.copyfile(req_header_file, req_header_file + '~')
      for resp_header_file in resp_header_files:
        shutil.copyfile(resp_header_file, resp_header_file + '~')
      f = open("request_headers.txt")
      current_req_headers = f.readlines()
      f.close()
      f = open("response_headers.txt")
      current_resp_headers = f.readlines()
      f.close()
    except:
      current_req_headers = []
      current_resp_headers = []

    # listas auxiliares, sin el newline al final, para que se comparen bien en el "not in" de luego
    curr_req_headers = []    
    curr_resp_headers = []
    for head in current_req_headers:
      curr_req_headers.append(head.rstrip('\n'))
    for head in current_resp_headers:
      curr_resp_headers.append(head.rstrip('\n'))

    del(current_req_headers)
    del(current_resp_headers)

    last_req_headers = urlopen('https://raw.githubusercontent.com/dh0ck/Headers/main/request_headers.txt').read().split('\n') #probar si en linux necesita solo \n
    last_resp_headers = urlopen('https://raw.githubusercontent.com/dh0ck/Headers/main/response_headers.txt').read().split('\n')
    f = open("request_headers.txt","a")
    for k, head in enumerate(last_req_headers):
      if head not in curr_req_headers:
        if k == 0: #por si por algun motivo estuviera vacio el archivo local
          f.write(head)
        else:
          f.write('\n' + head)
    f.close()
    f = open("response_headers.txt","a")
    for k, head in enumerate(last_resp_headers):
      if head not in curr_resp_headers:
        if k == 0: #por si por algun motivo estuviera vacio el archivo local
          f.write(head)
        else:
          f.write('\n' + head)
    f.close()

    return

  # ARREGLAR NOMBRES DE VARIABLES

  def save_json(self):
    print("save json!")
    return
  
  def update_endpoints(self, endpoint_table):
    self.model_unique_endpoints.setRowCount(0)
    self.model_all_endpoints.setRowCount(0)
    self.unique_entries = []

    for entry in endpoint_table:
      self.model_all_endpoints.addRow(entry)

    # matchea query string parameters:
    query_params = re.compile('=.*?&|=.*? ') #matchea lo que haya entre = y & o entre = y ' ', para el ultimo parametro de la linea
    # matchea numeros en la url tipo /asdf/1234/qwe/1234, matchearia los dos 1234 y secuencias de letras, numeros y guiones o puntos. igual algun caso raro se cuela, pero por lo que he visto pilla todo:
    number_between_forwardslash = re.compile('\/[a-zA-Z]*\d+[a-zA-Z0-9-_\.]*')
    for entry in endpoint_table:

      matches = query_params.findall(entry[0].split('HTTP/')[0])
      for match in matches:
        try:
          entry[0] = entry[0].replace(match[1:], '<*>' + match[-1])
        except:
          print('Error matching first regex when computing unique endpoints.')

      matches1 = number_between_forwardslash.findall(entry[0].split('HTTP/')[0])
      for match1 in matches1:
        try:
          entry[0] = entry[0].replace(match1[1:],  '<*>' )
        except:
          print('Error matching second regex when computing unique endpoints.')
        
      if entry not in self.unique_entries:
        self.unique_entries.append(entry)
        self.model_unique_endpoints.addRow(entry)

    ''' pasa que algunos endpoints no tienen todas las headers siempre, asi que a veces al marcar alguna no sale el header en naranja. poner como otra seccion al final con headers que estan en ese tipo de enpoint pero no justo en la que se ha marcado en ese momento, y explicar eso con un asterisco'''
    return

  def getUiComponent(self):
    panel = JPanel(GridBagLayout())
    
    # ================== Add button and filter ===================== #
    JPanel1 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.gridx = 0 
    y_pos = 0
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.filter_but = JButton('<html><b><font color="white">Update table</font></b></html>', actionPerformed = self.filter_entries)
    self.filter_but.setBackground(Color(210,101,47))
    JPanel1.add( self.filter_but, c )

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx = 1 
    c.gridy = y_pos
    self.filter = JTextField('Filter...')
    JPanel1.add(self.filter , c )
    
    c = GridBagConstraints()
    y_pos =0
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    panel.add( JPanel1 , c)


    # ================== Add empty label ===================== #

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel(" ")
    panel.add( text1 , c)

    # ================== Add table ===================== #

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.weighty = 2
    c.weightx = 2
    c.fill = GridBagConstraints.BOTH

    #todas las columnas del archivo: header name && description && example &&  (permanent, no se que es esto) &&
    self.colNames = ('<html><b>Header name</b></html>','<html><b>Appears in Host:</b></html>')

    self.model_tab_req = IssueTableModel([["",""]], self.colNames)
    self.table_tab_req = IssueTable(self.model_tab_req, "tab")

    self.table_tab_req.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_req.getColumnModel().getColumn(1).setPreferredWidth(100)

    self.model_tab_resp = IssueTableModel([["",""]], self.colNames)
    self.table_tab_resp = IssueTable(self.model_tab_resp, "tab")

    self.table_tab_resp.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_resp.getColumnModel().getColumn(1).setPreferredWidth(100)

    # IMPORTANT: tables must be inside a JScrollPane so that the Table headers (that is, the columns names) are visible!!!
    panelTab_req = JPanel(BorderLayout()) 
    panelTab_req.add(JScrollPane(self.table_tab_req))
    panelTab_resp = JPanel(BorderLayout()) 
    panelTab_resp.add(JScrollPane(self.table_tab_resp))

    self.tab_tabs = JTabbedPane() 
    self.tab_tabs.addTab('Requests', panelTab_req)
    self.tab_tabs.addTab('Responses', panelTab_resp)

    # ================== Add endpoints table ===================== #

    self.model_unique_endpoints = IssueTableModel([[""]], ["Unique endpoints for selected host"])
    self.table_unique_endpoints = IssueTable(self.model_unique_endpoints, "endpoints")

    self.model_all_endpoints = IssueTableModel([[""]], ["All endpoints for selected host"])
    self.table_all_endpoints = IssueTable(self.model_all_endpoints, "endpoints")

    
    self.endpoint_tabs = JTabbedPane()
    self.endpoint_tabs.addTab('Unique endpoints', JScrollPane(self.table_unique_endpoints))
    self.endpoint_tabs.addTab('All endpoints', JScrollPane(self.table_all_endpoints))
    
    self.header_summary = JEditorPane("text/html", "")

    splt_2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,self.endpoint_tabs, JScrollPane(self.header_summary))
    splt_2.setDividerLocation(300)

    splt_1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,JScrollPane(self.tab_tabs), splt_2) 
    splt_1.setDividerLocation(500)
    panel.add(splt_1, c)

    # ================== Add saving to file ===================== #
    JPanel2 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 0
    c.gridx = 1 # third column
    c.gridy = y_pos
    self.save_path = JTextField('Save headers to... (full path)')
    JPanel2.add(self.save_path , c )
    
    c = GridBagConstraints()
    c.gridx = 0 # third column
    #y_pos += 1
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.filter_but = JButton("Save headers", actionPerformed = self.save_json)
    JPanel2.add( self.filter_but, c )

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    panel.add( JPanel2 , c)

    return panel

  def clear_table(self):
    
    self.model_tab_req.setRowCount(0)
    self.model_tab_resp.setRowCount(0)
    self.for_table = []
    self.for_req_table = []
    self.for_resp_table = []
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.headers_already_in_table = []
    self.last_row = 0
    self.last_len = 0
    return

  def filter_entries(self, event):

    self.clear_table()

    global history1
    history1 = []
    history1 = self._callbacks.getProxyHistory()
    global host_endpoint

    for item in history1: # ver si puedo coger el index de la request para ponerlo luego en la endpoint table
      request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      
      # -------- find the host for every request --------#
      for req_head in req_headers[1:]:
        if 'Host: ' in req_head:
          host = req_head.split(': ')[1]
          break
      
      if (host, req_headers[0]) not in host_endpoint: #si encuentro el index del history meterlo en la siguiente linea
        host_endpoint.append((host, req_headers[0]))
      # -------------------- requests -------------------#
      
      for req_head in req_headers[1:]:
        req_head_name = req_head.split(': ')[0]
        # mira si ya existe ese header en el dict
        if req_head_name in self.req_header_dict:
          if host not in self.req_header_dict[req_head_name]:
            self.req_header_dict[req_head_name].append(host)
        # si no existe el header crea la primera entrada
        else:
          self.req_header_dict[req_head_name] = [host]
 
      # anade a otra table las lineas que iran en la extension, poniendo celdas vacias en el header name para no repetir cuando hay varios host con el mismo heade    # ----------------- responses ---------------#
      response = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
      resp_headers = response.split('\r\n')
      for resp_head in resp_headers[1:]:   
        resp_head_name = resp_head.split(': ')[0]
        if resp_head_name in self.resp_header_dict:
          if host not in self.resp_header_dict[resp_head_name]:
            self.resp_header_dict[resp_head_name].append(host)
        else:
          self.resp_header_dict[resp_head_name] = [host] 
    
    # el siguiente ya contiene toda la history, no pensar en que vienen otras request luego, ya estan todas
    req_keys = sorted(list(self.req_header_dict.keys()))
    resp_keys = sorted(list(self.resp_header_dict.keys()))

    for keys in [req_keys, resp_keys]: # seguro que esto hace lo que debe? es un array de 2 arrays, no uno solo con todas las keys, ok, creo que esto lo puse asi para no duplicar el bloque de abajo y hacer lo mismo para requests y responses con este for sin duplicar codigo, era por eso, 100% seguro
      
      if keys == req_keys:
        self.for_table = self.for_req_table
        self.header_dict = self.req_header_dict
        self.dataModel_tab = self.model_tab_req
      else:
        self.for_table = self.for_resp_table
        self.header_dict = self.resp_header_dict
        self.dataModel_tab = self.model_tab_resp

      for key in keys:
        k1 = 0
        for host in self.header_dict[key]:
          # Apply the filter:
          if self.filter.getText().lower() in host.lower() or self.filter.getText().lower() in key.lower() or self.filter.getText() == "Filter...":
            if [key, host] not in self.for_table:
              if k1 == 0 and key not in self.headers_already_in_table:
                self.for_table.append(['<html><b><font color="orange">' + key + '</font></b></html>', host])
                if key not in self.headers_already_in_table:
                  self.headers_already_in_table.append(key)
                k1 = 1
              else:
                self.for_table.append(["", host])
                if key not in self.headers_already_in_table:
                  self.headers_already_in_table.append(key)

        # Apply the filter to add dash line or not after group of entries for a single header
        if self.filter.getText().lower() in host.lower() or self.filter.getText().lower() in key.lower() or self.filter.getText() == "Filter...":
          self.for_table.append(['<html><b><font color="orange">' + '-'*300 + '</font></b></html>', '<html><b><font color="orange">' + '-'*300 + '</font></b></html>'*300])
    
      for table_entry in self.for_table[self.last_len:]:
        self.dataModel_tab.insertRow(self.last_row, table_entry)
        self.last_row += 1
      self.last_row = 0
      self.for_table = []
    self.last_len = len(history1)
    return

  def createMenuItems(self, context_menu):
    self.context = context_menu
    menu_list = ArrayList()
    menu_list.add(JMenuItem("Headers", actionPerformed=self.show_window))
    return menu_list

  def pullRequest(self, event):
    final_text = self.new_header_name.getText() + "&&" + \
    self.new_header_description.getText() + "&&" + \
    self.new_header_example.getText() + "&&" + \
    self.new_header_url.getText() +  "&&" + \
    self.new_header_risks.getText()
    self.to_submit_text.setLineWrap(True)
    self.to_submit_text.setText(final_text)
    return

  def show_window(self, event):

    # ----------------------------------------- crear diccionarios ---------------------------------------------#
    dict_req_headers = {}
    req_headers_description = open('request_headers.txt','r')
    for line in req_headers_description.readlines():
      line_split = line.split('&&')
      header_name = line_split[0]
      header_description = line_split[1]
      dict_req_headers[header_name] = header_description
    req_headers_description.close()

    dict_resp_headers = {}
    resp_headers_description = open('response_headers.txt','r')
    for line in resp_headers_description.readlines():
      line_split = line.split('&&')
      header_name = line_split[0]
      header_description = line_split[1]
      dict_resp_headers[header_name] = header_description
    resp_headers_description.close()

    # ------------- create tablas ------------------#
     
    http_traffic = self.context.getSelectedMessages()
    self.tableDataReq = []
    self.tableDataResp = []
    self.aux_names_req = []
    self.aux_names_resp = []
    
    for traffic in http_traffic:
      request = self._helpers.bytesToString(traffic.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      
      # -------- find the host for every request --------#
      for req_head in req_headers[1:]:
        if 'Host: ' in req_head:
          host = req_head.split(': ')[1]
          break
      
      # -------------------- requests -------------------#
      for req_head in req_headers[1:]:
        req_head_name = req_head.split(': ')[0]
        try:
          description = dict_req_headers[req_head_name]
        except:
          description = " --- Description unavailable --- "
        if req_head_name not in self.aux_names_req:
          self.tableDataReq.append(['<html><b><font color="orange">'+ req_head_name + '</b></font></html>', description, host])
        self.aux_names_req.append(req_head_name)
    
      # ----------------- responses ---------------#
      response = self._helpers.bytesToString(traffic.getResponse()).split('\r\n\r\n')[0]
      resp_headers = response.split('\r\n')
      for resp_head in resp_headers[1:]:
        resp_head_name = resp_head.split(': ')[0]
        try:
          description = dict_resp_headers[resp_head_name]
        except:
          description = " --- Description unavailable --- "
        if resp_head_name not in self.aux_names_resp:
          self.tableDataResp.append(['<html><b><font color="orange">'+ resp_head_name + '</b></font></html>', description, host])
        self.aux_names_resp.append(resp_head_name)

    self.tableDataReq.sort()      
    self.tableDataResp.sort()
    '''el numero en bytes es el valor binario de ascii, por ej N=78, y la newline que separa header y body es 0D 0A 0D 0A = 13 10 13 10 = \r\n\r\n'''

    # --------------- create tabs and place JTables inside -------------#
    tab1 = JPanel()
    tab2 = JPanel()

    frame = JFrame("Headers")
    frame.setSize(850, 350)
    colNames = ('Header name','Header description')
    #todas las columnas del archivo: header name && description && example &&  (permanent, no se que es esto) &&


    c=[x[0:2] for x in self.tableDataReq]      
    self.model_window_req = IssueTableModel(c, self.colNames)
    self.tableReq = IssueTable(self.model_window_req, "window")
    self.tableReq.getColumnModel().getColumn(0).setPreferredWidth(200)
    self.tableReq.getColumnModel().getColumn(1).setPreferredWidth(800)

    descriptionColumnReq = self.tableReq.getColumnModel().getColumn(1)

    """
    #Set up tool tips for the description cells.
    renderer = DefaultTableCellRenderer();
    renderer.setToolTipText(self.getToolTipText(event));
    #renderer.setToolTipText("Click for combo box");
    descriptionColumnReq.setCellRenderer(renderer);
    #}
    """


    d=[x[0:2] for x in self.tableDataResp]      
    self.model_window_resp = IssueTableModel(d, self.colNames)
    self.tableResp = IssueTable(self.model_window_resp, "window")
    self.tableResp.getColumnModel().getColumn(0).setPreferredWidth(200)
    self.tableResp.getColumnModel().getColumn(1).setPreferredWidth(800)
    
    # It's necessary to place JScrollPane insde a JPanel for it to resize and show the scrollbar:
    panelTab1 = JPanel(BorderLayout()) 
    panelTab1.add(JScrollPane(self.tableReq))
    panelTab2 = JPanel(BorderLayout()) 
    panelTab2.add(JScrollPane(self.tableResp))
    panelTab3 = JPanel(GridBagLayout())

    # ======================================================== #
    c = GridBagConstraints()
    c.gridx = 1 
    y_pos = 0
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel(" ")
    panelTab3.add(text1 ,c)
    
    c = GridBagConstraints()
    c.gridx = 1 
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel("Web technologies evolve fast and new headers constantly pop up. Please, contribute information about undocumented headers!")
    panelTab3.add( text1 , c)

    c = GridBagConstraints()
    c.gridx = 1 
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel( "To do it, fill in the fields below and press the button to create a new entry. Then create a pull request to:")
    panelTab3.add(text1 ,c)

    c = GridBagConstraints()
    c.gridx = 1 
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel("www.github.com/dh0ck/XXX with the generated text, or send it to @dh0ck via telegram.")
    panelTab3.add(text1 ,c)

    c = GridBagConstraints()
    c.gridx = 1 
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel("Alternatively, add these lines to your local file request_headers.txt and response_headers.txt")
    panelTab3.add(text1 ,c)


    c = GridBagConstraints()
    c.gridx = 1 
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel(" ")
    panelTab3.add(text1 ,c)

    # ========================== add text fields ============================== #
    fields_names = ['   Header Name:  ', '   Header Description:  ', '   Example:  ', '   URL explaining header:  ', '   Potential header risks:  ']

    self.new_header_name = self.new_header_description = self.new_header_example = self.new_header_url = self.new_header_risks = JTextField('')

    fields = [ self.new_header_name, self.new_header_description, self.new_header_example, self.new_header_url, self.new_header_risks ]

    for k, field in enumerate(fields):
      c = GridBagConstraints()
      c.gridx = 0 
      y_pos += 1
      c.gridy = y_pos 
      c.anchor = GridBagConstraints.EAST
      panelTab3.add(JLabel(fields_names[k]), c)

      c = GridBagConstraints()
      c.fill = GridBagConstraints.HORIZONTAL
      c.weightx = 1
      c.gridx = 1 
      c.gridy = y_pos 
      
      panelTab3.add(fields[k] , c)

    # ======================= add button ================================= #

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx = 1
    y_pos += 1
    c.gridy = y_pos
    but = JButton("submit", actionPerformed = self.pullRequest)
    but.setToolTipText("Click to generate a new entry. Please, submit it to @dh0ck or create a pull request to XXX. It will be reviewed before approval. Thanks for contributing!!!");
    panelTab3.add(but, c)

    # ========================== show entry to be submitted ============================== #
    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.weighty = 2
    c.gridx = 1
    y_pos += 1
    c.gridy = y_pos
    self.to_submit_text = JTextArea( '' , editable = 0, rows = 3)
    panelTab3.add(JScrollPane(self.to_submit_text), c)

    # ========================= about panel =============================== #
    panelTab4 = JPanel()
    panelTab4.setLayout(BoxLayout(panelTab4, BoxLayout.Y_AXIS ) )
    
    a1 = "    Thank you for using Headers"
    a2 = "    For tutorials, please visit:"
    a3 = "    <html><a href = XXX medium>Written tutorial</a></html>"
    a4 = "    <html><a href = XXX Video>Video tutorial</a></html>"
    a5 = " "
    a6 = "    If you have requests or suggestions please let me know via telegram (@dh0ck) or send pull requests to the GitHub repo."
    a7 = " "
    a8 = "    Acknoledegments: I adapted some code from: https://github.com/parsiya/Parsia-Code/tree/master/jython-swing-2/07-ObjectTableModel"
    a9 = " "

    for label in [a1, a2, a3, a4, a5, a6, a7, a8, a9]:
      panelTab4.add(JLabel(label))

    panelTab4.add(JButton("Update headers info", actionPerformed=self.UpdateHeaders))

    tabs = JTabbedPane() 
    tabs.addTab('Requests', panelTab1)
    tabs.addTab('Responses', panelTab2)
    tabs.addTab('Add new headers', panelTab3)
    tabs.addTab('About', panelTab4)
    frame.add(tabs)
    
    frame.setVisible(True)
    frame.toFront()
    frame.setAlwaysOnTop(True)


