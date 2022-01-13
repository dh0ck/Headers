from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
import java
import shutil, glob, re, sys, os
from time import sleep
from javax.swing import JFrame, JSplitPane, JTable, JScrollPane, JPanel, BoxLayout, WindowConstants, JLabel, JMenuItem, JTabbedPane, JButton, JTextField, JTextArea, SwingConstants, JEditorPane, JComboBox, DefaultComboBoxModel, JFileChooser, ImageIcon, JCheckBox, JRadioButton, ButtonGroup
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints, Point, Component, Color  # quitar los layout que no utilice
from java.util import List, ArrayList
from java.awt.event.MouseEvent import getPoint
from java.awt.event import MouseListener


burp_extender_instance = "" # variable global que sera el instance de bupr extender, para acceder a los valores de la instancia de IBurpExtender que burp crea, pero desde fuera, sobre todo para cambiar con clicks la tabla de endpoints
history1 = []
host_endpoint = [] #se rellena al darle a filter en la tab, pero habra que arreglar que no haya duplicados cuando cambian los valores de los query string  rameters (o puedo dejar que se repitan y ponerlos todos.) lo bueno seria poner tambien el index del history y en el text area poner los headers de la req  los de la resp, separados por una =========, etc
endpoint_table = []
selected_header_name = ""

f = open('dangerous_headers.txt')
dangerous_headers = []
for line in f.readlines():
  dangerous_headers.append(line.strip('\n'))
f.close()

f = open('security_headers.txt')
security_headers = []
for line in f.readlines():
  security_headers.append(line.strip('\n'))
f.close()

f = open('potentially_dangerous_headers.txt')
potentially_dangerous_headers = []
for line in f.readlines():
  potentially_dangerous_headers.append(line.strip('\n'))
f.close()



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
    """Extends the DefaultTableModel to make it readonly."""
    def __init__(self, data, headings):
        # call the DefaultTableModel constructor to populate the table
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, column):
        """Returns True if cells are editable."""
        canEdit = [False, False, False]
        return canEdit[column]


class IssueTableMouseListener(MouseListener):
  """Some necessary entries that must be present on all mouse listeners, so this is a parent class that is inherited by the other specific mouse listener clases below."""

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
    """Adds values to the extra information panel when an entry in the floating window is double clicked. The extra info panel is always there, double clicking elements of the floating window only makes it visible."""
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
    """Adds functionality to the Header-host table when its elements are clicked."""
    def mouseClicked(self, event):
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

        global host_endpoint
        global endpoint_table
        endpoint_table = []
        for (host, endpoint) in host_endpoint:
          
          if clicked_host == host:# and endpoint not in endpoint_table:
            endpoint_table.append([endpoint])
        
        ###global burp_extender_instance #variable global que representa la instancia de IBurpExtender que se crea al cargar la extension. se usa para acceder desde fuera (especialmente desde el mouse event handler para actualizar la endpoint_table) a propiedades y metodos de la instancia "principal" de la extension. el valor se lo doy dentro de la intancia, igualando esta variable a self
        global selected_header_name
        selected_header_name = header_value
        
        burp_extender_instance.selected_host = clicked_host
        burp_extender_instance.selected_header = header_value#header # este lo settea ok para la de endpoints
        burp_extender_instance.update_endpoints(endpoint_table)
        

class IssueTableMouseListener_Endpoints(IssueTableMouseListener):
    """Adds functionality to the click actions on rows of the "Unique endpoints" and "All endpoints" tables."""
    def extra_symbol(self, head):

      if head.split(": ")[0].lower() in security_headers:
        extra_symbol = '<b><font color="#00FF00"> [ + ] </font><b>'
      elif head.split(": ")[0].lower() in dangerous_headers:
        extra_symbol = '<b><font color="#FF0000"> [ X ] </font><b>'
      elif head.split(": ")[0].lower() in potentially_dangerous_headers:
        extra_symbol = '<b><font color="#4FC3F7"> [ ? ] </font><b>'
      else:
        extra_symbol = ""
      return extra_symbol


    def mouseClicked(self, event):
            
        if event.getClickCount() == 1:
            tbl = event.getSource()

        burp_extender_instance.clicked_endpoint(tbl, True)


class IssueTable(JTable):
    """Table class for the tables used in the extension. Needed to give the capacity to tables to perform actions when their rows are clicked."""
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
  """Main class of the Headers extension, instantiated by Burp."""
  def __init__(self):
    self.selected_host = ""
    self.selected_header = ""

  def apply_config(self):
    """Read the configuration file and load the configurations. It is run when the extension loads."""
    print("Applying config...")
    f = open("config.txt","r")
    for line in f.readlines():
      feature = line.split(' -- ')[0]
      value = line.split(' -- ')[1].strip('\n')
      if feature == "last_save_type":
        self.save_format.setSelectedItem(value)
        self.config_dict[feature] = value
        #self.save_format_config_value = value
      elif feature == "last_output_file":
        self.save_path.setText(value)        
        self.config_dict[feature] = value
        #self.save_path_config_value = value
      elif feature == "last_filter_type":
        self.preset_filters.setSelectedItem(value)
        self.config_dict[feature] = value
        #self.preset_filters_config_value = value
    f.close()
    f = open('security_headers.txt','r')
    self.total_security_headers = len(f.readlines())
    f.close()
    f = open('potentially_dangerous_headers.txt','r')
    self.total_potential_headers = len(f.readlines())
    f.close()
    f = open('dangerous_headers.txt','r')
    self.total_dangerous_headers = len(f.readlines())
    f.close()

  def update_config(self):#, feature, value):
    """Update the configuration file with values supplied in the configuration panel of the extension"""
    f = open("config.txt", "w")
    for key in list(self.config_dict.keys()):
      f.write(key + " -- " + self.config_dict[key] + "\n")  #comprobar 
    f.close()

  def compile_regex(self):
    """Compile regular expressions that will be used later by the extension to match URL parameters"""
    #matchea lo que haya entre = y & o entre = y ' ', para el ultimo parametro de la linea
    self.query_params = re.compile('=.*?&|=.*? ') 

    # matchea numeros en la url tipo /asdf/1234/qwe/1234, matchearia los dos 1234 y secuencias de letras, numeros y guiones o puntos. igual algun caso raro se cuela, pero por lo que he visto pilla todo
    self.number_between_forwardslash = re.compile('\/[a-zA-Z]*\d+[a-zA-Z0-9-_\.]*')

  def registerExtenderCallbacks(self, callbacks):
    """Import Burp Extender callbacks and execute some preliminary functions for setting up the extension when it's loaded with proper configurations"""
    self._callbacks = callbacks
    self._helpers = callbacks.helpers
    callbacks.setExtensionName("Headers")
    callbacks.registerContextMenuFactory(self)
    callbacks.addSuiteTab(self)
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.for_table = []
    self.header_host_table = []
    self.for_req_table = []
    self.for_resp_table = []
    self.headers_already_in_table = []
    self.last_len = 0
    self.last_row = 0
    ### global history1 # variable global con el history de requests
    history1 = self._callbacks.getProxyHistory()
    global burp_extender_instance
    burp_extender_instance = self
    self.config_dict = {}
    self.apply_config()
    self.compile_regex()
    
    return
    
  def getTabCaption(self):
    """Name that will be shown in the extension's tab in the Burp interface"""
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

  def ColorScore(self, value, total, type):
    """ Make a color more intense if more headers of that type are present. To be used in the unique endpoints table."""
    score = value * 255.0 / total
    if type == "security":
      color = "#00{}00".format(hex(int(score)).split('0x')[1].zfill(2))
      # if there are no headers of this type show the symbol as brown, looks better
      return color.replace("#000000", "#707070")

    elif type == "dangerous":
      color = "#{}0000".format(hex(int(score)).split('0x')[1].zfill(2))
      return color.replace("#000000", "#707070")

    elif type == "potential":
      R_factor = hex(int(int(0x4F) * score)).split('0x')[1]
      G_factor = hex(int(int(0xC3) * score)).split('0x')[1]
      B_factor = hex(int(int(0xF7) * score)).split('0x')[1]
      color = "#{0}{1}{2}".format(R_factor.zfill(2), G_factor.zfill(2), B_factor.zfill(2))
      return color.replace("#000000", "#707070")

  def UpdateHeaders(self, event):
    """Get the latest version of the request and response headers file from the Github repo. The urllib2 takes some seconds to load, so it's only loaded if this function is ever called, to improve performance."""
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

  def extra_symbol(self, head):
    """Creates the extra symbols for security [+], dangerous [X] and potentially dangrous [?] headers that are shown in the request header summary at the right side of the screen."""
    if head.split(": ")[0].lower() in security_headers:
      extra_symbol = '<b><font color="#00FF00"> [ + ] </font><b>'
    elif head.split(": ")[0].lower() in dangerous_headers:
      extra_symbol = '<b><font color="#FF0000"> [ X ] </font><b>'
    elif head.split(": ")[0].lower() in potentially_dangerous_headers:
      extra_symbol = '<b><font color="#4FC3F7"> [ ? ] </font><b>'
    else:
      extra_symbol = ""
    return extra_symbol

  def to_get_colors(self, url, host, from_click):
    """Get the count of each symbol for the unique endpoints table. That number will be transformed into color strings by the self.ColorScore function"""
    # get_colors == True -> just get how many symbols for categories there are. get_colors == False -> fill the summary
    count_colors = {"dangerous":0, "security":0, "potential":0} #count how many of each categories are for a certain request/response pair. this is used in the unique endpoints table to add brighter or fainter color symbols
    
    if from_click:
      val = url#val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())
    #else:
    #  val = tbl.getModel().getDataVector().elementAt(0)

    for item in history1:
      request = burp_extender_instance._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      endpoint = req_headers[0]

      endpoint = self.apply_regex(endpoint)  

      if endpoint == val: # si coincide un endpoint del history con el que hemos seleccionado
        
        for req_head in req_headers[1:]: # este for encuentra el Host header
          if 'Host: ' in req_head:
            host = req_head.split(': ')[1]
            break

        if host == burp_extender_instance.selected_host: # si coincide el host del history con el que clickamos en la tabla de headers. este if no es inutil?? bueno, creo que valdria si dos host distintos tienen un mismo endpoint

          for req_head in sorted(req_headers[1:]): # este for encuentra el Host header

              extra_symbol = self.extra_symbol(req_head)
              if "[ + ]" in extra_symbol:
                count_colors["security"] += 1
              elif "[ X ]" in extra_symbol:
                count_colors["dangerous"] += 1
              elif "[ ? ]" in extra_symbol:
                count_colors["potential"] += 1
   
          response = burp_extender_instance._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
          resp_headers = response.split('\r\n')
          for resp_head in sorted(resp_headers[1:]):

            extra_symbol = self.extra_symbol(resp_head)
            if "[ + ]" in extra_symbol:
              count_colors["security"] += 1
            elif "[ X ]" in extra_symbol:
              count_colors["dangerous"] += 1
            elif "[ ? ]" in extra_symbol:
              count_colors["potential"] += 1

          break

    return count_colors

  def replace_symbol(self, replace_here):
    """Replace the wildcard symbol with an html formatted one for colors. Implemented as a separate function becaused it is called several times, to avoid code duplication."""
    # it's important that the new symbol has spaces, some endpoints are so goddamn long that without spaces they don't fit and are completely hidden
    replace_here = replace_here.replace('[*]','<font color="orange">[ * ]</font>') 
    return replace_here

  def clicked_endpoint(self, tbl, from_click):#, from_unique):
    """Fill the summary (panel at the right side of the extension tab) when an endpoint (either from the "Unique endpoints" table or from the "All endpoints table") is clicked. The summary contains the request and response headers, marked with symbols if they are security headers, dangerous headers, or potentially dangerous headers."""
    
    if from_click:
      val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())
    else:
      val = tbl.getModel().getDataVector().elementAt(0)

        
    for item in history1:
      request = burp_extender_instance._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      endpoint = req_headers[0]
      buffer = ""

      # the next two ifs are for matching to elements in the history if we choose from the unique endpoints or from all endpoints, must be processed differently for the comparison
      if tbl.getModel() == self.model_unique_endpoints:
        match = self.replace_symbol(self.apply_regex(endpoint)) == val[0].split(' - ')[1].strip('<html>').strip('</html>') # si coincide un endpoint del history con el que hemos seleccionado
        
      if tbl.getModel() == self.model_all_endpoints:
        match = endpoint == val[0].strip('<html>').strip('</html>')


      if match:
        for req_head in req_headers[1:]: # este for encuentra el Host header
          if 'Host: ' in req_head:
            host = req_head.split(': ')[1]
            break

        clicked_header = self.selected_header

        if host == burp_extender_instance.selected_host: # si coincide el host del history con el que clickamos en la tabla de headers. 
          burp_extender_instance.header_summary.setText("")
          buffer += '<html><h2><font color="orange">Request headers:</h2>' + "\n"
          buffer += '<b>' + req_headers[0] + '</b>'
          buffer += '<ul padding-left=0>'
          print(sorted(req_headers[1:]))
          for req_head in sorted(req_headers[1:]): # este for encuentra el Host header

              extra_symbol = self.extra_symbol(req_head)
 
              req_head = req_head.replace('<','< ')
              req_head_name = req_head.split(': ')[0]
              req_head_value = req_head.split(': ')[1]

              if req_head.split(": ")[0] != "Host" and req_head.split(": ")[0] == clicked_header:
                buffer += '<li><b>' + '<font color="orange">' + req_head_name + "</font>" + extra_symbol + '<font color="orange">: </font>' + req_head_value + "</b><br></li>"

              elif req_head.split(": ")[0] == "Host":
                buffer += '<li><b>' + extra_symbol + '<font color="white">' + req_head + "</font></b><br></li>"
              else:
                buffer += '<li><b>' + req_head_name + extra_symbol + ":</b> " + req_head_value + "<br></li>"

          buffer += "</ul><br>" * 2 + "<hr>" + "<br>" 
          buffer += '<h2><font color="orange">Response headers:</h2>' 
          buffer += '<ul padding-left=0; width="10px">'

          response = burp_extender_instance._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
          resp_headers = response.split('\r\n')
          for resp_head in sorted(resp_headers[1:]):

            extra_symbol = self.extra_symbol(resp_head)

            resp_head = resp_head.replace('<','< ') #este es porque algunos headers tenian links en html y se renderizaba en cosas raras
            resp_head_name = resp_head.split(': ')[0]
            resp_head_value = resp_head.split(': ')[1]

          
            if resp_head.split(":")[0] == clicked_header:
              buffer += '<li><b>' + '<font color="orange">' + resp_head_name + "</font>" + extra_symbol + '<font color="orange">: </font>' + resp_head_value + "</b><br></li>"
            else:
              buffer += '<li><b>' + resp_head_name + extra_symbol + ":</b> " + resp_head_value + "<br></li>"

          buffer += '</ul>'
          buffer += '<br><hr><font color=\"white\"><b>*Note:</b> Some enpoints don\'t return some headers sometimes. If you can\'t find the header you selected on the table to the left, please select other endpoint, perhaps from the \"All Endpoints\" tab.</font><br><hr>' 
          buffer += '<br>Color legend for headers names (check yourself if the value is correct):'
          buffer += '<ul>'
          buffer += '<li><b><font color="#00FF00"> [ + ] </font><b>: Security header</li>'
          buffer += '<li><b><font color="#FF0000"> [ X ] </font><b>: Dangerous or too verbose header</li>'
          buffer += '<li><b><font color="#4FC3F7"> [ ? ] </font><b>: Potentially dangerous header</li>'
          burp_extender_instance.header_summary.setText(buffer + "</html>")
          
          # para que el summary no haga scroll down hasta el final al actualizarlo
          self.header_summary.setSelectionStart(0)
          self.header_summary.setSelectionEnd(0)
          break

  def choose_output_file(self, event):
    """File dialogue to choose the path where the output file will be written"""
    fc = JFileChooser()
    result = fc.showOpenDialog( None )
    if result == JFileChooser.APPROVE_OPTION :
      self.save_path.setText(str(fc.getSelectedFile()))
      #print(str(fc.getSelectedFile()))

    return

  def save_json(self,event):
    """Save data to an output file, either in JSON format or in plain text. Multiple output formats are available."""
    out_type = self.save_ComboBox.getSelectedItem()
    out_file_name = self.save_path.getText()
    

    hosts = []
    headers = []
    unique_headers = []
    for line in self.header_host_table:
        hosts.append(line[2])
        headers.append(line[0]) 
        unique_headers.append(line[1]) 

    unique_hosts = sorted(list(set(hosts)))
    try:
      unique_hosts.remove('\n')
    except:
      pass

    self.host_header_table = []

    for unique_host in unique_hosts:
      k = 0
      for line in self.header_host_table:
        if line[2] == unique_host:
          if k == 0:
            self.host_header_table.append([unique_host , unique_host , line[0]])
          else:
            self.host_header_table.append([unique_host , "" , line[0]])
          k += 1

    Error_frame3 = JFrame()#FlowLayout())
    Error_frame3.setLayout(FlowLayout())
    Error_frame3.setSize(260, 90)
    Error_frame3.setLocationRelativeTo(None)
    a=os.getcwd() + '\\error1.png'
    image_path=a.encode('string-escape')  #ver si esto falla al coger en linux el icono
    Error_frame3.add(JLabel(ImageIcon(image_path)))
    Error_frame3.add(JLabel("  Wrong output file."))
    Error_frame3.toFront()
    Error_frame3.setAlwaysOnTop(True)
    
    if "Save headers to..." in out_file_name or out_file_name == "":
      Error_frame1 = JFrame()
      Error_frame1.setLayout(FlowLayout())
      Error_frame1.setSize(260, 90)
      Error_frame1.setLocationRelativeTo(None)
      a=os.getcwd() + '\\error1.png'
      image_path=a.encode('string-escape')  #ver si esto falla al coger en linux el icono
      Error_frame1.add(JLabel(ImageIcon(image_path)))
      Error_frame1.add(JLabel("  Please, enter output file path."))
      Error_frame1.setVisible(True)
      Error_frame1.toFront()
      Error_frame1.setAlwaysOnTop(True)


      return

    if out_type == "Choose output format":
      Error_frame2 = JFrame()#FlowLayout())
      Error_frame2.setLayout(FlowLayout())
      Error_frame2.setSize(260, 90)
      Error_frame2.setLocationRelativeTo(None)
      a=os.getcwd() + '\\error1.png'
      image_path=a.encode('string-escape')  #ver si esto falla al coger en linux el icono
      Error_frame2.add(JLabel(ImageIcon(image_path)))
      Error_frame2.add(JLabel("  Please, select output format."))
      Error_frame2.setVisible(True)
      Error_frame2.toFront()
      Error_frame2.setAlwaysOnTop(True)
    
      return

    elif out_type == "TXT: Host -> Header":
      try:
        f = open(out_file_name, 'w')
        f.write("Columns:\n")
        f.write("Host; Unique Host; Header\n\n")

        for line in self.host_header_table:
          f.write("; ".join(line) + "\n")
        f.close()
      except:
        Error_frame3.setVisible(True)

    elif out_type == "TXT: Header -> Host":
      try:
        f = open(out_file_name, 'w')
        f.write("Columns:\n")
        f.write("Header; Unique Header; Host Name\n\n")
        for line in self.header_host_table:
          if "----------------" in line[1]:
            f.write("".join(line) + "\n")
          else:
            f.write("; ".join(line) + "\n")
        f.close()
      except:
        Error_frame3.setVisible(True)

    elif out_type == "TXT: Host -> Endpoint -> Headers":
      
      f = open(out_file_name, 'w')
      for unique_host in unique_hosts:
        endpoint_already_present = []
        for item in history1:
          request = burp_extender_instance._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
          req_headers = request.split('\r\n')
          response = burp_extender_instance._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
          resp_headers = response.split('\r\n')
          for req_head in req_headers:
            if 'Host: ' in req_head:
              if unique_host == req_head.split(': ')[1]:
                endpoint = self.apply_regex(req_headers[0])
                if endpoint not in endpoint_already_present:
                  f.write(unique_host + '; ' + endpoint + '; ' + "Request headers: " + str(req_headers[1:]) + " Response headers: " + str(resp_headers[1:]) + '\n')
                  endpoint_already_present.append(endpoint)
              else:
                break
      f.close() 

    elif out_type == "JSON: Host -> Header":
      try:
        first = True
        k = 0
        f = open(out_file_name, 'w')
        
        f.write("{\n")
        all_hosts = [self.host_header_table[i][1] for i in range(len(self.host_header_table))]
        #all_hosts.remove('') #for some reason this is not removing the empty element '', so I leave it commented and subtract 2 instead of 1 from the lenght in the if k < len... a few lines below
        print(set(all_hosts))
        for line in self.host_header_table:
          
          [host1, unique_host1, header] = line
          if unique_host1 != "":
            if not first:
              arr = str(arr_headers)
              arr = arr.replace("u'", "'")
              arr = arr.replace("'", '"')
              
              if k < len(set(all_hosts)) - 2: 
                f.write('    "' + host1 + '":' + arr + ',\n' )
              else:
                f.write('    "' + host1 + '":' + arr + '\n' )
              
            arr_headers = []
            arr_headers.append(header)
            k += 1
            
          else:
            arr_headers.append(header)
            first = False

        f.write("}")
        f.close()

      except:
        Error_frame3.setVisible(True)

    elif out_type == "JSON: Header -> Host ":
      pass
      '''f = open(out_file_name, 'w')
      for line in self.header_host_table:
        f.write(line)
      f.close()'''

    elif out_type == "JSON: Header -> Host -> Endpoint":
      pass
      '''f = open(out_file_name, 'w')
      for line in self.header_host_table:
        f.write(line)
      f.close()'''
    
    else:
      return


    
    print("save json!")

    update_now = False
    if self.save_format.getSelectedItem() != self.config_dict["last_save_type"]:
      self.config_dict["last_save_type"] = self.save_format.getSelectedItem()
      update_now = True
    if self.save_path.getText() != self.config_dict["last_output_file"]:
      self.config_dict["last_output_file"] = self.save_path.getText()
      update_now = True
    if update_now:
      self.update_config()#"last_filter_type", self.preset_filters.getSelectedItem())

    return
  
  def apply_regex(self, string_for_regex):
    """Applies regular expressions to URLs in order to replace query string parameters values with wildcards. This is used later to remove redundant endpoints in the "Unique endpoints" table, and keep only the unique ones."""
    #matchea lo que haya entre = y & o entre = y ' ', para el ultimo parametro de la linea
    #query_params = re.compile('=.*?&|=.*? ') 

    # matchea numeros en la url tipo /asdf/1234/qwe/1234, matchearia los dos 1234 y secuencias de letras, numeros y guiones o puntos. igual algun caso raro se cuela, pero por lo que he visto pilla todo
    #number_between_forwardslash = re.compile('\/[a-zA-Z]*\d+[a-zA-Z0-9-_\.]*')

    matches = self.query_params.findall(string_for_regex.split('HTTP/')[0])
    for match in matches:
      try:
        string_for_regex = string_for_regex.replace(match[1:], '[*]' + match[-1])
      except:
        print('Error matching first regex when computing unique endpoints.')
    matches1 = self.number_between_forwardslash.findall(string_for_regex.split('HTTP/')[0])
    for match1 in matches1:
      try:
        string_for_regex = string_for_regex.replace(match1[1:],  '[*]' )
      except:
        print('Error matching second regex when computing unique endpoints.')
    return string_for_regex

  def update_endpoints(self, endpoint_table):
    """Update the "Unique endpoints" table and the "All endpoints" table when a row in the Header-Host table (at the left side of the extension tab) is clicked. The endpoint tables show all the endpoints that exist in the Burp history for which the Host request header is the one clicked on the Header-Host table."""
    self.model_unique_endpoints.setRowCount(0)
    self.model_all_endpoints.setRowCount(0)
    self.unique_entries = []

    for entry in endpoint_table:
      self.model_all_endpoints.addRow(entry)

    for entry in endpoint_table:
      entry[0] = self.apply_regex(entry[0])
        
      if entry not in self.unique_entries:
        self.unique_entries.append(entry)
        #coger el host del elemento clickado en la tabla de la izda
        host = self.table_tab_req.getModel().getDataVector().elementAt(self.table_tab_req.getSelectedRow())[1]
        colors = self.to_get_colors(entry[0], host, True)  #colors es un dict

        symbols_color = {}
        for color in colors.keys():
          #print('uu'+color)
          
          if color == "security":
            total = self.total_security_headers
          elif color == "potential":
            total = self.total_potential_headers
          elif color == "dangerous":
            total = self.total_dangerous_headers
          symbols_color[color] = self.ColorScore(colors[color], total, color)

        symbols_string = '<b><font color="{0}">[{1}+]</font><font color="{2}">[{3}?]</font><font color="{4}">[{5}X]</font></b> - '.format(symbols_color["security"], colors["security"], symbols_color["potential"], colors["potential"], symbols_color["dangerous"], colors["dangerous"])
        #symbols_string = '<b><font color="{0}">[+]</font><font color="{1}">[?]</font><font color="{2}">[X]</font></b> - '.format(symbols_color["security"], symbols_color["potential"], symbols_color["dangerous"])
        #print(symbols_string +entry[0]+'</html>')

        ###################################
        #self.model_unique_endpoints.addRow( [symbols_string +  entry[0] + '</html>'])
        print('<html>' + entry[0].replace('[*]', '<font color=orange>[*]</font>') + '</html>')
        self.model_unique_endpoints.addRow( [ '<html>' + symbols_string + self.replace_symbol(entry[0]) + '</html>' ])
        #self.model_unique_endpoints.addRow( [ '<html>' + entry[0].replace('[*]', '<font color=orange>[*]</font>') + '</html>'])
        #self.model_unique_endpoints.addRow( [ entry[0] ])
        

    self.table_unique_endpoints.setRowSelectionInterval(0,0) 
    self.clicked_endpoint(self.table_unique_endpoints, False)
    return

  def addRB( self, pane, bg, text ):
    """Add radio buttons"""
    bg.add(pane.add(JRadioButton(text,itemStateChanged = self.toggle)))
    return

  def toggle( self, event ) :
    """Sets the file to which the user will add new headers of a certain category. If these headers are found in requests or responses in the history, the appropriate symbols will be applied to them in the "Unique endpoints" table and in the Summary."""
    text = event.getItem().getText()
    if text == "Security headers":
      self.file_to_add_headers = "security_headers.txt"
    elif text == "Potentially dangerous headers":
      self.file_to_add_headers = "potentially_dangerous_headers.txt"
    elif text == "Dangerous or verbose headers":
      self.file_to_add_headers = "dangerous_headers.txt"
    return

  def add_header_to_file(self, event):
    """Adds a new header supplied by the user to the corresponding category (security, dangerous, potentially dangerous)."""
    filename = self.file_to_add_headers
    text = self.header_to_add.getText()
    f = open(filename,"a")
    f.write("\n" + text)
    f.close()
    self.added_header_info.setText('Header "{0}" added to {1}'.format(text, filename))

  def add_headers_to_categories(self, event):
    """Configuration panel which the user can use to add new headers to category files."""
    self.file_to_add_headers = ""
    add_headers = JFrame("Add new header to categories")
    add_headers_panel = JPanel()
    add_headers_panel.setLayout(BoxLayout(add_headers_panel, BoxLayout.Y_AXIS ) )

    bg = ButtonGroup()
    add_headers_panel.add( JLabel( 'Select category to add header:' ) )
    self.addRB( add_headers_panel, bg, 'Security headers' )
    self.addRB( add_headers_panel, bg, 'Potentially dangerous headers' )
    self.addRB( add_headers_panel, bg, 'Dangerous or verbose headers' )
    add_headers_panel.add( JLabel( ' ' ) )
    add_headers_panel.add( JLabel( 'New header to be added:' ) )
    
    self.header_to_add = add_headers_panel.add(JTextField("New header"))
    self.add_header_button = add_headers_panel.add(JButton('Add new header', actionPerformed = self.add_header_to_file))
    self.add_header_button.setForeground(Color.WHITE)
    self.add_header_button.setBackground(Color(10,101,247))

    self.added_header_info = JTextArea("", rows=2, editable=False)
    self.added_header_info.setLineWrap(True)
    add_headers_panel.add(JScrollPane(self.added_header_info))

    
    

    add_headers.setSize(400, 220)
    add_headers.add(add_headers_panel)
    add_headers.setLocationRelativeTo(None)
    add_headers.setVisible( True )
    add_headers.toFront()
    add_headers.setAlwaysOnTop(True)

    
    return
    
  def getUiComponent(self):
    """Builds the interface of the extension tab."""
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


    self.preset_filters = DefaultComboBoxModel()
    self.preset_filters.addElement("Request + Response")
    self.preset_filters.addElement("Request + Response + <meta>")
    self.preset_filters.addElement("In scope only (se puede acceder al scope???)")
    self.preset_filters.addElement("Security headers only")
    self.preset_filters.addElement("Potentially dangerous headers only")
    self.preset_filters.addElement("Dangerous or unnecessary headers only")
    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx = 1 
    c.gridy = y_pos
    self.filterComboBox = JComboBox(self.preset_filters)
    JPanel1.add(self.filterComboBox , c )

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 8
    c.gridx = 2 
    c.gridy = y_pos
    self.filter = JTextField('Or enter keywords (separated by a comma)')
    self.filter.addActionListener(self.filter_entries)
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
    self.colNames_meta = ('<html><b><meta> header name</b></html>','<html><b>Appears in endpoint:</b></html>')

    self.model_tab_req = IssueTableModel([["",""]], self.colNames)
    self.table_tab_req = IssueTable(self.model_tab_req, "tab")

    self.table_tab_req.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_req.getColumnModel().getColumn(1).setPreferredWidth(100)

    self.model_tab_resp = IssueTableModel([["",""]], self.colNames)
    self.table_tab_resp = IssueTable(self.model_tab_resp, "tab")

    self.table_tab_resp.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_resp.getColumnModel().getColumn(1).setPreferredWidth(100)

    self.model_tab_meta = IssueTableModel([["",""]], self.colNames_meta)
    self.table_tab_meta = IssueTable(self.model_tab_meta, "tab")

    self.table_tab_meta.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_meta.getColumnModel().getColumn(1).setPreferredWidth(100)


    # IMPORTANT: tables must be inside a JScrollPane so that the Table headers (that is, the columns names) are visible!!!
    panelTab_req = JPanel(BorderLayout()) 
    panelTab_req.add(JScrollPane(self.table_tab_req))
    panelTab_resp = JPanel(BorderLayout()) 
    panelTab_resp.add(JScrollPane(self.table_tab_resp))
    panelTab_meta = JPanel(BorderLayout()) 
    panelTab_meta.add(JScrollPane(self.table_tab_meta))


    self.tab_tabs = JTabbedPane() 
    self.tab_tabs.addTab('Requests', panelTab_req)
    self.tab_tabs.addTab('Responses', panelTab_resp)
    self.tab_tabs.addTab('<meta>', panelTab_meta)


    # ================== Add endpoints table ===================== #

    ##self.model_unique_endpoints = IssueTableModel([[""]], ["HTTP method","HTTP version", "URL"])
    self.model_unique_endpoints = IssueTableModel([[""]], ["Unique endpoints for selected host"])
    self.table_unique_endpoints = IssueTable(self.model_unique_endpoints, "endpoints")

    self.model_all_endpoints = IssueTableModel([[""]], ["All endpoints for selected host"])
    self.table_all_endpoints = IssueTable(self.model_all_endpoints, "endpoints")

    
    self.endpoint_tabs = JTabbedPane()
    self.endpoint_tabs.addTab('Unique endpoints', JScrollPane(self.table_unique_endpoints))
    self.endpoint_tabs.addTab('All endpoints', JScrollPane(self.table_all_endpoints))
    
    self.header_summary = JEditorPane("text/html", "")
    self.scroll_summary = JScrollPane(self.header_summary)

    self.summary_summary = JEditorPane("text/html", "")
    self.scroll_summary_summary = JScrollPane(self.summary_summary)

    self.checkbox_panel = JPanel()
    self.checkbox_panel.setLayout(FlowLayout())
    self.checkbox_panel.add(JCheckBox("Security headers"))
    self.checkbox_panel.add(JCheckBox("Potentially dangerous headers"))
    self.checkbox_panel.add(JCheckBox("Dangerous headers"))
    self.checkbox_panel.add(JButton("Add new headers", actionPerformed = self.add_headers_to_categories))

    self.summary_panel = JPanel()
    self.summary_panel.setLayout(BoxLayout(self.summary_panel,BoxLayout.Y_AXIS))
    ###self.summary_panel.add(self.checkbox_panel) """  !!!!!!!!!!11 este impedia resizear !!!!!!!!!!! """
    self.summary_panel.add(self.summary_summary)

    self.splt_3 = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.scroll_summary, self.summary_panel)
    self.splt_3.setDividerLocation(550)

    self.splt_2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,self.endpoint_tabs, self.splt_3)#self.scroll_summary)
    #self.splt_2.setDividerLocation(300)

    self.splt_1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,JScrollPane(self.tab_tabs), self.splt_2) 
    #self.splt_1.setDividerLocation(500)
    panel.add(self.splt_1, c)

    # ================== Add saving to file ===================== #
    JPanel2 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.gridx = 0 # third column
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.save_but = JButton('<html><b><font color="white">Save headers</font></b></html>', actionPerformed = self.save_json)
    self.save_but.setBackground(Color(10,101,247))
    JPanel2.add( self.save_but, c )

    c.gridx += 1
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.save_but = JButton('<html><b><font color="white">Preview</font></b></html>', actionPerformed = self.save_json)
    self.save_but.setBackground(Color(10,101,247))
    JPanel2.add( self.save_but, c )

    #c = GridBagConstraints()
    c.gridx += 1
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.save_format = DefaultComboBoxModel()
    self.save_format.addElement("Choose output format")
    self.save_format.addElement("TXT: Host -> Header")
    self.save_format.addElement("TXT: Header -> Host")
    self.save_format.addElement("TXT: Host -> Endpoint -> Headers")
    self.save_format.addElement("TXT: Only security headers")
    self.save_format.addElement("TXT: Only potentially dangerous headers")
    self.save_format.addElement("TXT: Only dangerous or verbose headers")
    self.save_format.addElement("JSON: Host -> Header")
    self.save_format.addElement("JSON: Header -> Host ")
    self.save_format.addElement("JSON: Header -> Host -> Endpoint")
    self.save_format.addElement("JSON: Only security headers")
    self.save_format.addElement("JSON: Only potentially dangerous headers")
    self.save_format.addElement("JSON: Only dangerous or verbose headers")
    self.save_ComboBox = JComboBox(self.save_format)
    JPanel2.add( self.save_ComboBox, c )

    #c = GridBagConstraints()
    c.gridx += 1 # third column
    c.gridy = y_pos
    self.choose_file_but = JButton('<html><b><font color="white">Choose output file</font></b></html>', actionPerformed = self.choose_output_file)
    JPanel2.add( self.choose_file_but, c )

    #c = GridBagConstraints() #ojo, parece que esto solo hay que ponerlo una vez al principio, comprobar y quitar de donde sobre, hay otras mas arriba descomentadas!!! ejemplo: https://leo.ugr.es/elvira/devel/Tutorial/Java/uiswing/layout/gridbagExample.html
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx += 1 # third column
    c.gridy = y_pos
    self.save_path = JTextField('Save headers to... (write full path or click "Choose output file". The file will be created)')
    JPanel2.add(self.save_path , c )
    

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    panel.add( JPanel2 , c)

    return panel

  def clear_table(self):
    """Clears the Header-Host table. It is also called every time a filter is applied."""
    self.model_tab_req.setRowCount(0)
    self.model_tab_resp.setRowCount(0)
    self.for_table = []
    self.header_host_table = []
    self.for_req_table = []
    self.for_resp_table = []
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.headers_already_in_table = []
    self.last_row = 0
    self.last_len = 0
    return

  def filter_entries(self, event):
    """Applies the supplied filter(s) to the Header-Host table. If no filters are applied, all available entries are shown."""
    self.clear_table()
    
    global history1
    history1 = []
    history1 = self._callbacks.getProxyHistory()
    for k_progress, item in enumerate(history1): # ver si puedo coger el index de la request para ponerlo luego en la endpoint table
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
 
      # anade a otra table las lineas que iran en la extension, poniendo celdas vacias en el header name para no repetir cuando hay varios host con el mismo header
      # ----------------- responses ---------------#
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

    k2 = 0 # se usa para meter en el output file los titulos de request y response
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
        added_something = False #used at the end of the loop to determine if a dash line should be added
        k2 += 1
        k1 = 0
        if k2 == 1:
          self.header_host_table.append(["", "//---------------- REQUEST HEADERS -----------------//", "\n"])
          
        if k2 == len(req_keys) + 1:
          self.header_host_table.append(["\n", "//---------------- RESPONSE HEADERS -----------------//", "\n"])

        for host in self.header_dict[key]:
          # Apply the filter:

          keywords = self.filter.getText().lower().split(',')

          for keyword in keywords:
            if keyword.strip() in host.lower() or keyword in key.lower() or self.filter.getText() == "Or enter keywords (separated by a comma)":
              if [key, host] not in self.for_table:
                if k1 == 0 and key not in self.headers_already_in_table:
                  self.for_table.append(['<html><b><font color="orange">' + key + '</font></b></html>', host])
                  added_something = True
                  self.header_host_table.append([key, key, host])
                  if key not in self.headers_already_in_table:
                    self.headers_already_in_table.append(key)
                  k1 = 1
                else:
                  self.for_table.append(["", host])
                  self.header_host_table.append([key, "", host])
                  if key not in self.headers_already_in_table:
                    self.headers_already_in_table.append(key)



        # if some line was added to the header - host table, add a dashed line at the end. If not, don't add it
        if added_something:
          self.for_table.append(['<html><b><font color="orange">' + '-' * 300 + '</font></b></html>', '<html><b><font color="orange">' + '-' * 300 + '</font></b></html>' * 300])

      # enter only new rows in for_table, dont reload all the table every time (probably there should be something to check if some entries were deleted form history. create a variable that counts up to 5 every time the button is clicked and then compares the history with the stored history, to check for missing entries that should be removed from the history1 variable or from self.for_table?)
      for table_entry in self.for_table[self.last_len:]:
        self.dataModel_tab.insertRow(self.last_row, table_entry)
        self.last_row += 1
      self.last_row = 0
      self.for_table = []
    self.last_len = len(history1)

    # update config file with last filter type used
    if self.preset_filters.getSelectedItem() != self.config_dict["last_filter_type"]:
      self.config_dict["last_filter_type"] = self.preset_filters.getSelectedItem()
      self.update_config()
    return

  def createMenuItems(self, context_menu):
    """Adds an entry to Burp's context menu, when it is clicked the floating window with headers information of the selected item(s) in Burp history is shown"""
    self.context = context_menu
    menu_list = ArrayList()
    menu_list.add(JMenuItem("Headers", actionPerformed=self.show_window))
    return menu_list

  def pullRequest(self, event):
    """Creates the string to be submitted for contributing with new headers information"""
    final_text = self.new_header_name.getText() + "&&" + \
    self.new_header_description.getText() + "&&" + \
    self.new_header_example.getText() + "&&" + \
    self.new_header_url.getText() +  "&&" + \
    self.new_header_risks.getText()
    self.to_submit_text.setLineWrap(True)
    self.to_submit_text.setText(final_text)
    return

  def show_window(self, event):
    """Creates the floating window with the information about the headers present in the selected items of Burp's history"""
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

    self.new_header_name = JTextField('')
    self.new_header_description = JTextField('')
    self.new_header_example = JTextField('')
    self.new_header_url = JTextField('')
    self.new_header_risks = JTextField('')

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
    a8 = " "

    for label in [a1, a2, a3, a4, a5, a6, a7, a8]:
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




