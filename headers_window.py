from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
import shutil, glob
from javax.swing import JFrame, JSplitPane, JTable, JScrollPane, JPanel, BoxLayout, WindowConstants, JLabel, JMenuItem, JTabbedPane, JButton, JTextField, JTextArea, SwingConstants
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints, Point, Component  # quitar los layout que no utilice
from java.util import List, ArrayList
from java.awt.event.MouseEvent import getPoint
from java.awt.event import MouseListener

# el extra info window lo defino aqui fuera para que exista desde un principio y al hacer doble click en las tablas solamente se haga visible, pero no se cree un nuevo frame por cada doble click
extra_info = JFrame("Extended header info")
#extra_info.setLayout(BoxLayout())
extra_info.setSize(400, 750)
extra_info.toFront()
extra_info.setAlwaysOnTop(True)
extra_info_label1 = JTextArea("test1",rows=5, editable=True)
extra_info_label1.setLineWrap(True)
extra_info.add(JScrollPane(extra_info_label1))



#/////////////////////////////////////////////////////

class IssueTableModel(DefaultTableModel):
    """Extends the DefaultTableModel to make it readonly (among other
    things)."""

    def __init__(self, data, headings):
        # call the DefaultTableModel constructor to populate the table
        DefaultTableModel.__init__(self, data, headings)
        print('issute table model instantiated')

    def isCellEditable(self, row, column):
        """Returns True if cells are editable."""
        # make all rows and columns uneditable.
        # do we need to check the column value here?
        canEdit = [False, False]#, False, False, False]
        return canEdit[column]
        # return False

    '''def getColumnClass(self, column):
        """Returns the column data class. Optional in this case."""
        from java.lang import Integer, String, Object
        # return Object if you don't know the type.
        # only works if we are not changing the number of columns
        columnClasses = [String, String]#[Integer, String, String, String, String]
        return columnClasses[column]'''


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
        print("get clicked row was clicked")
        print(tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow()))
        return tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())

    def mousePressed(self, event):
      pass

    def mouseReleased(self, event):
      pass

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            # print "single-click. clicked index:", self.getClickedRow(event)

            # modify the items in the panel
            print("single-click: ", self.getClickedRow(event))
            yy = self.getClickedRow(event)
            print(type(yy))
            extra_info_label1.setText(str(yy))
        if event.getClickCount() == 2:
            # open the dialog to edit
            print("double-click: ", self.getClickedRow(event))
            #self.show_info_window()
            extra_info.setVisible(True)


    # the following two are necessary, although they are empty, otherwise the extension crashes when the mouse cursor enters or exits the table
    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class IssueTable(JTable):
    """Issue table."""

    #def __init__(self, data, headers):
    def __init__(self, model):
        print('issue table instantiated')
        # set the table model
        ##model = IssueTableModel(data, headers)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        # disable the reordering of columns
        self.getTableHeader().setReorderingAllowed(False)
        # assign panel to a field
        self.addMouseListener(IssueTableMouseListener())
        print("clicked imported")

#/////////////////////////////////////////////////////

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.helpers
    callbacks.setExtensionName("Headers info")
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
  

  def getUiComponent(self):
    panel = JPanel(GridBagLayout())
    
    # ================== Add button and filter ===================== #
    JPanel1 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.gridx = 0 # third column
    y_pos =0#+= 1
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.filter_but = JButton("Update table", actionPerformed = self.filter_entries)
    JPanel1.add( self.filter_but, c )

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx = 1 # third column
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
    self.colNames = ('<html><b>Header name</b></html>','<html><b>Appears in...</b></html>')

    self.model_tab_req = IssueTableModel([["",""]], self.colNames)
    self.table_tab_req = IssueTable(self.model_tab_req)

    self.table_tab_req.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_req.getColumnModel().getColumn(1).setPreferredWidth(300)

    self.model_tab_resp = IssueTableModel([["",""]], self.colNames)
    self.table_tab_resp = IssueTable(self.model_tab_resp)

    self.table_tab_resp.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_resp.getColumnModel().getColumn(1).setPreferredWidth(300)

    # IMPORTANT: tables must be inside a JScrollPane so that the Table headers (that is, the columns names) are visible!!!
    panelTab_req = JPanel(BorderLayout()) 
    panelTab_req.add(JScrollPane(self.table_tab_req))
    panelTab_resp = JPanel(BorderLayout()) 
    panelTab_resp.add(JScrollPane(self.table_tab_resp))

    self.tab_tabs = JTabbedPane() 
    self.tab_tabs.addTab('Requests', panelTab_req)
    self.tab_tabs.addTab('Responses', panelTab_resp)

    #panel.add(JScrollPane(self.tab_tabs),c)
    splt = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,JScrollPane(self.tab_tabs), JTextArea()) 
    splt.setDividerLocation(700)
    panel.add(splt, c)

    # ================== Add text area ===================== #
    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.anchor = GridBagConstraints.EAST
    c.weighty = 1
    c.fill = GridBagConstraints.HORIZONTAL
    text_area1 = JTextArea("",rows=5, editable=True)
    panel.add( text_area1 , c)

    # ================== Add saving to file ===================== #
    JPanel2 = JPanel(GridBagLayout())

    
    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 0
    c.gridx = 1 # third column
    c.gridy = y_pos
    self.filter = JTextField('Save headers to... (full path)')
    JPanel2.add(self.filter , c )
    
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

    history = self._callbacks.getProxyHistory()
    for k, item in enumerate(history):
      request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      
      # -------- find the host for every request --------#
      for req_head in req_headers[1:]:
        if 'Host: ' in req_head:
          host = req_head.split(': ')[1]
          break
      
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
        self._for_table = self.for_resp_table
        self.header_dict = self.resp_header_dict
        self.dataModel_tab = self.model_tab_resp

      for key in keys:
        for k1, host in enumerate(self.header_dict[key]):
          if [key, host] not in self.for_table:
            if k1 == 0 and key not in self.headers_already_in_table:
              self.for_table.append(['<html><b><font color="orange">' + key + '</font></b></html>', host])
              if key not in self.headers_already_in_table:
                self.headers_already_in_table.append(key)
            else:
              self.for_table.append(["", host])
              if key not in self.headers_already_in_table:
                self.headers_already_in_table.append(key)
        self.for_table.append(['<html><b><font color="orange">' + '='*300 + '</font></b></html>', '<html><b><font color="orange">' + '='*300 + '</font></b></html>'*300])
    
      for table_entry in self.for_table[self.last_len:]:
        self.dataModel_tab.insertRow(self.last_row, table_entry)
        self.last_row += 1
      self.last_row = 0
      self.for_table = []
    self.last_len = len(history)
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

    frame = JFrame("Headers info")
    frame.setSize(850, 350)
    colNames = ('Header name','Header description')
    #todas las columnas del archivo: header name && description && example &&  (permanent, no se que es esto) &&


    



    c=[x[0:2] for x in self.tableDataReq]      
    self.model_window_req = IssueTableModel(c, self.colNames)
    self.tableReq = IssueTable(self.model_window_req)
    #dataModelReq = DefaultTableModel(c, colNames)
    #self.tableReq = JTable(dataModelReq)
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
    dataModelResp = DefaultTableModel(d, colNames)
    self.tableResp = JTable(dataModelResp)
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
    fields_names = [
              '   Header Name:  ', 
              '   Header Description:  ', 
              '   Example:  ', 
              '   URL explaining header:  ', 
              '   Potential header risks:  '
              ]

    self.new_header_name = JTextField('')
    self.new_header_description = JTextField( '' )
    self.new_header_example = JTextField( '' )
    self.new_header_url = JTextField('')
    self.new_header_risks = JTextField('')

    fields = [ self.new_header_name, self.new_header_description, self.new_header_example, self.new_header_url, self.new_header_risks ]

    for k, field in enumerate(fields):
      c = GridBagConstraints()
      c.gridx = 0 
      y_pos += 1
      c.gridy = y_pos 
      c.anchor = GridBagConstraints.EAST
      panelTab3.add( JLabel(fields_names[k]), c )

      c = GridBagConstraints()
      c.fill = GridBagConstraints.HORIZONTAL
      c.weightx = 1
      c.gridx = 1 
      c.gridy = y_pos 
      
      panelTab3.add(fields[k] , c )

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

