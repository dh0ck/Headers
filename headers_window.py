from burp import IBurpExtender, ITab
from burp import IContextMenuFactory

import threading
#import java
import shutil, glob, re, sys, os, subprocess
#from time import sleep
from javax.swing import JFrame, JProgressBar, JSplitPane, JTable, JScrollPane, JPanel, BoxLayout, WindowConstants, JLabel, JMenuItem, JTabbedPane, JButton, JTextField, JTextArea, SwingConstants, JEditorPane, JComboBox, DefaultComboBoxModel, JFileChooser, ImageIcon, JCheckBox, JRadioButton, ButtonGroup, KeyStroke
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints, Point, Component, Color  # quitar los layout que no utilice
from java.util import List, ArrayList
from java.lang import Boolean, String, Integer
#from java.awt.event.MouseEvent import getPoint
from java.awt.event import MouseListener, FocusListener


burp_extender_instance = "" # variable global que sera el instance de bupr extender, para acceder a los valores de la instancia de IBurpExtender que burp crea, pero desde fuera, sobre todo para cambiar con clicks la tabla de endpoints
history1 = []
host_endpoint = [] #se rellena al darle a filter en la tab, pero habra que arreglar que no haya duplicados cuando cambian los valores de los query string  rameters (o puedo dejar que se repitan y ponerlos todos.) lo bueno seria poner tambien el index del history y en el text area poner los headers de la req  los de la resp, separados por una =========, etc
endpoint_table = []
endpoint_table_meta = []
selected_header_name = ""


class RawHtmlRenderer(DefaultTableCellRenderer):
    def __init__(self):
        self.result = JLabel()
        self.DTCR = DefaultTableCellRenderer()

    def getTableCellRendererComponent(
        self,
        table,               # JTable  - table containing value
        value,               # Object  - value being rendered
        isSelected,          # boolean - Is value selected?
        hasFocus,            # boolean - Does this cell have focus?
        row,                 # int     - Row # (0..N)
        col                  # int     - Col # (0..N)
    ) :
        comp = self.DTCR.getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, col
        )
        


        result = self.result

        ############################################################################
        ###### something is not right, clicking on cells doesn't change selected background
        result.setBorder( comp.getBorder() )
        if (isSelected):
            result.setBackground(table.getSelectionBackground())
            #result.setBackground(Color.blue))
            result.setForeground(table.getSelectionForeground())

        else:
            result.setBackground(table.getBackground())
            result.setForeground(table.getForeground())
        ################################################################################
        result.setText(value)
        result.putClientProperty("html.disable", None)

        return result

class ConfigTableModel(DefaultTableModel):
  def __init__(self, data, headings):
    DefaultTableModel.__init__(self, data, headings)
  
  def getColumnClass(self, col):
    return [Boolean, String][col]

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

            header = header[0].split('<font color="{}">'.format(burp_extender_instance.color1))[1].split('</b></font>')[0] #debe haber mas abajo al reves el orden de las closing tabs b y font
            burp_extender_instance.extra_info_textarea1.setText(header)
            if header in list(burp_extender_instance.dict_req_headers.keys()) and header not in list(burp_extender_instance.dict_resp_headers.keys()):
              burp_extender_instance.extra_info_textarea2.setText(burp_extender_instance.dict_req_headers[header][0])
              burp_extender_instance.extra_info_textarea3.setText(burp_extender_instance.dict_req_headers[header][1])
              burp_extender_instance.extra_info_textarea4.setText(burp_extender_instance.dict_req_headers[header][2])
              burp_extender_instance.extra_info_textarea5.setText(burp_extender_instance.dict_req_headers[header][3])
            if header not in (list(burp_extender_instance.dict_req_headers.keys())) and header not in list(burp_extender_instance.dict_resp_headers.keys()):
              burp_extender_instance.extra_info_textarea2.setText('Description unavailable for header: ' + header)
              burp_extender_instance.extra_info_textarea3.setText('Example unavailable for header: ' + header)
              burp_extender_instance.extra_info_textarea4.setText('URL unavailable for header: ' + header)
              burp_extender_instance.extra_info_textarea5.setText('Potential risks unavailable for header: ' + header)
            if header in list(burp_extender_instance.dict_resp_headers.keys()):
              burp_extender_instance.extra_info_textarea2.setText(burp_extender_instance.dict_resp_headers[header][0])
              burp_extender_instance.extra_info_textarea3.setText(burp_extender_instance.dict_resp_headers[header][1])
              burp_extender_instance.extra_info_textarea4.setText(burp_extender_instance.dict_resp_headers[header][2])
              burp_extender_instance.extra_info_textarea5.setText(burp_extender_instance.dict_resp_headers[header][3])
        if event.getClickCount() == 2:  # double click to make extra info panel visible
            burp_extender_instance.extra_info.setVisible(True) 

class IssueTableMouseListener_Meta(IssueTableMouseListener):
  """Adds functionality to the Header-host table (to the <meta> tab) when its elements are clicked."""
  def mouseClicked(self, event):
    burp_extender_instance.is_meta = True 
    if event.getClickCount() == 1:
      tbl = event.getSource()
      val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())

      identifier = val[0]
      clicked_host = val[1]

      k = tbl.getSelectedRow()
      if identifier == '':
        while identifier == '':
          k -= 1
          identifier = tbl.getModel().getDataVector().elementAt(k)[0]

      global endpoint_table_meta # igual no tiene que ser gobal
      endpoint_table_meta = []

      # meta_table tiene columnas: host | url | meta tag, una para cada tag, repitiendo host y url si hay mas de una tag en una url
      for (host, endpoint, meta) in burp_extender_instance.meta_table:
        #if identifier not in meta and clicked_host != host:
        if clicked_host == host:
          spl = endpoint.split(' ')
          line = spl[0] + " :: " + host + " :: " + " ".join(spl[1:]) 
          endpoint_table_meta.append([endpoint]) #poner el host antes de la url pero despues del method
          #endpoint_table_meta.append([line]) #poner el host antes de la url pero despues del method

          #ESTA COGIENDO ENPOINTS QUE NO CORRESPONDEN, VER SI ES QUE COINCIDEN CON UN HOST DIFERENTE. TAMBIEN TENGO QUE APLICAR REGEX EN LOS UNIQUE ENDPOINTS
      
      burp_extender_instance.selected_meta_header = identifier#header # este lo settea ok para la de endpoints
      burp_extender_instance.selected_host = clicked_host
      burp_extender_instance.update_meta_endpoints(endpoint_table_meta)

class IssueTableMouseListener_Tab(IssueTableMouseListener):
    """Adds functionality to the Header-host table when its elements are clicked."""
    def mouseClicked(self, event):
        burp_extender_instance.is_meta = False
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
        header_value = header.split('<font color="{}">'.format(burp_extender_instance.color1))[1].split('</font>')[0]
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
        burp_extender_instance.endpoint_table1 = endpoint_table
        burp_extender_instance.update_endpoints(endpoint_table)
        
class IssueTableMouseListener_Endpoints(IssueTableMouseListener):
    """Adds functionality to the click actions on rows of the "Unique endpoints" and "All endpoints" tables."""
    def extra_symbol(self, head):

      if head.split(": ")[0].lower() in self.security_headers:
        extra_symbol = '<b><font color="#00FF00"> [ + ] </font><b>'
      elif head.split(": ")[0].lower() in self.dangerous_headers:
        extra_symbol = '<b><font color="#FF0000"> [ X ] </font><b>'
      elif head.split(": ")[0].lower() in self.potentially_dangerous_headers:
        extra_symbol = '<b><font color="#4FC3F7"> [ ? ] </font><b>'
      else:
        extra_symbol = ""
      return extra_symbol


    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            tbl = event.getSource()

        burp_extender_instance.clicked_endpoint(tbl, True)

class summary_unique_mouse_listener(IssueTableMouseListener):
  def mouseClicked(self, event):
    print('summary table clicked')

class summary_all_mouse_listener(IssueTableMouseListener):
  def mouseClicked(self, event):
    print('summary all clicked, go to history and show request/response')

class SummaryTableModel_left(DefaultTableModel):
  def __init__(self, data, headings):
    DefaultTableModel.__init__(self, data, headings)
  
  def getColumnClass(self, col):
    # columnas: add to report?, Host
    return [Boolean, String][col]
  
  def isCellEditable(self, row, column):
    """Returns True if cells are editable."""
    canEdit = [True, False]
    return canEdit[column]

class SummaryTableModel_right(DefaultTableModel):
  def __init__(self, data, headings):
    DefaultTableModel.__init__(self, data, headings)
  
  def getColumnClass(self, col):
    # columnas: history index, add to report?, issue type, host, unique endpoint
    # issue types:
    # - missing security headers
    # - dangerous
    # - potentially dangerous
    # - http verbs
    # - cookies without flags

    return [Boolean, String, String, String][col]
    #return [Integer, Boolean, String, String, String][col]
  
  def isCellEditable(self, row, column):
    """Returns True if cells are editable."""
    canEdit = [False, True, False, False, False]
    return canEdit[column]

class IssueTable(JTable):
    """Table class for the tables used in the extension. Needed to give the capacity to tables to perform actions when their rows are clicked."""
    def __init__(self, model, table_type):
        self.setModel(model)
        self.getTableHeader().setReorderingAllowed(False)
        if table_type == "tab":
          self.addMouseListener(IssueTableMouseListener_Tab())
        elif table_type == "meta":
          self.addMouseListener(IssueTableMouseListener_Meta())
        elif table_type == "window":
          self.addMouseListener(IssueTableMouseListener_Window())
        elif table_type == "endpoints":
          self.addMouseListener(IssueTableMouseListener_Endpoints())
        elif table_type == "config_headers":
          pass
        elif table_type == "summary_unique_endpoints":
          self.addMouseListener(summary_unique_mouse_listener())
        elif table_type == "summary_all_endpoints":
          self.addMouseListener(summary_all_mouse_listener())

    '''def getTableCellRendererComponent(
        self,
        table,               # JTable  - table containing value
        value,               # Object  - value being rendered
        isSelected,          # boolean - Is value selected?
        hasFocus,            # boolean - Does this cell have focus?
        row,                 # int     - Row # (0..N)
        col                  # int     - Col # (0..N)
    ) :
        comp = self.DTCR.getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, col
        )
        result = self.result
        result.setText(value)
        result.putClientProperty("html.disable", None)

        return result'''


#este es para los filtros, que al borrar el texto se ponga la hint, pero no funciona, mejor pasar de ello
'''class HintTextField(JTextField, FocusListener):

  def __init__(self, hint, showingHint):
    #print('xxx 1')
    self.hint = hint
    self.showingHint = showingHint

  def HintTextField(self, hint):
    #print('xxx 2')
    self.hint = hint
    self.showingHint = True
    super().addFocusListener(self)
  

  def focusGained(self, event): 
    #print('xxx 3')
    if(self.getText().isEmpty()): 
      super().setText("");
      self.showingHint = False;
    
  
  def focusLost(self, event): 
    #print('xxx 4')
    if(self.getText().isEmpty()):
      super().setText(hint)
      self.showingHint = True
    
  def getText(self): 
    #print('xxx 4')
    #return showingHint ? "" : super().getText()
    return "" if self.showingHint else super().getText()'''
  

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
  """Main class of the Headers extension, instantiated by Burp."""

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
      elif feature == "last_output_file":
        self.save_path.setText(value)        
        self.config_dict[feature] = value
      elif feature == "last_filter_type":
        self.preset_filters.setSelectedItem(value)
        self.config_dict[feature] = value
      elif feature == "UI_theme":
        self.UI_theme = value
        self.config_dict[feature] = value
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
    f = open('cookie_flags.txt','r')
    self.total_cookie_flags = len(f.readlines())
    f.close()
    
    # UI colors
    if self.UI_theme == "dark":
      f = open('UI_theme_dark.txt', 'r')
    elif self.UI_theme == "light":
      f = open('UI_theme_light.txt', 'r')
    for k, line in enumerate(f.readlines()):
      if k == 0:
        self.color1 = line.strip('\n')  # for titles and dashed lines
      elif k == 1:
        self.color2 = line.strip('\n') # for security headers
      elif k == 2:
        self.color3 = line.strip('\n')  # for potentially dangerous headers
      elif k == 3:
        self.color4 = line.strip('\n')  # for dangerous or verbose headers
      elif k == 4:
        self.color5 = line.strip('\n')  # for the rest of headers
      elif k == 5:
        self.color6 = line.strip('\n')  # for the wildcards in the unique endpoints URL
    f.close()

  def update_config(self):#, feature, value):
    """Update the configuration file with values supplied in the configuration panel of the extension"""
    f = open("config.txt", "w")
    for key in list(self.config_dict.keys()):
      f.write(key + " -- " + self.config_dict[key] + "\n")  #comprobar 
    f.close()

  def read_headers(self):
    """ Read the values currently checked in the advanced config tables and use them in the future """

    self.table_config_security = []
    self.table_config_dangerous = []
    self.table_config_potentially_dangerous = []
    self.table_config_cookie_flags = []
    

    for i in range(self.initial_count_security_headers):
      if self.model_tab_config_security.getValueAt(i,0):
        self.table_config_security.append([True, self.model_tab_config_security.getValueAt(i,1)]) 

    for i in range(self.initial_count_dangerous_headers):
      if self.model_tab_config_dangerous.getValueAt(i,0):
        self.table_config_dangerous.append([True, self.model_tab_config_dangerous.getValueAt(i,1)]) 
    
    for i in range(self.initial_count_potentially_dangerous_headers):
      if self.model_tab_config_potentially_dangerous.getValueAt(i,0):
        self.table_config_potentially_dangerous.append([True, self.model_tab_config_potentially_dangerous.getValueAt(i,1)]) 

    print('333333333')
    print(self.initial_count_cookie_flags)
    print(self.model_tab_config_cookie_flags, self.model_tab_config_cookie_flags.getValueAt(0,0))
    for i in range(self.initial_count_cookie_flags):

      if self.model_tab_config_cookie_flags.getValueAt(i,0):
        self.table_config_cookie_flags.append([True, self.model_tab_config_cookie_flags.getValueAt(i,1)]) 

    print('555555555')
    self.dangerous_headers = [] 
    self.security_headers = [] 
    self.potentially_dangerous_headers = [] 
    self.cookie_flags = []

    for line in self.table_config_security:
        self.security_headers.append(line[1].strip('\n').lower())
    
    for line in self.table_config_dangerous:
        self.dangerous_headers.append(line[1].strip('\n'))
    
    for line in self.table_config_potentially_dangerous:
        self.potentially_dangerous_headers.append(line[1].strip('\n'))

    for line in self.table_config_cookie_flags:
        self.cookie_flags.append(line[1].strip('\n'))

  def make_chosen_headers_permanent(self, event):
    self.security_headers = []
    f = open("security_headers.txt","w")
    for i in range(self.initial_count_security_headers):
      #print(str(i) + '/' + str(self.initial_count_security_headers))
      if i < self.initial_count_security_headers - 1:
        if self.model_tab_config_security.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_security.getValueAt(i,1) + '\n')
          self.security_headers.append(self.model_tab_config_security.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_security.getValueAt(i,1) + '\n')
      else:
        if self.model_tab_config_security.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_security.getValueAt(i,1))
          self.security_headers.append(self.model_tab_config_security.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_security.getValueAt(i,1))

    f.close()

    f = open("dangerous_headers.txt","w")
    self.dangerous_headers = []
    for i in range(self.initial_count_dangerous_headers):
      if i < self.initial_count_dangerous_headers - 1:
        if self.model_tab_config_dangerous.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_dangerous.getValueAt(i,1) + '\n')
          self.dangerous_headers.append(self.model_tab_config_dangerous.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_dangerous.getValueAt(i,1) + '\n')
      else:
        if self.model_tab_config_dangerous.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_dangerous.getValueAt(i,1))
          self.dangerous_headers.append(self.model_tab_config_dangerous.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_dangerous.getValueAt(i,1))

    f.close()
    
    f = open("potentially_dangerous_headers.txt","w")
    self.potentially_dangerous_headers = []
    for i in range(self.initial_count_potentially_dangerous_headers):
      if i < self.initial_count_potentially_dangerous_headers - 1:
        if self.model_tab_config_potentially_dangerous.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_potentially_dangerous.getValueAt(i,1) + '\n')
          self.potentially_dangerous_headers.append(self.model_tab_config_potentially_dangerous.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_potentially_dangerous.getValueAt(i,1) + '\n')
      else:
        if self.model_tab_config_potentially_dangerous.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_potentially_dangerous.getValueAt(i,1))
          self.potentially_dangerous_headers.append(self.model_tab_config_potentially_dangerous.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_potentially_dangerous.getValueAt(i,1))
    f.close()

    f = open("cookie_flags.txt","w")
    self.cookie_flags = []
    for i in range(self.initial_count_cookie_flags):
      if i < self.initial_count_cookie_flags - 1:
        if self.model_tab_config_cookie_flags.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_cookie_flags.getValueAt(i,1) + '\n')
          self.cookie_flags.append(self.model_tab_config_cookie_flags.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_cookie_flags.getValueAt(i,1) + '\n')
      else:
        if self.model_tab_config_cookie_flags.getValueAt(i,0):
          f.write("1 " + self.model_tab_config_cookie_flags.getValueAt(i,1))
          self.cookie_flags.append(self.model_tab_config_cookie_flags.getValueAt(i,1))
        else:
          f.write("0 " + self.model_tab_config_cookie_flags.getValueAt(i,1))
    f.close()

  def create_extra_info_window(self):
    # el extra info window lo defino aqui fuera para que exista desde un principio y al hacer doble click en las tablas solamente se haga visible, pero no se  ee un nuevo frame por cada doble click
    self.extra_info = JFrame("Extended header info")
    self.extra_info_panel = JPanel()
    self.extra_info_panel.setLayout(BoxLayout(self.extra_info_panel, BoxLayout.Y_AXIS ) )
    self.extra_info.setSize(400, 350)
    self.extra_info.setLocation(840, 0)
    self.extra_info.toFront()
    self.extra_info.setAlwaysOnTop(True)

    self.extra_info_label1 = JLabel("<html><b><font color='orange'>Header Name:</font></b></html>")
    self.extra_info_label1.putClientProperty("html.disable", None)
    #extra_info_label1 = JLabel("<html><b><font color='{}'>Header Name:</font></b></html>".format(self.color1))
    self.extra_info_label1.setAlignmentX(JLabel.LEFT_ALIGNMENT)
    self.extra_info_textarea1 = JTextArea("Header Name", rows=1, editable=False)
    self.extra_info_textarea1.setLineWrap(True)
    self.scrollPane_1 = JScrollPane(self.extra_info_textarea1)
    self.scrollPane_1.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

    self.extra_info_label2 = JLabel("<html><b><font color='orange'>Header Description:</font></b></html>")
    self.extra_info_label2.putClientProperty("html.disable", None)
    #extra_info_label2 = JLabel("<html><b><font color='{}'>Header Description:</font></b></html>".format(self.color1))
    self.extra_info_label2.setAlignmentX(JLabel.LEFT_ALIGNMENT)
    self.extra_info_textarea2 = JTextArea("Description",rows=5, editable=False)
    self.extra_info_textarea2.setLineWrap(True)
    self.scrollPane_2 = JScrollPane(self.extra_info_textarea2)
    self.scrollPane_2.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

    self.extra_info_label3 = JLabel("<html><b><font color='orange'>Usage example:</font></b></html>")
    self.extra_info_label3.putClientProperty("html.disable", None)
    #extra_info_label3 = JLabel("<html><b><font color='{}'>Usage example:</font></b></html>".format(self.color1))
    self.extra_info_label3.setAlignmentX(JLabel.LEFT_ALIGNMENT)
    self.extra_info_textarea3 = JTextArea("Example",rows=3, editable=False)
    self.extra_info_textarea3.setLineWrap(True)
    self.scrollPane_3 = JScrollPane(self.extra_info_textarea3)
    self.scrollPane_3.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

    self.extra_info_label4 = JLabel("<html><b><font color='orange'>URL describing header:</font></b></html>")
    self.extra_info_label4.putClientProperty("html.disable", None)
    #extra_info_label4 = JLabel("<html><b><font color='{}'>URL describing header:</font></b></html>".format(self.color1))
    self.extra_info_label4.setAlignmentX(JLabel.LEFT_ALIGNMENT)
    self.extra_info_textarea4 = JTextArea("URL2",rows=2, editable=False)
    self.extra_info_textarea4.setLineWrap(True)
    self.scrollPane_4 = JScrollPane(self.extra_info_textarea4)
    self.scrollPane_4.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

    self.extra_info_label5 = JLabel("<html><b><font color='orange'>Potential risks associated with header:</font></b></html>")
    self.extra_info_label5.putClientProperty("html.disable", None)
    #extra_info_label5 = JLabel("<html><b><font color='{}'>Potential risks associated with header:</font></b></html>".format(self.color1))
    self.extra_info_label5.setAlignmentX(JLabel.LEFT_ALIGNMENT)
    self.extra_info_textarea5 = JTextArea("There are no potential risks associated with this header",rows=3, editable=False)
    self.extra_info_textarea5.setLineWrap(True)
    self.scrollPane_5 = JScrollPane(self.extra_info_textarea5)
    self.scrollPane_5.setAlignmentX(JScrollPane.LEFT_ALIGNMENT)

    for element in [self.extra_info_label1, self.scrollPane_1, self.extra_info_label2, self.scrollPane_2, self.extra_info_label3, self.scrollPane_3, self.extra_info_label4, self.scrollPane_4, self.extra_info_label5, self.scrollPane_5]:
      self.extra_info_panel.add(element)

    self.extra_info.add(self.extra_info_panel)
    self.dict_req_headers = {}
    self.req_headers_description = open('request_headers.txt','r')
    for line in self.req_headers_description.readlines():
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
      self.dict_req_headers[header_name] = (header_description, header_example, header_url, header_risk)
    self.req_headers_description.close()

    self.dict_resp_headers = {}
    self.resp_headers_description = open('response_headers.txt','r')
    for line in self.resp_headers_description.readlines():
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
      self.dict_resp_headers[header_name] = (header_description, header_example, header_url, header_risk)
    self.resp_headers_description.close()

  def compile_regex(self):
    """Compile regular expressions that will be used later by the extension to match URL parameters"""
    #matchea lo que haya entre = y & o entre = y ' ', para el ultimo parametro de la linea
    self.query_params = re.compile('=.*?&|=.*? ') 

    # matchea numeros en la url tipo /asdf/1234/qwe/1234, matchearia los dos 1234 y secuencias de letras, numeros y guiones o puntos. igual algun caso raro se cuela, pero por lo que he visto pilla todo
    self.number_between_forwardslash = re.compile('\/[a-zA-Z]*\d+[a-zA-Z0-9-_\.]*')

    # match de <meta> headers
    self.meta = re.compile('<meta .*?>')

  def find_host(self, req_headers):  
    """Given a request-response object, find the Host to which it was requested"""
    for req_head in req_headers[1:]:
      if 'Host: ' in req_head:
        host = req_head.split(': ')[1]
        break
    return host

  def restore_save_thresholds_func(self, event):
    f = open('thresholds.txt', 'r')
    thresholds = f.readlines()
    f.close()

    check_box_security_value = thresholds[0].split(' ')[0]
    check_box_potentially_dangerous_value = thresholds[1].split(' ')[0]
    check_box_dangerous_value = thresholds[2].split(' ')[0]
    
    threshold_security_value = thresholds[0].split(' ')[1]
    threshold_potentially_dangerous_value = thresholds[1].split(' ')[1]
    threshold_dangerous_value = thresholds[2].split(' ')[1]

    security_checkbox_state = True if check_box_security_value == '1' else False
    potentially_dangerous_checkbox_state = True if check_box_potentially_dangerous_value == '1' else False
    dangerous_checkbox_state = True if check_box_dangerous_value == '1' else False

    self.check_box_security.setSelected(security_checkbox_state)
    self.check_box_potentially_dangerous.setSelected(potentially_dangerous_checkbox_state)
    self.check_box_dangerous.setSelected(dangerous_checkbox_state)

    self.threshold_count_security.setText(threshold_security_value)
    self.threshold_count_potentially_dangerous.setText(threshold_potentially_dangerous_value)
    self.threshold_count_dangerous.setText(threshold_dangerous_value)

  def save_threshold_config_func(self, event):
    f = open('thresholds.txt', 'w')
    selected_security = '1' if self.check_box_security.isSelected() == True else '0'
    selected_potentially_dangerous = '1' if self.check_box_potentially_dangerous.isSelected() == True else '0'
    selected_dangerous = '1' if self.check_box_dangerous.isSelected() == True else '0'
    
    f.write(selected_security + ' ' + self.threshold_count_security.getText() + '\n')
    f.write(selected_potentially_dangerous + ' ' + self.threshold_count_potentially_dangerous.getText() + '\n')
    f.write(selected_dangerous + ' ' + self.threshold_count_dangerous.getText())

    f.close()
    return

  def reset_threshold_config_func(self, event):
    self.threshold_count_security.setText(str(self.initial_count_security_headers))
    self.threshold_count_potentially_dangerous.setText("{}".format(self.initial_count_potentially_dangerous_headers))
    self.threshold_count_dangerous.setText("{}".format(self.initial_count_dangerous_headers))

    self.check_box_security.setSelected(False)
    self.check_box_dangerous.setSelected(False)
    self.check_box_potentially_dangerous.setSelected(False)
    return

  def create_advanced_config_frame(self):
    self.advanced_config_panel = JFrame("Advanced configuration")
    self.advanced_config_panel.setLayout(BorderLayout())
    self.advanced_config_panel.toFront()
    self.advanced_config_panel.setAlwaysOnTop(True)
    self.advanced_config_panel.setSize(800, 600)
    self.advanced_config_panel.setLocationRelativeTo(None)    

    # --------------------- Theme selection ------------------------#
    self.theme_model = DefaultComboBoxModel()
    self.theme_model.addElement("Dark")
    self.theme_model.addElement("Light")
    theme_selector = JComboBox(self.theme_model)
    # ----------------------------------------------------------------#



    # --------------------- Headers selection ------------------------#
    self.table_config_security = []
    self.table_config_potentially_dangerous = []
    self.table_config_dangerous = []
    self.table_config_cookie_flags = []

    f = open('security_headers.txt','r')
    for line in f.readlines():
      active = line.split(' ')[0]
      if active == '1':
        self.table_config_security.append([True, line.split(' ')[1].strip('\n')])
      else: 
        self.table_config_security.append([False, line.split(' ')[1].strip('\n')])
    f.close()

    f = open('potentially_dangerous_headers.txt','r')
    for line in f.readlines():
      active = line.split(' ')[0]
      if active == '1':
        self.table_config_potentially_dangerous.append([True, line.split(' ')[1].strip('\n')])
      else: 
        self.table_config_potentially_dangerous.append([False, line.split(' ')[1].strip('\n')])
    f.close()

    f = open('dangerous_headers.txt','r')
    for line in f.readlines():
      active = line.split(' ')[0]
      if active == '1':
        self.table_config_dangerous.append([True, line.split(' ')[1].strip('\n')])
      else: 
        self.table_config_dangerous.append([False, line.split(' ')[1].strip('\n')])
    f.close()
    
    f = open('cookie_flags.txt','r')
    for line in f.readlines():
      active = line.split(' ')[0]
      if active == '1':
        self.table_config_cookie_flags.append([True, line.split(' ')[1].strip('\n')])
      else: 
        self.table_config_cookie_flags.append([False, line.split(' ')[1].strip('\n')])
    f.close()

    self.config_column_names = ("Use?", "Header name")
    self.config_column_names_flags = ("Use?", "Flag name")

    self.model_tab_config_security = ConfigTableModel(self.table_config_security, self.config_column_names)
    self.table_tab_config_security = JTable(self.model_tab_config_security)

    self.model_tab_config_potentially_dangerous = ConfigTableModel(self.table_config_potentially_dangerous, self.config_column_names)
    self.table_tab_config_potentially_dangerous = JTable(self.model_tab_config_potentially_dangerous)

    self.model_tab_config_dangerous = ConfigTableModel(self.table_config_dangerous, self.config_column_names)
    self.table_tab_config_dangerous = JTable(self.model_tab_config_dangerous)

    self.model_tab_config_cookie_flags = ConfigTableModel(self.table_config_cookie_flags, self.config_column_names_flags)
    self.table_tab_config_cookie_flags = JTable(self.model_tab_config_cookie_flags)
    
    self.table_tab_config_security.getColumnModel().getColumn(0).setMaxWidth(50)
    self.table_tab_config_security.getColumnModel().getColumn(1).setPreferredWidth(400)

    self.table_tab_config_potentially_dangerous.getColumnModel().getColumn(0).setMaxWidth(50)
    self.table_tab_config_potentially_dangerous.getColumnModel().getColumn(1).setPreferredWidth(400)

    self.table_tab_config_dangerous.getColumnModel().getColumn(0).setMaxWidth(50)
    self.table_tab_config_dangerous.getColumnModel().getColumn(1).setPreferredWidth(400)

    self.table_tab_config_cookie_flags.getColumnModel().getColumn(0).setMaxWidth(50)
    self.table_tab_config_cookie_flags.getColumnModel().getColumn(1).setPreferredWidth(400)

    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL

    security_headers_tab = JPanel(GridBagLayout()) 
    security_headers_tab.add(JScrollPane(self.table_tab_config_security), c)

    dangerous_headers_tab = JPanel(GridBagLayout()) 
    dangerous_headers_tab.add(JScrollPane(self.table_tab_config_dangerous), c)

    dangerous_headers_tab = JPanel(GridBagLayout()) 
    dangerous_headers_tab.add(JScrollPane(self.table_tab_config_cookie_flags), c)

    potentially_dangerous_headers_tab = JPanel(GridBagLayout()) 
    potentially_dangerous_headers_tab.add(JScrollPane(self.table_tab_config_potentially_dangerous), c)
    # ----------------------------------------------------------------#
    

    # ------------------ Add contents to main tabs -------------------#
    aux_panel = JPanel(BorderLayout())
    theme_panel = JPanel(GridBagLayout())

    # Add buttons at the bottom inside a panel
    add_header_to_category_button = JButton("<html><b>Add header to category</b></html>", actionPerformed = self.add_headers_to_categories)
    add_header_to_category_button.putClientProperty("html.disable", None)
    add_header_to_category_button.setForeground(Color.WHITE)
    add_header_to_category_button.setBackground(Color(10,101,247))

    remove_header_from_category_button = JButton("<html><b>Remove header from category</b></html>", actionPerformed = self.remove_headers_from_categories)
    remove_header_from_category_button.putClientProperty("html.disable", None)
    remove_header_from_category_button.setForeground(Color.WHITE)
    remove_header_from_category_button.setBackground(Color(210,101,47))#Color(10,101,247)) Color(210,101,47)

    make_curr_selection_permanent_button = JButton("<html><b>Apply changes</b></html>", actionPerformed = self.make_chosen_headers_permanent)
    make_curr_selection_permanent_button.putClientProperty("html.disable", None)
    make_curr_selection_permanent_button.setForeground(Color.WHITE)
    make_curr_selection_permanent_button.setBackground(Color(10,101,247))

    button_panel = JPanel(GridBagLayout())
    e = GridBagConstraints()
    e.fill = GridBagConstraints.HORIZONTAL
    e.gridx = 0
    e.weightx = 1
    e.gridy = 0
    button_panel.add(add_header_to_category_button, e) 
    e.gridx += 1
    button_panel.add(remove_header_from_category_button, e) 
    e.gridx += 1
    button_panel.add(make_curr_selection_permanent_button, e)


    # Fill the tables for each category
    self.categories_tabs = JTabbedPane()
    self.categories_tabs.add("Security headers", JScrollPane(self.table_tab_config_security))
    self.categories_tabs.add("Potentially dangerous headers", JScrollPane(self.table_tab_config_potentially_dangerous))
    self.categories_tabs.add("Dangerous headers", JScrollPane(self.table_tab_config_dangerous))
    self.categories_tabs.add("Cookie Flags", JScrollPane(self.table_tab_config_cookie_flags))
    aux_panel.add(self.categories_tabs, BorderLayout.CENTER)
    aux_panel.add(button_panel, BorderLayout.SOUTH)


    #--------------- threshold panel ---------------------
    threshold_panel = JPanel(GridBagLayout())
    c = GridBagConstraints()
    c.anchor = GridBagConstraints.WEST
    c.gridx = 0
    c.gridy = 0
    c.weightx = 1
    c.fill = GridBagConstraints.HORIZONTAL
    threshold_panel.add(JLabel("Use threshold for Security headers?"), c)
    c.gridy += 1
    threshold_panel.add(JLabel("Use threshold for Potentially Dangerous headers?"), c) 
    c.gridy += 1
    threshold_panel.add(JLabel("Use threshold for Dangerous headers?"), c) 

    c.gridx = 1
    c.gridy = 0
    self.check_box_security = JCheckBox()
    threshold_panel.add(self.check_box_security, c)
    c.gridy += 1
    self.check_box_potentially_dangerous = JCheckBox()
    threshold_panel.add(self.check_box_potentially_dangerous, c)
    c.gridy += 1
    self.check_box_dangerous = JCheckBox()
    threshold_panel.add(self.check_box_dangerous, c)

    c.gridx = 2
    c.gridy = 0
    self.threshold_count_security = JTextField("{}".format(len(self.table_config_security)))
    threshold_panel.add(self.threshold_count_security, c)
    c.gridy += 1
    self.threshold_count_potentially_dangerous = JTextField("{}".format(len(self.table_config_potentially_dangerous)))
    threshold_panel.add(self.threshold_count_potentially_dangerous, c)

    c.gridy += 1
    self.threshold_count_dangerous = JTextField("{}".format(len(self.table_config_dangerous)))
    threshold_panel.add(self.threshold_count_dangerous, c)

    c.gridx = 0
    c.gridy += 1
    save_threshold_config = JButton("Save thresholds", actionPerformed = self.save_threshold_config_func)
    threshold_panel.add(save_threshold_config, c)

    c.gridx += 1
    restore_threshold_config = JButton("Restore saved thresholds", actionPerformed = self.restore_save_thresholds_func)
    threshold_panel.add(restore_threshold_config, c)

    c.gridx += 1
    reset_threshold_config = JButton("Reset to default", actionPerformed = self.reset_threshold_config_func)
    threshold_panel.add(reset_threshold_config, c)
    


    # Theme panel contents
    d = GridBagConstraints()
    d.fill = GridBagConstraints.HORIZONTAL
    d.gridx = 0
    d.gridy = 0
    theme_panel.add(JLabel("If you use Burp's dark theme, you will probably see better this extension by selecting 'dark', and vice versa."), d)
    d.gridy += 1
    theme_panel.add(theme_selector, d)


    # add the main tabs
    self.main_tabs = JTabbedPane() 
    self.main_tabs.addTab('Configure headers criteria', aux_panel)
    self.main_tabs.addTab('Configure thresholds', threshold_panel)
    self.main_tabs.addTab('Theme', theme_panel)

    self.advanced_config_panel.add(self.main_tabs, BorderLayout.CENTER)
    # ----------------------------------------------------------------#

    return

  def show_advanced_config(self, event):
    """Show the advanced configuration window when clicking the gear button"""
    self.advanced_config_panel.setVisible(True)

  def get_categories_headers_length(self):
    """ Get how many headers are in each category when the extension is loaded. Used in read_headers()
    to tell it how many times it must loop to generate arrays of each category of headers"""

    f = open('security_headers.txt','r')
    # the filter in the next line removes all occurences of '', i.e. doesnt consider empty lines for counting the number of headers
    self.initial_count_security_headers = len(list(filter(('').__ne__, f.readlines())))
    #self.initial_count_security_headers = len(f.readlines())
    f.close()

    f = open('dangerous_headers.txt','r')
    self.initial_count_dangerous_headers= len(list(filter(('').__ne__, f.readlines())))
    #self.initial_count_dangerous_headers= len(f.readlines())
    f.close()
    
    f = open('potentially_dangerous_headers.txt','r')
    self.initial_count_potentially_dangerous_headers = len(list(filter(('').__ne__, f.readlines())))
    #self.initial_count_potentially_dangerous_headers = len(f.readlines())
    f.close()

    f = open('cookie_flags.txt','r')
    self.initial_count_cookie_flags = len(list(filter(('').__ne__, f.readlines())))
    #self.initial_count_dangerous_headers= len(f.readlines())
    f.close()

  def check_python_modules(self, event):
    # subprocess que guarde en una variable output de python -c import ...
    
    os_type = sys.platform.getshadow()
    win_python_command = "py --version"
    linux_python_command = 'python3 --version'
    win_python_command = 'py docx.py'
    print(os_type)
    if 'win' in os_type:
      #proc = subprocess.Popen(win_python_command, stdout=subprocess.PIPE)
      proc = subprocess.Popen("py --version", stdout=subprocess.PIPE)
    elif 'linux' in os_type:
      #proc = subprocess.Popen(linux_python_command, stdout=subprocess.PIPE)
      proc = subprocess.Popen("python3 --version", stdout=subprocess.PIPE)
    else:
      raise("Error identifying operating system type. Provide path to Python3 binary.")


    if 'docxtpl' not in sys.modules.keys():
      os.system('pip install docxtpl')

    docxtpl_version = subprocess.Popen('''python -c "import docxtpl; print('Docxtpl version:',docxtpl.__version__)"''',stdout=subprocess.PIPE)

    output = proc.stdout.read()
    self.python_msg.setText(output.strip('\r\n') + '; ' + docxtpl_version.stdout.read())

  def create_docx_frame(self):
    self.docx_frame = JFrame("Configure .docx report")
    self.docx_frame.setLayout(GridBagLayout())
    self.docx_frame.setAlwaysOnTop(True)
    self.docx_frame.setSize(800, 600)
    self.docx_frame.setLocationRelativeTo(None)  
    self.docx_frame.toFront()
    self.docx_frame.setAlwaysOnTop(True)

    c = GridBagConstraints()
    c.gridx = 0
    c.weightx = 0
    c.gridy = 0
    self.docx_frame.add(JLabel('Make sure your Python3 installation runs on windows by typing "py" on Powershell or python3 or bash'), c)
    c.gridy += 1
    c.weightx = 1
    c.fill = GridBagConstraints.HORIZONTAL
    self.python_path_textfield = JTextField()
    self.docx_frame.add(self.python_path_textfield, c)

    c.gridy += 1
    self.check_python_docx_modules = JButton("Check docx modules", actionPerformed = self.check_python_modules)
    self.docx_frame.add(self.check_python_docx_modules, c)

    c.gridy += 1
    self.python_msg = JTextArea()
    self.docx_frame.add(self.python_msg, c)

  def registerExtenderCallbacks(self, callbacks):
    """Import Burp Extender callbacks and execute some preliminary functions for setting up the extension when it's loaded with proper configurations"""
    self._callbacks = callbacks
    self._helpers = callbacks.helpers
    callbacks.setExtensionName("Headers")
    callbacks.registerContextMenuFactory(self)
    callbacks.addSuiteTab(self)
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.for_table = [] # Items in this table will be shown in the Header-Host table (left side of the screen) for Requests and Responses headers
    self.header_host_table = [] # This holds data in three columns with Headers, Unique headers and Hosts and it's used for saving data to a file
    self.for_req_table = []
    self.for_resp_table = []
    self.headers_already_in_table = []
    self.meta_headers_already_in_table = []
    self.last_len = 0
    self.last_len_meta = 0
    self.last_row = 0
    self.last_row_meta = 0
    ### global history1 # variable global con el history de requests
    history1 = self._callbacks.getProxyHistory()
    global burp_extender_instance
    burp_extender_instance = self
    self.config_dict = {}
    self.apply_config()
    self.compile_regex()
    self.create_advanced_config_frame()
    self.create_extra_info_window()
    self.get_categories_headers_length()
    self.read_headers()
    self.create_docx_frame()
    self.selected_host = ""
    self.selected_header = ""
    self.is_meta = False
    self.dic_host_unique_endpoint = {}
    
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
    
    if type == "security":
      if total != 0: #this is done to avoid dividing by zero. if there are no selected headers for a category, return brown color
        score = value * 255.0 / total
        if self.check_box_security.isSelected() and value >= int(self.threshold_count_security.getText()):
          score = 255.0
        elif self.check_box_security.isSelected() and value < int(self.threshold_count_security.getText()):
          score = 0.0
        elif score > 255.0:
          score = 255.0
        color = "#00{}00".format(hex(int(score)).split('0x')[1].zfill(2))
        # if there are no headers of this type show the symbol as brown, looks better
        return color.replace("#000000", "#707070")
      else:
        return "#707070"

    elif type == "dangerous":
      if total != 0:
        score = value * 255.0 / total
        if self.check_box_dangerous.isSelected() and value >= int(self.threshold_count_dangerous.getText()):
          score = 255.0
        elif self.check_box_dangerous.isSelected() and value < int(self.threshold_count_dangerous.getText()):
          score = 0.0
        elif score > 255.0:
          score = 255.0
        color = "#{}0000".format(hex(int(score)).split('0x')[1].zfill(2))
        return color.replace("#000000", "#707070")
      else:
        return "#707070"

    elif type == "potential":
      if total != 0:
        score = value * 255.0 / total
        if self.check_box_potentially_dangerous.isSelected() and value >= int(self.threshold_count_potentially_dangerous.getText()):
          score = 255.0
        elif self.check_box_potentially_dangerous.isSelected() and value < int(self.threshold_count_potentially_dangerous.getText()):
          score = 0.0
        elif score > 255.0:
          score = 255.0
        R_factor = hex(int(int(0x4F) * score)).split('0x')[1]
        G_factor = hex(int(int(0xC3) * score)).split('0x')[1]
        B_factor = hex(int(int(0xF7) * score)).split('0x')[1]
        color = "#{0}{1}{2}".format(R_factor.zfill(2), G_factor.zfill(2), B_factor.zfill(2))
        return color.replace("#000000", "#707070")
      else:
        return "#707070"

  def UpdateHeaders(self, event):
    """Get the latest version of the request and response headers file from the Github repo. The urllib2 takes some seconds to load, so it's only loaded if this function is ever called, to improve performance."""
    from urllib2 import urlopen #importo aqui esto para que tarde menos en cargar la extension. esta habia que instalarla o viene con jython por defecto? poner instrucciones si hace falta!!!
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
    
    
    if head.split(": ")[0].lower() in self.security_headers:
      extra_symbol = '<b><font color="#00FF00"> [ + ] </font><b>'
    elif head.split(": ")[0].lower() in self.dangerous_headers:
      extra_symbol = '<b><font color="#FF0000"> [ X ] </font><b>'
    elif head.split(": ")[0].lower() in self.potentially_dangerous_headers:
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
        
        host = self.find_host(req_headers)

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
    replace_here = replace_here.replace('[*]','<font color="{}"><b> * </b></font>'.format(self.color6)) 
    #replace_here = replace_here.replace('[*]','<font color="{}">[ * ]</font>'.format(self.color6)) 
    return replace_here

  def clicked_endpoint(self, tbl, from_click):
    """Fill the summary (panel at the right side of the extension tab) when an endpoint (either from the "Unique endpoints" table or from the "All endpoints table") is clicked. The summary contains the request and response headers, marked with symbols if they are security headers, dangerous headers, or potentially dangerous headers."""

    # update the headers categories to be considered, by looking at the checkboxes in the advanced config table
    self.read_headers()

    if from_click:
      val = tbl.getModel().getDataVector().elementAt(tbl.getSelectedRow())
    else:
      val = tbl.getModel().getDataVector().elementAt(0)
      tbl.setRowSelectionInterval(0, 0)

    # lo siguiente es porque se selecciona (en principio) un endpoint de la lista de uniques, que han sido modificados, y hay que encontrar el bueno
    for item in history1:
      request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
      req_headers = request.split('\r\n')
      iter_host = self.find_host(req_headers)
      endpoint = req_headers[0]
      match = False


      # the next three ifs are for matching to elements in the history if we choose from the unique endpoints or from all endpoints, must be processed differently for the comparison
      if tbl.getModel() == self.model_unique_endpoints and self.is_meta == False and iter_host == self.selected_host:
        match = self.replace_symbol(self.apply_regex(endpoint)) == val[0].split(' - ')[1].strip('<html>').strip('</html>') 
        
      if tbl.getModel() == self.model_unique_endpoints and self.is_meta == True and iter_host == self.selected_host:
        match = self.replace_symbol(self.apply_regex(endpoint)) == val[0]

      if tbl.getModel() == self.model_all_endpoints and iter_host == self.selected_host:
        match = endpoint == val[0].strip('<html>').strip('</html>')

      if match:
        host = self.find_host(req_headers) #del loop del history
        clicked_header = self.selected_header

        # Run this block and exit this function if an item from the Meta headers tab was clicked
        if self.is_meta:
          metas = []
          request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
          host = self.find_host(req_headers) #del loop del history
          response = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
          resp_headers = response.split('\r\n')
          for k, resp_head in enumerate(resp_headers[1:]):   
            if "Content-Type: text/html" in resp_head:
              resp_html_head = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[1].split('</head>')[0]#.encode('utf-8')
              metas = self.meta.findall(resp_html_head)

          buffer = "<h2><font color={}>Meta headers</font></h2>".format(self.color1)
          buffer += "<b>Host</b>: {}<br>".format(host) 
          buffer += "<b>Endpoint</b>: {}<br>".format(endpoint)
          for meta in metas:
            meta_line =  meta.encode('utf-8').replace('<','&lt;').replace('>','&gt;')
            # Add colors to the meta fields in the summary pannel
            meta_line = meta_line.replace('&lt;meta', '<font color={}>&lt;meta</font>'.format(self.color2))
            meta_line = meta_line.replace(' charset=', '<font color={}> charset</font>='.format(self.color3))
            meta_line = meta_line.replace(' name=', '<font color={}> name</font>='.format(self.color3))
            meta_line = meta_line.replace(' property=', '<font color={}> property</font>='.format(self.color3))
            meta_line = meta_line.replace(' http-equiv=', '<font color={}> http-equiv</font>='.format(self.color3))
            meta_line = meta_line.replace(' content=', '<font color={}> content</font>='.format(self.color3))
            meta_line = meta_line.replace('&gt;', '<font color={}>&gt;</font>'.format(self.color2))

            buffer += '<li>' + meta_line + '</li>\n'
          buffer += '</ul></html>'

          self.header_summary.setText(buffer)
          return


        if host == self.selected_host: # si coincide el host del history con el que clickamos en la tabla de headers. 
          buffer = ""

          self.header_summary.setText("")
          buffer += '<html><h2><font color="{}">Request headers:</h2>'.format(self.color1) + "\n"
          buffer += '<b>' + req_headers[0] + '</b>'
          buffer += '<ul padding-left=0>'
          for req_head in sorted(req_headers[1:]): # este for encuentra el Host header

              extra_symbol = self.extra_symbol(req_head)
 
              req_head = req_head.replace('<','< ')
              req_head_name = req_head.split(': ')[0]
              req_head_value = req_head.split(': ')[1]

              if req_head.split(": ")[0] != "Host" and req_head.split(": ")[0] == clicked_header:
                buffer += '<li><b>' + '<font color="{}">'.format(self.color1) + req_head_name + "</font>" + extra_symbol + '<font color="{}">: </font>'.format(self.color1) + req_head_value + "</b><br></li>"

              elif req_head.split(": ")[0] == "Host":
                buffer += '<li><b>' + extra_symbol + '<font color="white">' + req_head + "</font></b><br></li>"
              else:
                buffer += '<li><b>' + req_head_name + extra_symbol + ":</b> " + req_head_value + "<br></li>"

          buffer += "</ul><br>" * 2 + "<hr>" + "<br>" 
          buffer += '<h2><font color="{}">Response headers:</h2>'.format(self.color1)
          buffer += '<ul padding-left=0; width="10px">'

          response = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
          resp_headers = response.split('\r\n')

          self.missing_header_array = []
          for i in range(self.model_tab_config_security.getRowCount()):
            if self.model_tab_config_security.getValueAt(i,0):
              self.missing_header_array.append(self.model_tab_config_security.getValueAt(i,1))

          self.missing_header_array = list(map(lambda x: x.lower(), self.missing_header_array))
          for resp_head in sorted(resp_headers[1:]):
            #print(resp_head)
            try:
              self.missing_header_array.remove(resp_head.split(":")[0].lower())
            except:
              pass
            extra_symbol = self.extra_symbol(resp_head)

            resp_head = resp_head.replace('<','< ') #este es porque algunos headers tenian links en html y se renderizaba en cosas raras
            resp_head_name = resp_head.split(': ')[0]
            resp_head_value = resp_head.split(': ')[1]

            # highlight the clicked header on the summary 
            if resp_head.split(":")[0] == clicked_header:
              buffer += '<li><b>' + '<font color="{}">'.format(self.color1) + resp_head_name + "</font>" + extra_symbol + '<font color="{}">: </font>'.format(self.color1) + resp_head_value + "</b><br></li>"
            else:
              buffer += '<li><b>' + resp_head_name + extra_symbol + ":</b> " + resp_head_value + "<br></li>"

          buffer += '</ul><hr><b>Missing security headers:</b><ul>'
          for missing_header in self.missing_header_array:
            buffer += '<li><b><font color=\"orange\"> [ - ] </font> {}</b>'.format(missing_header.title())

          buffer += '</ul>'
          buffer += '<br><hr><font color=\"white\"><b>*Note:</b> Some enpoints don\'t return some headers sometimes. If you can\'t find the header you selected on the table to the left, please select other endpoint, perhaps from the \"All Endpoints\" tab.</font><br><hr>' 
          buffer += '<br>Color legend for headers names (check yourself if the value is correct):'
          buffer += '<ul>'
          buffer += '<li><b><font color="#00FF00"> [ + ] </font><b>: Security header</li>'
          buffer += '<li><b><font color="orange"> [ - ] </font><b>: Missing security header</li>'
          buffer += '<li><b><font color="#FF0000"> [ X ] </font><b>: Dangerous or too verbose header</li>'
          buffer += '<li><b><font color="#4FC3F7"> [ ? ] </font><b>: Potentially dangerous header</li>'
          self.header_summary.setText(buffer + "</html>")
          
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
        #print(set(all_hosts))
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

  def update_meta_endpoints(self, endpoint_table):
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
        #host = self.table_tab_req.getModel().getDataVector().elementAt(self.table_tab_req.getSelectedRow())[1]
        self.model_unique_endpoints.addRow( [ self.replace_symbol(entry[0]) ])
        

    self.table_unique_endpoints.setRowSelectionInterval(0,0) 
    self.clicked_endpoint(self.table_unique_endpoints, False)
    return

  def call_filter_endpoints(self, event):
    self.update_endpoints(self.endpoint_table1)
    return

  def determine_progress(self):
    #self.progressBar.setIndeterminate(1)
    self.progressBar.setIndeterminate(1)
    self.framewait.setLocationRelativeTo(None)
    self.framewait.setVisible(True)
    self.framewait.toFront()
    self.framewait.setAlwaysOnTop(True) 

  def update_endpoints_worker(self, endpoint_table):
    """Update the "Unique endpoints" table and the "All endpoints" table when a row in the Header-Host table (at the left side of the extension tab) is clicked. The endpoint tables show all the endpoints that exist in the Burp history for which the Host request header is the one clicked on the Header-Host table."""

    self.model_unique_endpoints.setRowCount(0)
    self.model_all_endpoints.setRowCount(0)
    self.unique_entries = []
    self.progressBar.setIndeterminate(0)
    self.progressBar.setValue(0)

    
    total_security = 0
    total_dangerous = 0
    total_potentially_dangerous = 0
    for i in range(self.model_tab_config_security.getRowCount()):
      total_security += self.model_tab_config_security.getValueAt(i,0)
    for i in range(self.model_tab_config_potentially_dangerous.getRowCount()):
      total_potentially_dangerous += self.model_tab_config_potentially_dangerous.getValueAt(i,0)
    for i in range(self.model_tab_config_dangerous.getRowCount()):
      total_dangerous += self.model_tab_config_dangerous.getValueAt(i,0)

    #meter filtro de endpoints
    keywords = self.filter_endpoints.getText().lower().split(',')

    
    for entry in endpoint_table:
      for keyword in keywords:
        #print('----')
        print (keyword.lower().strip())
        #print(entry[0].lower())
        if keyword.lower().strip() in entry[0].lower() or self.filter_endpoints.getText() == "To filter endpoints enter keywords (separated by a comma)" or self.filter_endpoints.getText() == "":
          self.model_all_endpoints.addRow(entry)

    for k_progress, entry in enumerate(endpoint_table):
      if k_progress % 5 == 0:
        self.progressBar.setValue(100 * k_progress // len(endpoint_table))

      entry[0] = self.apply_regex(entry[0])
      for keyword in keywords:
        if keyword.lower().strip() in entry[0].lower() or self.filter_endpoints.getText() == "To filter endpoints enter keywords (separated by a comma)" or self.filter_endpoints.getText() == "":
        
          if entry not in self.unique_entries:

            self.unique_entries.append(entry)
            #coger el host del elemento clickado en la tabla de la izda
            try:
              host = self.table_tab_req.getModel().getDataVector().elementAt(self.table_tab_req.getSelectedRow())[1]
            except:
              host = self.table_tab_resp.getModel().getDataVector().elementAt(self.table_tab_resp.getSelectedRow())[1]
            colors = self.to_get_colors(entry[0], host, True)  #colors es un dict


            symbols_color = {}
            for color in colors.keys():

              if color == "security":
                total = total_security
                #total = self.total_security_headers
              elif color == "potential":
                total = total_potentially_dangerous 
                #total = self.total_potential_headers
              elif color == "dangerous":
                total = total_dangerous 
                #total = self.total_dangerous_headers
              symbols_color[color] = self.ColorScore(colors[color], total, color)

            symbols_string = '<b><font color="{0}">[{1}+]</font><font color="{2}">[{3}?]</font><font color="{4}">[{5}X]</font></b> - '.format(symbols_color   ["security"], colors["security"], symbols_color["potential"], colors["potential"], symbols_color["dangerous"], colors["dangerous"])
            #symbols_string = '<b><font color="{0}">[+]</font><font color="{1}">[?]</font><font color="{2}">[X]</font></b> - '.format(symbols_color["security"],    symbols_color["potential"], symbols_color["dangerous"])
            #print(symbols_string +entry[0]+'</html>')

            ###################################
            #self.model_unique_endpoints.addRow( [symbols_string +  entry[0] + '</html>'])
            #print('<html>' + entry[0].replace('[*]', '<font color="{}">[*]</font>'.format(self.color1)) + '</html>')
            self.model_unique_endpoints.addRow( [ '<html>' + symbols_string + self.replace_symbol(entry[0]) + '</html>' ])
            '''if host in self.dic_host_unique_endpoint.keys():
              self.dic_host_unique_endpoint[host] = [entry[0]]
            else:
              self.dic_host_unique_endpoint[host].append(entry[0])'''
              

            #print( [ '<html>' + symbols_string + self.replace_symbol(entry[0]) + '</html>' ])
            #self.model_unique_endpoints.addRow( [ '<html>' + entry[0].replace('[*]', '<font color="{}">[*]</font>'.format(self.color1)) + '</html>'])
            #self.model_unique_endpoints.addRow( [ entry[0] ])
        

    self.table_unique_endpoints.setRowSelectionInterval(0,0) 
    self.clicked_endpoint(self.table_unique_endpoints, False)
    self.framewait.setVisible(False)
    return

  def update_endpoints(self, event):
    thread_show_progress = threading.Thread(target=self.determine_progress)
    update_endpoints_worker = threading.Thread(target=self.update_endpoints_worker, args=(endpoint_table,))
    thread_show_progress.start()
    update_endpoints_worker.start()

  def addRB( self, pane, bg, text ):
    """Add radio buttons"""
    button = JRadioButton(text,itemStateChanged = self.toggle)
    index = self.categories_tabs.getSelectedIndex()
    if index == 0 and text == 'Security headers':
      button.doClick()
      self.toggle
    if index == 1 and text == 'Potentially dangerous headers':
      button.doClick()
      self.toggle
    if index == 2 and text == 'Dangerous or verbose headers':
      button.doClick()
      self.toggle

    bg.add(pane.add(button))

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
    """Adds a new header supplied by the user to the corresponding category (security, dangerous, potentially dangerous). Not saved to file here, that is done with the button for persisting changes."""
    filename = self.file_to_add_headers
    text = self.header_to_add.getText()

    if filename == "security_headers.txt":
      self.table_config_security.append([True, text])
      self.model_tab_config_security.addRow([True, text])
      self.initial_count_security_headers += 1

    elif filename == "dangerous_headers.txt":
      self.table_config_dangerous.append([True, text])
      self.model_tab_config_dangerous.addRow([True, text])
      self.initial_count_dangerous_headers += 1

    elif filename == "potentially_dangerous_headers.txt":
      self.table_config_potentially_dangerous.append([True, text])
      self.model_tab_config_potentially_dangerous.addRow([True, text])
      self.initial_count_potentially_dangerous_headers += 1
      
    self.added_header_info.setText('Header "{0}" added to {1}'.format(text, filename))

  def remove_headers_from_categories(self, event):
    selected_tab = self.categories_tabs.getSelectedIndex()

    if selected_tab == 0:
      selected = self.table_tab_config_security.getSelectedRows()
      # we need to remove from the last selected to the first selected to avoid confusions when the table model resizes every time we remove an element
      for i in selected[::-1]:
        self.initial_count_security_headers -= 1
        #print(self.initial_count_security_headers)
        self.model_tab_config_security.removeRow(i)

    if selected_tab == 1:
      selected = self.table_tab_config_potentially_dangerous.getSelectedRows()
      for i in selected[::-1]:
        self.model_tab_config_potentially_dangerous.removeRow(i)
        self.initial_count_potentially_dangerous_headers -= 1

    if selected_tab == 2:
      selected = self.table_tab_config_dangerous.getSelectedRows()
      for i in selected[::-1]:
        self.model_tab_config_dangerous.removeRow(i)
        self.initial_count_dangerous_headers -= 1

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

    new_header_textfield = JTextField("New header")
    new_header_textfield.addActionListener(self.add_header_to_file)
    self.header_to_add = add_headers_panel.add(new_header_textfield)
    

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

    self.threshold_count_security.setText(str(len(self.table_config_security)))
    self.threshold_count_potentially_dangerous.setText(str(len(self.table_config_potentially_dangerous)))
    self.threshold_count_dangerous.setText(str(len(self.table_config_dangerous)))
    
    return
    
  def show_docx(self, event):
    self.docx_frame.setVisible(True)
    self.docx_frame.toFront()
    self.docx_frame.setAlwaysOnTop(True)

  def summary_update_hosts(self, event):
    unique_hosts = set([x[2] for x in self.header_host_table])
    self.output_hosts_summary_model.setRowCount(0)
    for host in sorted(unique_hosts):
      # para test los pongo todos a true, normalmente iran a false, pero intentar poner una forma de seleccionar todos con un boton
      self.output_hosts_summary_model.addRow([True, host])
      #self.output_hosts_summary_model.addRow([False, host])

  def data_from_request(self, item):  
    """ Returns header data from a request-response object """
    request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
    req_headers = request.split('\r\n')
    #iter_host = self.find_host(req_headers)
    endpoint = req_headers[0]
    unique_endpoint = self.apply_regex(endpoint.split(' ')[1])
    try: #some responses return None and the next split fails, for that reason the try-except is used
      response = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
    except:
      response = ''
    resp_headers = response.split('\r\n')
    return req_headers, endpoint, response, resp_headers, unique_endpoint
  
  def check_depth(self, url, depth):
    """takes a URL (example: /dev/admin) and returns the url of only the given depth (for example, /dev for depth==1).
    If depth==0 returns the whole URL. Depth can be useful if different directories in the webapp apply different headers
    (for example using nested .htaccess files???)"""
    url = url.split('?')[0]
    if depth == 0:
      return url
    url = url.split('/')
    return '/' + '/'.join(url[0:depth]).rstrip('/').lstrip('/')

  def summary_update_endpoints_worker(self):
    self.selected_output_hosts = []
    self.unique_endpoints_summary_model.setRowCount(0)
    self.progressBar.setIndeterminate(0)
    self.progressBar.setValue(0)
    if self.depth_textbox.getText() == "Depth (0=all; Default=1)":
      self.depth = 1
    else:
      if self.depth_textbox.getText().isnumeric():
        self.depth = int(self.depth_textbox.getText())
      else:
        self.depth_textbox.setText('Enter a number')
        


    '''self.dic_summary es un diccionario de diccionarios, que contiene como keys los issue_types, y como
    valor para cada key otra diccionario, cuyas keys son los host y para cada host el value es una lista
    de las unique urls afectadas'''
    self.dic_summary = {
                        "Missing Security Headers":{},
                        "Dangerous Headers":{},
                        "Potentially Dangerous Headers":{},
                        "Bad HTTP Methods":{},
                        "Cookies Without Flags":{}
                        }

    # adds the selected hosts to a new array, works well
    for i in range(self.output_hosts_summary_model.getRowCount()):
      if self.output_hosts_summary_model.getValueAt(i,0) == True:
        to_add = self.output_hosts_summary_model.getValueAt(i,1)
        self.selected_output_hosts.append(to_add)



    for k_progress, item in enumerate(history1):
      if k_progress % 10 == 0:
        self.progressBar.setValue(100 * k_progress // len(history1))

      host = item.getHost()

      req_headers, endpoint, response, resp_headers, unique_endpoint = self.data_from_request(item)


      if host in self.selected_output_hosts:
        req_headers, endpoint, response, resp_headers, unique_endpoint = self.data_from_request(item)

        ### - bad http methods
        '''http_method = endpoint.split(' ')[0]
        if http_method in ['PUT', 'TRACE', 'DELETE']:
          self.unique_endpoints_summary_model.addRow([True, "Bad HTTP methods", host, self.apply_regex(url)])
          if host not in self.dic_summary["Bad HTTP Methods"].keys() : #si no exite el host, anadelo
            self.dic_summary["Bad HTTP Methods"][host] = []
          if self.apply_regex(url) not in self.dic_summary["Bad HTTP Methods"][host]: # si para ese host no esta la url unique, anadela
            self.dic_summary["Bad HTTP Methods"][host].append("Method: " + http_method + "; URL: " + self.appl_regex(url))'''


        ##################################### HAY MAS FLAGS, MIRAR AQUI: https://www.invicti.com/learn/cookie-security-flags/
        for header in resp_headers:
          
          ### - cookies without flags
          #self.flags= ['secure','httponly']
          for flag in self.cookie_flags:
            if self.checkbox_cookies.isSelected():
              if 'set-cookie' in header.lower():
                if flag not in header.lower():
                  if host not in self.dic_summary["Cookies Without Flags"].keys():
                    self.dic_summary["Cookies Without Flags"][host] = []

                  string_to_add = 'Missing "{}" header - URL: '.format(flag.title()) + self.check_depth(unique_endpoint, self.depth)
                  if string_to_add not in self.dic_summary["Cookies Without Flags"][host]:
                    self.unique_endpoints_summary_model.addRow([True, "Cookies without flags", host, string_to_add])
                    self.dic_summary["Cookies Without Flags"][host].append(string_to_add)


            
          ### - missing security headers
          if self.checkbox_missing_security.isSelected():
            pass
            #print('iiiiiiiiiiiiii')
            #print(self.security_headers)
            #print('iiiiiiiiiiiiii')


          ### - dangerous header
          if self.checkbox_dangerous.isSelected():
            for dangerous_header in self.dangerous_headers:
              if dangerous_header in header.lower():
                if host not in self.dic_summary["Dangerous Headers"].keys():
                  self.dic_summary["Dangerous Headers"][host] = []

                string_to_add = '"{0}" header - URL: {1}'.format(dangerous_header.title(), self.check_depth(unique_endpoint, self.depth))
                if string_to_add not in self.dic_summary["Dangerous Headers"][host]:
                  self.unique_endpoints_summary_model.addRow([True, "Dangerous header", host, string_to_add])
                  self.dic_summary["Dangerous Headers"][host].append(string_to_add)
          
          ### - potentially dangerous
          if self.checkbox_potentially_dangerous.isSelected():
            for potentially_dangerous_header in self.potentially_dangerous_headers:
              if potentially_dangerous_header in header.lower():
                if host not in self.dic_summary["Potentially Dangerous Headers"].keys():
                  self.dic_summary["Potentially Dangerous Headers"][host] = []

                string_to_add = '"{0}" header - URL: {1}'.format(potentially_dangerous_header.title(), self.check_depth(unique_endpoint, self.depth))
                if string_to_add not in self.dic_summary["Potentially Dangerous Headers"][host]:
                  self.unique_endpoints_summary_model.addRow([True, "Potentially Dangerous header", host, string_to_add])
                  self.dic_summary["Potentially Dangerous Headers"][host].append(string_to_add)
 


    self.framewait.setVisible(False)

  def summary_update_endpoints(self, event):
    thread_show_progress = threading.Thread(target=self.determine_progress)
    summary_update_endpoints_worker = threading.Thread(target=self.summary_update_endpoints_worker)
    thread_show_progress.start()
    summary_update_endpoints_worker.start()

  def create_summary(self):
    self.summary_frame = JFrame("Summary")
    self.summary_frame.setLayout(BorderLayout())
    self.summary_frame.setSize(1200, 600)
    self.summary_frame.setLocationRelativeTo(None)  

    colNames_left = ("Include?", "Host" )

    self.depth = 0

    c = GridBagConstraints()
    c.gridx = 0
    c.gridy = 0
    c.weightx = 1
    c.weighty = 1
    c.fill = GridBagConstraints.BOTH
    
    self.output_hosts_summary_model = SummaryTableModel_left([], colNames_left)
    self.output_hosts_summary_table = JTable(self.output_hosts_summary_model)
    self.output_hosts_summary_table.getColumnModel().getColumn(0).setPreferredWidth(60)
    self.output_hosts_summary_table.getColumnModel().getColumn(0).setMaxWidth(60)

    c.fill = GridBagConstraints.HORIZONTAL  
    c.gridy += 1
    

    c.fill = GridBagConstraints.BOTH
    c.gridy += 1
    colNames_right = ("Report?", "Issue type", "Host", "Details" )
    self.unique_endpoints_summary_model = SummaryTableModel_right([], colNames_right)

    summary_all_table = JTable(self.unique_endpoints_summary_model)

    summary_all_table.getColumnModel().getColumn(0).setPreferredWidth(60)
    summary_all_table.getColumnModel().getColumn(0).setMaxWidth(60)
    summary_all_table.getColumnModel().getColumn(1).setPreferredWidth(60)
    summary_all_table.getColumnModel().getColumn(2).setPreferredWidth(60)
    summary_all_table.getColumnModel().getColumn(3).setPreferredWidth(60)

    left_panel = JPanel(GridBagLayout())
    c = GridBagConstraints()
    c.anchor = GridBagConstraints.WEST
    
    button_update_hosts = JButton('<html><font color="white">Update Hosts</font></html>',actionPerformed=self.summary_update_hosts)
    button_update_for_selected_hosts = JButton('<html><font color="white">Update for selected Hosts</font></html>', actionPerformed=self.summary_update_endpoints)
    
    button_update_hosts.putClientProperty("html.disable", None)
    button_update_for_selected_hosts.putClientProperty("html.disable", None)

    button_update_hosts.setBackground(Color(10,101,247))
    button_update_for_selected_hosts.setBackground(Color(10,101,247))

    left_panel.add(button_update_hosts,c)
    left_panel.add(button_update_for_selected_hosts,c)

    c.weightx = 1
    self.checkbox_missing_security = JCheckBox("Missing security headers")
    self.checkbox_potentially_dangerous = JCheckBox("Potentially Dangerous headers")
    self.checkbox_dangerous = JCheckBox("Dangerous or verbose headers")
    self.checkbox_cookies = JCheckBox("Cookies without flags")
    #self.depth_label = JLabel("Depth (0 = all)\0")
    #self.depth_label.putClientProperty("html.disable", None)
    self.depth_textbox = JTextField("Depth (0=all; Default=1)")

    self.checkbox_missing_security.setSelected(True)
    self.checkbox_potentially_dangerous.setSelected(True)
    self.checkbox_dangerous.setSelected(True)
    self.checkbox_cookies.setSelected(True)

    left_panel.add(self.checkbox_missing_security, c)
    left_panel.add(self.checkbox_potentially_dangerous, c)
    left_panel.add(self.checkbox_dangerous, c)
    left_panel.add(self.checkbox_cookies, c)
    #c.anchor = GridBagConstraints.EAST
    #left_panel.add(self.depth_label, c)
    #c.anchor = GridBagConstraints.WEST
    c.weightx = 2
    c.fill = GridBagConstraints.HORIZONTAL
    left_panel.add(self.depth_textbox, c)

    self.summary_frame.add(left_panel, BorderLayout.NORTH)

    split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.output_hosts_summary_table), JScrollPane(summary_all_table))
    split.setDividerLocation(200)
    self.summary_frame.add(split, BorderLayout.CENTER)  

    right_panel = JPanel(GridBagLayout())
    c = GridBagConstraints()
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    c.weightx = 0
    right_panel.add(JButton("Choose output file"), c)
    c.weightx = 1
    right_panel.add(JTextField("Output file"), c)
    c.anchor = GridBagConstraints.WEST
    c.weightx = 0
    right_panel.add(JButton(".docx report", actionPerformed = self.show_docx), c)
    self.summary_frame.add(right_panel, BorderLayout.SOUTH)
    
  def show_summary(self, event):
    self.summary_frame.setVisible(True)
    self.summary_frame.toFront()
    self.summary_frame.setAlwaysOnTop(True)
  
  def getUiComponent(self):
    """Builds the interface of the extension tab."""

    self.framewait = JFrame()
    self.panelwait = JPanel()
    self.panelwait.setLayout(BoxLayout(self.panelwait, BoxLayout.Y_AXIS))
    self.framewait.setSize(350, 100)
    self.panelwait.add(JLabel("Please wait, may take some time..."))
    self.panelwait.add(JLabel(" "))
    self.progressBar = JProgressBar()
    self.progressBar.setMaximum(100)
    self.progressBar.setMinimum(1)
    self.panelwait.add(self.progressBar)
    self.framewait.add(self.panelwait)



    self.create_summary()

    panel = JPanel(GridBagLayout())
    
    # ================== Add button and filter ===================== #
    JPanel1 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.gridx = 0 
    y_pos = 0
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    #self.filter_but = JButton('<html><b><font color="white">Update table</font></b></html>', actionPerformed = self.filter_entries)
    self.filter_but = JButton('<html><b><font color="white">Update</font></b></html>', actionPerformed = self.filter_entries)
    self.filter_but.putClientProperty("html.disable", None)
    self.filter_but.setBackground(Color(210,101,47))
    JPanel1.add( self.filter_but, c )


    self.preset_filters = DefaultComboBoxModel()
    self.preset_filters.addElement("Request + Response + <meta>")
    self.preset_filters.addElement("Request + Response")
    self.preset_filters.addElement("In scope only (se puede acceder al scope???)")
    self.preset_filters.addElement("Security headers only")
    self.preset_filters.addElement("Potentially dangerous headers only")
    self.preset_filters.addElement("Dangerous or unnecessary headers only")

    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx += 1 
    self.filterComboBox = JComboBox(self.preset_filters)
    JPanel1.add(self.filterComboBox , c )

    c.weightx = 8
    c.gridx += 1 
    self.filter = JTextField('To filter headers enter keywords (separated by a comma)')
    dim = Dimension(500,23)
    self.filter.setPreferredSize(dim)
    self.filter.addActionListener(self.filter_entries)
    JPanel1.add(self.filter , c )

    c.weightx = 8
    c.gridx += 1 
    # en este y el anterior intentaba meter las hints en la textbox con la clase de arriba, pero no va y es complicado, la converti de java y seguro que falta algo
    #self.filter_endpoints = HintTextField('To filter endpoints enter keywords (separated by a comma)', True)
    self.filter_endpoints = JTextField('To filter endpoints enter keywords (separated by a comma)')
    dim = Dimension(500,23)
    self.filter_endpoints.setPreferredSize(dim)
    self.filter_endpoints.addActionListener(self.call_filter_endpoints)
    JPanel1.add(self.filter_endpoints , c )

    c.weightx = 0
    c.gridx += 1
    c.gridy = y_pos
    a=os.getcwd() + '\\gear_2.png'
    image_path=a.encode('string-escape')  #ver si esto falla al coger en linux el icono
    self.advanced_config_button = JButton(ImageIcon(image_path))
    self.advanced_config_button.addActionListener(self.show_advanced_config)
    self.advanced_config_button.setPreferredSize(Dimension(23, 23))
    JPanel1.add(self.advanced_config_button, c)

    c = GridBagConstraints()
    y_pos =0
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    panel.add(JPanel1 , c)

    # ================== Add small separation between filter and tables (Consider removing) ===================== #

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.fill = GridBagConstraints.HORIZONTAL
    c.anchor = GridBagConstraints.WEST
    text1 = JLabel("<html><hr></html> ")
    text1.putClientProperty("html.disable", None)
    panel.add( text1 , c)

    # ================== Add table ===================== #

    c = GridBagConstraints()
    y_pos += 1
    c.gridy = y_pos 
    c.weighty = 2
    c.weightx = 2
    c.fill = GridBagConstraints.BOTH

    #todas las columnas del archivo: header name && description && example &&  (permanent, no se que es esto) &&
    self.colNames = ('Header name','Appears in Host')
    self.colNames_meta = ('Meta header identifier','Meta header content')

    self.model_tab_req = IssueTableModel([["",""]], self.colNames)
    self.table_tab_req = IssueTable(self.model_tab_req, "tab")
    self.table_tab_req.getColumnModel().getColumn(0).setCellRenderer(RawHtmlRenderer())
    self.table_tab_req.getColumnModel().getColumn(1).setCellRenderer(RawHtmlRenderer())
    self.table_tab_req.putClientProperty("html.disable", None)
    #im = self.table_tab_req.getInputMap(JTable.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
    #im.put(KeyStroke.getKeyStroke("DOWN"), self.printxx)
    #im.put(KeyStroke.getKeyStroke("DOWN", 0), self.printxx)

    self.table_tab_req.getColumnModel().getColumn(0).setPreferredWidth(130)
    self.table_tab_req.getColumnModel().getColumn(0).setMaxWidth(130)
    self.table_tab_req.getColumnModel().getColumn(1).setPreferredWidth(100)

    self.model_tab_resp = IssueTableModel([["",""]], self.colNames)
    self.table_tab_resp = IssueTable(self.model_tab_resp, "tab")
    self.table_tab_resp.getColumnModel().getColumn(0).setCellRenderer(RawHtmlRenderer())
    self.table_tab_resp.getColumnModel().getColumn(1).setCellRenderer(RawHtmlRenderer())

    self.table_tab_resp.getColumnModel().getColumn(0).setPreferredWidth(100)
    self.table_tab_resp.getColumnModel().getColumn(1).setPreferredWidth(100)

    self.model_tab_meta = IssueTableModel([["",""]], self.colNames_meta)
    self.table_tab_meta = IssueTable(self.model_tab_meta, "meta")
    self.table_tab_meta.getColumnModel().getColumn(0).setCellRenderer(RawHtmlRenderer())
    self.table_tab_meta.getColumnModel().getColumn(1).setCellRenderer(RawHtmlRenderer())

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


    self.model_unique_endpoints = IssueTableModel([[""]], ["Unique endpoints for selected host"])
    self.table_unique_endpoints = IssueTable(self.model_unique_endpoints, "endpoints")
    self.table_unique_endpoints.getColumnModel().getColumn(0).setCellRenderer(RawHtmlRenderer())

    self.model_all_endpoints = IssueTableModel([[""]], ["All endpoints for selected host"])
    self.table_all_endpoints = IssueTable(self.model_all_endpoints, "endpoints")

    
    self.endpoint_tabs = JTabbedPane()
    self.endpoint_tabs.addTab('Unique endpoints', JScrollPane(self.table_unique_endpoints))
    self.endpoint_tabs.addTab('All endpoints', JScrollPane(self.table_all_endpoints))
    

    self.header_summary = JEditorPane("text/html", "")
    self.header_summary.putClientProperty("html.disable", None)
    self.scroll_summary = JScrollPane(self.header_summary)

    self.summary_summary = JEditorPane("text/html", "")
    self.scroll_summary_summary = JScrollPane(self.summary_summary)

    self.summary_panel = JPanel()
    self.summary_panel.setLayout(BorderLayout())
    self.summary_panel.add(self.scroll_summary, BorderLayout.CENTER)

    self.splt_2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,self.endpoint_tabs, self.summary_panel)

    self.splt_1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,JScrollPane(self.tab_tabs), self.splt_2) 
    #self.splt_1.setDividerLocation(300)
    panel.add(self.splt_1, c)

    # ================== Add saving to file ===================== #
    JPanel2 = JPanel(GridBagLayout())

    c = GridBagConstraints()
    c.gridx = 0 
    c.gridy = y_pos
    c.anchor = GridBagConstraints.WEST
    self.save_but = JButton('<html><b><font color="white">Save headers</font></b></html>', actionPerformed = self.save_json)
    self.save_but.putClientProperty("html.disable", None)
    self.save_but.setBackground(Color(10,101,247))
    JPanel2.add( self.save_but, c )



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

    c.gridx += 1 
    c.gridy = y_pos
    self.choose_file_but = JButton('<html><b><font color="white">Choose output file</font></b></html>', actionPerformed = self.choose_output_file)
    self.choose_file_but.putClientProperty("html.disable", None)
    JPanel2.add( self.choose_file_but, c )

    c.fill = GridBagConstraints.HORIZONTAL
    c.weightx = 1
    c.gridx += 1 
    c.gridy = y_pos
    self.save_path = JTextField('Save headers to... (write full path or click "Choose output file". The file will be created)')
    JPanel2.add(self.save_path , c )
    
    c.gridx += 1
    c.weightx = 0
    c.gridy = y_pos
    c.anchor = GridBagConstraints.EAST
    self.save_but = JButton('<html><b><font color="white">Summary</font></b></html>', actionPerformed = self.show_summary)
    self.save_but.putClientProperty("html.disable", None)
    self.save_but.setBackground(Color(10,101,247))
    JPanel2.add( self.save_but, c )

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
    self.model_tab_meta.setRowCount(0)
    self.for_table = []
    self.header_host_table = []
    self.for_req_table = []
    self.for_resp_table = []
    self.for_table_meta = []
    self.req_header_dict = {}
    self.resp_header_dict = {}
    self.headers_already_in_table = []
    self.meta_headers_already_in_table = []
    self.last_row = 0
    self.last_len = 0
    self.last_row_meta = 0
    self.last_len_meta = 0
    return

  def get_meta_tags(self):
    global history2
    history2 = []
    history2 = self._callbacks.getProxyHistory()
    self.meta_table = []

    keywords = self.filter.getText().lower().split(',')
    for item in history2: 
      ''' This try / except is because for some reason some entries fail somewhere here. also happens for the normal request responses, not only metas'''
      try:
        response = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[0]
        resp_headers = response.split('\r\n')
        for resp_head in resp_headers[1:]:   
          if "Content-Type: text/html" in resp_head:
            resp_html_head = self._helpers.bytesToString(item.getResponse()).split('\r\n\r\n')[1].split('</head>')[0]
            metas = self.meta.findall(resp_html_head)
            for meta in metas:
              if meta not in self.meta_table:
                request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
                req_headers = request.split('\r\n')
                host = self.find_host(req_headers)
                endpoint = req_headers[0]
                self.meta_table.append([host, endpoint, meta])
            break
      except:
        pass
      
    self.for_table_meta = [] # the two columns that appear on the meta tag in the left table
    meta_header_item = []
    for metax in self.meta_table:
      meta_values = metax[2].split(" ")
      host = metax[0]
      if len(meta_values[1:]) == 1: # if the meta tag has two items. 
        val = [meta_values[1], ""]
        if val not in self.for_table_meta:
          self.for_table_meta.append(val)
          meta_header_item.append(meta_values[1]) #only meta header first item, used below
      else: # if the meta tag has more than two items
        val = [meta_values[1], host]
        if val not in self.for_table_meta:
          self.for_table_meta.append(val) 
          meta_header_item.append(meta_values[1])


    self.for_table_meta_uniques = sorted([list(x) for x in list({tuple(i) for i in self.for_table_meta})]) 

    self.meta_headers_already_in_table = []

    #self.model_tab_meta.putClientProperty("html.disable", None)
    last_meta = ''
    k = 0
    for table_entry_meta in self.for_table_meta_uniques:
      for keyword in keywords:
        # Apply filter to meta headers
        if keyword.lower().strip() in table_entry_meta[0] or keyword.lower().strip() in table_entry_meta[1] or self.filter.getText() == "To filter headers enter keywords (separated by a comma)" or self.filter.getText() == "":

          if last_meta != table_entry_meta[0] and k > 0:
            self.model_tab_meta.insertRow(self.last_row_meta, ['<html><b><font color="{}">'.format(self.color1) + '-' * 300 + '</font></b></html>',     '<html><b><font color="{}">'.format(self.color1) + '-' * 300 + '</font></b></html>' * 300])
            self.last_row_meta += 1

          if table_entry_meta[0] not in self.meta_headers_already_in_table:
            self.meta_headers_already_in_table.append(table_entry_meta[0])
            self.model_tab_meta.insertRow(self.last_row_meta, table_entry_meta)
            self.last_row_meta += 1
          else:
            self.model_tab_meta.insertRow(self.last_row_meta, ["",table_entry_meta[1]])
            self.last_row_meta += 1
      last_meta = table_entry_meta[0]
      k += 1

    self.last_len_meta = len(history2)
    return

  def filter_entries_worker(self):
    """Applies the supplied filter(s) to the Header-Host table. If no filters are applied, all available entries are shown."""
    self.clear_table()
    self.read_headers()
    
    #if True:
    if self.preset_filters.getSelectedItem() == "Request + Response + <meta>":
      self.get_meta_tags() 

    global history1
    history1 = []
    history1 = self._callbacks.getProxyHistory()
    self.progressBar.setIndeterminate(0)
    for k_progress, item in enumerate(history1): # ver si puedo coger el index de la request para ponerlo luego en la endpoint table
      if k_progress % 20 == 0:
        self.progressBar.setValue(100 * k_progress // len(history1))

      # Sometimes some strange errors happen for some requests, with this we just skip them. 
      '''algunas fallan en algun punto de aqui dentro'''
      try:
        request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
        req_headers = request.split('\r\n')

        # -------- find the host for every request --------#
        host = self.find_host(req_headers)

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
  
        # anade a otra table las lineas que iran en la extension, poniendo celdas vacias en el header name para no repetir cuando hay varios host con el mismo  header
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
      except:
        request = self._helpers.bytesToString(item.getRequest()).split('\r\n\r\n')[0]
        req_headers = request.split('\r\n')
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
          self.header_host_table.append(["", "//---------------- REQUEST HEADERS -----------------//", "\n"]) # used for saving data to file in disk
          
        if k2 == len(req_keys) + 1:
          self.header_host_table.append(["\n", "//---------------- RESPONSE HEADERS -----------------//", "\n"]) # used for saving data to file in disk


        for host in self.header_dict[key]:
          # Apply the filter:
          keywords = self.filter.getText().lower().split(',')

          for keyword in keywords:
            if keyword.lower().strip() in host.lower() or keyword.lower() in key.lower() or self.filter.getText() == "To filter headers enter keywords (separated by a comma)":
              if [key, host] not in self.for_table:
                if k1 == 0 and key not in self.headers_already_in_table:
                  self.for_table.append(['<html><b><font color="{}">'.format(self.color1) + key + '</font></b></html>', host]) # used for displaying data in Host-Header table
                  ############## self.for_table.putClientProperty("html.disable", None)
                  added_something = True
                  self.header_host_table.append([key, key, host]) # used for saving data to file in disk
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
          self.for_table.append(['<html><b><font color="{}">'.format(self.color1) + '-' * 300 + '</font></b></html>', '<html><b><font color="{}">'.format(self.color1) + '-' * 300 + '</font></b></html>' * 300])

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

    self.framewait.setVisible(False)
    return

  def filter_entries(self, event):
    thread_show_progress = threading.Thread(target=self.determine_progress)
    filter_entries_worker = threading.Thread(target=self.filter_entries_worker)
    thread_show_progress.start()
    filter_entries_worker.start()

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
      host = self.find_host(req_headers)
      
      # -------------------- requests -------------------#
      for req_head in req_headers[1:]:
        req_head_name = req_head.split(': ')[0]
        try:
          description = dict_req_headers[req_head_name]
        except:
          description = " --- Description unavailable --- "
        if req_head_name not in self.aux_names_req:
          self.tableDataReq.append(['<html><b><font color="{}">'.format(self.color1) + req_head_name + '</b></font></html>', description, host])
        self.aux_names_req.append(req_head_name)
        self.tableDataReq.putClientProperty("html.disable", None)
    
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
          self.tableDataResp.append(['<html><b><font color="{}">'.format(self.color1) + resp_head_name + '</b></font></html>', description, host])
        self.aux_names_resp.append(resp_head_name)
        self.tableDataResp.putClientProperty("html.disable", None)

    self.tableDataReq.sort()      
    self.tableDataResp.sort()
    '''el numero en bytes es el valor binario de ascii, por ej N=78, y la newline que separa header y body es 0D 0A 0D 0A = 13 10 13 10 = \r\n\r\n'''

    # --------------- create tabs and place JTables inside -------------#
    #tab1 = JPanel()
    #tab2 = JPanel()

    frame = JFrame("Headers")
    frame.setSize(850, 350)
    #colNames = ('Header name','Header description')
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
    but.setToolTipText("Click to generate a new entry. Please, submit it to @dh0ck or create a pull request to XXX. It will be reviewed before approval. Thanks for contributing!!!")
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
    panelTab4.putClientProperty("html.disable", None)
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




