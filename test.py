from burp import IBurpExtender,ITab
from javax.swing import JPanel, JButton, JTable, JScrollPane
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints, Point, Component, Color
from javax.swing.table import DefaultTableModel


class BurpExtender(IBurpExtender,ITab):
	def registerExtenderCallbacks(self, callbacks):
		callbacks.setExtensionName("hello woorld")
		callbacks.printOutput("hello")
		callbacks.addSuiteTab(self)
		return

	# para poner el nombre que sale en la tab
	def getTabCaption(self):
		return "hello world"
        
        def save_json():
            print("helloxxx")

	# detalles de la GUI
	def getUiComponent(self):
		panel = JPanel(GridBagLayout())
                c = GridBagConstraints()




                self.tableData = [
                  ['<html><b><font color=red>numbers</font></b></html>', '67890' ,'This'],
                  ['mo numbers', '2598790', 'is'],
                  ['got Math', '2598774', 'a'],
                  ['got Numbers', '1234567', 'Column'],
                  ['got pi','3.1415926', 'Apple'],
                   ]
                colNames = ('Col Labels','Go','Here')
                dataModel = DefaultTableModel(self.tableData, colNames)
                self.table = JTable(dataModel)

            
                scrollPane = JScrollPane()
                scrollPane.setPreferredSize(Dimension(300,100))
                scrollPane.getViewport().setView((self.table))
                c.gridx = 0 
                c.gridy = 0
                c.anchor = GridBagConstraints.WEST
                panel = JPanel()
                panel.add(scrollPane, c)
                        


		return panel
