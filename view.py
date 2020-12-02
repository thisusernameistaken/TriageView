import traceback
import binaryninjaui
from binaryninja.settings import Settings
from binaryninja import log
from binaryninja.interaction import show_message_box
from binaryninja.binaryview import BinaryView
from binaryninjaui import View, ViewType, UIContext, ViewFrame, FileContext
from PySide2.QtWidgets import QGridLayout, QLabel, QScrollArea, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QGroupBox, QSplitter
from PySide2.QtCore import Qt
from PySide2.QtGui import QPalette, QColor
import os 
import re
os.environ['PWNLIB_NOTERM'] = "true"
from pwn import ELF,process
from . import headers
from . import entropy
from . import imports
from . import exports
from . import sections
from . import byte
from . import shared_libs

BinaryView.set_default_session_data("linker",{})
BinaryView.set_default_session_data("relocs",{})

class TriageView(QScrollArea, View):
    def __init__(self, parent, data):
        QScrollArea.__init__(self, parent)
        View.__init__(self)
        View.setBinaryDataNavigable(self, True)
        self.setupView(self)
        self.data = data
        self.currentOffset = 0
        self.byteView = None
        self.fullAnalysisButton = None
        self.importsWidget = None
        self.linker = shared_libs.Linker(self.data)
        self.lib_layout = None
        self.lib_group = None

        not_elf = False
        try:
            e = ELF(self.data.file.original_filename,checksec=False)
        except:
            not_elf = True

        container = QWidget(self)
        layout = QVBoxLayout()

        entropyGroup = QGroupBox("Entropy", container)
        entropyLayout = QVBoxLayout()
        entropyLayout.addWidget(entropy.EntropyWidget(entropyGroup, self, self.data))
        entropyGroup.setLayout(entropyLayout)
        layout.addWidget(entropyGroup)

        hdr = None
        try:
            if self.data.view_type == "PE":
                hdr = headers.PEHeaders(self.data)
            elif self.data.view_type != "Raw":
                hdr = headers.GenericHeaders(self.data)
        except:
            log.log_error(traceback.format_exc())

        if hdr is not None:
            headerSplitter = QSplitter(Qt.Horizontal)

            headerGroup = QGroupBox("Headers", container)
            headerLayout = QVBoxLayout()
            headerWidget = headers.HeaderWidget(headerGroup, hdr)
            headerLayout.addWidget(headerWidget)
            headerLayout.addStretch(1)
            headerGroup.setLayout(headerLayout)
            headerSplitter.addWidget(headerGroup)

            checkSecGroup = QGroupBox("CheckSec",container)
            checkLayout = QGridLayout()
            checkLayout.setSpacing(0)
            checkLayout.setAlignment(Qt.AlignTop|Qt.AlignLeft)
            p = re.compile("\s{2,}")
            d1 = p.sub("",e.checksec())
            check_data = d1.split("\n")
            for i,d in enumerate(check_data):
                s = d.split(":")
                label = QLabel(s[0]+":\t")
                checkLayout.addWidget(label,i,0)
                val = QLabel(s[1])
                red = ["No RELRO","No canary found", "NX disabled"]
                yellow = ["Partial RELRO"]
                pie = re.findall("No PIE",s[1])
                RWX = re.findall("RWX",s[1])
                if s[1] in red or len(pie)>0 or len(RWX)>0:
                    val.setStyleSheet("QLabel { color:red;}")
                elif s[1] in yellow:
                    val.setStyleSheet("QLabel { color:yellow;}")
                else:
                    val.setStyleSheet("QLabel { color:green;}")
                checkLayout.addWidget(val,i,1)
            checkSecGroup.setLayout(checkLayout)
            headerSplitter.addWidget(checkSecGroup)			
            layout.addWidget(headerSplitter)

        if self.data.executable:
            importExportSplitter = QSplitter(Qt.Horizontal)

            importGroup = QGroupBox("Imports", container)
            importLayout = QVBoxLayout()
            self.importsWidget = imports.ImportsWidget(importGroup, self, self.data)
            importLayout.addWidget(self.importsWidget)
            importGroup.setLayout(importLayout)
            importExportSplitter.addWidget(importGroup)

            exportGroup = QGroupBox("Exports", container)
            exportLayout = QVBoxLayout()
            exportLayout.addWidget(exports.ExportsWidget(exportGroup, self, self.data))
            exportGroup.setLayout(exportLayout)
            importExportSplitter.addWidget(exportGroup)

            layout.addWidget(importExportSplitter)

            if self.data.view_type != "PE":
                segmentsGroup = QGroupBox("Segments", container)
                segmentsLayout = QVBoxLayout()
                segmentsWidget = sections.SegmentsWidget(segmentsGroup, self.data)
                segmentsLayout.addWidget(segmentsWidget)
                segmentsGroup.setLayout(segmentsLayout)
                layout.addWidget(segmentsGroup)
                if len(segmentsWidget.segments) == 0:
                    segmentsGroup.hide()

            sectionSplitter = QSplitter(Qt.Horizontal)

            sectionsGroup = QGroupBox("Sections", container)
            sectionsLayout = QVBoxLayout()
            sectionsWidget = sections.SectionsWidget(sectionsGroup, self.data)
            sectionsLayout.addWidget(sectionsWidget)
            sectionsGroup.setLayout(sectionsLayout)
            sectionSplitter.addWidget(sectionsGroup)

            if len(sectionsWidget.sections) == 0:
                sectionsGroup.hide()

            if e.statically_linked == False:
                dynLibGroup = QGroupBox("Dynamic Libraries", container)
                dynLibLayout = QGridLayout()
                dynLibLayout.setSpacing(0)
                dynLibLayout.setAlignment(Qt.AlignTop|Qt.AlignLeft)
                cmd = "objdump -p {} | grep NEEDED".format(self.data.file.original_filename)
                libs_needed = process(cmd, shell=True).readall().split(b"\n")
                for index,lib in enumerate(libs_needed[:-1]):
                    s = lib.replace(b"  NEEDED               ",b"")
                    label = QLabel("Required:\t")
                    dynLibLayout.addWidget(label,index,0,Qt.AlignTop)
                    lib_name = QLabel(s.decode()+"\t")
                    dynLibLayout.addWidget(lib_name,index,1,Qt.AlignTop)
                    link = ClickableLabel("Add library file",self.add_lib,self.alreadyLinked,s.decode())
                    dynLibLayout.addWidget(link,index, 2)

                    # label = QLabel(self.linker[lib_name].file.filename)
                    # dynLibLayout.addWidget(label,index,2)
                    dynLibLayout.setRowStretch(index,0)
                    dynLibLayout.setColumnStretch(index,0)
                dynLibLayout.setContentsMargins(0,0,0,0)
                # dynLibLayout.addStretch(1)
                dynLibGroup.setLayout(dynLibLayout)   
                sectionSplitter.addWidget(dynLibGroup)


            layout.addWidget(sectionSplitter)
            self.lib_layout = layout
        else:
            self.byteView = byte.ByteView(self, self.data)
            layout.addWidget(self.byteView, 1)

        container.setLayout(layout)
        self.setWidgetResizable(True)
        self.setWidget(container)

        if self.fullAnalysisButton is not None and Settings().get_string("analysis.mode", data) == "full":
            self.fullAnalysisButton.hide()

    def add_lib(self,lib_name,uc=None):
        # dialog to open a shared object
        # open bv in new tab
        # create a shared db between both views to handle relocation
        # add plugin to right click, follow extern to other view
        lib_bv = self.linker.link_lib(lib_name,uc)
        self.linker.relocate()
        self.update_libs(lib_name,lib_bv)
        # -------------OLD--------------
        # create a bv for shared object
        # get code section
        # map it to segment of orginal bv
        # fix relocations to point to added funcs

    def getData(self):
        return self.data

    def getCurrentOffset(self):
        if self.byteView is not None:
            return self.byteView.getCurrentOffset()
        return self.currentOffset

    def getSelectionOffsets(self):
        if self.byteView is not None:
            return self.byteView.getSelectionOffsets()
        return (self.currentOffset, self.currentOffset)

    def setCurrentOffset(self, offset):
        self.currentOffset = offset
        UIContext.updateStatus(True)

    def getFont(self):
        return binaryninjaui.getMonospaceFont(self)

    def navigate(self, addr):
        if self.byteView:
            return self.byteView.navigate(addr)
        return False

    def startFullAnalysis(self):
        Settings().set_string("analysis.mode", "full", self.data)
        for f in self.data.functions:
            if f.analysis_skipped:
                f.reanalyze()
        self.data.update_analysis()
        self.fullAnalysisButton.hide()

    def navigateToFileOffset(self, offset):
        if self.byteView is None:
            addr = self.data.get_address_for_data_offset(offset)
            view_frame = ViewFrame.viewFrameForWidget(self)
            if view_frame is None:
                return
            if addr is None:
                view_frame.navigate("Hex:Raw", offset)
            else:
                view_frame.navigate("Linear:" + view_frame.getCurrentDataType(), addr)
        else:
            if self.data == self.data.file.raw:
                addr = offset
            else:
                addr = self.data.get_address_for_data_offset(offset)
            if addr is None:
                view_frame = ViewFrame.viewFrameForWidget(self)
                if view_frame is not None:
                    view_frame.navigate("Hex:Raw", offset)
            else:
                self.byteView.navigate(addr)
                self.byteView.setFocus(Qt.OtherFocusReason)

    def focusInEvent(self, event):
        if self.byteView is not None:
            self.byteView.setFocus(Qt.OtherFocusReason)

    def update_libs(self,lib_name,lib_bv):
        grid_layout = self.lib_layout.itemAt(4).widget().children()[0].children()[0]
        num_libs = grid_layout.count()//3
        print(num_libs)
        for i in range(num_libs):
            i = i*3
            if grid_layout.itemAt(i+1).widget().text().replace("\t","") == lib_name:
                link_label = grid_layout.itemAt(i+2).widget()
                link_label.setText(lib_bv.file.filename)
                link_label.setLib()
    
    def alreadyLinked(self,lib_name):
        lib_bv = self.data.session_data.linker[lib_name]
        found = shared_libs.find_tab(lib_bv)
        if found == False:
            uc = UIContext.activeContext()
            show_message_box("Unable to Find Tab","Tab with associated library is missing. Please Choose again")
            self.add_lib(lib_name,uc)

class ClickableLabel(QLabel):
    def __init__(self, text, func, func2, lib_name):
        super(ClickableLabel, self).__init__(text)
        self.setStyleSheet("text-decoration: underline; color: red;")
        self.setFont(binaryninjaui.getMonospaceFont(self))
        self.setFunction = func
        self.already_set = func2
        self.lib_name = lib_name
        self.lib_set = False

    def mousePressEvent(self, event):
        if self.lib_set == False:
            self.setFunction(self.lib_name)
        else:
            self.already_set(self.lib_name)
            
    def setLib(self):
        self.lib_set = True
        self.setStyleSheet("text-decoration: underline; color: green;")
    
class TriageViewType(ViewType):
    def __init__(self):
        super(TriageViewType, self).__init__("Triage", "Triage Summary")

    def getPriority(self, data, filename):
        is_full = Settings().get_string("analysis.mode", data) == "full"
        always_prefer = Settings().get_bool("triage.preferSummaryView", data)
        prefer_for_raw = Settings().get_bool("triage.preferSummaryViewForRaw", data)
        if data.executable and (always_prefer or not is_full):
            return 100
        if len(data) > 0:
            if always_prefer or data.executable or prefer_for_raw:
                return 25
            return 1
        return 0

    def create(self, data, view_frame):
        return TriageView(view_frame, data)


Settings().register_group("triage", "Triage")
Settings().register_setting("triage.preferSummaryView", """
    {
        "title" : "Prefer Triage Summary View",
        "type" : "boolean",
        "default" : false,
        "description" : "Always prefer Triage Summary View when opening a binary, even when performing full analysis."
    }
    """)

Settings().register_setting("triage.preferSummaryViewForRaw", """
    {
        "title" : "Prefer Triage Summary View for Raw Files",
        "type" : "boolean",
        "default" : false,
        "description" : "Prefer Triage Summary View when opening a binary that is Raw file type."
    }
    """)

ViewType.registerViewType(TriageViewType())
