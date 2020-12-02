from binaryninjaui import UIContext, DockHandler, UIActionHandler
from binaryninja.interaction import get_open_filename_input
from binaryninja.plugin import PluginCommand
from binaryninja import SymbolType, log


class Linker:
    def __init__(self,bv):
        self.base = bv
        self.libs = {}

    def link_lib(self,lib_name,uc=None):
        if uc ==None:
            uc = UIContext.activeContext()
        fname = get_open_filename_input("Link lib")
        uc.openFilename(fname.decode())
        dh = DockHandler.getActiveDockHandler()
        vf = dh.getViewFrame()
        ac = vf.actionContext()
        lib_bv = ac.binaryView
        self.libs[lib_name]=lib_bv
        self.base.session_data.linker=self.libs
        handler = UIActionHandler().actionHandlerFromWidget(dh.parent())
        handler.executeAction("Previous Tab")
        return lib_bv
    
    def relocate(self):
        imports = self.base.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
        rels = {}
        libs = self.base.session_data.linker
        for imprt in imports:
            for lib_name,lib_bv in libs.items():
                if imprt.name.endswith("@PLT"):
                    name = imprt.name[:-4]
                else:
                    name = imprt.name
                sym = lib_bv.get_symbol_by_raw_name(name)
                if sym != None:
                    rels[name] = {lib_bv:sym.address}
        self.base.session_data.relocs = rels
        return rels

def jumpToReloc(bv,addr):
    sym = bv.get_symbol_at(addr)
    sym_name = sym.name.split("@")[0]
    if sym != None and sym.type==SymbolType.ImportAddressSymbol:
        if sym_name in bv.session_data.relocs.keys():
            found = bv.session_data.relocs[sym_name]
            lib_bv = list(found.keys())[0]
            lib_name = lib_bv.file.filename
            address = found[lib_bv]
            log.log_info("Found {} in {} at {}".format(sym.name,lib_name,address))
            found = find_tab(lib_bv)
            if found:
                dh = DockHandler.getActiveDockHandler()
                vf = dh.getViewFrame()
                vf.navigate("Linear:"+vf.getCurrentDataType(),address)

def find_tab(lib_bv):
    not_found = True
    counter = 0
    while not_found:
        if counter == 20:
            log.log_error("Cant find tab")
            not_found = False
            return False
        counter +=1
        dh = DockHandler.getActiveDockHandler()
        handler = UIActionHandler().actionHandlerFromWidget(dh.parent())
        handler.executeAction("Next Tab")
        dh = DockHandler.getActiveDockHandler()
        vf = dh.getViewFrame()
        ac = vf.actionContext()
        bv = ac.binaryView
        if bv == lib_bv:
            not_found = False
            return True
    
PluginCommand.register_for_address("Follow call","Follow call to shared lib",jumpToReloc)

