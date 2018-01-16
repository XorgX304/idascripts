#
# This example tries to load a decompiler plugin corresponding to the current
# architecture (and address size) right after auto-analysis is performed,
# and then tries to decompile all the functions
#
# Run it with the following parameters:
# ida.exe -A -B -S"decompile.py" -L"c:\log\ida.txt" binary
#

from idaapi import *
import ida_hexrays

def main():
    ida_auto.auto_wait()

    ALL_DECOMPILERS = {
        ida_idp.PLFM_386 : ("hexrays", "hexx64"),
        ida_idp.PLFM_ARM : ("hexarm", "hexarm64"),
        ida_idp.PLFM_PPC : ("hexppc", "hexppc64"),
    }
    pair = ALL_DECOMPILERS.get(ida_idp.ph.id, None)
    if pair:
        decompiler = pair[1 if ida_ida.cvar.inf.is_64bit() else 0]
        if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
            eqty = ida_entry.get_entry_qty()
            if eqty:
                decompiled = []
                
                # For all entrypoints
                for i in xrange(0, eqty):
                    
                    # Get current ea
                    ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(i))
                    
                    # Get segment class
                    seg = getseg(ea)

                    # Loop from segment start to end
                    func_ea = seg.startEA

                    # Get a function at the start of the segment (if any)
                    func = get_func(func_ea)
                    if func is None:
                        # No function there, try to get the next one
                        func = get_next_func(func_ea)

                    seg_end = seg.end_ea
                    while func is not None and func.start_ea < seg_end:
                        funcea = func.start_ea
                        # Skip function if already decompiled
                        if get_func_name(funcea) not in decompiled:
                            decompiled.append(get_func_name(funcea))
                            print "Function %s at 0x%X" % (get_func_name(funcea), funcea)
                            print("Decompiling at: 0x%X" % funcea)
                            try:
                                cf = ida_hexrays.decompile(funcea)                    
                                if cf:
                                    print(cf)
                                else:
                                    print("Decompilation failed")
                            except:
                                print('')

                        func = get_next_func(funcea)

            else:
                print("No known entrypoint. Cannot decompile.")
        else:
            print("Couldn't load or initialize decompiler: \"%s\"" % decompiler)
    else:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
    print decompiled

main()
idc.Exit(0)
