import importlib
import traceback
import logging

from icicle import UC_ARM_REG_PC

from ..exit import do_exit
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES
from ..util import parse_address_value

logger = logging.getLogger("emulator")

mmio_handlers = []
def mmio_access_handler_wrapper_hook(uc, access, address, size, value, user_data):
    global mmio_handlers

    curr_pc = uc.reg_read(UC_ARM_REG_PC)
    for start, end, pc, callback in mmio_handlers:
        if start <= address <= end and pc in (0, curr_pc):
            if callback(uc, access, address, size, value, user_data):
                # Request serviced
                break

def register_handler(start, end, pc, callback):
    global mmio_handlers
    mmio_handlers.append((start, end, pc, callback))

def custom_test_hook(uc, access, address, size, value, user_data):
    logger.info("Custom handler invoked for read at 0x{:08x}".format(address))
    return False

def get_entries():
    return mmio_handlers

def register_custom_handlers(uc, declarations):
    """
    Add a function hook.

    If func is None (and do_return is True) this is effectively a nop-out without using a real hook!
    Makes it faster to not have to call into python for hooks we don't need.
    """
    for entry in declarations.values():
        assert (
            'start' in entry and
            'end' in entry and
            'handler' in entry
        )
        start = entry['start']
        end = entry['end']
        func = entry['handler']
        if 'pc' in entry:
            pc = parse_address_value(uc.symbols, entry['pc'])
        else:
            # default value
            pc = MMIO_HOOK_PC_ALL_ACCESS_SITES

        try:
            # Resolve the function name
            mod_name, func_name = func.rsplit('.', 1)
            mod = importlib.import_module(mod_name)
            func_obj = getattr(mod, func_name)
            mmio_handlers.append((start, end, pc, func_obj))
        except:
            logger.error("Unable to hook function {} for range {:08x} - {:08x}".format(repr(func), start, end))
            traceback.print_exc()
            do_exit(uc, 1)
