import functools
import struct

import const
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# ghidra api
def find(find_bytes, min_addr=None):
    min_addr = min_addr or currentProgram.getMinAddress()
    return currentProgram.getMemory().findBytes(min_addr, find_bytes, None, True, monitor)

def create_label(addr, label_name, source=SourceType.USER_DEFINED):
    sym_table = currentProgram.getSymbolTable()
    sym_table.createLabel(addr, label_name, source)

def get_instructions_from(addr=None):
    return currentProgram.getListing().getInstructions(addr, True)

def get_all_instructions():
    return currentProgram.getListing().getInstructions(True)

def get_instruction_at(addr):
    return getInstructionAt(addr)

def get_memory_address_ranges():
    return currentProgram.getMemory().getAddressRanges()

def has_scalar_operand(inst, idx=1):
    return inst.getScalar(idx) is not None

def set_eol_comment(addr, text):
    code_unit = currentProgram.getListing().getCodeUnitAt(addr)
    code_unit.setComment(CodeUnit.EOL_COMMENT, text)

def get_function_containing(addr):
    return getFunctionContaining(addr)

def get_instructions_in_func(func):
    inst = get_instruction_at(func.getEntryPoint())
    while inst and getFunctionContaining(inst.getAddress()) == func:
        yield inst
        inst = inst.getNext()


# partial funcs
pack_uint64 = functools.partial(struct.pack, '<Q')
pack_long = functools.partial(struct.pack, '<L')

# global value
# generate scalar on operand and its address pairs
SCALAR_ADDR_PAIRS = {inst.getScalar(1).getValue(): inst.getAddress() for inst in filter(has_scalar_operand, get_all_instructions())}


class NonSparseConst:
    BYTE = 'B'
    LONG = 'L'
    UINT64 = 'Q'

    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.size = const['size']
        self.array = const['array']
        self._byte_array = None

    def handle_byte(self):
        return self.array

    def handle_long(self):
        return ''.join(map(pack_long, self.array))

    def handle_uint64(self):
        return ''.join(map(pack_uint64, self.array))

    def to_bytes(self):
        handler = {
            self.BYTE: self.handle_byte,
            self.LONG: self.handle_long,
            self.UINT64: self.handle_uint64
            # if there'll be another types, add handler here
        }.get(self.size)

        if handler is None:
            raise ValueError('{} is not supported'.format(self.size))
        
        return bytes(bytearray(handler()))

    @property
    def byte_array(self):
        if self._byte_array is None:
            self._byte_array = self.to_bytes()
        return self._byte_array
    
    @property
    def label_name(self):
        return '{alg}_{name}'.format(alg=self.algorithm, name=self.name)


class SparseConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.array = const['array']
    
    @property
    def label_name(self):
        return '{alg}_{name}'.format(alg=self.algorithm, name=self.name)

class OperandConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.value = const['value']
    
    @property
    def label_name(self):
        return '{alg}_{name}'.format(alg=self.algorithm, name=self.name)


def find_crypt_non_sparse_consts():
    print('[*] processing non-sparse consts')
    for nsc in map(NonSparseConst, const.non_sparse_consts):
        found = find(nsc.byte_array)
        if found:
            print(' [+] find {name} at {addr}'.format(name=nsc.label_name, addr=found))
            create_label(found, nsc.label_name)

def find_crypt_sparse_consts():
    print('[*] processing sparse consts')

    for sc in map(SparseConst, const.sparse_consts):
        # get address of first const matched one in operands 
        found_addr = SCALAR_ADDR_PAIRS.get(sc.array[0])
        if found_addr:
            # check the rest of consts, maybe it should be in the same function
            # it is noted that it will be failed if the constants are not used in function (like shellcode).
            maybe_crypto_func = get_function_containing(found_addr)
            insts = get_instructions_in_func(maybe_crypto_func)

            # get all scalars in same function
            insts_with_scalars = filter(has_scalar_operand, insts)
            scalars = map(lambda x: x.getScalar(1).getValue(), insts_with_scalars)

            # check all values in consts array are contained in scalars in same function 
            if all([c in scalars for c in sc.array]):
                # if all consts are contained
                # add comment at the first found const's address
                print(' [+] find {name} at {addr}'.format(name=sc.label_name, addr=found_addr))
                create_label(found_addr, sc.label_name)

def find_crypt_operand_consts():
    print('[*] processing operand consts')
    for oc in map(OperandConst, const.operand_consts):
        found_addr = SCALAR_ADDR_PAIRS.get(oc.value)
        if found_addr:
            print(' [+] find {name} at {addr}'.format(name=oc.label_name, addr=found_addr))
            set_eol_comment(found_addr, oc.label_name)

def main():
    find_crypt_non_sparse_consts()
    find_crypt_sparse_consts()
    find_crypt_operand_consts()


if __name__ == '__main__':
    main()