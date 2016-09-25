#!/usr/bin/env python2
## -*- coding: utf-8 -*-

from triton  import *
from ast     import *
from pintool import *

snapshot_done = False
argv1 = 0
symVarConstraints = []
PASSWORD_SIZE = 11
def superAnd(constraints):
    pathConstraints_and = ast.equal(bvtrue(), bvtrue())
    for i in range(len(constraints)):
        pathConstraints_and = ast.land(pathConstraints_and, constraints[i])
    return (pathConstraints_and)

def model2string(model):
    s = str()
    for i in range(PASSWORD_SIZE):
        try :s += chr(model[i].getValue())
        except: pass
    return s

def inject(address, data):
    for index, char in enumerate(data):
        setCurrentMemoryValue(address + index, ord(char))

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate


ENTRY = 0x4005b6
# basic blocks to avoid (reflecting password errors)
avoid = [ 0x40070c, 0x40071f, 0x40073c, 0x400755, 0x400774, 0x400793, 0x4007af, 0x4007d3, 0x40081b, 0x400853, 0x400878, 0x4008b9,  0x400952]
# basic blocks to take (reflecting password match)
take = [0x4007f7, 0x4008fa]

@static_vars(last_injected = "", numMandatoryPaths = 0)
def before_symproc(instruction):
    pathConstraints = []
    ins_addr = instruction.getAddress()

    if ins_addr in take:
        before_symproc.numMandatoryPaths = before_symproc.numMandatoryPaths + 1

    if (ins_addr in avoid) or\
            ((ins_addr == 0x4007fb) and (before_symproc.numMandatoryPaths != 1)) or\
            ((ins_addr == 0x4008fe) and (before_symproc.numMandatoryPaths !=2) ):
        before_symproc.numMandatoryPaths = 0
        print "[+] Wrong password"
        pco = getPathConstraints()
        for pc in pco:
            if pc.isMultipleBranches():
                for branch in pc.getBranchConstraints():
                    # filter out branch constraints which lead to addresses we want
                    # to avoid
                    if branch['dstAddr'] in avoid:
                        pathConstraints.append(lnot(branch['constraint']))
                    # force taking mandatory branches
                    if branch['dstAddr'] in take:
                        pathConstraints.append((branch['constraint']))

        # Get a model that will not go through previous bad password basic
        # blocks and verifiying that all inputs are printable (see symVarConstraints
        # creation)
        full_constraint = superAnd(symVarConstraints + pathConstraints)
        model = getModel(ast.assert_(full_constraint))
        string = model2string(model)
        before_symproc.last_injected = string
        print "[+] Possible solution : \"%s\" (%s)"\
            % (string, string.encode('hex'))
        string += "\x00"
        print "[+] Injecting it, and restoring snapshot"
        inject(argv1, string)
        clearPathConstraints()
        restoreSnapshot()
    if ins_addr == 0x40095c:
        print "[+] Good password: ", before_symproc.last_injected
        disableSnapshot()
        clearPathConstraints()
        setCurrentRegisterValue(REG.RIP, 0x40096b)


def before(inst):
    global snapshot_done
    global argv1
    ins_addr = inst.getAddress()

    if inst.getAddress() == ENTRY:
        if not snapshot_done:
            # On 64 bits archs rdi id arc and rsi is argv
            rsi = getCurrentRegisterValue(REG.RSI)
            argv1 = getCurrentMemoryValue(rsi + 8, CPUSIZE.REG)

            offset = 0
            # The binary is expecting a filname size of 11 bytes as the checks are
            # done on arv[1][0] to argv[1][10]
            # So we need to symbolize 9 bytes starting from &agrv[0][0]
            # Then we need to symbolize these 9 bytes
            while (offset < PASSWORD_SIZE):
                setCurrentMemoryValue(argv1 + offset, ord("_"))
                # symbolize current input (argv[1][offset])
                symvar = convertMemoryToSymbolicVariable(MemoryAccess(argv1 + offset, CPUSIZE.BYTE))
                # Inputs must be printable, so we add that constraint to each one
                # of the inputs:
                symVarConstraints.append(ast.bvuge(variable(symvar), bv(0x20,  8)))
                symVarConstraints.append(ast.bvule(variable(symvar), bv(0x7E, 8)))
                # Go get next input
                offset += 1
            # End it with a null char for strlen to work properly
            setCurrentMemoryValue(argv1 + offset, ord('\0'))
            print "[+] Symbolized %d bytes of memory at 0x%x" % (offset, argv1)

            print "[+] Taking snapshot"
            takeSnapshot()
            snapshot_done = True

def constantFolding(node):
    if node.isSymbolized():
        return node
    return ast.bv(node.evaluate(), node.getBitvectorSize())

if __name__ == '__main__':
    # Define the architecture
    setArchitecture(ARCH.X86_64)

    enableSymbolicOptimization(OPTIMIZATION.ALIGNED_MEMORY, True)
    enableSymbolicOptimization(OPTIMIZATION.ONLY_ON_SYMBOLIZED, True)
    # Start the symbolic analysis from the 'main' function
    startAnalysisFromAddress(ENTRY)

    # Add callbacks
    addCallback(constantFolding, CALLBACK.SYMBOLIC_SIMPLIFICATION)
    insertCall(before, INSERT_POINT.BEFORE)
    insertCall(before_symproc,   INSERT_POINT.BEFORE_SYMPROC)

    # Run the instrumentation - Never returns
    runProgram()

