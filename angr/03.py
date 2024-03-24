import angr
import claripy

p=angr.Project("C:/Users/Aar0n/Desktop/angr/03_angr_symbolic_registers")

start_addr=0x08049583
init_state=p.factory.blank_state(addr=start_addr)

pass1=claripy.BVS('pass1',32)
pass2=claripy.BVS('pass2',32)
pass3=claripy.BVS('pass3',32)

init_state.regs.eax=pass1
init_state.regs.ebx=pass2
init_state.regs.edx=pass3

sm=p.factory.simulation_manager(init_state)

def is_good(state):
    return b'Good Job.'in state.posix.dumps(1)

def is_bad(state):
    return b'Try again.'in state.posix.dumps(1)

sm.explore(find=is_good,avoid=is_bad)

if(sm.found):
    found_state=sm.found[0]

    passwd1 = found_state.solver.eval(pass1)
    passwd2 = found_state.solver.eval(pass2)
    passwd3 = found_state.solver.eval(pass3)
    print("Solution:{:x} {:x} {:x}".format(passwd1,passwd2,passwd3))
