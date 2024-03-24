import angr
import claripy

p=angr.Project("C:/Users/Aar0n/Desktop/angr/06_angr_symbolic_dynamic_memory")

start_addr=0x0804938F

init_state=p.factory.blank_state(addr=start_addr)

print("esp: ",init_state.regs.esp)  #addr = 0x7fff0000

buf0 = 0x7fff0000-64
buf1 = 0x7fff0000-128

buf0_addr = 0x0A5B649C
buf1_addr = 0x0A5B64A4

init_state.memory.store(buf0_addr,buf0,endness=p.arch.memory_endness)
init_state.memory.store(buf1_addr,buf1,endness=p.arch.memory_endness)

pass1=init_state.solver.BVS('pass1',64)
pass2=init_state.solver.BVS('pass2',64)

init_state.memory.store(buf0,pass1)
init_state.memory.store(buf1,pass2)


sm = p.factory.simgr(init_state)

def good(state):
    return b'Good Job.'in state.posix.dumps(1)

def bad(state):
    return b'Try again.'in state.posix.dumps(1)

sm.explore(find=good,avoid=bad)

if(sm.found):
    found_state=sm.found[0]
    passwd1 = found_state.solver.eval(pass1,cast_to=bytes).decode("utf-8")
    passwd2 = found_state.solver.eval(pass2,cast_to=bytes).decode("utf-8")
    print("Solutions: {} {}".format(passwd1,passwd2))
else:
    raise Exception("Have no found...")