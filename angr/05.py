import angr
import claripy

p=angr.Project("C:/Users/Aar0n/Desktop/angr/05_angr_symbolic_memory")

start_addr=0x08049318
init_state=p.factory.blank_state(addr=start_addr)

pass1 = init_state.solver.BVS('pass1',64)
pass2 = init_state.solver.BVS('pass2',64)
pass3 = init_state.solver.BVS('pass3',64)
pass4 = init_state.solver.BVS('pass4',64)

pass1_addr = 0x0B411140
pass2_addr = 0x0B411148
pass3_addr = 0x0B411150
pass4_addr = 0x0B411158

init_state.memory.store(pass1_addr,pass1)
init_state.memory.store(pass2_addr,pass2)
init_state.memory.store(pass3_addr,pass3)
init_state.memory.store(pass4_addr,pass4)

sm=p.factory.simgr(init_state)

def is_good(state):
    return b'Good Job.'in state.posix.dumps(1)

def is_bad(state):
    return b'Try again.'in state.posix.dumps(1)

sm.explore(find=is_good,avoid=is_bad)
if(sm.found):
    found_state = sm.found[0]
    passwd1 = found_state.solver.eval(pass1,cast_to=bytes).decode("utf-8")
    passwd2 = found_state.solver.eval(pass2,cast_to=bytes).decode("utf-8")
    passwd3 = found_state.solver.eval(pass3,cast_to=bytes).decode("utf-8")
    passwd4 = found_state.solver.eval(pass4,cast_to=bytes).decode("utf-8")

    print("Solutions-> {} {} {} {}".format(passwd1,passwd2,passwd3,passwd4))

else:
    raise Exception("Have no Solutions...")

