import angr
import claripy

p=angr.Project("C:/Users/Aar0n/Desktop/angr/04_angr_symbolic_stack")

start_addr=0x080493F2
init_state=p.factory.blank_state(addr=start_addr)
padding_size = 8

init_state.stack_push(init_state.regs.ebp)
init_state.regs.ebp = init_state.regs.esp

init_state.regs.esp -= padding_size

pass1=init_state.solver.BVS('pass1',32)
pass2=init_state.solver.BVS('pass2',32)

init_state.stack_push(pass1)
init_state.stack_push(pass2)

#simulation_manager()==simgr() -->
sm=p.factory.simgr(init_state)

def is_good(state):
    return b'Good Job.'in state.posix.dumps(1)

def is_bad(state):
    return b'Try again.'in state.posix.dumps(1)

sm.explore(find=is_good,avoid=is_bad)

if sm.found:
    found_state=sm.found[0]
    passwd1 = found_state.solver.eval(pass1)
    passwd2 = found_state.solver.eval(pass2)
    print("Solutions-->{} {}".format(passwd1,passwd2))
else:
    raise Exception("Have no Solutions...")