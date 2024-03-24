from angr import *
import claripy

p = Project('./08_angr_constraints')

start_addr = 0x8049360
start_state = p.factory.blank_state(addr = start_addr)

flag = claripy.BVS('flag', 8 * 16)
buffer_addr = 0x804C040

start_state.memory.store(buffer_addr, flag)

end_addr = 0x804929C
sm = p.factory.simgr(start_state)

sm.explore(find = end_addr)

if sm.found:
    end_state = sm.found[0]
    check = end_state.memory.load(buffer_addr, 16)
    cipher = "CCWOYSWFAXOQVZIR"
    end_state.add_constraints(check == cipher)
    print ("Solution: {}".format(end_state.solver.eval(flag, cast_to=bytes).decode("utf-8")))
else:
    raise Exception("Have no Solutions...")
