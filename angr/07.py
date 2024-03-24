import angr
import claripy

p=angr.Project("./07_angr_symbolic_file")

start_addr = 0x08049567
init_state = p.factory.blank_state(addr=start_addr)

filename = "PTRCUWFD.txt"
filesize = 0x40

passwd = init_state.solver.BVS("passwd",filesize*8)
sim_file = angr.storage.SimFile(filename,content=passwd,size=filesize)

init_state.fs.insert(filename,sim_file)

def good(state):
    return b'Good Job.'in state.posix.dumps(1)

def bad(state):
    return b'Try again.'in state.posix.dumps(1)

sm = p.factory.simgr(init_state)

sm.explore(find=good,avoid=bad)

if(sm.found):
    found_state = sm.found[0]

    passwd_bytes = found_state.solver.eval(passwd,cast_to=bytes).decode("utf-8")
    print("Solutions: {}".format(passwd_bytes))
else:
    raise Exception("Have No Solutions...")

