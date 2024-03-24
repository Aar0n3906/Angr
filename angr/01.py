import angr

p=angr.Project("C:/Users/Aar0n/Desktop/angr/01_angr_avoid")

init_state=p.factory.entry_state()

sm=p.factory.simulation_manager(init_state)
sm.explore(find=0x080492FB,avoid=0x080492BF)

found_state=sm.found[0]
found_state.posix.dumps(0)

print(found_state.posix.dumps(0))