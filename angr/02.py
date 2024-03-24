import angr
import sys


p=angr.Project("C:/Users/Aar0n/Desktop/angr/02_angr_find_condition")

init_state=p.factory.entry_state()
sm=p.factory.simulation_manager(init_state)


def is_good(state):
    return b'Good Job' in state.posix.dumps(1)

def is_bad(state):
    return b'Try again' in state.posix.dumps(1)

sm.explore(find=is_good,avoid=is_bad)

if(sm.found):
    found_state=sm.found[0]
    print("Simulation:{}".format(found_state.posix.dumps(0)))

