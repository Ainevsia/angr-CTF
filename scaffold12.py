# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr

p = angr.Project('12_angr_veritesting')

s = p.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

def is_successful(state):
    stdout_output = state.posix.dumps(1)
    return b'Good' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(1)
    return b'Try' in stdout_output

simgr = p.factory.simgr(s)
# simgr = p.factory.simgr(s, veritesting=True)

simgr.explore(find=is_successful, avoid=should_abort)

try:
    solution = simgr.found[0].posix.dumps(0).decode()
    print(solution)
except:
    raise Exception('Could not find the solution')