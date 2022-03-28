# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.
import angr

p = angr.Project('13_angr_static_binary')
p.hook(0x080512f0,angr.SIM_PROCEDURES['libc']['printf']())
p.hook(0x08051340,angr.SIM_PROCEDURES['libc']['scanf']())
p.hook(0x0805ec90,angr.SIM_PROCEDURES['libc']['puts']())
p.hook(0x0806d530,angr.SIM_PROCEDURES['libc']['strcmp']())

s = p.factory.blank_state(
    addr=0x8049e1f,
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