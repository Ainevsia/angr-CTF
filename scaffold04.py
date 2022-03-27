# This challenge will be more challenging than the previous challenges that you
# have encountered thus far. Since the goal of this CTF is to teach symbolic
# execution and not how to construct stack frames, these comments will work you
# through understanding what is on the stack.
#   ! ! !
# IMPORTANT: Any addresses in this script aren't necessarily right! Dissassemble
#            the binary yourself to determine the correct addresses!
#   ! ! !

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary, auto_load_libs=False)

  # For this challenge, we want to begin after the call to scanf. Note that this
  # is in the middle of a function.
  #
  # This challenge requires dealing with the stack, so you have to pay extra
  # careful attention to where you start, otherwise you will enter a condition
  # where the stack is set up incorrectly. In order to determine where after
  # scanf to start, we need to look at the dissassembly of the call and the
  # instruction immediately following it:
  #   sub    $0x4,%esp
  #   lea    -0x10(%ebp),%eax
  #   push   %eax
  #   lea    -0xc(%ebp),%eax
  #   push   %eax
  #   push   $0x80489c3
  #   call   8048370 <__isoc99_scanf@plt>
  #   add    $0x10,%esp
  # Now, the question is: do we start on the instruction immediately following
  # scanf (add $0x10,%esp), or the instruction following that (not shown)?
  # Consider what the 'add $0x10,%esp' is doing. Hint: it has to do with the
  # scanf parameters that are pushed to the stack before calling the function.
  # Given that we are not calling scanf in our Angr simulation, where should we
  # start?
  # (!)
  start_address = 0x80493f2
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # We are jumping into the middle of a function! Therefore, we need to account
  # for how the function constructs the stack. The second instruction of the
  # function is:
  #   mov    %esp,%ebp
  # At which point it allocates the part of the stack frame we plan to target:
  #   sub    $0x18,%esp
  # Note the value of esp relative to ebp. The space between them is (usually)
  # the stack space. Since esp was decreased by 0x18
  #
  #        /-------- The stack --------\
  # ebp -> |                           |
  #        |---------------------------|
  #        |                           |
  #        |---------------------------|
  #         . . . (total of 0x18 bytes)
  #         . . . Somewhere in here is
  #         . . . the data that stores
  #         . . . the result of scanf.
  # esp -> |                           |
  #        \---------------------------/
  #
  # Since we are starting after scanf, we are skipping this stack construction
  # step. To make up for this, we need to construct the stack ourselves. Let us
  # start by initializing ebp in the exact same way the program does.
  initial_state.regs.ebp = initial_state.regs.esp

  # scanf("%u %u") needs to be replaced by injecting two bitvectors. The
  # reason for this is that Angr does not (currently) automatically inject
  # symbols if scanf has more than one input parameter. This means Angr can
  # handle 'scanf("%u")', but not 'scanf("%u %u")'.
  # You can either copy and paste the line below or use a Python list.
  # (!)
  password0 = claripy.BVS('password0', 32)
  password1 = claripy.BVS('password1', 32)
  
  initial_state.regs.esp -= 0x18
  initial_state.mem[initial_state.regs.ebp-0x10].uint32_t = password1
  initial_state.mem[initial_state.regs.ebp-0xc].uint32_t = password0

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0)
    solution1 = solution_state.solver.eval(password1)

    solution = f'''{solution0} {solution1}'''
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
