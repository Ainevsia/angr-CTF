import angr
import claripy
import sys

def main(argv):
  path_to_binary = './06_angr_symbolic_dynamic_memory'
  project = angr.Project(path_to_binary, auto_load_libs=False)

  start_address = 0x804938f
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s").
  # (!)
  buffer0 = claripy.BVS('buffer0', 64)
  buffer1 = claripy.BVS('buffer1', 64)

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  fake_heap_address0 = 0xdeadbeef
  fake_heap_address1 = 0xcafebabe
  pointer_to_malloc_memory_address0 = project.loader.find_symbol('buffer0').rebased_addr
  pointer_to_malloc_memory_address1 = project.loader.find_symbol('buffer1').rebased_addr
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)
  
  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, buffer0)
  initial_state.memory.store(fake_heap_address1, buffer1)

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

    solution0 = solution_state.solver.eval(buffer0,cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(buffer1,cast_to=bytes).decode()
    solution = solution0 + ' ' + solution1

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
