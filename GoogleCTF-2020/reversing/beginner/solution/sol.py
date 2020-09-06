# Adapted from https://github.com/angr/angr-doc/blob/master/examples/b01lersctf2020_little_engine/solve.py

import angr
import claripy


def get_flag():
    p = angr.Project("../a.out")

    # 15-character symbolic string
    flag_chars = [claripy.BVS("flag_%d" % i, 8) for i in range(15)]
    # Append a newline at the end of the first input
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

    # enable unicorn engine for fast efficient solving
    st = p.factory.full_init_state(
        args=["./../a.out"],
        add_options=angr.options.unicorn,
        stdin=flag,
    )
    # To get rid of the warning
    st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # constrain the flag characters to be a printable ascii characters.
    for k in flag_chars:
        st.solver.add(k < 0x7F)
        st.solver.add(k > 0x20)

    # Construct a simulation manager from the initial state (with the constraints) and run it.
    sm = p.factory.simulation_manager(st)
    sm.run()

    # Output the first final state with `SUCCESS` in the stdout
    y = []
    for x in sm.deadended:
        if b"SUCCESS" in x.posix.dumps(1):
            flag_out = x.posix.dumps(0)
            # parse it into a string
            flag = "".join([chr(flag_out[i]) for i in range(0, len(flag_out))]).strip()
            return flag

    raise Exception("Cannot find an input that results in SUCCESS.")


if __name__ == "__main__":
    flag = get_flag()
    print(flag)