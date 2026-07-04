# bpf-load-c

The goal of the project is to explore how to compile C to eBPF and then install
it as a BPF_PROG_TYPE_CGROUP_DEVICE but do all of that without any help from
libbpf.

The practical use case is to replace snapd's original hand written BPF assembly
progrem seen here
https://github.com/canonical/snapd/blob/3f9c2337f3fce9458e34fcb806b052fdbffa072b/cmd/libsnap-confine-private/device-cgroup-support.c#L185-L241
with a piece of C code, which is easier to review and extend.

The requirements:
- must not rely on BTF
- it needs to be possible to generate the eBPF assembly from C locally and
  commit that to the source tree
- the generated output needs to contain textual information on llvm/clang used
  and likely a hash of the input file
- as first step, the gnerated code should be directly importable into C, e.g.
  through #include
  
