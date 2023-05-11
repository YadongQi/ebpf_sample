
Useful commands
===============
```
    sudo apt install bpfcc-tools
    sudo trace-bpfcc 'r::construct_eptp "%llx, %x, %llx", arg2, arg3, retval'
```




Write C app for eBPF:
Sample:
```
mkdir ebpf_sample
cd ebpf_sample
git clone https://github.com/libbpf/libbpf-bootstrap.git
cd libbpf-bootstrap && git submodule update --init --recursive && cd -
git clone https://github.com/iovisor/bcc.git
cd bcc && git submodule update --init --recursive && cd -
cd bcc/src/cc/libbpf && git clone https://github.com/libbpf/libbpf.git . && cd -
cp kvm_dump.c kvm_dump.bpf.c kvm_dump.h bcc/libbpf-tools/
cd bcc/libbpf-tools/
# Modify Makefile to add kvm_dump to 'APP' target
make BPFTOOL_SRC=../../libbpf-bootstrap/bpftool/src CLANG=/usr/bin/clang-12
```
