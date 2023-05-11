#ifndef __KVM_DUMP_H
#define __KVM_DUMP_H

struct data_t {
    __u32 pid;
    __u64 root_hpa;
    __u32 root_level;
    __u64 eptp;
};

#endif //__KVM_DUMP_H
