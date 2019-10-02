#define PROC_TASK_OFF (0x10)
#define PROC_P_PID_OFF (0x60)
#define OS_STRING_STRING_OFF (0x10)
#define OS_DICTIONARY_COUNT_OFF (0x14)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define IO_DT_NVRAM_OF_DICT_OFF (0xC0)
#define TASK_ITK_REGISTERED_OFF (0x2E8)
#define OS_DICTIONARY_DICT_ENTRY_OFF (0x20)
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define APPLE_MOBILE_AP_NONCE_GENERATE_NONCE_SEL (0xC8)
#define APPLE_MOBILE_AP_NONCE_BOOT_NONCE_OS_SYMBOL_OFF (0xC0)

#define ARM_PGSHIFT_4K (12U)
#define ARM_PGSHIFT_16K (14U)
#define KADDR_FMT "0x%" PRIx64
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define SHA384_DIGEST_LENGTH (48)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ARM_PGMASK (ARM_PGBYTES - 1ULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ARM_PGBYTES (1U << arm_pgshift)
#define IO_OBJECT_NULL ((io_object_t)0)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define kBootNoncePropertyKey "com.apple.System.boot-nonce"
#define kIONVRAMDeletePropertyKey "IONVRAM-DELETE-PROPERTY"
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))
#define kIONVRAMForceSyncNowPropertyKey "IONVRAM-FORCESYNCNOW-PROPERTY"



#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint64_t kaddr_t;
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_registry_entry_t;


typedef struct {
	kaddr_t sec_text_start;
	uint64_t sec_text_sz;
	void *sec_text;
	kaddr_t sec_cstring_start;
	uint64_t sec_cstring_sz;
	void *sec_cstring;
} pfinder_t;

typedef struct {
	kaddr_t key;
	kaddr_t value;
} dict_entry_t;

mach_port_t tfp0;
kaddr_t kbase, kslide;
pfinder_t pfinder;

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
IORegistryEntrySetCFProperty(io_registry_entry_t, CFStringRef, CFTypeRef);

kern_return_t
IOConnectCallStructMethod(io_connect_t, uint32_t, const void *, size_t, void *, size_t *);

kern_return_t
IOServiceClose(io_connect_t);

extern const mach_port_t kIOMasterPortDefault;

unsigned arm_pgshift;
kaddr_t allproc, our_task;


kern_return_t init_tfp0(void);

kern_return_t init_arm_pgshift(void);

kaddr_t get_kbase(kaddr_t *kslide);

kern_return_t pfinder_init(pfinder_t *pfinder, kaddr_t kbase);

kern_return_t pfinder_init_offsets(pfinder_t pfinder);

void pfinder_term(pfinder_t *pfinder);

kern_return_t sync_nonce(io_service_t nvram_serv);

io_service_t get_serv(const char *name);

uint64_t dimentio_find_os_string_addr();
