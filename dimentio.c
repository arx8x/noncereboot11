#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include "dimentio.h"



// static task_t tfp0 = MACH_PORT_NULL;

uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0U >> (32U - length));
}

uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64U - length - start)) >> (64U - length));
}

kern_return_t
init_arm_pgshift(void) {
	int cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(!sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0)) {
		switch(cpufamily) {
			case CPUFAMILY_ARM_CYCLONE:
			case CPUFAMILY_ARM_TYPHOON:
				arm_pgshift = ARM_PGSHIFT_4K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TWISTER:
			case CPUFAMILY_ARM_HURRICANE:
			case CPUFAMILY_ARM_MONSOON_MISTRAL:
			case CPUFAMILY_ARM_VORTEX_TEMPEST:
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIx32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	task_dyld_info_data_t dyld_info;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	return 0;
}

kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz) {
		read_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

void *
kread_buf_alloc(kaddr_t addr, mach_vm_size_t read_sz) {
	void *buf = malloc(read_sz);

	if(buf) {
		if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
			return buf;
		}
		free(buf);
	}
	return NULL;
}

kern_return_t
kread_addr(kaddr_t addr, kaddr_t *value) {
	return kread_buf(addr, value, sizeof(*value));
}

kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz) {
		write_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
		if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

const struct section_64 *
find_section(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)(sgp + 1);
	uint32_t i;

	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->sec_text = pfinder->sec_cstring = NULL;
	pfinder->sec_text_start = pfinder->sec_text_sz = 0;
	pfinder->sec_cstring_start = pfinder->sec_cstring_sz = 0;
}

kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
	const struct segment_command_64 *sgp;
	kern_return_t ret = KERN_FAILURE;
	const struct section_64 *sp;
	struct mach_header_64 mh64;
	uint32_t i;
	void *ptr;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && (ptr = kread_buf_alloc(kbase + sizeof(mh64), mh64.sizeofcmds))) {
		sgp = (const struct segment_command_64 *)ptr;
		for(i = 0; i < mh64.ncmds; ++i) {
			if(sgp->cmd == LC_SEGMENT_64) {
				if(!strncmp(sgp->segname, SEG_TEXT_EXEC, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_TEXT))) {
					pfinder->sec_text_start = sp->addr;
					pfinder->sec_text_sz = sp->size;
					printf("sec_text_start: " KADDR_FMT ", sec_text_sz: 0x%" PRIx64 "\n", pfinder->sec_text_start, pfinder->sec_text_sz);
				} else if(!strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_CSTRING))) {
					pfinder->sec_cstring_start = sp->addr;
					pfinder->sec_cstring_sz = sp->size;
					printf("sec_cstring_start: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIx64 "\n", pfinder->sec_cstring_start, pfinder->sec_cstring_sz);
				}
			}
			if(pfinder->sec_text_sz && pfinder->sec_cstring_sz) {
				if((pfinder->sec_text = kread_buf_alloc(pfinder->sec_text_start, pfinder->sec_text_sz))) {
					if((pfinder->sec_cstring = kread_buf_alloc(pfinder->sec_cstring_start, pfinder->sec_cstring_sz))) {
						ret = KERN_SUCCESS;
					} else {
						free(pfinder->sec_text);
					}
				}
				break;
			}
			sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
		}
		free(ptr);
	}
	return ret;
}

kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	const uint32_t *insn = pfinder.sec_text;
	uint64_t x[32] = { 0 };
	size_t i;

	for(i = (start - pfinder.sec_text_start) / sizeof(*insn); i < pfinder.sec_text_sz / sizeof(*insn); ++i) {
		if(IS_LDR_X(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + LDR_X_IMM(insn[i]);
		} else if(IS_ADR(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + ADR_IMM(insn[i]);
		} else if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(pfinder.sec_text_start + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
			continue;
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + LDR_X_UNSIGNED_IMM(insn[i]);
		} else if(IS_RET(insn[i])) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn[i]) == rd) {
			if(to) {
				if(x[rd] == to) {
					return pfinder.sec_text_start + (i * sizeof(*insn));
				}
			} else {
				return x[rd];
			}
		}
	}
	return 0;
}

kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p = pfinder.sec_cstring, *e = p + pfinder.sec_cstring_sz;
	size_t len;

	do {
		len = strlen(p) + 1;
		if(!strncmp(str, p, len)) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text_start, pfinder.sec_cstring_start + (kaddr_t)(p - (const char *)pfinder.sec_cstring));
		}
		p += len;
	} while(p < e);
	return 0;
}

kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(!ref) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return ref ? pfinder_xref_rd(pfinder, 8, ref, 0) : 0;
}

kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder))) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

void
pfinder_term(pfinder_t *pfinder) {
	free(pfinder->sec_text);
	free(pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

io_service_t
get_serv(const char *name) {
	io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));

	return MACH_PORT_VALID(serv) ? serv : IO_OBJECT_NULL;
}

kaddr_t
get_port(mach_port_t port) {
	kaddr_t ipc_port = 0;

	if(mach_ports_register(mach_task_self(), &port, 1) == KERN_SUCCESS) {
		if(kread_addr(our_task + TASK_ITK_REGISTERED_OFF, &ipc_port) != KERN_SUCCESS) {
			ipc_port = 0;
		}
		mach_ports_register(mach_task_self(), NULL, 0);
	}
	return ipc_port;
}

kern_return_t
get_object(io_service_t serv, kaddr_t *object) {
	kaddr_t ipc_port;

	if((ipc_port = get_port(serv))) {
		printf("ipc_port: " KADDR_FMT "\n", ipc_port);
		return kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, object);
	}
	return KERN_FAILURE;
}

kern_return_t
nonce_generate(io_service_t nonce_serv) {
	uint8_t nonce_d[SHA384_DIGEST_LENGTH];
	size_t nonce_d_sz = sizeof(nonce_d);
	kern_return_t ret = KERN_FAILURE;
	io_connect_t nonce_conn;

	if(IOServiceOpen(nonce_serv, mach_task_self(), 0, &nonce_conn) == KERN_SUCCESS && MACH_PORT_VALID(nonce_conn)) {
		printf("nonce_conn: 0x%" PRIx32 "\n", nonce_conn);
		ret = IOConnectCallStructMethod(nonce_conn, APPLE_MOBILE_AP_NONCE_GENERATE_NONCE_SEL, NULL, 0, nonce_d, &nonce_d_sz);
		IOServiceClose(nonce_conn);
	}
	return ret;
}

kern_return_t
get_boot_nonce_os_symbol(io_service_t nonce_serv, kaddr_t *boot_nonce_os_symbol) {
	kaddr_t nonce_object;

	if(get_object(nonce_serv, &nonce_object) == KERN_SUCCESS) {
		printf("nonce_object: " KADDR_FMT "\n", nonce_object);
		return kread_addr(nonce_object + APPLE_MOBILE_AP_NONCE_BOOT_NONCE_OS_SYMBOL_OFF, boot_nonce_os_symbol);
	}
	return KERN_FAILURE;
}

kern_return_t
get_of_dict(io_service_t nvram_serv, kaddr_t *of_dict) {
	kaddr_t nvram_object;

	if(get_object(nvram_serv, &nvram_object) == KERN_SUCCESS) {
		printf("nvram_object: " KADDR_FMT "\n", nvram_object);
		return kread_addr(nvram_object + IO_DT_NVRAM_OF_DICT_OFF, of_dict);
	}
	return KERN_FAILURE;
}

kaddr_t
lookup_key_in_os_dict(kaddr_t os_dict, kaddr_t key) {
	kaddr_t os_dict_entry_ptr, value = 0;
	dict_entry_t *os_dict_entries;
	uint32_t i, os_dict_cnt;

	if(kread_buf(os_dict + OS_DICTIONARY_COUNT_OFF, &os_dict_cnt, sizeof(os_dict_cnt)) == KERN_SUCCESS && os_dict_cnt) {
		printf("os_dict_cnt: 0x%" PRIx32 "\n", os_dict_cnt);
		if(kread_addr(os_dict + OS_DICTIONARY_DICT_ENTRY_OFF, &os_dict_entry_ptr) == KERN_SUCCESS && os_dict_entry_ptr) {
			printf("os_dict_entry_ptr: " KADDR_FMT "\n", os_dict_entry_ptr);
			if((os_dict_entries = kread_buf_alloc(os_dict_entry_ptr, os_dict_cnt * sizeof(*os_dict_entries)))) {
				for(i = 0; i < os_dict_cnt; ++i) {
					printf("key: " KADDR_FMT ", value: " KADDR_FMT "\n", os_dict_entries[i].key, os_dict_entries[i].value);
					if(os_dict_entries[i].key == key) {
						value = os_dict_entries[i].value;
						break;
					}
				}
				free(os_dict_entries);
			}
		}
	}
	return value;
}

kern_return_t
sync_nonce(io_service_t nvram_serv) {
	if(IORegistryEntrySetCFProperty(nvram_serv, CFSTR("temp_key"), CFSTR("temp_value")) == KERN_SUCCESS && IORegistryEntrySetCFProperty(nvram_serv, CFSTR(kIONVRAMDeletePropertyKey), CFSTR("temp_key")) == KERN_SUCCESS) {
		return IORegistryEntrySetCFProperty(nvram_serv, CFSTR(kIONVRAMForceSyncNowPropertyKey), CFSTR(kBootNoncePropertyKey));
	}
	return KERN_FAILURE;
}

void
entangle_nonce(uint64_t nonce, const void *key) {
	uint8_t entangled_nonce[SHA384_DIGEST_LENGTH];
	uint64_t src[] = { 0, nonce }, dst[2];
	size_t i, out_sz;

	if(CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, key, kCCKeySizeAES128, NULL, src, sizeof(src), dst, sizeof(dst), &out_sz) == kCCSuccess && out_sz == sizeof(dst)) {
		CC_SHA384(dst, sizeof(dst), entangled_nonce);
		printf("entangled_nonce: ");
		for(i = 0; i < sizeof(entangled_nonce); ++i) {
			printf("%02x", entangled_nonce[i]);
		}
		putchar('\n');
	}
}


uint64_t dimentio_find_os_string_addr()
{
	kaddr_t boot_nonce_os_symbol, of_dict, os_string;
	uint64_t string_ptr = 0;
	io_service_t nonce_serv, nvram_serv;

	if(init_arm_pgshift() == KERN_SUCCESS)
	{
		printf("arm_pgshift: %u\n", arm_pgshift);
		if((kbase = get_kbase(&kslide)))
		{
			printf("kbase: " KADDR_FMT "\n", kbase);
			printf("kslide: " KADDR_FMT "\n", kslide);
			if(pfinder_init(&pfinder, kbase) == KERN_SUCCESS)
			{
				if(pfinder_init_offsets(pfinder) == KERN_SUCCESS)
				{
					if(find_task(getpid(), &our_task) == KERN_SUCCESS)
					{
						printf("our_task: " KADDR_FMT "\n", our_task);
						if((nonce_serv = get_serv("AppleMobileApNonce")) != IO_OBJECT_NULL)
						{
							printf("nonce_serv: 0x%" PRIx32 "\n", nonce_serv);
							if(nonce_generate(nonce_serv) == KERN_SUCCESS && get_boot_nonce_os_symbol(nonce_serv, &boot_nonce_os_symbol) == KERN_SUCCESS)
							{
								printf("boot_nonce_os_symbol: " KADDR_FMT "\n", boot_nonce_os_symbol);
								if((nvram_serv = get_serv("IODTNVRAM")) != IO_OBJECT_NULL)
								{
									printf("nvram_serv: 0x%" PRIx32 "\n", nvram_serv);
									if(get_of_dict(nvram_serv, &of_dict) == KERN_SUCCESS)
									{
										printf("of_dict: " KADDR_FMT "\n", of_dict);
										if((os_string = lookup_key_in_os_dict(of_dict, boot_nonce_os_symbol)))
										{
											printf("os_string: " KADDR_FMT "\n", os_string);
											if(kread_addr(os_string + OS_STRING_STRING_OFF, &string_ptr) == KERN_SUCCESS && string_ptr)
											{
												printf("string_ptr: " KADDR_FMT "\n", string_ptr);
											}
										}
									}
									IOObjectRelease(nvram_serv);
								}
							}
							IOObjectRelease(nonce_serv);
						}
					}
				}
				pfinder_term(&pfinder);
			}
		}
	}
	return string_ptr;
}
