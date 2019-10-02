//    This is originally created by @stek29(full credits to him) and I, ARX8x only modified parts of it
//    to make it work with my tweak, System Info
//    Changes
//    - removed help instructions for user
//    - 0 args = print generator
//    - first arg is considered as input generator to be set
//    - added generator validation
//    - everything goes to stdout
//    - added setuid patch for electra jailbreak



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "unlocknvram.h"
#include "KernelUtilities.h"
#include "KernelMemory.h"
#include "nonce.h"
#include "dimentio.h"
#include "debug.h"

#include <CoreFoundation/CoreFoundation.h>
bool DO_PATCHES;
bool DID_UNLOCK_NVRAM;
#define FLAG_PLATFORMIZE (1 << 1)
extern CFTypeRef MGCopyAnswer(CFStringRef key) WEAK_IMPORT_ATTRIBUTE;
bool IS_ELECTRA = false;
uint64_t boot_nonce_ref = 0;

// uint64_t kbase, kslide;
// pfinder_t pfinder;
mach_port_t tfp0;

void load_offsets()
{

    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("/jb/offsets.plist"), kCFURLPOSIXPathStyle, false);
    if (fileURL == NULL) {
        DEBUG("Unable to create URL");
        return;
    }
    CFDataRef off_file_data;
    SInt32 errorCode;
    Boolean status = CFURLCreateDataAndPropertiesFromResource(
                                                              kCFAllocatorDefault, fileURL, &off_file_data,
                                                              NULL, NULL, &errorCode);

    CFRelease(fileURL);
    if (!status) {
        DEBUG("Unable to read /jb/offsets.plist");
        return;
    }

    DEBUG("off_file_data: %p", off_file_data);
    CFPropertyListRef offsets = CFPropertyListCreateWithData(kCFAllocatorDefault, (CFDataRef)off_file_data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(off_file_data);
    if (offsets == NULL) {
        DEBUG("Unable to convert /jb/offsets.plist to property list");
        return;
    }

    if (CFGetTypeID(offsets) != CFDictionaryGetTypeID()) {
        DEBUG("/jb/offsets.plist did not convert to a dictionary");
        CFRelease(offsets);
        return;
    }


    offs.kernel_task        = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelTask")), kCFStringEncodingUTF8), NULL, 16);
    DEBUG("offset_kernel_task: %llx",  offs.kernel_task);

    CFRelease(offsets);


    DEBUG("tfp0: %x", tfp0);
}

kern_return_t init_tfpzero(void) {
    kern_return_t ret;
    tfp0 = MACH_PORT_NULL;

    host_t host = mach_host_self();
    ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);

    if (ret != KERN_SUCCESS) {
        printf("Failed to get kernel_task\n");
        return ret;
    }

    ret = MACH_PORT_VALID(tfp0) ? KERN_SUCCESS : KERN_FAILURE;

    if (ret != KERN_SUCCESS) {
        printf("kernel_task is not valid\n");
    } else {
        DEBUG("kernel_task = 0x%08x\n", tfp0);
    }

    return ret;
}

int validate_input_generator(const char * generator)
{
  char compareString[22];
  uint64_t rawGeneratorValue;

  sscanf(generator, "0x%16llx", &rawGeneratorValue);
  sprintf(compareString, "0x%016llx", rawGeneratorValue);
  printf("Re-generated %s\n", compareString);
  return strcmp(compareString, generator);
}

void patch_setuid()
{
  void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
  if (!handle)
  {
    printf("Couldn't get libjb : %s\n", dlerror());
    return;
  }
  // Reset errors
  dlerror();
  typedef void (*fix_setuid_prt_t)(pid_t pid);
  fix_setuid_prt_t ptr = (fix_setuid_prt_t)dlsym(handle, "jb_oneshot_fix_setuid_now");

  const char *dlsym_error = dlerror();
  if (dlsym_error)
  {
    printf("sym error\n");
    return;
  }
  ptr(getpid());
}



int main(int argc, char *argv[])
{
  loglevel = lvlNONE;
  DO_PATCHES = (kCFCoreFoundationVersionNumber > 1349.70);
  DID_UNLOCK_NVRAM = false;
  int retval = EXIT_FAILURE;

  FILE *file;
  if ((file = fopen("/usr/lib/libjailbreak.dylib", "r")))
  {
      // printf("Electra detected\n");
    IS_ELECTRA = true;
    fclose(file);
  }

  if(DO_PATCHES)
  {
    // printf("performing electra patches\n");
    if(IS_ELECTRA)
    {
      patch_setuid();
      setuid(0); // Electra needs this to be called twice for some reason
    }

    if(setuid(0))
    {
      printf("Failed to get uid 0\n");
    }

    if(init_tfpzero())
    {
      printf("failed to init tfpzero\n");
      return EXIT_FAILURE;
    }
    // these offsets are for unc0ver and may only work for A11 and below
    // patching is different on A12
    load_offsets();
    boot_nonce_ref = dimentio_find_os_string_addr();
    if(!boot_nonce_ref)
    {
      printf("dimentio: could not get the boot nonce os string address\n");
      printf("unlocking nvram\n");
      if(unlocknvram())
      {
        printf("Failed to unlock nvram\n");
        return EXIT_FAILURE;
      }
      else
      {
        DID_UNLOCK_NVRAM = true;
      }
    }
    else
    {
      printf("boot_nonce_ref : %llx\n", boot_nonce_ref);
    }

  }


  if(argc < 2)
  {
    if(boot_nonce_ref)
    {
      char generator_dimentio[2 * sizeof(uint64_t) + sizeof("0x")];
      printf("%d\n", (2 * sizeof(uint64_t) + sizeof("0x")));
      size_t off = kread(boot_nonce_ref, &generator_dimentio, sizeof(generator_dimentio));
      printf("generator:%s\n", generator_dimentio);
      retval = EXIT_SUCCESS;
    }
    else
    {
      char *gen = getgen();
      if(gen != NULL)
      {
        printf("generator:%s\n", gen);
        retval = EXIT_SUCCESS;
      }
      else
      {
        printf("Failed to read generator\n");
        retval = EXIT_FAILURE;
      }
    }

  }
  else
  {
    const char *arg1 = argv[1];
    char *generator;
    if(strcmp("-n", arg1) == 0)
    {
      CFDataRef CFNonce = (CFDataRef) MGCopyAnswer(CFSTR("ApNonce"));
      int nonce_length =  CFDataGetLength(CFNonce);
      const unsigned char *bytes = (const unsigned char *)CFDataGetBytePtr(CFNonce);
      char *nonce = (char *)malloc(nonce_length);
      int ref = 0;
      for (int i = 0; i < nonce_length; i++)
      {
          ref += sprintf(&nonce[ref], "%02x", bytes[i]);
      }
      printf("ApNonce: %s\n", nonce);
      printf("SEPNonce: Unknown\n");
      retval = KERN_SUCCESS;
    }
    else
    {
      generator = arg1;

      if(!validate_input_generator(generator))
      {
        if(boot_nonce_ref)
        {
          size_t off = kwrite(boot_nonce_ref, generator, strlen(generator));
          printf("Success :%s\n", generator);
          printf("%ld\n", off);
          printf("%ld\n", strlen(generator));
          retval = EXIT_SUCCESS;
        }
        else
        {
          if(!setgen(generator))
          {
            printf("Success : %s\n", getgen());
            retval = EXIT_SUCCESS;
          }
          else
          {
            printf("Failed to set generator\n");
            retval = EXIT_FAILURE;
          }
        }
      }
      else
      {
        printf("Generator validation failed\n");
        retval = EXIT_FAILURE;
      }
    }

  }

  if(DID_UNLOCK_NVRAM)
  {
    printf("Locking nvram back\n");
    if(locknvram())
    {
      printf("nvram was unlocked but failed to lock back. Please reboot to avoid system malfunction\n");
    }
  }

  mach_port_deallocate(mach_task_self(), tfp0);
  return retval;
}
