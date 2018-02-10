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
#include "unlocknvram.h"
#include "nonce.h"
#include "kutils.h"
#include "debug.h"
#include <CoreFoundation/CoreFoundation.h>
bool DO_PATCHES;
bool DID_UNLOCK_NVRAM;
#define FLAG_PLATFORMIZE (1 << 1)



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
    DO_PATCHES = (kCFCoreFoundationVersionNumber > 1348.22);
    DID_UNLOCK_NVRAM = false;
    int retval = EXIT_SUCCESS;
    
    if(DO_PATCHES)
    {

        patch_setuid();

        if(setuid(0))
        {
            printf("Failed to get uid 0\n");
        }
        
        
        
        if (init_tfpzero())
        {
            printf("failed to init tfpzero\n");
            return EXIT_FAILURE;
        }
        
        if (unlocknvram())
        {
            printf("Failed to unlock nvram\n");
            return EXIT_FAILURE;
        }
        else
        {
            DID_UNLOCK_NVRAM = true;
        }
    }
    
    if(argc < 2)
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
    else
    {
        const char *generator = argv[1];
        char generatorToSet[22];
        char compareString[22];
        uint64_t rawGeneratorValue;
        
        sscanf(generator, "0x%16llx",&rawGeneratorValue);
        sprintf(compareString, "0x%016llx", rawGeneratorValue);
        
        if(!strcmp(compareString, generator))
        {
            sprintf(generatorToSet, "0x%llx", rawGeneratorValue);
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
        else
        {
            printf("Re-generated %s\n", compareString);
            printf("Generator validation failed\n");
            retval = EXIT_FAILURE;
        }
    }
    
    if(DID_UNLOCK_NVRAM)
    {
        if(unlocknvram())
        {
            printf("nvram was unlocked but failed to lock back. Please reboot to avoid system malfunction\n");
        }
    }
    
    return retval;
}
