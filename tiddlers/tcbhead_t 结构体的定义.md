```c
typedef struct
{
    void *tcb;                /* Pointer to the TCB.  Not necessarily the
                               thread descriptor used by libpthread.  */
    dtv_t *dtv;
    void *self;                /* Pointer to the thread descriptor.  */
    int multiple_threads;
    int gscope_flag;
    uintptr_t sysinfo;
    uintptr_t stack_guard;        //栈canary, fs:0x28
    uintptr_t pointer_guard;      //指针加密, fs:0x30
    unsigned long int vgetcpu_cache[2];
    /* Bit 0: X86_FEATURE_1_IBT.
         Bit 1: X86_FEATURE_1_SHSTK.
       */
    unsigned int feature_1;
    int __glibc_unused1;
    /* Reservation of some values for the TM ABI.  */
    void *__private_tm[4];
    /* GCC split stack support.  */
    void *__private_ss;
    /* The lowest address of shadow stack,  */
    unsigned long long int ssp_base;
    /* Must be kept even if it is no longer used by glibc since programs,
         like AddressSanitizer, depend on the size of tcbhead_t.  */
    __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));

void *__padding[8];
} tcbhead_t;
```