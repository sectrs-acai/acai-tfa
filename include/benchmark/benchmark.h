#ifndef RMM_CCA_BENCHMARK_H_
#define RMM_CCA_BENCHMARK_H_

#define STR(s) #s

// #define MICRO_BENCH 1

#ifndef MICRO_BENCH
#define CCA_MARKER(marker) __asm__ volatile("MOV XZR, " STR(marker))
#define CCA_BENCHMARK_START
#define CCA_BENCHMARK_STOP

#else
#define CCA_FLUSH __asm__ volatile("ISB");
#define CCA_MARKER(marker) CCA_FLUSH __asm__ volatile("MOV XZR, " STR(marker))
#define CCA_TRACE_START  __asm__ volatile("HLT 0x1337");
#define CCA_TRACE_STOP __asm__ volatile("HLT 0x1337");

#define CCA_BENCHMARK_START                                             \
  CCA_TRACE_START;                                                             \
  CCA_FLUSH;                                                                             \
  CCA_MARKER(0x1)

#define CCA_BENCHMARK_STOP                                                     \
  CCA_MARKER(0x2);                                                             \
  CCA_FLUSH;                                                                             \
  CCA_TRACE_STOP
#endif

/*---------BOOT MARKERS----------*/
#define CCA_TFA_BL1_LOAD_BL2() \
CCA_MARKER(0x101C); \

#define CCA_TFA_BL2_LOAD_BL31() \
CCA_MARKER(0x101D); \

#define CCA_TFA_BL31_RMM_INIT() \
CCA_MARKER(0x101E); \

//this is written directly into assembly as MOV XZR, #0x10F
#define CCA_TFA_BL31_END() \
CCA_MARKER(0x101F ); \

//this is written directly into assembly as MOV XZR, #0x110
#define CCA_TFA_BL1_END() \
CCA_MARKER(0x1020 ); \

#define CCA_TFA_RMM_BOOT_DONE() \
CCA_MARKER(0x1025); \


/*---------OTHER MARKERS----------*/
#define CCA_TFA_SMC_RMM() \
CCA_MARKER(0x111); \

#define CCA_TFA_SMC_ALL() \
CCA_MARKER(0x122); \

#define CCA_TFA_FORWARD_SMC_NS_REALM() \
CCA_MARKER(0x114); \

#define CCA_TFA_FORWARD_SMC_REALM_NS() \
CCA_MARKER(0x115); \

#define CCA_TFA_CMDQUEUE_SUBMIT() \
CCA_MARKER(0x117); \

#define CCA_TFA_SMC_TRANSITION_STREAM_TABLE() \
CCA_MARKER(0x118); \

#define CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY() \
CCA_MARKER(0x119); \

#define CCA_TFA_SMC_DELEGATE_RING_BUFFER() \
CCA_MARKER(0x120); \

#define CCA_TFA_SMC_MOVE_PAGE_TO_REALM() \
CCA_MARKER(0x121); \


#ifdef MICRO_BENCH
    /*---------START STOP FUNCTION MARKERS----------*/
    #define CCA_TFA_SMC_DELEGATE_PAS_START() \
    CCA_MARKER(0x1021); \

    #define CCA_TFA_SMC_DELEGATE_PAS_STOP() \
    CCA_MARKER(0x1022); \

    #define CCA_TFA_SMC_UNDELEGATE_PAS_START() \
    CCA_MARKER(0x1023); \

    #define CCA_TFA_SMC_UNDELEGATE_PAS_STOP() \
    CCA_MARKER(0x1024); \

    #define CCA_TFA_GPT_L0_INIT_START() \
    CCA_MARKER(0x1026); \

    #define CCA_TFA_GPT_L0_INIT_STOP() \
    CCA_MARKER(0x1027); \

    #define CCA_TFA_GPT_L1_INIT_START() \
    CCA_MARKER(0x1028); \

    #define CCA_TFA_GPT_L1_INIT_STOP() \
    CCA_MARKER(0x1029); \

    #define CCA_TFA_SMC_DEL_DEV_PAS_START() \
    CCA_MARKER(0x1030); \

    #define CCA_TFA_SMC_DEL_DEV_PAS_STOP() \
    CCA_MARKER(0x1031); \

    #define CCA_TFA_SMC_ATTACH_DEV_START() \
    CCA_MARKER(0x1032); \

    #define CCA_TFA_SMC_ATTACH_DEV_STOP() \
    CCA_MARKER(0x1033); \

    #define CCA_TFA_ENTER_SMC_MAP_PAGES() \
    CCA_MARKER(0x1034); \

    #define CCA_TFA_EXIT_SMC_MAP_PAGES() \
    CCA_MARKER(0x1035); \

    #define CCA_TFA_ENTER_SMC_UNMAP_PAGES() \
    CCA_MARKER(0x1036); \

    #define CCA_TFA_EXIT_SMC_UNMAP_PAGES() \
    CCA_MARKER(0x1037); \

    #define CCA_TFA_SMC_TRANSITION_STREAM_TABLE_START() \
    CCA_MARKER(0x1038); \

    #define CCA_TFA_SMC_TRANSITION_STREAM_TABLE_STOP() \
    CCA_MARKER(0x1039); \
    
    #define CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_START() \
    CCA_MARKER(0x1044); \
    
    #define CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_STOP() \
    CCA_MARKER(0x1045); \

     #define CCA_TFA_SMC_DELEGATE_RING_BUFFER_START() \
    CCA_MARKER(0x1046); \

     #define CCA_TFA_SMC_DELEGATE_RING_BUFFER_STOP() \
    CCA_MARKER(0x1047); \

     #define CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_START() \
    CCA_MARKER(0x1048); \

     #define CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_STOP() \
    CCA_MARKER(0x1049); \

         #define CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_START() \
    CCA_MARKER(0x1060); \

     #define CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_STOP() \
    CCA_MARKER(0x1061); \


    

#else
    #define CCA_TFA_SMC_DELEGATE_PAS_START() \
    CCA_MARKER(0x721); \

    #define CCA_TFA_SMC_DELEGATE_PAS_STOP() 

    #define CCA_TFA_SMC_UNDELEGATE_PAS_START() \
    CCA_MARKER(0x723); \

    #define CCA_TFA_SMC_UNDELEGATE_PAS_STOP()

    #define CCA_TFA_GPT_L0_INIT_START() \
    CCA_MARKER(0x726); \

    #define CCA_TFA_GPT_L0_INIT_STOP() 

    #define CCA_TFA_GPT_L1_INIT_START() \
    CCA_MARKER(0x728); \

    #define CCA_TFA_GPT_L1_INIT_STOP() 

    #define CCA_TFA_SMC_DEL_DEV_PAS_START() \
    CCA_MARKER(0x730); \

    #define CCA_TFA_SMC_DEL_DEV_PAS_STOP() 

    #define CCA_TFA_SMC_ATTACH_DEV_START() \
    CCA_MARKER(0x732); \

    #define CCA_TFA_SMC_ATTACH_DEV_STOP() 

    #define CCA_TFA_ENTER_SMC_MAP_PAGES() \
    CCA_MARKER(0x734); \

    #define CCA_TFA_EXIT_SMC_MAP_PAGES() 

    #define CCA_TFA_ENTER_SMC_UNMAP_PAGES() \
    CCA_MARKER(0x736); \

    #define CCA_TFA_EXIT_SMC_UNMAP_PAGES()

    #define CCA_TFA_SMC_TRANSITION_STREAM_TABLE_START()

    #define CCA_TFA_SMC_TRANSITION_STREAM_TABLE_STOP()
    
    #define CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_START() 
    
    #define CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_STOP()

    #define CCA_TFA_SMC_DELEGATE_RING_BUFFER_START() 

    #define CCA_TFA_SMC_DELEGATE_RING_BUFFER_STOP() 

    #define CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_START()

    #define CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_STOP() 

    #define CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_START() 

    #define CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_STOP() 

#endif

#endif