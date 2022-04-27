#ifndef RMM_CCA_BENCHMARK_H_
#define RMM_CCA_BENCHMARK_H_

#define STR(s) #s
#define CCA_MARKER(marker) __asm__ volatile("MOV XZR, " STR(marker))

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

#define CCA_TFA_SMC_DEL_DEV_PAS() \
CCA_MARKER(0x112); \

#define CCA_TFA_SMC_ATTACH_DEV() \
CCA_MARKER(0x113); \

#define CCA_TFA_FORWARD_SMC_NS_REALM() \
CCA_MARKER(0x114); \

#define CCA_TFA_FORWARD_SMC_REALM_NS() \
CCA_MARKER(0x115); \

/*---------START STOP FUNCTION MARKERS----------*/
#define CCA_TFA_SMC_DELEGATE_PAS_START() \
CCA_MARKER(0x1021); \

#define CCA_TFA_SMC_DELEGATE_PAS_STOP() \
CCA_MARKER(0x1022); \

#define CCA_TFA_SMC_UNDELEGATE_PAS_START() \
CCA_MARKER(0x1023); \

#define CCA_TFA_SMC_UNDELEGATE_PAS_STOP() \
CCA_MARKER(0x1024); \


#endif