/*
 * Copyright (c) 2021-2022, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

#include <arch_helpers.h>
#include <arch_features.h>
#include <bl31/bl31.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <context.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/el3_runtime/pubsub.h>
#include <lib/gpt_rme/gpt_rme.h>

#include <lib/spinlock.h>
#include <lib/utils.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <plat/common/common_def.h>
#include <plat/common/platform.h>
#include <platform_def.h>
#include <services/rmmd_svc.h>
#include <smccc_helpers.h>
#include <lib/extensions/sve.h>
#include "rmmd_initial_context.h"
#include "rmmd_private.h"
#include <plat/arm/common/arm_def.h>
#include <benchmark/benchmark.h>

#define CUSTOM_DEBUG 0


#define Q_IDX(cmd_queue) ((cmd_queue.producer_value) & ( (cmd_queue.size >> (3 + 1) ) - 1))

static unsigned long __map_pages( uint64_t iova, uint64_t paddr, uint64_t pgcount, uint64_t prot, 
					 	uint64_t ptep, uint64_t sid, unsigned int sec_state);

// The sec state will be determined based on the partent node. 

// On transition to Realm we will flag the PGD as REALM and nuke all mappings
// Subsequent mapping rely on the information of the partent and inherit the tag.

/*******************************************************************************
 * RMM boot failure flag
 ******************************************************************************/
static bool rmm_boot_failed;

/*******************************************************************************
 * RMM context information.
 ******************************************************************************/
rmmd_rmm_context_t rmm_context[PLATFORM_CORE_COUNT];

/*******************************************************************************
 * RMM entry point information. Discovered on the primary core and reused
 * on secondary cores.
 ******************************************************************************/
static entry_point_info_t *rmm_ep_info;

/*******************************************************************************
 * Static function declaration.
 ******************************************************************************/
static int32_t rmm_init(void);


static spinlock_t pgtable_s2_lock;

static spinlock_t page_marking_lock;

static spinlock_t ongoing_rmi_call_lock;

static struct rmi_init_pte pending_call_data; 

static struct stream_table_config stream_table_data; 

static struct s2_table_mem_area s2_mem_struct = {
	.base_addr = 0,
	.current_ptr = 0,
	.size = 0,
};

static struct cmd_queue_struct command_queue;

/*******************************************************************************
 * This function takes an RMM context pointer and performs a synchronous entry
 * into it.
 ******************************************************************************/
uint64_t rmmd_rmm_sync_entry(rmmd_rmm_context_t *rmm_ctx)
{
	uint64_t rc;

	assert(rmm_ctx != NULL);

	cm_set_context(&(rmm_ctx->cpu_ctx), REALM);

	/* Restore the realm context assigned above */
	cm_el1_sysregs_context_restore(REALM);
	cm_el2_sysregs_context_restore(REALM);
	cm_set_next_eret_context(REALM);

	/* Enter RMM */
	rc = rmmd_rmm_enter(&rmm_ctx->c_rt_ctx);

	/*
	 * Save realm context. EL1 and EL2 Non-secure
	 * contexts will be restored before exiting to
	 * Non-secure world, therefore there is no need
	 * to clear EL1 and EL2 context registers.
	 */
	cm_el1_sysregs_context_save(REALM);
	cm_el2_sysregs_context_save(REALM);

	return rc;
}

/*******************************************************************************
 * This function returns to the place where rmmd_rmm_sync_entry() was
 * called originally.
 ******************************************************************************/
__dead2 void rmmd_rmm_sync_exit(uint64_t rc)
{
	rmmd_rmm_context_t *ctx = &rmm_context[plat_my_core_pos()];

	/* Get context of the RMM in use by this CPU. */
	assert(cm_get_context(REALM) == &(ctx->cpu_ctx));

	/*
	 * The RMMD must have initiated the original request through a
	 * synchronous entry into RMM. Jump back to the original C runtime
	 * context with the value of rc in x0;
	 */
	rmmd_rmm_exit(ctx->c_rt_ctx, rc);

	panic();
}

static void rmm_el2_context_init(el2_sysregs_t *regs)
{
	regs->ctx_regs[CTX_SPSR_EL2 >> 3] = REALM_SPSR_EL2;
	regs->ctx_regs[CTX_SCTLR_EL2 >> 3] = SCTLR_EL2_RES1;
}

/*******************************************************************************
 * Enable architecture extensions on first entry to Realm world.
 ******************************************************************************/
static void manage_extensions_realm(cpu_context_t *ctx)
{
#if ENABLE_SVE_FOR_NS
	/*
	 * Enable SVE and FPU in realm context when it is enabled for NS.
	 * Realm manager must ensure that the SVE and FPU register
	 * contexts are properly managed.
	 */
	sve_enable(ctx);
#else
	/*
	 * Disable SVE and FPU in realm context when it is disabled for NS.
	 */
	sve_disable(ctx);
#endif /* ENABLE_SVE_FOR_NS */
}

/*******************************************************************************
 * Jump to the RMM for the first time.
 ******************************************************************************/
static int32_t rmm_init(void)
{
	long rc;
	rmmd_rmm_context_t *ctx = &rmm_context[plat_my_core_pos()];

	INFO("RMM init start.\n");

	/* Enable architecture extensions */
	manage_extensions_realm(&ctx->cpu_ctx);

	/* Initialize RMM EL2 context. */
	rmm_el2_context_init(&ctx->cpu_ctx.el2_sysregs_ctx);

	rc = rmmd_rmm_sync_entry(ctx);
	if (rc != E_RMM_BOOT_SUCCESS) {
		ERROR("RMM init failed: %ld\n", rc);
		/* Mark the boot as failed for all the CPUs */
		rmm_boot_failed = true;
		return 0;
	}

	INFO("RMM init end.\n");

	return 1;
}

/*******************************************************************************
 * Load and read RMM manifest, setup RMM.
 ******************************************************************************/
int rmmd_setup(void)
{
	size_t shared_buf_size __unused;
	uintptr_t shared_buf_base;
	uint32_t ep_attr;
	unsigned int linear_id = plat_my_core_pos();
	rmmd_rmm_context_t *rmm_ctx = &rmm_context[linear_id];
	rmm_manifest_t *manifest;
	int rc;

	/* Make sure RME is supported. */
	assert(get_armv9_2_feat_rme_support() != 0U);

	rmm_ep_info = bl31_plat_get_next_image_ep_info(REALM);
	if (rmm_ep_info == NULL) {
		WARN("No RMM image provided by BL2 boot loader, Booting "
		     "device without RMM initialization. SMCs destined for "
		     "RMM will return SMC_UNK\n");
		return -ENOENT;
	}

	/* Under no circumstances will this parameter be 0 */
	assert(rmm_ep_info->pc == RMM_BASE);

	/* Initialise an entrypoint to set up the CPU context */
	ep_attr = EP_REALM;
	if ((read_sctlr_el3() & SCTLR_EE_BIT) != 0U) {
		ep_attr |= EP_EE_BIG;
	}

	SET_PARAM_HEAD(rmm_ep_info, PARAM_EP, VERSION_1, ep_attr);
	rmm_ep_info->spsr = SPSR_64(MODE_EL2,
					MODE_SP_ELX,
					DISABLE_ALL_EXCEPTIONS);

	shared_buf_size =
			plat_rmmd_get_el3_rmm_shared_mem(&shared_buf_base);

	assert((shared_buf_size == SZ_4K) &&
					((void *)shared_buf_base != NULL));

	/* Load the boot manifest at the beginning of the shared area */
	manifest = (rmm_manifest_t *)shared_buf_base;
	rc = plat_rmmd_load_manifest(manifest);
	if (rc != 0) {
		ERROR("Error loading RMM Boot Manifest (%i)\n", rc);
		return rc;
	}
	flush_dcache_range((uintptr_t)shared_buf_base, shared_buf_size);

	/*
	 * Prepare coldboot arguments for RMM:
	 * arg0: This CPUID (primary processor).
	 * arg1: Version for this Boot Interface.
	 * arg2: PLATFORM_CORE_COUNT.
	 * arg3: Base address for the EL3 <-> RMM shared area. The boot
	 *       manifest will be stored at the beginning of this area.
	 */
	rmm_ep_info->args.arg0 = linear_id;
	rmm_ep_info->args.arg1 = RMM_EL3_INTERFACE_VERSION;
	rmm_ep_info->args.arg2 = PLATFORM_CORE_COUNT;
	rmm_ep_info->args.arg3 = shared_buf_base;

	/* Initialise RMM context with this entry point information */
	cm_setup_context(&rmm_ctx->cpu_ctx, rmm_ep_info);

	INFO("RMM setup done.\n");

	/* Register init function for deferred init.  */
	bl31_register_rmm_init(&rmm_init);

	return 0;
}

/*******************************************************************************
 * Forward SMC to the other security state
 ******************************************************************************/
static uint64_t	rmmd_smc_forward(uint32_t src_sec_state,
				 uint32_t dst_sec_state, uint64_t x0,
				 uint64_t x1, uint64_t x2, uint64_t x3,
				 uint64_t x4, void *handle)
{	

	cpu_context_t *ctx = cm_get_context(dst_sec_state);

	/* Save incoming security state */
	cm_el1_sysregs_context_save(src_sec_state);
	cm_el2_sysregs_context_save(src_sec_state);

	/* Restore outgoing security state */
	cm_el1_sysregs_context_restore(dst_sec_state);
	cm_el2_sysregs_context_restore(dst_sec_state);
	cm_set_next_eret_context(dst_sec_state);

	//Pertie 
	// gpt_change(src_sec_state, dst_sec_state);
	/*
	 * As per SMCCCv1.2, we need to preserve x4 to x7 unless
	 * being used as return args. Hence we differentiate the
	 * onward and backward path. Support upto 8 args in the
	 * onward path and 4 args in return path.
	 * Register x4 will be preserved by RMM in case it is not
	 * used in return path.
	 */
	if (src_sec_state == NON_SECURE) {
			CCA_TFA_FORWARD_SMC_NS_REALM();
		SMC_RET8(ctx, x0, x1, x2, x3, x4,
			 SMC_GET_GP(handle, CTX_GPREG_X5),
			 SMC_GET_GP(handle, CTX_GPREG_X6),
			 SMC_GET_GP(handle, CTX_GPREG_X7));
	}else if (src_sec_state == REALM){
		CCA_TFA_FORWARD_SMC_REALM_NS();
	}

	SMC_RET5(ctx, x0, x1, x2, x3, x4);
}


/*******************************************************************************
 * This function handles all SMCs in the range reserved for RMI. Each call is
 * either forwarded to the other security state or handled by the RMM dispatcher
 ******************************************************************************/
uint64_t rmmd_rmi_handler(uint32_t smc_fid, uint64_t x1, uint64_t x2,
			  uint64_t x3, uint64_t x4, void *cookie,
			  void *handle, uint64_t flags)
{
	uint32_t src_sec_state;

	/* If RMM failed to boot, treat any RMI SMC as unknown */
	if (rmm_boot_failed) {
		WARN("RMMD: Failed to boot up RMM. Ignoring RMI call\n");
		SMC_RET1(handle, SMC_UNK);
	}

	/* Determine which security state this SMC originated from */
	src_sec_state = caller_sec_state(flags);

	/* RMI must not be invoked by the Secure world */
	if (src_sec_state == SMC_FROM_SECURE) {
		WARN("RMMD: RMI invoked by secure world.\n");
		SMC_RET1(handle, SMC_UNK);
	}

	/*
	 * Forward an RMI call from the Normal world to the Realm world as it
	 * is.
	 */
	if (src_sec_state == SMC_FROM_NON_SECURE) {
		//WARN("RMMD: RMI call from non-secure world.\n");
		return rmmd_smc_forward(NON_SECURE, REALM, smc_fid,
					x1, x2, x3, x4, handle);
	}

	if (src_sec_state != SMC_FROM_REALM) {
		SMC_RET1(handle, SMC_UNK);
	}

	//WARN("RMMD: RMI call from REALM world.\n");
	switch (smc_fid) {
	case RMM_RMI_REQ_COMPLETE: {
		uint64_t x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
		return rmmd_smc_forward(REALM, NON_SECURE, x1,
					x2, x3, x4, x5, handle);
	}
	default:
		WARN("RMMD: Unsupported RMM call 0x%08x\n", smc_fid);
		SMC_RET1(handle, SMC_UNK);
	}
}

/*******************************************************************************
 * This cpu has been turned on. Enter RMM to initialise R-EL2.  Entry into RMM
 * is done after initialising minimal architectural state that guarantees safe
 * execution.
 ******************************************************************************/
static void *rmmd_cpu_on_finish_handler(const void *arg)
{
	long rc;
	uint32_t linear_id = plat_my_core_pos();
	rmmd_rmm_context_t *ctx = &rmm_context[linear_id];

	if (rmm_boot_failed) {
		/* RMM Boot failed on a previous CPU. Abort. */
		ERROR("RMM Failed to initialize. Ignoring for CPU%d\n",
								linear_id);
		return NULL;
	}

	/*
	 * Prepare warmboot arguments for RMM:
	 * arg0: This CPUID.
	 * arg1 to arg3: Not used.
	 */
	rmm_ep_info->args.arg0 = linear_id;
	rmm_ep_info->args.arg1 = 0ULL;
	rmm_ep_info->args.arg2 = 0ULL;
	rmm_ep_info->args.arg3 = 0ULL;

	/* Initialise RMM context with this entry point information */
	cm_setup_context(&ctx->cpu_ctx, rmm_ep_info);

	/* Enable architecture extensions */
	manage_extensions_realm(&ctx->cpu_ctx);

	/* Initialize RMM EL2 context. */
	rmm_el2_context_init(&ctx->cpu_ctx.el2_sysregs_ctx);

	rc = rmmd_rmm_sync_entry(ctx);

	if (rc != E_RMM_BOOT_SUCCESS) {
		ERROR("RMM init failed on CPU%d: %ld\n", linear_id, rc);
		/* Mark the boot as failed for any other booting CPU */
		rmm_boot_failed = true;
	}

	return NULL;
}

/* Subscribe to PSCI CPU on to initialize RMM on secondary */
SUBSCRIBE_TO_EVENT(psci_cpu_on_finish, rmmd_cpu_on_finish_handler);

/* Convert GPT lib error to RMMD GTS error */
static int gpt_to_gts_error(int error, uint32_t smc_fid, uint64_t address)
{
	int ret;

	if (error == 0) {
		return E_RMM_OK;
	}

	if (error == -EINVAL) {
		ret = E_RMM_BAD_ADDR;
	} else {
		/* This is the only other error code we expect */
		assert(error == -EPERM);
		ret = E_RMM_BAD_PAS;
	}

    if (CUSTOM_DEBUG) {
        VERBOSE("RMMD: PAS Transition failed. GPT ret = %d, PA: 0x%"PRIx64 ", FID = 0x%x\n",
                error, address, smc_fid);
    }
	return ret;
}

// TODO: Must be protected by a lock to avoid race conditions
// TODO: Must contain VMID/SID information, to avoid malicious realm/hypervirsor attacks
// TODO: Remove stuff since it is deprecated now....
char *phys_granule_information = (char*)ARM_LINUX_GPT_TABLE_BASE;

static int owned_by_realm(uint64_t table_phys_addr){
	int idx = PHYS_GRANULE_IDX(table_phys_addr);

	if(table_phys_addr < RESERVED_MEM_SIZE){
		ERROR("table size too small\n");
		return 0;
	}
	if(CUSTOM_DEBUG){
		WARN("owned_by_realm; phys addr: %lx | idx: %x\n",table_phys_addr,idx);
	}
	if (phys_granule_information[idx] & GRANULE_BELONGS_TO_REALM){
		return 1;
	}
	return 0;
}


static int tag_as_realm_page(uint64_t phys_addr, bool is_table){
	int idx = PHYS_GRANULE_IDX(phys_addr);
	// We map GIC memory which is in the iomem region
	// Skip this case
	if(phys_addr < RESERVED_MEM_SIZE){
		ERROR("phys_addr < RESERVED_MEM_SIZE: phys: %lx\n",phys_addr);
		return 0;
	}
	spin_lock(&page_marking_lock);
	if (phys_granule_information[idx] != GRANULE_UNINITIALIZED){
        if (CUSTOM_DEBUG) {
            VERBOSE("FAILED TO MOVE PAGE TO PROTECTED NS, ALREADY INITIALIZED; phys_addr: %lx, tag: %x\n",phys_addr,phys_granule_information[idx]);
        }
		spin_unlock(&page_marking_lock);
		return 0;
	} 
	if(CUSTOM_DEBUG){
		WARN("MOVE PAGE TO PROTECTED NS (REALM): %lx\n",phys_addr);
	}
	// TODO(bene): call move function to modify GPT.
	// TODO(check): already done by supraja. (Another SMC call)
	phys_granule_information[idx] = is_table ? TABLE_BELONGS_TO_REALM : GRANULE_BELONGS_TO_REALM;
	spin_unlock(&page_marking_lock);

	return 0;
}

static int tag_as_ns_page(uint64_t phys_addr, bool is_table){
	int idx = PHYS_GRANULE_IDX(phys_addr);
	// We map GIC memory which is in the iomem region
	// Skip this case
	if(phys_addr < RESERVED_MEM_SIZE){
		ERROR("phys_addr < RESERVED_MEM_SIZE: phys: %lx\n",phys_addr);
		return 0;
	}
	spin_lock(&page_marking_lock);
	if(CUSTOM_DEBUG){
		WARN("MOVE PAGE TO PROTECTED NS (NS): %lx\n",phys_addr);
	}
	if (phys_granule_information[idx] != GRANULE_UNINITIALIZED){
        if (CUSTOM_DEBUG) {
            ERROR(
                "FAILED TO MOVE PAGE TO PROTECTED NS, ALREADY INITIALIZED; phys_addr: %lx, tag: %x\n",
                phys_addr,
                phys_granule_information[idx]);
        }
		spin_unlock(&page_marking_lock);
		return 0;
	}
	spin_unlock(&page_marking_lock);
	phys_granule_information[idx] = is_table ? TABLE_BELONGS_TO_NS : GRANULE_BELONGS_TO_NS;

	return 0;
}

static int tag_as_uninitialized(uint64_t phys_addr){
	int idx = PHYS_GRANULE_IDX(phys_addr);
	// We map GIC memory which is in the iomem region
	// Skip this case
	if(phys_addr < RESERVED_MEM_SIZE){
		ERROR("phys_addr < RESERVED_MEM_SIZE: phys: %lx\n",phys_addr);
		return 0;
	}
	spin_lock(&page_marking_lock);
	if(CUSTOM_DEBUG){
		WARN("MOVE PAGE TO UNINITIALIZED STATE: %lx\n",phys_addr);
	}
	phys_granule_information[idx] = GRANULE_UNINITIALIZED;
	spin_unlock(&page_marking_lock);
	
	return 0;
}

static uint8_t get_security_tag(uint64_t phys_addr){
	int idx = PHYS_GRANULE_IDX(phys_addr);
	// We map GIC memory which is in the iomem region
	// Skip this case
	if(phys_addr < RESERVED_MEM_SIZE){
		ERROR("phys_addr < RESERVED_MEM_SIZE: phys: %lx\n",phys_addr);
		return 0;
	}
	return phys_granule_information[idx] & 0x3;
}

static bool is_tagged_as_table(uint64_t phys_addr){
	int idx = PHYS_GRANULE_IDX(phys_addr);
	// We map GIC memory which is in the iomem region
	// Skip this case
	if(phys_addr < RESERVED_MEM_SIZE){
		ERROR("phys_addr < RESERVED_MEM_SIZE: phys: %lx\n",phys_addr);
		return 0;
	}
	if (phys_granule_information[idx] & GRANULE_IS_TABLE){
		return 1;
	}
	return 0;
}

int claim_device_for_realm(uint64_t sid, uint64_t vmid, unsigned int sec_state){
	uint64_t *ste_config,*vttbr;
	// Only allow the call from realm
	if (sec_state != SMC_FROM_REALM){
		return -1;
	}
	// Only allow the call once the stream tables are initialized
	if (!stream_table_data.initialized){
		return -1;
	}
	// Only allow calls to sid's in range
	if (sid * STRTAB_STE_DWORDS >= stream_table_data.size){
		return -1;
	}
	// TODO: Do some checks here if we are allowed to claim the device. 
	// Maybe some handshake with ns?
	// TODO: Assign the sid the vmid, through a global array.
	spin_lock(&pgtable_s2_lock);
	ste_config = &stream_table_data.base_addr[sid * STRTAB_STE_DWORDS];
	vttbr = (uint64_t *)le64toh(ste_config[3]);
	if (!vttbr){
		WARN("vttbr is NULL, probably uninitalized, sid: %lx, vmid: %lx\n",sid,vmid);
		return -1;
	}
	// Reset the s2 tables.
	memset(vttbr,0,4096);
	// Reset the page
	tag_as_uninitialized((uint64_t)vttbr);
	tag_as_realm_page((uint64_t)vttbr,true);

	spin_unlock(&pgtable_s2_lock);
	if (CUSTOM_DEBUG){
		WARN("assigned device sid: %lx to vmid: %lx\n",sid,vmid);
	}
	return 0;
}

static uint64_t * get_vttbr_from_sid(uint64_t sid){
	uint64_t *ste_config;

	if(!stream_table_data.initialized){
		WARN("get_vttbr_from_sid without an initalized stream table");
		return 0;
	}
	ste_config = &stream_table_data.base_addr[sid * STRTAB_STE_DWORDS];
	return (uint64_t *)le64toh(ste_config[3]);
} 


// Insecure, we must directly communicate with the smmu got get/set the addr of this table.
int transition_stream_table(uint64_t base_phys_addr, uint64_t size){
	uint64_t *ste_config,*vttbr;
	uint64_t i = 0;

	// TODO: validate that base_phys_addr and size are correct.
	if(CUSTOM_DEBUG){
		WARN("-----------transition_stream_table-----------\n");
		WARN("stream table base %lx, size %lx\n",base_phys_addr, size);
	}
	stream_table_data.base_addr = (uint64_t *)base_phys_addr;
	stream_table_data.size = size;
	gpt_delegate_dev_pas((uint64_t)stream_table_data.base_addr, 4096, SMC_FROM_REALM, 1);
	// we may need to flush before setting initalized to true to prevent races
	// not sure how the compiler will order this statements and in which order
	// they become visible to other security states.
	// TODO: flush 
	stream_table_data.initialized = true;
	// Nuke all table vttbr's.
	// This will also reset mapped MSI regions. (problem for later)
	while(i*STRTAB_STE_DWORDS < (stream_table_data.size >> 3)){
		ste_config = &stream_table_data.base_addr[i * STRTAB_STE_DWORDS];
		vttbr = (uint64_t *)le64toh(ste_config[3]);
		if (!vttbr){
			if (CUSTOM_DEBUG){
				WARN("vttbr is NULL, probably uninitalized, sid %lx\n",i);
			}
			++i;
			continue;
		}
		if (gpt_delegate_dev_pas((uint64_t)vttbr, 4096, SMC_FROM_REALM, 1)){
			ERROR("error adjusting the GPT table (vtbbr )");
			return -1;
		}
		tag_as_uninitialized((uint64_t)vttbr);
		// By default all devices are registered to NS.
		tag_as_ns_page((uint64_t)vttbr,true);
		if(CUSTOM_DEBUG){
			WARN("nuking vttbr: %p\n",vttbr);
		}
		memset(vttbr,0,4096);
		//WARN("SKIPPED nuking vttbr: %p\n",vttbr);
		++i;
	}
	// may be omitted.
	claim_device_for_realm(31,0,SMC_FROM_REALM);
	return 0;
}

// Checks if there is a pending rmi for THE physical addr
// So NS page table operations are not affected.
bool pending_delegate_dev_rmi(uint64_t phys_addr){
	// Check if we are waiting for the downcall after an RMI.
	if (pending_call_data.valid == 0){
		return false;
	}
	// If there is an ongoing rmi check if this is the downcall from NS
	// We are waiting for OR if its a call to setup NS page tables.
	if(pending_call_data.phys_addr != phys_addr){
		return false;
	}
	// If we haven't returned yet phys_addr == pending addr and the data is valid
	// So this is a pending RMI.
	return true;
}

 __attribute__ ((unused)) static int validate_args_for_install_table(uint64_t table, uint64_t ptep, uint64_t sid, uint64_t iova){
	// Stream Table Entry Config
	uint64_t *ste_config;
	uint64_t *vttbr, *tmp;

	// 3 = log2(sizeof(u64))
	// 4096 >> 3 = 512
	uint16_t page_table_index[] = { 
		iova >> (36 + 3) & 0x1ff, 
		iova >> (27 + 3) & 0x1ff,
		iova >> (18 + 3) & 0x1ff,
		iova >> (9 + 3) & 0x1ff,
	};

	if (stream_table_data.initialized == false){
		// TODO: return -1 and throw error
		ERROR("stream table not transitioned to root and validate_args_for_install_table was requested\n");
		return 0;
	}
	if (CUSTOM_DEBUG){
		WARN("deferencing stream table base %p stream id: %lx\n",stream_table_data.base_addr, sid);
	}
	ste_config = &stream_table_data.base_addr[sid * STRTAB_STE_DWORDS];
	if (!ste_config){
		ERROR("no entry found in stream table with sid %lx\n",sid);
		return 0;
	}
	if (CUSTOM_DEBUG){
		WARN("deferencing ste_config entry %p\n",ste_config);
	}
	
	vttbr = (uint64_t *)le64toh(ste_config[3]);
	if (CUSTOM_DEBUG){
		WARN("vttbr: %p, ptep 0x%lx\n",vttbr, ptep);
	}
	if (vttbr == (uint64_t *)ptep){
		return 0;
	}

	tmp = (vttbr+page_table_index[0]);
	if (CUSTOM_DEBUG){
		WARN("first level pointer: %p\n", tmp);
	}
	if (tmp == (uint64_t *)ptep){
		return 0;
	}
	tmp = (uint64_t *) (*tmp & ARM_LPAE_PTE_ADDR_MASK);
	tmp = tmp+page_table_index[1];
	if (CUSTOM_DEBUG){
		WARN("second level dereference: %p\n", tmp);
	}
	if (tmp == (uint64_t *)ptep){
		return 0;
	}
	tmp = (uint64_t *) (*tmp & ARM_LPAE_PTE_ADDR_MASK);
	tmp = tmp+page_table_index[2];
	if (CUSTOM_DEBUG){
		WARN("third level dereference: %p\n", tmp);
	}
	if (tmp == (uint64_t *)ptep){
		return 0;
	}
	ERROR("table insertion is invalid ptep: 0x%lx | calculated last level idx: %p\n",ptep, tmp);
	return -1;
}

// zero means success
// -X means error code
// get vttbr from sid (s2 tables) and walk through it 
// we must reach ptep as the last table directory, where we want to install
// phys_addr into. 
// We get the virt_addr from the saved state. 
int validate_page_table_pos_for_init_pte(uint64_t phys_addr, uint64_t ptep, uint64_t sid){
	// TODO: implement the page walk.
	// Stream Table Entry Config
	uint64_t *ste_config;
	uint64_t *vttbr, *tmp;

	// 3 = log2(sizeof(u64))
	// 4096 >> 3 = 512
	uint16_t page_table_index[] = { 
		pending_call_data.iova >> (36 + 3) & 0x1ff, 
		pending_call_data.iova >> (27 + 3) & 0x1ff,
		pending_call_data.iova >> (18 + 3) & 0x1ff,
		pending_call_data.iova >> (9 + 3) & 0x1ff,
	};	

	if (stream_table_data.initialized == false){
		// TODO: return -1 and throw error
		ERROR("stream table not transitioned to root and mappings from realm were requested");
		return -1;
	}
	if (CUSTOM_DEBUG){
		WARN("deferencing stream table base %p stream id: %lx\n",stream_table_data.base_addr, sid);
	}
	ste_config = &stream_table_data.base_addr[sid * STRTAB_STE_DWORDS];
	if (!ste_config){
		ERROR("no entry found in stream table with sid %lx\n",sid);
		return -1;
	}
	if (CUSTOM_DEBUG){
		WARN("deferencing ste_config entry %p\n",ste_config);
	}
	
	vttbr = (uint64_t *)le64toh(ste_config[3]);
	if (CUSTOM_DEBUG){
		WARN("vttbr: %p, ptep 0x%lx\n",vttbr, ptep);
	}

	tmp = (uint64_t *) (*(vttbr+page_table_index[0]) & ARM_LPAE_PTE_ADDR_MASK);
	if (CUSTOM_DEBUG){
		WARN("first level dereference: %p\n", tmp);
	}
	
	tmp = (uint64_t *) (*(tmp+page_table_index[1]) & ARM_LPAE_PTE_ADDR_MASK);
	if (CUSTOM_DEBUG){
		WARN("second level dereference: %p\n", tmp);
	}

	tmp = (uint64_t *) (*(tmp+page_table_index[2]) & ARM_LPAE_PTE_ADDR_MASK);
	if (CUSTOM_DEBUG){
		WARN("third level dereference: %p\n", tmp);
		WARN("final stage: %p | ptep: %lx | idx: %x\n", (tmp+page_table_index[3]), ptep, page_table_index[3]);
	}
	
	if ( (tmp+page_table_index[3]) != (uint64_t *)ptep ){
		ERROR("malicious mapping PANIC");
		return -1;
	}
	if (CUSTOM_DEBUG){
		WARN("success, map pages call is benign continue...\n");
	}
	// tmp should be zero, since the last level page table is not installed atm.
	// sanity check for developing, no security implications.
	tmp = (uint64_t *) (*(tmp+page_table_index[3]) & ARM_LPAE_PTE_ADDR_MASK);
	if (tmp != NULL){
		WARN("tmp unequal to NULL, page is already mapped: %p\n", tmp);
	}
	
	return 0;
}

// * Spin lock works 17.03.2023
// This call will block unless we did a downcall and used the old result
int lock_delegate_dev_rmi(uint64_t phys_addr, uint64_t iova, uint32_t sid){
	rmi_call_lock();
	if (pending_call_data.valid == true){
		ERROR("pending_call_data.valid is true, even though only we hold the lock | concurrent access?");
	}
	pending_call_data.phys_addr = phys_addr;
	pending_call_data.iova = iova;
	pending_call_data.sid = sid;
	pending_call_data.valid = true;
	return 0;
}

void rmi_call_lock(){
	WARN("rmi_call_lock\n");
	spin_lock(&ongoing_rmi_call_lock);
}

void rmi_call_unlock(){
	WARN("rmi_call_unlock\n");
	spin_unlock(&ongoing_rmi_call_lock);
}

// will be called once we exit the RMM and passing control back to the Hypervisor.
// The Hypervisor must release the lock and clean the 'pending_call_data' state.
// It does so by executing the rmmd_init_pte for the CORRECT sid and entry.
// TODO: this blocks much and is extremly slow, might need to update it. 
int __gpt_delegate_dev_pas(uint64_t base, size_t size, unsigned int src_sec_state, unsigned long delegate_flag, uint64_t iova){
	uint64_t sid = 31;
	int ret;
	// TODO: add sid.
	//lock_delegate_dev_rmi(base,iova,31);
	// 0x6d4 taken from Linux Kernel (consistent for same mapping type)
	ret = __map_pages(iova,base,1,0x6d4,0,sid,src_sec_state);
	if (ret){
        if (CUSTOM_DEBUG) {
            ERROR("mapping pages failed (from realm); phys 0x%lx;iova: 0x%lx; ret 0x%x\n",
                  base,
                  iova,
                  ret);
        }
	}
	return gpt_delegate_dev_pas(base, size, src_sec_state,delegate_flag);
}


static uint64_t paddr_to_iopte(uint64_t paddr)
{
	uint64_t pte = paddr;

	/* 
	 * Of the bits which overlap, either 51:48 or 15:12 are always RES0 
	 * WHY IS IT SHIFTED and ORed ???????????????? Ok I guess I know
	*/
	return (pte | (pte >> (48 - 12))) & ARM_LPAE_PTE_ADDR_MASK;
}

static uint64_t iopte_to_paddr(uint64_t pte)
{
	return pte & ARM_LPAE_PTE_ADDR_MASK;
}

static int __arm_lpae_init_pte(uint64_t num_entries, uint64_t paddr, uint64_t ptep, uint64_t lvl,
				 uint64_t bits_per_level, uint64_t prot , uint32_t src_sec_state)
{
	uint64_t pte = prot;
	size_t sz = ARM_LPAE_BLOCK_SIZE(lvl, bits_per_level);
	int i;
	// int ret;

	if (lvl == ARM_LPAE_MAX_LEVELS - 1)
		pte |= ARM_LPAE_PTE_TYPE_PAGE;
	else
		pte |= ARM_LPAE_PTE_TYPE_BLOCK;

	for (i = 0; i < num_entries; i++){
		// This call ensures the security of the page mapping
		// Whenever NS tries to map a page tagged as realm we fail here.
/* 		if (src_sec_state == SMC_FROM_REALM){
			ret = tag_as_realm_page(paddr + i * sz, false);
		}else{
			ret = tag_as_ns_page(paddr + i * sz, false);
		}
		// TODO: if we fail we could cleanup the state or just panic the NS system.
		if(ret){
            if (CUSTOM_DEBUG) {
                ERROR("__arm_lpae_init_pte, possible security risk\n");
            }
			return -EPERM;
		} */
		((uint64_t*)ptep)[i] = pte | paddr_to_iopte(paddr + i * sz);
	}
	return 0;
}

static int __arm_lpae_remove_pte(uint64_t num_entries, uint64_t paddr, uint64_t ptep, uint64_t lvl,
				 uint64_t bits_per_level, uint32_t src_sec_state)
{
	size_t sz = ARM_LPAE_BLOCK_SIZE(lvl, bits_per_level);
	int i, ret;

	for (i = 0; i < num_entries; i++){
		if ( (get_security_tag(paddr + i * sz) != GRANULE_BELONGS_TO_REALM) && (src_sec_state == SMC_FROM_REALM)){
			ERROR("NS tried to unmap realm pages, exiting | phys_addr: %lx", paddr + i * sz);
			return -EPERM;
		}
		// Not necessary to do the other check, since the RMM will check that the addresses are valid
		// Since the RMM belongs to the TCB we can rely on it.

		//WARN("before deref of ptep\n");
		// Once the page is tagges as uninitialized we allow remappings. Thus we must zero it before.
		// This might break functionality for applications which unmap DMA pages and then still want to use their data
		// TODO: check if unmapping and reusing is possible / actually used.
		memset((void*)(paddr + i * sz),0,4096);
		ret = tag_as_uninitialized(paddr + i * sz);
		if(ret){
			ERROR("__arm_lpae_remove_pte, internal error, could not mark page %lx as uninitialized | continue with possible corrupted internal state\n",paddr + i * sz);
		}
		((uint64_t*)ptep)[i] = 0;
	}
	dmboshst();
	// TODO: signalize the smmu that the s2 table has been updated and flush the TLB
	return 0;
}

int rmmd_init_pte_realm(uint64_t num_entries, uint64_t paddr, uint64_t ptep, uint64_t lvl,
				 uint64_t bits_per_level, uint64_t prot, unsigned long sid, uint64_t iova){
	int ret;
	if (CUSTOM_DEBUG){
		WARN("init_pte paddr %lx\n",paddr);
		WARN("saved paddr %lx\n",pending_call_data.phys_addr);
		WARN("saved sid %lx\n",pending_call_data.sid);
		WARN("saved valid %x\n",pending_call_data.valid);
	}
	spin_lock(&pgtable_s2_lock);
	if (!pending_delegate_dev_rmi(paddr)){
		ERROR("no pending rmi for paddr: %lx\n", paddr);
		return -1;
	}
	if(validate_page_table_pos_for_init_pte(iova,ptep, sid)){
		// TODO: Probably we should panic here to not have the REALM in an undefined state.
		// TODO: we may also set the return value of the mapping call to false (more work).
		ERROR("wrong ptep (0x%lx) or sid (%lx) for paddr: %lx", ptep, sid, paddr);
		return -1;
	}
	// set the data to be invalid.
	pending_call_data.valid = false;
	rmi_call_unlock();
	// Not fully implemented, the actual driver does some sanity checks before for all pages which we skip.
	ret =  __arm_lpae_init_pte(num_entries, paddr, ptep, lvl, bits_per_level, prot , SMC_FROM_REALM); 
	spin_unlock(&pgtable_s2_lock);
	return ret;
}

int rmmd_init_pte_ns(uint64_t num_entries, uint64_t paddr, uint64_t ptep, uint64_t lvl,
				 uint64_t bits_per_level, uint64_t prot, unsigned long sid){
	int ret;
	spin_lock(&pgtable_s2_lock);
	if(owned_by_realm(paddr)){
		ERROR("paddr: %lx we want to map belongs to realm", paddr);
		return -1;
	}
	// Not fully implemented, the actual driver does some sanity checks before for all pages which we skip.
	ret =  __arm_lpae_init_pte(num_entries, paddr, ptep, lvl, bits_per_level, prot , SMC_FROM_NON_SECURE); 
	spin_unlock(&pgtable_s2_lock);
	return ret;
}

int rmmd_init_pte(uint64_t num_entries, uint64_t paddr, uint64_t ptep, uint64_t lvl,
				 uint64_t bits_per_level, uint64_t prot, unsigned long sid, uint64_t iova)
{
	// TODO: (SECURITY RELEVANT)
	// Limit num_entries to 1 or do the double check; otherwise NS can overwrite arbitrariy memory.
	switch (get_security_tag(ptep))
	{
	case GRANULE_UNINITIALIZED:
		ERROR("ptep uninitialized\n");
		return -1;
	case GRANULE_BELONGS_TO_REALM:
		return rmmd_init_pte_realm(num_entries, paddr, ptep, lvl, bits_per_level, prot, sid, iova);
	case GRANULE_BELONGS_TO_NS: 
		return rmmd_init_pte_ns(num_entries, paddr, ptep, lvl, bits_per_level, prot, sid);
	default:
		ERROR("unreachable statement, internal error\n");
		return -1;
	}
}

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define u64 uint64_t

#define __CMPXCHG_CASE(w, sfx, name, sz, mb, acq, rel, cl, constraint)	\
static inline u##sz						\
__ll_sc__cmpxchg_case_##name##sz(volatile void *ptr,			\
					 unsigned long old,		\
					 u##sz new)			\
{									\
	unsigned long tmp;						\
	u##sz oldval;							\
	/*									\
	 * Sub-word sizes require explicit casting so that the compare  \
	 * part of the cmpxchg doesn't end up interpreting non-zero	\
	 * upper bits of the register containing "old".			\
	 */								\
	if (sz < 32)							\
		old = (u##sz)old;					\
									\
	asm volatile(							\
	"	prfm	pstl1strm, %[v]\n"				\
	"1:	ld" #acq "xr" #sfx "\t%" #w "[oldval], %[v]\n"		\
	"	eor	%" #w "[tmp], %" #w "[oldval], %" #w "[old]\n"	\
	"	cbnz	%" #w "[tmp], 2f\n"				\
	"	st" #rel "xr" #sfx "\t%w[tmp], %" #w "[new], %[v]\n"	\
	"	cbnz	%w[tmp], 1b\n"					\
	"	" #mb "\n"						\
	"2:"								\
	: [tmp] "=&r" (tmp), [oldval] "=&r" (oldval),			\
	  [v] "+Q" (*(u##sz *)ptr)					\
	: [old] __stringify(constraint) "r" (old), [new] "r" (new)	\
	: cl);								\
									\
	return oldval;							\
}

__CMPXCHG_CASE( ,  ,     , 64,        ,  ,  ,         , L)


// attack: just map pages all over again and use the addresses as values.
// the MMU will stop after the 4-stage walk, but we don't know at which level we are (atm.).
static int install_table(uint64_t table, uint64_t ptep, uint64_t curr, uint64_t sid,  uint64_t iova){
	uint64_t old=0, new;
/* 	uint8_t ptep_tag = get_security_tag(ptep);

	// We can only modify pages marked as table
	if (!is_tagged_as_table(ptep)){
		WARN("ptep: %lx is not tagged as table, tag: %x",ptep,ptep_tag);
		return -1;
	}
	// We allow to overwrite REALM entries, which effectively unmap certain regions
	// This is not a security vulnerability, it's a DOS attack.  
	if(validate_args_for_install_table(table, ptep, sid,iova)){
		ERROR("validate_args_for_install_table \n");
		return -1;
	}

	switch (ptep_tag)
	{
	case GRANULE_BELONGS_TO_NS:
		tag_as_ns_page(table,true);
		break;
	case GRANULE_BELONGS_TO_REALM:
		tag_as_realm_page(table,true);
		break;
	case GRANULE_UNINITIALIZED:
		ERROR("ptep is uninitalized %lx\n", ptep);
		// TODO: panic????
		return -1;
	default:
		ERROR("unknow tag (%x) for ptep: %lx\n", ptep_tag, ptep);
		break;
	} */
	// TODO: Security, verify the level of the page.

	new = paddr_to_iopte(table) | ARM_LPAE_PTE_TYPE_TABLE;
	// careful, page with msb set is not available
	new |= ARM_LPAE_PTE_NSTABLE;

	// * memset whole table to 0 to prevent pre-mapping attacks.
	memset((void *)table,0,4096);
	/*
	 * Ensure the table itself is visible before its PTE can be.
	 * Whilst we could get away with cmpxchg64_release below, this
	 * doesn't have any ordering semantics when !CONFIG_SMP.
	 */
	dmboshst();
	if (CUSTOM_DEBUG){
		WARN("smmuv3: install table, ptep: %lx |  curr: %lx | new: %lx\n",ptep,curr,new);
	}
	// old = cmpxchg64_relaxed(ptep, curr, new);
	// code to atomic swap
	old = __ll_sc__cmpxchg_case_64((void*)ptep,curr,new);
/* 	ptep[curr] ^= new;
	new ^= ptep[curr];
	ptep[curr] ^= new; */ 
	if (CUSTOM_DEBUG){
		WARN("smmuv3: install table, ptep: %lx |  curr: %lx | new: %lx | %lx\n",ptep,curr,new, old);
	}
	if (old == curr)
		*(volatile uint64_t*)ptep = new | ARM_LPAE_PTE_SW_SYNC;
	return old;
}

int rmmd_install_table(uint64_t table, uint64_t ptep,uint64_t curr, uint64_t sid, uint64_t iova)
{	
	int ret;
	spin_lock(&pgtable_s2_lock);
	if (gpt_delegate_dev_pas(table, 4096, SMC_FROM_REALM, 1)){
		ERROR("error adjusting the GPT table");
		return -1;
	}
	// Not fully implemented, the actual driver does some sanity checks before for all pages which we skip.;
	// We can skip this, since we did not ran into it atm. 
	// However, once we encounter issues double check with the real implementation.
	ret = install_table(table, ptep, curr, sid, iova);
	spin_unlock(&pgtable_s2_lock);
	return ret;
}

// only needed for testing, will be removed..
// TODO: remove
static int rmmd_move_pgd(uint64_t pgd, uint32_t src_sec_state){
	if (CUSTOM_DEBUG){
		WARN("moving pgd to protected NS, tag page as %x\n", src_sec_state);
	}
	if (gpt_delegate_dev_pas(pgd, 4096, SMC_FROM_REALM, 1)){
		ERROR("error adjusting the GPT table");
		return -1;
	}
	if (src_sec_state == SMC_FROM_REALM){
		return tag_as_realm_page(pgd, true);
	}
	return tag_as_ns_page(pgd, true);
}

// pointer dereference is non-critial data, since the pages are all protected 
// through the GPT.
unsigned long get_pte_from_table(uint64_t pte){
	if (CUSTOM_DEBUG){
		WARN("check if PTE is present \n");
	}
	// ONLY allow dereferences of table entries (aka table flag is set)
	if (!is_tagged_as_table(pte)){
		WARN("PTE is not tagged as TABLE %lx\n",pte);
		return -1;
	}
	return *(uint64_t*)pte;
}

void *alloc_page(){
	s2_mem_struct.current_ptr += 4096;
	if (s2_mem_struct.base_addr+s2_mem_struct.size <= s2_mem_struct.current_ptr){
		ERROR("not enough memory for s2 tables, panic");
		panic();
	}
	return s2_mem_struct.current_ptr;
}

unsigned long map_pages(uint64_t iova, uint64_t paddr, uint64_t pgcount, uint64_t prot, 
					 	uint64_t lvl, uint64_t *ptep, uint64_t sid, uint64_t* mapped, uint32_t src_sec_state){
	uint64_t *cptep, pte;
	int ret = 0, num_entries, max_entries, map_idx_start;

	/* Find our entry at the current level */
	// +3 to convert byte idx to uint64_t idx.
	map_idx_start = iova >> (9*(4-lvl) + 3) & 0x1ff,
	// ptep is always the pointer to the top/bottom of the curren page table at level lvl.
	// Get the idx.
	ptep += map_idx_start;

	if (CUSTOM_DEBUG){
		WARN("smmuv3: __arm_lpae_map page on level: %lx | iova: %lx | phys: %lx | idx: 0x%x\n",lvl,iova, paddr, map_idx_start);
	}

	/* If we can install a leaf entry at this level, then do so */
	if (lvl == 3) {
		if (CUSTOM_DEBUG){
			WARN("smmuv3: trying to map entry at current level %lx\n",lvl);
		}
		// 512 = 4096 >> 3
		max_entries = 512 - map_idx_start;
		num_entries = pgcount >  max_entries ? max_entries : pgcount;
		ret = __arm_lpae_init_pte(num_entries, paddr, (uint64_t)ptep, lvl, 9, prot , src_sec_state);
		//ret = arm_lpae_init_pte(data, iova, paddr, prot, lvl, num_entries, ptep);
		if (!ret){
			*mapped += num_entries * 4096;
			if (CUSTOM_DEBUG){
				WARN("smmuv3: map success, paddr: %lx | va: %lx | num_entries: %x\n", paddr, iova, num_entries);
			}
		}	
		return ret;
	}

	pte = *ptep;
	//WARN("ptev3 readonce: %lx\n", pte);
	if (!pte) {
		// If there is no next level page allocated at the current idx
		// we need to allocate a page.
		cptep = (uint64_t *)alloc_page();
		if (!cptep)
			return -ENOMEM;
		
		// * We will call to EL3 here.
		pte = install_table((uint64_t)cptep, (uint64_t)ptep, 0, sid, iova);
		//pte = arm_lpae_install_table(cptep, ptep, 0, data);
		if (pte){
			ERROR("error installing table, non recoverable");
			panic();
		}
	}
	if (pte /* && !iopte_leaf(pte, lvl, data->iop.fmt) */) {
		cptep = (uint64_t *)iopte_to_paddr(pte);
	}
	/* Rinse, repeat */
	return map_pages(iova, paddr, pgcount, prot, lvl + 1,
			      cptep, sid,mapped, src_sec_state);
}

unsigned long unmap_pages(uint64_t iova, uint64_t paddr, uint64_t pgcount, 
					 	uint64_t lvl, uint64_t *ptep, uint64_t sid, uint64_t* unmapped, uint32_t src_sec_state){
	uint64_t *cptep, pte;
	int ret = 0, num_entries, max_entries, map_idx_start;

	/* Find our entry at the current level */
	// +3 to convert byte idx to uint64_t idx.
	map_idx_start = iova >> (9*(4-lvl) + 3) & 0x1ff,
	// ptep is always the pointer to the top/bottom of the curren page table at level lvl.
	// Get the idx.
	ptep += map_idx_start;

	if (CUSTOM_DEBUG){
		WARN("smmuv3: __arm_lpae_unmap page on level: %lx | iova: %lx | phys: %lx | idx: 0x%x\n",lvl,iova, paddr, map_idx_start);
	}

	/* If we can install a leaf entry at this level, then do so */
	if (lvl == 3) {
		if (CUSTOM_DEBUG){
			WARN("smmuv3: trying to map entry at current level %lx\n",lvl);
		}
		// 512 = 4096 >> 3
		max_entries = 512 - map_idx_start;
		num_entries = pgcount >  max_entries ? max_entries : pgcount;
		ret = __arm_lpae_remove_pte(num_entries, paddr, (uint64_t)ptep, lvl, 9,src_sec_state);
		if (!ret){
			*unmapped += num_entries * 4096;
			if (CUSTOM_DEBUG){
				WARN("smmuv3: unmap success, paddr: %lx | va: %lx | num_entries: %x\n", paddr, iova, num_entries);
			}
		}	
		return ret;
	}

	pte = *ptep;
	//WARN("ptev3 readonce: %lx\n", pte);
	if (!pte) {
		// the page is not mapped at all
		return -EFAULT;
	}
	if (pte /* && !iopte_leaf(pte, lvl, data->iop.fmt) */) {
		cptep = (uint64_t *)iopte_to_paddr(pte);
	}
	/* Rinse, repeat */
	return unmap_pages(iova, paddr, pgcount, lvl + 1,
			      cptep, sid,unmapped,src_sec_state);
}

// TODO: implement
static bool sid_belongs_to_realm(uint64_t sid){
	return false;
}

static unsigned long __unmap_pages( uint64_t iova, uint64_t paddr, uint64_t pgcount, 
					 	uint64_t ptep, uint64_t sid, unsigned int sec_state){
	uint64_t unmapped,ret, _pgcount;
	uint64_t *vttbr = (uint64_t *)ptep;
	_pgcount = pgcount;
	unmapped = 0;
	spin_lock(&pgtable_s2_lock);
	if (sid_belongs_to_realm(sid) && sec_state != SMC_FROM_REALM){
		WARN("NS tried to manipulate realm device pages\n");
		spin_unlock(&pgtable_s2_lock);
		return -EPERM;
	}

	if(vttbr == NULL){
		if (CUSTOM_DEBUG){
			WARN("vttbr is NULL, deriving it from SID: %lx\n", sid);
		}
		vttbr = get_vttbr_from_sid(sid);
	}

	if(vttbr == NULL){
		ERROR("vttbr is NULL after deriving, panic\n");
		panic();
	}
	if (CUSTOM_DEBUG){
		WARN("called map_pages, iova: %lx, paddr: %lx, ptep: %lx, sid: %lx\n",iova,paddr,ptep,sid);
	}
	/* Find our entry at the current level */;
	// TODO: think about what happens if we allow NS to unmap arbitrary pages.
	while (unmapped != pgcount * 4096){
		ret = unmap_pages(iova, paddr, _pgcount, 0,
			      vttbr, sid, &unmapped, sec_state);
		if (ret){
			ERROR("unmapping pages error, ret: %lx", ret);
			spin_unlock(&pgtable_s2_lock);
			return ret;
		}
		_pgcount = pgcount - (unmapped >> 12);
	}
	spin_unlock(&pgtable_s2_lock);
	return 0; 
}

static unsigned long __map_pages( uint64_t iova, uint64_t paddr, uint64_t pgcount, uint64_t prot, 
					 	uint64_t ptep, uint64_t sid, unsigned int sec_state){
	uint64_t mapped,ret, _pgcount;
	uint64_t *vttbr = (uint64_t *)ptep;
	_pgcount = pgcount;
	mapped = 0;
	spin_lock(&pgtable_s2_lock);
	if (sid_belongs_to_realm(sid) && sec_state != SMC_FROM_REALM){
		WARN("NS tried to manipulate realm device pages\n");
		spin_unlock(&pgtable_s2_lock);
		return -EPERM;
	}

	if(vttbr == NULL){
		if (CUSTOM_DEBUG){
			WARN("vttbr is NULL, deriving it from SID: %lx\n", sid);
		}
		vttbr = get_vttbr_from_sid(sid);
	}

	if(vttbr == NULL){
		ERROR("vttbr is NULL after deriving, panic\n");
		panic();
	}
	if (CUSTOM_DEBUG){
		WARN("called map_pages, iova: %lx, paddr: %lx, ptep: %lx, sid: %lx\n",iova,paddr,ptep,sid);
	}
	/* Find our entry at the current level */;
	while (mapped != pgcount * 4096){
		ret = map_pages(iova, paddr, _pgcount, prot, 0,
			      vttbr, sid, &mapped, sec_state);
		if (ret){
            if (CUSTOM_DEBUG) {
                ERROR("mapping pages error, ret: %lx", ret);
            }
			spin_unlock(&pgtable_s2_lock);
			return ret;
		}
		_pgcount = pgcount - (mapped >> 12);
	}
	spin_unlock(&pgtable_s2_lock);
	return 0; 
}

unsigned long delegate_s2_mem(uint64_t base_ptr, uint64_t size){
	if (CUSTOM_DEBUG){
		WARN("DELEGATE_S2_MEM CALLED\n");
	}
	s2_mem_struct.base_addr = (void*)base_ptr;
	s2_mem_struct.size = size;
	s2_mem_struct.current_ptr = (void*)base_ptr-4096;
	
	// If we do it like this we have high init costs
	// Otherwise we can delegate on request
	for (size_t i = 0; i < size; i+=4096)
	{
		gpt_delegate_dev_pas(base_ptr+i, 4096, SMC_FROM_REALM, 1);
		// Will be done in table init a second time.
		memset((void *)base_ptr+i,0,4096);
	}
	return 0;
}

unsigned long delegate_ring_buffer(uint64_t base_ptr, uint64_t producer, uint64_t consumer, uint64_t size){
	uint64_t idx = 0;
	spin_lock(&command_queue.lock);
	WARN("base addr ptr for ring buffer %p\n",(void*)base_ptr);
	WARN("consumer offset for ring buffer %p\n",(uint32_t *)consumer);
	WARN("producer offset for ring buffer %p\n",(uint32_t *)producer);
	command_queue.base_addr = (void*)base_ptr;
	command_queue.consumer_ptr = (uint32_t *)consumer;
	command_queue.producer_ptr = (uint32_t *)producer;
	command_queue.size = size;
	command_queue.producer_value = 0;
	
	*command_queue.producer_ptr = command_queue.producer_value;

	// the queue needs to at least one page (derived from Linux source)
	do{
		gpt_delegate_dev_pas((uint64_t)command_queue.base_addr+idx,4096,SMC_FROM_REALM,1);
		idx += 4096;
	}while(idx < size);
	spin_unlock(&command_queue.lock);
	return 0;
}

// TODO: MAP THE DEVICE REGION ~20XXXX - ~30XXXX to ROOT as NS memory.
// SYNC CMDD is probably just 8 byte long (instead of 16)
unsigned long submit_to_cmdq(uint64_t first_val,uint64_t second_val){
	uint64_t consumer,producer;
	uint64_t *ptr_producer;
	spin_lock(&command_queue.lock);
	if (CUSTOM_DEBUG){
		WARN("submitting command to cmd queue\n");
	}
	consumer = (*command_queue.consumer_ptr);
	producer = (*command_queue.producer_ptr);
	if (CUSTOM_DEBUG){
		WARN("consumer pointer %p, producer pointer %p\n", command_queue.consumer_ptr,command_queue.producer_ptr);
		WARN("consumer 0x%lx, producer 0x%lx | size -1 %lx | idx %lx\n", consumer,producer, (command_queue.size >> 4)-1, Q_IDX(command_queue));
	}
	ptr_producer = (command_queue.base_addr + 2 * Q_IDX(command_queue));
	ptr_producer[0] = first_val;
	ptr_producer[1] = second_val;
	command_queue.producer_value += 1;
	//WARN("write to queue pointer %p | %p\n", &ptr_producer[0],&ptr_producer[1]);
	//WARN("write to queue pointer cmd[0] %lx | cmd[1]%lx\n", first_val,second_val);
	*command_queue.producer_ptr = command_queue.producer_value;
	__asm__ __volatile__("": : :"memory");
	dmboshst();
	spin_unlock(&command_queue.lock);
	return 0;
}

unsigned long read_from_cmdq(){
	WARN("submitting command to cmd queue\n");
	dmboshst();
	return  0; //*((uint32_t *)(*command_queue.consumer));
}


// TODO: Validate num args as well or only allow 1 page at a time to be mapped.

/*******************************************************************************
 * This function handles RMM-EL3 interface SMCs
 ******************************************************************************/
uint64_t rmmd_rmm_el3_handler(uint32_t smc_fid, uint64_t x1, uint64_t x2,
				uint64_t x3, uint64_t x4, void *cookie,
				void *handle, uint64_t flags)
{   CCA_TFA_SMC_RMM();
	unsigned long ret;
	unsigned int src_sec_state;
	uint64_t x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
	uint64_t x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
	//uint64_t x7 = SMC_GET_GP(handle, CTX_GPREG_X7);
	//uint64_t x8 = SMC_GET_GP(handle, CTX_GPREG_X8);

	/* If RMM failed to boot, treat any RMM-EL3 interface SMC as unknown */
	if (rmm_boot_failed) {
		WARN("RMMD: Failed to boot up RMM. Ignoring RMM-EL3 call\n");
		SMC_RET1(handle, SMC_UNK);
	}

	/* Determine which security state this SMC originated from */
	src_sec_state = caller_sec_state(flags);

	/*
 	if (src_sec_state != SMC_FROM_REALM) {
		WARN("RMMD: RMM-EL3 call originated from secure or normal world\n");
		SMC_RET1(handle, SMC_UNK);
	} */
	//WARN("RMMD: RMM-EL3 call %x | sec state %x\n",smc_fid, src_sec_state);

	switch (smc_fid) {
	case RMM_GTSI_DELEGATE:
		CCA_TFA_SMC_DELEGATE_PAS_START();
		ret = gpt_delegate_pas(x1, PAGE_SIZE_4KB, SMC_FROM_REALM);
		CCA_TFA_SMC_DELEGATE_PAS_STOP();
		SMC_RET1(handle, gpt_to_gts_error(ret, smc_fid, x1));
	case RMM_GTSI_UNDELEGATE:
		CCA_TFA_SMC_UNDELEGATE_PAS_START();
		ret = gpt_undelegate_pas(x1, PAGE_SIZE_4KB, SMC_FROM_REALM);
		CCA_TFA_SMC_UNDELEGATE_PAS_STOP();
		SMC_RET1(handle, gpt_to_gts_error(ret, smc_fid, x1));
	case RMM_ATTEST_GET_PLAT_TOKEN:
		ret = rmmd_attest_get_platform_token(x1, &x2, x3);
		SMC_RET2(handle, ret, x2);
	case RMM_ATTEST_GET_REALM_KEY:
		ret = rmmd_attest_get_signing_key(x1, &x2, x3);
		SMC_RET2(handle, ret, x2);

	// * Stream Table Stuff
	// ! Boot
	case RMM_TRANSITION_STREAM_TABLE:
		CCA_TFA_SMC_TRANSITION_STREAM_TABLE_START()
		ret = transition_stream_table(x1, x2);
		CCA_TFA_SMC_TRANSITION_STREAM_TABLE_STOP()
		SMC_RET1(handle, ret);

	// * Reimplementation of S2 table map
	case RMM_MOVE_PAGE_TO_REALM:
		// Will only be called once to move pgd initially
		CCA_TFA_SMC_MOVE_PAGE_TO_REALM();
		ret = rmmd_move_pgd(x1,src_sec_state);
		SMC_RET1(handle, ret);
	case RMM_MAP_PAGES:
		CCA_TFA_ENTER_SMC_MAP_PAGES();
		ret = __map_pages(x1,x2,x3,x4,x5,x6,src_sec_state);
		CCA_TFA_EXIT_SMC_MAP_PAGES();
		SMC_RET1(handle, ret);
	// ! Boot
	case RMM_DELEGATE_S2_TBL_MEMORY:
		CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_START();
		ret = delegate_s2_mem(x1,x2);
		CCA_TFA_SMC_DELEGATE_S2_TBL_MEMORY_STOP();
		SMC_RET1(handle,ret);
	case RMM_UNMAP_PAGES:
		CCA_TFA_ENTER_SMC_UNMAP_PAGES(); 
		ret = __unmap_pages(x1,x2,x3,x4,x5,src_sec_state);
		CCA_TFA_EXIT_SMC_UNMAP_PAGES(); 
		SMC_RET1(handle,ret);

	// * Ring buffer delegation
	// ! Boot
	case RMM_DELEGATE_RING_BUFFER:
	CCA_TFA_SMC_DELEGATE_RING_BUFFER_START();
		CCA_TFA_SMC_DELEGATE_RING_BUFFER();
		ret = delegate_ring_buffer(x1,x2,x3,x4);
		CCA_TFA_SMC_DELEGATE_RING_BUFFER_STOP();
		SMC_RET1(handle,ret);
	case RMM_CMDQUEUE_SUBMIT:
		CCA_TFA_CMDQUEUE_SUBMIT();
		ret = submit_to_cmdq(x1,x2);
		SMC_RET1(handle,ret);
	// ! Boot
	case RMM_TRANSITION_CONTROL_PAGE:
		// * PAGE 0
		// We ignore the enhanced control queue interface for now (also no Linux support yet)
		// * PAGE 1
		// According to the spec the page only contains READING queues which are non, critical for security operation.
		// Thus we don't need to touch it in any way 
		if (CUSTOM_DEBUG){
			WARN("------TRANSITION CONTROL_PAGE TO ROOT------\n");
		}
		CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_START();
		ret = gpt_delegate_dev_pas(x1,4096,SMC_FROM_REALM,1);
		// 0x8000 is the offset for the SECURE programming interface, we are not using it atm, but lock it anyways
		// * This could also be done on TFA boot to ensure not EL2 HV manipulation.
		ret |= gpt_delegate_dev_pas(x1+0x8000,4096,SMC_FROM_REALM,1);
		CCA_TFA_RMM_TRANSITION_CONTROL_PAGE_STOP();
		SMC_RET1(handle,ret);
	case RMM_MEMSET:
		memset((void*)x1,x2,4096);
		SMC_RET1(handle,0);

	case RMM_BOOT_COMPLETE:
		CCA_TFA_RMM_BOOT_DONE();
		VERBOSE("RMMD: running rmmd_rmm_sync_exit\n");
		rmmd_rmm_sync_exit(x1);
	case RMM_GTSI_DELEGATE_DEV:
		CCA_TFA_SMC_DEL_DEV_PAS_START();
		ret = __gpt_delegate_dev_pas(x1, PAGE_SIZE_4KB, SMC_FROM_REALM, x2,x3);
		CCA_TFA_SMC_DEL_DEV_PAS_STOP();
		SMC_RET1(handle, gpt_to_gts_error(ret, smc_fid, x1));
	// ! REALM
	case RMM_REQUEST_DEVICE_OWNERSHIP:
		CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_START();
		ret = claim_device_for_realm(x1, x2, src_sec_state);
		CCA_TFA_RMM_REQUEST_DEVICE_OWNERSHIP_STOP();
		SMC_RET1(handle, 0);
	case RMM_GTSI_ATTACH_DEV:
		CCA_TFA_SMC_ATTACH_DEV_START();
		ret = gpt_attach_dev(x1);
		CCA_TFA_SMC_ATTACH_DEV_STOP();
		SMC_RET1(handle, gpt_to_gts_error(ret, smc_fid, x1));
	default:
		WARN("RMMD: Unsupported RMM-EL3 call 0x%08x\n", smc_fid);
		SMC_RET1(handle, SMC_UNK);
	}
}
