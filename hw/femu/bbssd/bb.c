#include "../nvme.h"
#include "./ftl.h"

static void bb_init_ctrl_str(FemuCtrl *n)
{
    static int fsid_vbb = 0;
    const char *vbbssd_mn = "FEMU BlackBox-SSD Controller";
    const char *vbbssd_sn = "vSSD";

    nvme_set_ctrl_name(n, vbbssd_mn, vbbssd_sn, &fsid_vbb);
}

/* bb <=> black-box */
static void bb_init(FemuCtrl *n, Error **errp)
{
    struct ssd *ssd = n->ssd = g_malloc0(sizeof(struct ssd));

    bb_init_ctrl_str(n);

    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    femu_debug("Starting FEMU in Blackbox-SSD mode ...\n");
    ssd_init(n);
}

static void bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    struct ssd *ssd = n->ssd;
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        ssd->sp.enable_gc_delay = true;
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_GC_DELAY:
        ssd->sp.enable_gc_delay = false;
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_ENABLE_DELAY_EMU:
        ssd->sp.pg_rd_lat = NAND_READ_LATENCY;
        ssd->sp.pg_wr_lat = NAND_PROG_LATENCY;
        ssd->sp.blk_er_lat = NAND_ERASE_LATENCY;
        ssd->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_DELAY_EMU:
        ssd->sp.pg_rd_lat = 0;
        ssd->sp.pg_wr_lat = 0;
        ssd->sp.blk_er_lat = 0;
        ssd->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_RESET_ACCT:
        femu_log("清空前设备: %s的重删计数,清空前重删page: %lu, 未重删page: %lu, 总io: %lu\n",
        n->devname, n->dedup_pgs, n->no_dedup_pgs, n->nr_tt_ios);

        n->nr_tt_ios = 0;
        n->nr_tt_late_ios = 0;

        n->dedup_pgs = 0;
        n->no_dedup_pgs = 0;

        femu_log("清空前设备: %s的重删计数,清空前重删page: %lu, 未重删page: %lu, 总io: %lu\n",
        n->devname, n->dedup_pgs, n->no_dedup_pgs, n->nr_tt_ios);


        femu_log("%s,Reset tt_late_ios/tt_ios,%lu/%lu\n", n->devname,
                n->nr_tt_late_ios, n->nr_tt_ios);



        break;
    case FEMU_ENABLE_LOG:
        n->print_log = true;

        femu_log("%s,Log print [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_LOG:
        n->print_log = false;
        femu_log("%s,Log print [Disabled]!\n", n->devname);
        break;
    case FEMU_RESET_FINGERSTORE:
        g_free(ssd->seg);
        ssd->seg = g_malloc0(sizeof(struct segment) * NUM_SEG);
        for (int i = 0; i < NUM_SEG; i++) {
            ssd->seg[i].nbkts = 0;
            ssd->seg[i].bkts = NULL;
            ssd->seg[i].cur_bkt = NULL;
        }

        struct ssdparams *spp = &ssd->sp;

        ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
        for (int i = 0; i < spp->tt_pgs; i++) {
            ssd->maptbl[i].ppa = UNMAPPED_PPA;
        }

        ssd->secmaptbl = g_malloc0(sizeof(struct ppa_ref) * spp->tt_pgs / 1);
        for (int i = 0; i < spp->tt_pgs/1; i++) {
            ssd->secmaptbl[i].ppa.ppa = UNMAPPED_PPA;
            ssd->secmaptbl[i].reference = 0;
        }
        ssd->valid_vba_cnt = 0;
        ssd->cur_vba = 0;  
        ssd->cmp_cnt = 0;
        ssd->Yuqi = 0;
        ssd->Shij = 0;

        femu_log("重置指纹库 映射表\n");

        break;
    case FEMU_OPM0:
        bool st0 = ssd->opm0;
        ssd->opm0 = !st0;
        if (ssd->opm0)
            femu_log("优化0打开\n");
        else   
            femu_log("优化0关闭\n");            
        break;   
    case FEMU_OPM1:
        bool st1 = ssd->opm1;
        ssd->opm1 = !st1;
        if (ssd->opm1)
            femu_log("优化1打开\n");
        else   
            femu_log("优化1关闭\n");            
        break;    
    case FEMU_OPM2:
        bool st2 = ssd->opm2;
        ssd->opm2 = !st2;
        if (ssd->opm2)
            femu_log("优化2打开\n");
        else   
            femu_log("优化2关闭\n");  
        break;    
    case FEMU_OPM3:
        bool st3 = ssd->opm3;
        ssd->opm3 = !st3;
        if (ssd->opm3)
            femu_log("优化3打开\n");
        else   
            femu_log("优化3关闭\n");  
        break;    
    case FEMU_OPM4:
        bool st4 = ssd->opm4;
        ssd->opm4 = !st4;
        if (ssd->opm4)
            femu_log("优化4打开\n");
        else   
            femu_log("优化4关闭\n");  
        break;    
    case FEMU_CNT:
        femu_log("comparison cnt:%lu\n", ssd->cmp_cnt);
        femu_log("Yuqi: %lu, Shij: %lu\n", ssd->Yuqi, ssd->Shij);
        break;   
    default:
        printf("FEMU:%s,Not implemented flip cmd (%lu)\n", n->devname, cdw10);
    }
}

static uint16_t bb_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    return nvme_rw(n, ns, cmd, req);
}

static uint16_t bb_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return bb_nvme_rw(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t bb_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_FLIP:
        bb_flip(n, cmd);
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

int nvme_register_bbssd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = bb_init,
        .exit             = NULL,
        .rw_check_req     = NULL,
        .admin_cmd        = bb_admin_cmd,
        .io_cmd           = bb_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}

