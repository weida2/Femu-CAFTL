#include <openssl/sha.h>
#include "ftl.h"
#include "crc32.h"
#include <sys/time.h>
#include <string.h>

// #define femu_log_FTL


// struct timeval Start; /*only used for recording the cost*/
// double Cost = 0;

// static inline void cost_start(void) {
// 	Cost = 0;
// 	gettimeofday(&Start, NULL);
// }

// static inline void cost_end(void) {
// 	double elapsed;
// 	struct timeval costEnd;
// 	gettimeofday(&costEnd, NULL);
// 	elapsed = ((costEnd.tv_sec*1000000+costEnd.tv_usec)-(Start.tv_sec*1000000+Start.tv_usec));
// 	Cost += elapsed;
// }


static void mark_page_invalid(struct ssd *ssd, struct ppa *ppa);
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa);
static struct ppa get_new_vba(struct ssd *ssd);
static void ssd_advance_vba(struct ssd *ssd);
static void *ftl_thread(void *arg);
static uint32_t fetch_pre_be(uint8_t *buffer);


static uint32_t fetch_pre_be(uint8_t *buffer) {
    const uint8_t b0 = buffer[0], b1 = buffer[1], b2 = buffer[2], b3 = buffer[3]; 

    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3; 
}



static inline unsigned int get_seg_num(unsigned char *sha1) {
    return *(unsigned short *)sha1 >> (8*sizeof(unsigned short) - SEG_NUM_BITS);
}

static inline int sha1_cmp(unsigned char *x, unsigned char *y) {
    return memcmp(x, y, SHA_DIGEST_LENGTH);
}

/* search sha1 in bkt, return 1 and result written into vba if found, 
    if not found, return 0 and insert sha1 into seg. */
static int search_in_bucket(struct bucket *p_bkt, unsigned char *sha1, struct ppa *vba) {
    struct finger_entry *p_entry = p_bkt->first_entry;
    
    // opm0: min and max sha1
    if (sha1_cmp(sha1, p_bkt->min_sha1) < 0 || 
    sha1_cmp(sha1, p_bkt->max_sha1) > 0 ) {
        return 0;
    }

    bool opm1 = true;
    
    if (opm1) {
    // opm1: binary search
        int l = 0, r = p_bkt->nentries;
        int mid = 0;
        while (l <= r) {
            mid = (l + r) / 2;
            int check = sha1_cmp(sha1, p_entry[mid].sha1);
            if (check < 0) r = mid - 1;
            else if (check > 0) l = mid + 1;
            else {
                vba->ppa = p_entry[mid].vba.ppa;
                p_entry[mid].count ++;  //
                femu_log("[search]: sha1 found in seg#%u,bkt#%d,entry#%d\n",get_seg_num(sha1),p_bkt->number,mid);
                return 1;
            }
        }
    } else {
        for (; p_entry < p_bkt->first_entry+p_bkt->nentries; p_entry++) {
            if (!sha1_cmp(sha1, p_entry->sha1)) {
                vba->ppa = p_entry->vba.ppa;
                p_entry->count ++;  //
                femu_debug("[search]: sha1 found in seg#%u,bkt#%d,entry#%ld\n",get_seg_num(sha1),p_bkt->number,p_entry-p_bkt->first_entry);
                return 1;
            }
        }
    }
    return 0;
}

static inline void set_entry(struct finger_entry *entry, unsigned char *sha1, struct ppa *vba, uint8_t count) {
    entry->vba.ppa = vba->ppa;
    entry->count = count;
    memcpy(entry->sha1, sha1, SHA_DIGEST_LENGTH);
}

static int find_least_cnt_entry(struct bucket *bkt) {
    int res = 0;
    int least_cnt = 100;
    for (int i=0; i<bkt->nentries; i++) {
        if(bkt->first_entry[i].count < least_cnt) {
            least_cnt = bkt->first_entry[i].count;
            res = i;
        }
    }
    return res;
}

static void add_sha1_to_seg(struct ssd *ssd, struct segment *seg, unsigned char *sha1, struct ppa *vba) {
    struct bucket *p_bkt = seg->cur_bkt;
    struct ppa new_vba;
    new_vba = get_new_vba(ssd);
    ssd_advance_vba(ssd);
    vba->ppa = new_vba.ppa;
    femu_log("获得新的 vba->ppa: %lu", vba->ppa);

    bool opm1 = true;

    if (seg->nbkts < NUM_BKT_PER_SEG ) {
        // seg not full,
        if (seg->nbkts == 0 || p_bkt->nentries >= NUM_ENTRY_PER_BKT) {
            // bkt full or no bkt, make a new one
            femu_log("[FGPRT]:make a new bkt\n");
            struct bucket *new_bkt = g_malloc0(sizeof(struct bucket));
            new_bkt->nentries = 0;
            new_bkt->number = seg->nbkts;
            memcpy(new_bkt->max_sha1, sha1, SHA_DIGEST_LENGTH);
            memcpy(new_bkt->min_sha1, sha1, SHA_DIGEST_LENGTH);
            // init entry
            set_entry(new_bkt->first_entry, sha1, vba, 1);
            new_bkt->nentries++;
            // update seg
            seg->nbkts++;
            if (seg->cur_bkt) {
                // there are bkts already
                seg->cur_bkt->next = new_bkt;
            }
            else {
                // no bkt
                seg->bkts = new_bkt;
            }
            seg->cur_bkt = new_bkt;
            new_bkt->next = seg->bkts; // circle
        }
        else {
            // bkt not full, jush add
            femu_log("[FGPRT]:add to bkt\n");
            
            // optimization1 sort bpkt'entry
            if (opm1) {
                int i = 0;
                for (i = 0; i < p_bkt->nentries; i++) {
                    // find a insert idx
                    if (sha1_cmp(sha1, p_bkt->first_entry[i].sha1) < 0) {
                    for (int j = p_bkt->nentries; j >= i + 1; j--) {
                            p_bkt->first_entry[j] = p_bkt->first_entry[j - 1];
                    }
                    break;
                    }
                }
                set_entry(p_bkt->first_entry + i, sha1, vba, 1);
                p_bkt->nentries++;
            }else {
                set_entry(p_bkt->first_entry+p_bkt->nentries, sha1, vba, 1);
                p_bkt->nentries++;
            }

            if (sha1_cmp(sha1, p_bkt->min_sha1) < 0) {
                memcpy(p_bkt->min_sha1, sha1, SHA_DIGEST_LENGTH);
            }
            else if (sha1_cmp(sha1, p_bkt->max_sha1) > 0) {
                memcpy(p_bkt->max_sha1, sha1, SHA_DIGEST_LENGTH);
            }
        }
    }
    else {
        // all bkts full, select bkt in round-robin mode
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
        femu_log("[FGPRT]:all bkts full, select bkt in round-robin mode\n");
        p_bkt = seg->cur_bkt = seg->cur_bkt->next;
        
        // victimize the least counted entry
        int n = find_least_cnt_entry(p_bkt);
        set_entry(p_bkt->first_entry+n, sha1, vba, 1);
        p_bkt->nentries++;
        if (sha1_cmp(sha1, p_bkt->min_sha1) < 0) {
            memcpy(p_bkt->min_sha1, sha1, SHA_DIGEST_LENGTH);
        }
        else if (sha1_cmp(sha1, p_bkt->max_sha1) > 0) {
            memcpy(p_bkt->max_sha1, sha1, SHA_DIGEST_LENGTH);
        }
    }
}

int search_in_segment(struct ssd *ssd, struct segment *seg, unsigned char *sha1, struct ppa *vba) {
    unsigned int n = get_seg_num(sha1);
    femu_log("[search]:seg_num=%d, there're %d bkts\n",n,seg[n].nbkts);

    bool opm2 = false;

    struct segment *p_seg = seg + n;
    if (!p_seg->nbkts) {
        add_sha1_to_seg(ssd, p_seg, sha1, vba);
        return 0;
    }

    // opm2 : sort seg'bkt, binary search seg'bkt
    if (opm2 && p_seg->nbkts > 10) {
        int l = 0, r = p_seg->nbkts;
        int mid = 0;
        struct bucket *check_bkt = p_seg->bkts;
        while (l <= r) {
            mid = (l + r) / 2;
            check_bkt = p_seg->bkts;
            for (int i = 0; i < mid; i++) check_bkt = check_bkt->next;
            if (sha1_cmp(sha1, check_bkt->min_sha1) < 0) {
                r = mid - 1;
            }else if (sha1_cmp(sha1, check_bkt->min_sha1) > 0)l = mid + 1;
            else break;
        }
        if (search_in_bucket(check_bkt, sha1, vba)) {
            return 1;
        }      

    } else {
        struct bucket *p_bkt = p_seg->cur_bkt;
        for (int i=0; i<p_seg->nbkts; p_bkt=p_bkt->next,i++) {
            if (search_in_bucket(p_bkt, sha1, vba)) {
                return 1;
            }
        }
    }

    add_sha1_to_seg(ssd, p_seg, sha1, vba);
    return 0;
}



static inline bool should_gc(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines_high);
}

static inline struct ppa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
    return ssd->maptbl[lpn];
}

static inline struct ppa get_secmaptbl_ent(struct ssd *ssd, struct ppa *vba)
{
    struct ppa vba2;
    vba2.ppa = vba->ppa;
    vba2.g.rsv = 0;
    return ssd->secmaptbl[vba2.ppa].ppa;
}

static inline struct ppa get_secmaptbl_ent2(struct ssd *ssd, uint64_t vbn)
{
    return ssd->secmaptbl[vbn].ppa;
}

static inline uint8_t get_secmaptbl_ref(struct ssd *ssd, uint64_t vbn)
{
    return ssd->secmaptbl[vbn].reference;
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    ftl_assert(lpn < ssd->sp.tt_pgs);
    ssd->maptbl[lpn] = *ppa;
}

static inline void set_secmaptbl_ent(struct ssd *ssd, struct ppa *vba, struct ppa *ppa)
{
    struct ppa vba2;
    vba2.ppa = vba->ppa;
    vba2.g.rsv = 0;
    ftl_assert(vba2.ppn < ssd->sp.tt_pgs / 10);
    ssd->secmaptbl[vba2.ppa].ppa = *ppa;
    ssd->secmaptbl[vba2.ppa].reference= 1;
}

static inline void add_secmaptbl_res(struct ssd *ssd, struct ppa *vba)
{
    struct ppa vba2;
    vba2.ppa = vba->ppa;
    vba2.g.rsv = 0;
    if (ssd->secmaptbl[vba2.ppa].reference < 255) {
        ssd->secmaptbl[vba2.ppa].reference++;
    }
}

static inline void minus_secmaptbl_ref(struct ssd *ssd, struct ppa *vba)
{
    struct ppa vba2;
    vba2.ppa = vba->ppa;
    vba2.g.rsv = 0;
    if (ssd->secmaptbl[vba2.ppa].reference > 0) {
        ssd->secmaptbl[vba2.ppa].reference--;
    }
    else {
        femu_err("secmaptbl[%lu].reference=%d\n", vba2.ppa, ssd->secmaptbl[vba2.ppa].reference);
    }
}

// get next vba of secmaptbl
static void ssd_advance_vba(struct ssd *ssd) {
    ssd->cur_vba++;
    if (get_secmaptbl_ref(ssd, ssd->cur_vba) == 0) {
        //todo
        // struct ppa ppa = get_secmaptbl_ent2(ssd, ssd->cur_vba)
        // if (mapped_ppa(&ppa)) {
        //     mark_page_invalid(ssd, &ppa);
        // }
        return;
    }
    while (ssd->cur_vba + 1 < ssd->sp.tt_pgs / 2) {
        if (get_secmaptbl_ref(ssd, ssd->cur_vba) != 0) {
            ssd->cur_vba++;
        }
        else return;
    } 

    // find a empty vba entry from the beginning
    for(uint64_t vbn=0; vbn<ssd->sp.tt_pgs / 2; vbn++) {
        if(get_secmaptbl_ref(ssd, vbn) == 0) {
            // ref == 0, page invalid
            ssd->cur_vba = vbn;
            return;
        }
    }
    femu_err("no empty vba!\n");
}

static struct ppa get_new_vba(struct ssd *ssd)
{
    struct ppa vba;
    // vba.g.ch = -1;
    // vba.g.lun = -1;
    // vba.g.pg = -1;
    // vba.g.blk = -1;
    // vba.g.pl = -1;
    vba.g.rsv = 1;
    vba.ppa = ssd->cur_vba;
    ssd->valid_vba_cnt++;
    return vba;
}

static uint64_t ppa2pgidx(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pgidx;

    pgidx = ppa->g.ch  * spp->pgs_per_ch  + \
            ppa->g.lun * spp->pgs_per_lun + \
            ppa->g.pl  * spp->pgs_per_pl  + \
            ppa->g.blk * spp->pgs_per_blk + \
            ppa->g.pg;

    ftl_assert(pgidx < spp->tt_pgs);

    return pgidx;
}

static inline uint64_t get_rmap_ent(struct ssd *ssd, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    return ssd->rmap[pgidx];
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    ssd->rmap[pgidx] = lpn;
}

static inline int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_line_get_pri(void *a)
{
    return ((struct line *)a)->vpc;
}

static inline void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->vpc = pri;
}

static inline size_t victim_line_get_pos(void *a)
{
    return ((struct line *)a)->pos;
}

static inline void victim_line_set_pos(void *a, size_t pos)
{
    ((struct line *)a)->pos = pos;
}

static void ssd_init_lines(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *line;

    lm->tt_lines = spp->blks_per_pl;
    ftl_assert(lm->tt_lines == spp->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
            victim_line_get_pri, victim_line_set_pri,
            victim_line_get_pos, victim_line_set_pos);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->ipc = 0;
        line->vpc = 0;
        line->pos = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    ftl_assert(lm->free_line_cnt == lm->tt_lines);
    lm->victim_line_cnt = 0;
    lm->full_line_cnt = 0;
}

static void ssd_init_write_pointer(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;

    /* wpp->curline is always our next-to-write super-block */
    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = 0;
    wpp->pl = 0;
}

static inline void check_addr(int a, int max)
{
    ftl_assert(a >= 0 && a < max);
}

static struct line *get_next_free_line(struct ssd *ssd)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    if (!curline) {
        ftl_err("No free lines left in [%s] !!!!\n", ssd->ssdname);
        return NULL;
    }

    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    return curline;
}

static void ssd_advance_write_pointer(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch == spp->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                wpp->pg = 0;
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == spp->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    ftl_assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    ftl_assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < spp->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    ftl_assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, spp->blks_per_pl);
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ssd);
                if (!wpp->curline) {
                    /* TODO */
                    abort();
                }
                wpp->blk = wpp->curline->id;
                check_addr(wpp->blk, spp->blks_per_pl);
                /* make sure we are starting from page 0 in the super block */
                ftl_assert(wpp->pg == 0);
                ftl_assert(wpp->lun == 0);
                ftl_assert(wpp->ch == 0);
                /* TODO: assume # of pl_per_lun is 1, fix later */
                ftl_assert(wpp->pl == 0);
            }
        }
    }
}

static struct ppa get_new_page(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct ppa ppa;
    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;
    ftl_assert(ppa.g.pl == 0);

    return ppa;
}

static void check_params(struct ssdparams *spp)
{
    /*
     * we are using a general write pointer increment method now, no need to
     * force luns_per_ch and nchs to be power of 2
     */

    //ftl_assert(is_power_of_2(spp->luns_per_ch));
    //ftl_assert(is_power_of_2(spp->nchs));
}

static void ssd_init_params(struct ssdparams *spp)
{
    spp->secsz = 512;
    spp->secs_per_pg = 8;
    spp->pgs_per_blk = 256;
    spp->blks_per_pl = 128; /* 4GB */
    spp->pls_per_lun = 2;
    spp->luns_per_ch = 8;
    spp->nchs = 4;

    spp->pg_rd_lat = NAND_READ_LATENCY;
    spp->pg_wr_lat = NAND_PROG_LATENCY;
    spp->blk_er_lat = NAND_ERASE_LATENCY;
    spp->ch_xfer_lat = 0;

    /* calculated values */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls = spp->pls_per_ch * spp->nchs;

    spp->tt_luns = spp->luns_per_ch * spp->nchs;

    /* line is special, put it at the end */
    spp->blks_per_line = spp->tt_luns; /* TODO: to fix under multiplanes */
    spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines = spp->blks_per_lun; /* TODO: to fix under multiplanes */

    spp->gc_thres_pcent = 0.75;
    spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high = 0.95;
    spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay = true;


    check_params(spp);
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
    pg->nsecs = spp->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (int i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
    blk->npgs = spp->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (int i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], spp);
    }
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
    pl->nblks = spp->blks_per_pl;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (int i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], spp);
    }
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
    lun->npls = spp->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (int i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(&lun->pl[i], spp);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

static void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
    ch->nluns = spp->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

static void ssd_init_seg(struct segment *seg)
{
    seg->nbkts = 0;
    seg->bkts = NULL;
    seg->cur_bkt = NULL;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
    }

    ssd->secmaptbl = g_malloc0(sizeof(struct ppa_ref) * spp->tt_pgs / 10);
    for (int i = 0; i < spp->tt_pgs/10; i++) {
        ssd->secmaptbl[i].ppa.ppa = UNMAPPED_PPA;
        ssd->secmaptbl[i].reference = 0;
    }
    ssd->valid_vba_cnt = 0;
    ssd->cur_vba = 0;

    ssd->CrcCherry.crc_vec = g_malloc0(sizeof(struct Crccherry) * spp->tt_pgs / 10);
    ssd->CrcCherry.idx = 0;
}

static void ssd_init_rmap(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->sp;

    ftl_assert(ssd);

    ssd_init_params(spp);

    /* initialize ssd internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(&ssd->ch[i], spp);
    }

    /* initialize ssd internal layout architecture */
    ssd->seg = g_malloc0(sizeof(struct segment) * NUM_SEG);
    for (int i = 0; i < NUM_SEG; i++) {
        ssd_init_seg(&(ssd->seg[i]));
    }

    /* initialize maptbl */
    ssd_init_maptbl(ssd);

    /* initialize rmap */
    ssd_init_rmap(ssd);

    /* initialize all the lines */
    ssd_init_lines(ssd);

    /* initialize write pointer, this is how we allocate new pages for writes */
    ssd_init_write_pointer(ssd);

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}

static inline bool valid_ppa(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < spp->nchs && lun >= 0 && lun < spp->luns_per_ch && pl >=
        0 && pl < spp->pls_per_lun && blk >= 0 && blk < spp->blks_per_pl && pg
        >= 0 && pg < spp->pgs_per_blk && sec >= 0 && sec < spp->secs_per_pg)
        return true;

    return false;
}

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
    return ppa->g.rsv==0 && !(ppa->ppa == UNMAPPED_PPA);
}

static inline bool mapped_vba(struct ppa *vba)
{
    return vba->g.rsv==1 && !(vba->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, struct ppa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_plane *pl = get_pl(ssd, ppa);
    return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = get_blk(ssd, ppa);
    return &(blk->pg[ppa->g.pg]);
}

static uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa, struct
        nand_cmd *ncmd)
{
    int c = ncmd->cmd;
    uint64_t cmd_stime = (ncmd->stime == 0) ? \
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
    uint64_t nand_stime;
    struct ssdparams *spp = &ssd->sp;
    struct nand_lun *lun = get_lun(ssd, ppa);
    uint64_t lat = 0;

    switch (c) {
    case NAND_READ:
        /* read: perform NAND cmd first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;
        lat = lun->next_lun_avail_time - cmd_stime;
#if 0
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

        /* read: then data transfer through channel */
        chnl_stime = (ch->next_ch_avail_time < lun->next_lun_avail_time) ? \
            lun->next_lun_avail_time : ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        lat = ch->next_ch_avail_time - cmd_stime;
#endif
        break;

    case NAND_WRITE:
        /* write: transfer data through channel first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        if (ncmd->type == USER_IO) {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        } else {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        }
        lat = lun->next_lun_avail_time - cmd_stime;

#if 0
        chnl_stime = (ch->next_ch_avail_time < cmd_stime) ? cmd_stime : \
                     ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        /* write: then do NAND program */
        nand_stime = (lun->next_lun_avail_time < ch->next_ch_avail_time) ? \
            ch->next_ch_avail_time : lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
#endif
        break;

    case NAND_ERASE:
        /* erase: only need to advance NAND status */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
        break;

    default:
        ftl_err("Unsupported NAND command: 0x%x\n", c);
    }

    return lat;
}

/* update SSD status about one page from PG_VALID -> PG_VALID */
static void mark_page_invalid(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    bool was_full_line = false;
    struct line *line;

    /* update corresponding page status */
    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_VALID);
    pg->status = PG_INVALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        ftl_assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    /* Adjust the position of the victime line in the pq under over-writes */
    if (line->pos) {
        /* Note that line->vpc will be updated by this call */
        pqueue_change_priority(lm->victim_line_pq, line->vpc - 1, line);
    } else {
        line->vpc--;
    }

    if (was_full_line) {
        /* move line: "full" -> "victim" */
        QTAILQ_REMOVE(&lm->full_line_list, line, entry);
        lm->full_line_cnt--;
        pqueue_insert(lm->victim_line_pq, line);
        lm->victim_line_cnt++;
    }
}

static void mark_page_valid(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < ssd->sp.pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ssd->sp.pgs_per_line);
    line->vpc++;
}

static void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        ftl_assert(pg->nsecs == spp->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt++;
}

static void gc_read_page(struct ssd *ssd, struct ppa *ppa)
{
    /* advance ssd status, we don't care about how long it takes */
    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcr;
        gcr.type = GC_IO;
        gcr.cmd = NAND_READ;
        gcr.stime = 0;
        ssd_advance_status(ssd, ppa, &gcr);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);

    ftl_assert(valid_lpn(ssd, lpn));
    new_ppa = get_new_page(ssd);
    /* update maptbl */
    set_maptbl_ent(ssd, lpn, &new_ppa);
    /* update rmap */
    set_rmap_ent(ssd, lpn, &new_ppa);

    mark_page_valid(ssd, &new_ppa);

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ssd);

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, &new_ppa, &gcw);
    }

    /* advance per-ch gc_endtime as well */
#if 0
    new_ch = get_ch(ssd, &new_ppa);
    new_ch->gc_endtime = new_ch->next_ch_avail_time;
#endif

    new_lun = get_lun(ssd, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;

    return 0;
}

static struct line *select_victim_line(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = NULL;

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
    victim_line->pos = 0;
    lm->victim_line_cnt--;

    /* victim_line is a danggling node now */
    return victim_line;
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter = NULL;
    int cnt = 0;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* there shouldn't be any free page in victim blocks */
        ftl_assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            /* delay the maptbl update until "write" happens */
            gc_write_page(ssd, ppa);
            cnt++;
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == cnt);
}

static void mark_line_free(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *line = get_line(ssd, ppa);
    line->ipc = 0;
    line->vpc = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
}

static int do_gc(struct ssd *ssd, bool force)
{
    struct line *victim_line = NULL;
    struct ssdparams *spp = &ssd->sp;
    struct nand_lun *lunp;
    struct ppa ppa;
    int ch, lun;

    victim_line = select_victim_line(ssd, force);
    if (!victim_line) {
        return -1;
    }

    ppa.g.blk = victim_line->id;
    ftl_debug("GC-ing line:%d,ipc=%d,victim=%d,full=%d,free=%d\n", ppa.g.blk,
              victim_line->ipc, ssd->lm.victim_line_cnt, ssd->lm.full_line_cnt,
              ssd->lm.free_line_cnt);

    /* copy back valid data */
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            lunp = get_lun(ssd, &ppa);
            clean_one_block(ssd, &ppa);
            mark_block_free(ssd, &ppa);

            if (spp->enable_gc_delay) {
                struct nand_cmd gce;
                gce.type = GC_IO;
                gce.cmd = NAND_ERASE;
                gce.stime = 0;
                ssd_advance_status(ssd, &ppa, &gce);
            }

            lunp->gc_endtime = lunp->next_lun_avail_time;
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);

    return 0;
}

static uint64_t ssd_read(FemuCtrl *n, struct ssd *ssd, NvmeRequest *req)
{
    // femu_log("ssd_read begin\n");
    struct ssdparams *spp = &ssd->sp;
    uint64_t lba = req->slba;
    int nsecs = req->nlb;
    struct ppa ppa;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs - 1) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ssd->sp.tt_pgs);
    }

    // status = nvme_io_cmd(n, &cmd, req);
    
    // NvmeRwCmd *rw = (NvmeRwCmd *)(&(req->cmd));
    // uint64_t slba = le64_to_cpu(rw->slba);
    // NvmeNamespace *ns = req->ns;
    // const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    // const uint8_t data_shift = ns->id_ns.lbaf[lba_index].lbads;
    // uint64_t data_offset = slba << data_shift;
    
    // QEMUSGList *qsg = &req->qsg;
    // int sg_cur_index = 0;
    // dma_addr_t sg_cur_byte = 0;
    // dma_addr_t cur_len;
    // // void *mb = n->mbe->logical_space;

    
    /* normal IO read path */
    // femu_log("即将进入normal IO path");
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        // femu_log("进入了");
        ppa = get_maptbl_ent(ssd, lpn);
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
            //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
            //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
            continue;
        }

        // hash engine

        // get data from memory backend
        // assert(sg_cur_index < qsg->nsg);
        // cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        
        // unsigned char sha1[SHA_DIGEST_LENGTH];
        // SHA1(mb + data_offset, cur_len, sha1);
        
        // femu_log("[read]: lpn=%lu, SHA1=%lu,%lu\n", lpn, *(unsigned long*)sha1,*((unsigned long*)sha1+1));

        // sg_cur_byte += cur_len;
        // if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
        //     sg_cur_byte = 0;
        //     ++sg_cur_index;
        // }
        // data_offset += cur_len;


        struct nand_cmd srd;
        srd.type = USER_IO;
        srd.cmd = NAND_READ;
        srd.stime = req->stime;
        sublat = ssd_advance_status(ssd, &ppa, &srd);
        maxlat = (sublat > maxlat) ? sublat : maxlat;
    }
    
    // qemu_sglist_destroy(qsg);
    // femu_log("ssd_read end\n");
    // femu_log("ssd_read end\n");
    return maxlat;
}

static uint64_t ssd_write(FemuCtrl *n, struct ssd *ssd, NvmeRequest *req)
{
    femu_log("ssd_write begin\n");
    uint64_t lba = req->slba;
    struct ssdparams *spp = &ssd->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    struct ppa ppa, vba;
    struct ppa new;
    new = get_new_vba(ssd);
    vba.ppa = new.ppa;
    femu_log("[search]: 获得新的 vba 结果= %lu %d\n", vba.ppa, new.g.rsv);
    ssd_advance_vba(ssd);

    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    int r;
    bool hash_flag = false;

    bool opm3 = false, sample_st = false;
    uint32_t sample_bytes = 0;
    uint64_t sample_lpn = 0;

    bool opm4 = false, crc_st = false;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ssd->sp.tt_pgs);
    }

    while (should_gc_high(ssd)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ssd, true);
        if (r == -1)
            break;
    }

    // status = nvme_io_cmd(n, &(req->cmd), req);
    
    NvmeRwCmd *rw = (NvmeRwCmd *)(&(req->cmd));
    uint64_t slba = le64_to_cpu(rw->slba);
    NvmeNamespace *ns = req->ns;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].lbads;
    uint64_t data_offset = slba << data_shift;
    
    QEMUSGList *qsg = &req->qsg;
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_len;
    void *mb = n->mbe->logical_space;

    femu_log("开始lpn:%lu, 结束:lpn:%lu\n", start_lpn, end_lpn);

    // fetch pre 4 bytes as sample bytes
    if (opm3) {
        uint64_t tmp_data_offset = slba << data_shift;
        
        int tmp_sg_cur_index = 0;
        dma_addr_t tmp_sg_cur_byte = 0;
        dma_addr_t tmp_cur_len;
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            assert(tmp_sg_cur_index < qsg->nsg);

            tmp_cur_len = qsg->sg[tmp_sg_cur_index].len - tmp_sg_cur_byte;
            uint32_t tmp = fetch_pre_be((uint8_t *)(mb + tmp_data_offset));
            if (sample_bytes < tmp) {
                sample_bytes = tmp;
                sample_lpn = lpn;
            }
            tmp_sg_cur_byte += tmp_cur_len;
            if (tmp_sg_cur_byte == qsg->sg[tmp_sg_cur_index].len) {
                tmp_sg_cur_byte = 0;
                ++tmp_sg_cur_index;
            }
            tmp_data_offset += tmp_cur_len;
        }

        tmp_data_offset = slba << data_shift;
        tmp_sg_cur_index = 0;
        tmp_sg_cur_byte = 0;
        tmp_cur_len = 0;

        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            assert(tmp_sg_cur_index < qsg->nsg);
            tmp_cur_len = qsg->sg[tmp_sg_cur_index].len - tmp_sg_cur_byte;


            if (lpn == sample_lpn) {
                struct ppa tmp_vba;
                tmp_vba = get_new_vba(ssd);
                unsigned char sha1[SHA_DIGEST_LENGTH];
                SHA1(mb + data_offset, cur_len, sha1); 
                int res = search_in_segment(ssd, ssd->seg, sha1, &tmp_vba); 
                if (res) sample_st = true;
                break;
            }


            tmp_sg_cur_byte += tmp_cur_len;
            if (tmp_sg_cur_byte == qsg->sg[tmp_sg_cur_index].len) {
                tmp_sg_cur_byte = 0;
                ++tmp_sg_cur_index;
            }
            tmp_data_offset += tmp_cur_len;
        }
    }


    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {

        // crc
        if (opm4 && sample_st) {
            uint64_t stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            u32 crc = crc32(0, mb + data_offset, cur_len);
            uint64_t etime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            femu_log("crc32 cost: %luns\n", etime-stime);
            femu_log("[write]: lpn=%lu, crc32=%u\n", lpn, crc);

            for (int i = 0; i < ssd->CrcCherry.idx; i++) {
                if (ssd->CrcCherry.crc_vec[i] == crc) {
                    crc_st = true;
                    break;
                }
            }if (!crc_st) {
                ssd->CrcCherry.crc_vec[ssd->CrcCherry.idx++] = crc;
            }
            
        }

        hash_flag = crc_st;
        
        if (hash_flag) {
            // get data from memory backend
            assert(sg_cur_index < qsg->nsg);
            cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
            



            
            // hash engine       
            unsigned char sha1[SHA_DIGEST_LENGTH];
            uint64_t stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            SHA1(mb + data_offset, cur_len, sha1);
            uint64_t etime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            femu_log("sha1 cost: %luns\n", etime-stime);
            // femu_log("[write]: lpn=%lu, SHA1=%lu,%lu\n", lpn, *(unsigned long*)sha1,*((unsigned long*)sha1+1));
            
            // lookup hash
            stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            int res = search_in_segment(ssd, ssd->seg, sha1, &vba);
            etime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            femu_log("[search]: time=%luns, lpn=%lu, SHA1=%lu, res=%d, lba=%lu\n", 
            etime-stime, lpn, *(unsigned long*)sha1,res,lba);
            femu_log("[search]: 返回 vba 结果= %lu\n", vba.ppa);
            
            if (res) {
                // found, just map to secmaptbl
                ppa = get_maptbl_ent(ssd, lpn);
                if (ppa.ppa == vba.ppa) {
                    femu_log("[hit]: same lpn->vba\n");
                }
                else {
                    if (mapped_vba(&ppa)) {
                        minus_secmaptbl_ref(ssd, &ppa);
                    }
                    set_maptbl_ent(ssd, lpn, &vba);
                    add_secmaptbl_res(ssd, &vba);
                    femu_log("[hit]:map%lu ---> vba%ld, ref=%d\n", lpn, (long)vba.ppa, get_secmaptbl_ref(ssd, vba.ppa));
                }
            } 
            else {
                // not found, map to secmaptbl and map secmaptbl to ppa
                
                // old ppa
                ppa = get_maptbl_ent(ssd, lpn);
                if (mapped_ppa(&ppa)) {
                    /* update old page information first */
                    mark_page_invalid(ssd, &ppa);   
                    set_rmap_ent(ssd, INVALID_LPN, &ppa);
                }
                else if (mapped_vba(&ppa)) {
                    /* update old page information first */
                    minus_secmaptbl_ref(ssd, &ppa);
                }

                /* new write */
                ppa = get_new_page(ssd);
                /* update secmaptbl */
                get_new_vba(ssd);
                set_secmaptbl_ent(ssd, &vba, &ppa);

                /* update maptbl */
                set_maptbl_ent(ssd, lpn, &vba);
                /* update rmap */
                set_rmap_ent(ssd, lpn, &vba);
                mark_page_valid(ssd, &ppa);

                /* need to advance the write pointer here */
                ssd_advance_write_pointer(ssd);
                ssd_advance_vba(ssd);

                struct nand_cmd swr;
                swr.type = USER_IO;
                swr.cmd = NAND_WRITE;
                swr.stime = req->stime;
                /* get latency statistics */
                curlat = ssd_advance_status(ssd, &ppa, &swr);
                maxlat = (curlat > maxlat) ? curlat : maxlat;
                femu_log("[miss]:map%lu ---> vba%lu ---> ppa%lu, maxlat=%luns\n", lpn, (long)vba.ppa, ppa.ppa, maxlat);
            }
        }
        else {
            // normal write
            
            ppa = get_maptbl_ent(ssd, lpn);
            if (mapped_ppa(&ppa)) {
                /* update old page information first */
                mark_page_invalid(ssd, &ppa);   // todo
                set_rmap_ent(ssd, INVALID_LPN, &ppa);
            }

            /* new write */
            ppa = get_new_page(ssd);
            /* update maptbl */
            set_maptbl_ent(ssd, lpn, &ppa);
            /* update rmap */
            set_rmap_ent(ssd, lpn, &ppa);

            mark_page_valid(ssd, &ppa);

            /* need to advance the write pointer here */
            ssd_advance_write_pointer(ssd);

            struct nand_cmd swr;
            swr.type = USER_IO;
            swr.cmd = NAND_WRITE;
            swr.stime = req->stime;
            /* get latency statistics */
            curlat = ssd_advance_status(ssd, &ppa, &swr);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
        }
        
        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }
        data_offset += cur_len;
    }
    
    qemu_sglist_destroy(qsg);
    femu_log("ssd_write end\n");
    femu_log("\n\n\n\n------开始分割-------\n\n\n\n");
    return maxlat;
}

static void *ftl_thread(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    struct ssd *ssd = n->ssd;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
    int i;

    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    /* FIXME: not safe, to handle ->to_ftl and ->to_poller gracefully */
    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (1) {
        for (i = 1; i <= n->num_poller; i++) {
            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
                continue;

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                printf("FEMU: FTL to_ftl dequeue failed\n");
            }

            ftl_assert(req);
            switch (req->cmd.opcode) {
            case NVME_CMD_WRITE:
                lat = ssd_write(n, ssd, req);
                break;
            case NVME_CMD_READ:
                lat = ssd_read(n, ssd, req);
                break;
            case NVME_CMD_DSM:
                lat = 0;
                break;
            default:
                //ftl_err("FTL received unkown request type, ERROR\n");
                ;
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* clean one line if needed (in the background) */
            if (should_gc(ssd)) {
                do_gc(ssd, false);
            }
        }
    }

    return NULL;
}

