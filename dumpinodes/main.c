/**
 * main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2015 Jaegeuk Kim <jaegeuk@kernel.org>
 *  : implement defrag.f2fs
 * Copyright (C) 2015 Huawei Ltd.
 *   Hou Pengyang <houpengyang@huawei.com>
 *   Liu Shuoran <liushuoran@huawei.com>
 *   Jaegeuk Kim <jaegeuk@kernel.org>
 *  : add sload.f2fs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "../fsck/fsck.h"
#include <libgen.h>
#include <ctype.h>
#include <getopt.h>
//#include "quotaio.h"
#include <locale.h>
#include <limits.h>


struct f2fs_fsck gfsck;

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
extern struct sparse_file *f2fs_sparse_file;
#endif

enum action {
	LAYOUT_SCORE,
	DENTRY_PROCESS
};

void get_nat_entry(struct f2fs_sb_info *sbi, nid_t nid,
                                struct f2fs_nat_entry *raw_nat);

static char * segbitmap;

static void process_inode_num(struct f2fs_sb_info *sbi, nid_t nid,
                int ftype, float *layout_score, int * total_files);
static void process_dentries_in_block(struct f2fs_sb_info *sbi, block_t blkaddr, u8 is_enc,
		float* layout_score, int * total_files);


void get_node_info_nat(struct f2fs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct f2fs_nat_entry raw_nat;

	ni->nid = nid;
	get_nat_entry(sbi, nid, &raw_nat);
	node_info_from_raw_nat(ni, &raw_nat);
}

void set_min_max_segid(block_t blknr, uint *min_segid, uint *max_segid)
{
	uint segid;

	segid = blknr / DEFAULT_BLOCKS_PER_SEGMENT;
	if (segid < *min_segid)
		*min_segid = segid;
	if (segid > *max_segid)
		*max_segid = segid;

	return;
}

void set_blknr(block_t blknr)
{
	char mask;
	int bytenr;
	int bitnr;

	bytenr = blknr / 8;
	bitnr = blknr % 8;
	mask = 1 << bitnr;

	segbitmap[bytenr] = segbitmap[bytenr] | mask;

}

/* This is the last level of the block - and this holds
 * data
 */
void process_direct_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *node, u8 action,
		int *seq_count, int *total_blks, block_t *prev_nr, float *layout_score,
		int *total_files)
{
	int idx;
	block_t blkaddr;
	//printf("\t");
	for (idx = 0; idx < ADDRS_PER_BLOCK; idx++) {
		blkaddr = le32_to_cpu(node->dn.addr[idx]);
		if (blkaddr == 0)
			continue;
		if (LAYOUT_SCORE == action) {
			printf("\n %d block:%lu segno:%lu ", total_blks, blkaddr, GET_SEGNO(sbi, blkaddr));
			if (*prev_nr + 1 == blkaddr)
				(*seq_count)++;
			(*total_blks)++;
			*prev_nr = blkaddr;
		} else { 
			ASSERT(DENTRY_PROCESS == action);
			/* TODO: assert that the inode is a DIR */
			process_dentries_in_block(sbi, blkaddr, file_is_encrypt(&node->i), layout_score, total_files);
		}
	}
	//printf("\n");
}

void process_indirect_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *node, int action,
		int *seq_count, int *total_blks, block_t *prev_nr, float *layout_score,
		int *total_files)
{
	int idx, ret;
	nid_t nid;
	struct f2fs_node *dnode;
	struct node_info ni;
	
	dnode = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(dnode != NULL);

	for (idx = 0; idx < NIDS_PER_BLOCK; idx++) {
		nid = le32_to_cpu(node->in.nid[idx]);
		if (nid == 0)
			continue;
		//printf("\n nid: %u idx: %d \n", nid, idx);
		get_node_info_nat(sbi, nid, &ni);
		//printf("\n process_indirect_blocks(): reading nid: %d, ni.blk_addr: %d", nid, ni.blk_addr);
		ret = dev_read_block(dnode, ni.blk_addr);
		ASSERT(ret >= 0);
		process_direct_blocks(sbi, dnode, action, seq_count, total_blks, prev_nr, layout_score, total_files);
	}
	free(dnode);
}

void process_dindirect_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *dindnode, int action,
		int *seq_count, int *total_blks, block_t *prev_nr, float * layout_score,
		int *total_files)
{
	int idx, ret;
	nid_t nid;
	struct f2fs_node *indnode;
	struct node_info ni;
	
	indnode = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(indnode != NULL);

	for (idx = 0; idx < NIDS_PER_BLOCK; idx++) {
		nid = le32_to_cpu(dindnode->in.nid[idx]);
		if (nid == 0)
			continue;
		get_node_info_nat(sbi, nid, &ni);
		ret = dev_read_block(indnode, ni.blk_addr);
		ASSERT(ret >= 0);
		process_indirect_blocks(sbi, indnode, action, seq_count, total_blks, prev_nr, layout_score,
				total_files);
	}
	free(indnode);
}

enum block_type {
	DIRECT,
	INDIRECT,
	DINDIRECT
};


void process_blk(struct f2fs_sb_info *sbi, nid_t nid, int level, u8 action,
		int *seq_count, int *total_blks, block_t *prev_nr,
		float *layout_score, int *total_files)
{
	struct f2fs_node *node;
	struct node_info ni;
	int ret;

	if (nid == 0)
		return;

	node = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node != NULL);
	get_node_info_nat(sbi, nid, &ni);
	ret = dev_read_block(node, ni.blk_addr);
	ASSERT(ret >= 0);
	switch(level) {
		case DIRECT:
			process_direct_blocks(sbi, node, action, seq_count, total_blks, prev_nr, layout_score, total_files);
			break;
		case INDIRECT:
			process_indirect_blocks(sbi, node, action, seq_count, total_blks, prev_nr, layout_score, total_files);
			break;
		case DINDIRECT:
			process_dindirect_blocks(sbi, node, action, seq_count, total_blks, prev_nr, layout_score, total_files);
			break;
		default:
			ASSERT(1);
	}
	free(node);
}

void print_extra_inode_info(struct f2fs_inode *inode, char flag)
{

	//void *xattr_addr;
	char en[F2FS_PRINT_NAMELEN];
	//struct f2fs_xattr_entry *ent;
	int enc_name;
	int namelen;
	long ofs;

	namelen = le32_to_cpu(inode->i_namelen);
	enc_name = file_enc_name(inode);
	ofs = __get_extra_isize(inode);

	if (!flag)
		return;

	pretty_print_filename(inode->i_name, namelen, en, enc_name);
	if (inode->i_name && en[0]) {
		MSG(0, " - File name         : %s%s\n", en,
				enc_name ? " <encrypted>" : "");
		setlocale(LC_ALL, "");
		MSG(0, " - File size         : %'llu (bytes)\n",
				le64_to_cpu(inode->i_size));
		return;
	}

	DISP_u64(inode, i_size);
	DISP_u64(inode, i_blocks);

	DISP_u64(inode, i_atime);
	DISP_u32(inode, i_atime_nsec);
	DISP_u64(inode, i_ctime);
	DISP_u32(inode, i_ctime_nsec);
	DISP_u64(inode, i_mtime);
	DISP_u32(inode, i_mtime_nsec);

	DISP_u32(inode, i_generation);
	DISP_u32(inode, i_inline);
	DISP_u32(inode, i_pino);
	DISP_u32(inode, i_dir_level);

	if (en[0]) {
		DISP_u32(inode, i_namelen);
		printf("%-30s\t\t[%s]\n", "i_name", en);
	}

	printf("i_ext: fofs:%x blkaddr:%x len:%x\n",
			le32_to_cpu(inode->i_ext.fofs),
			le32_to_cpu(inode->i_ext.blk_addr),
			le32_to_cpu(inode->i_ext.len));


}


/*
 * Print all the blk numbers involved
 * Print all the segment numbers involved
 * Print the mtime of the segment numbers involved
 * Print the distance from the block that has the parent
 * inode number and the block that holds this directory entry
 */

struct f2fs_inode * read_inode(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_node *node = NULL;
	struct f2fs_inode *inode;
	struct node_info ni;
	int ret;

	node = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node != NULL);

	get_node_info_nat(sbi, nid, &ni);
	//ASSERT(ni.blk_addr != 0);
	if(ni.blk_addr == 0)
		return NULL;
	ret = dev_read_block(node, ni.blk_addr);
	ASSERT(ret >= 0);
	ASSERT(node->footer.nid == node->footer.ino);
	printf("\n Footer.nid: %lu, nid:%lu\n", node->footer.nid, nid);
	ASSERT(node->footer.nid == nid);

	inode = &node->i;
	return inode;
}


float process_inode_info(struct f2fs_sb_info *sbi, nid_t nid, struct f2fs_inode *inode)
{
	unsigned int i = 0;
	block_t blknr, prevnr;
	int total_blks = 0;
	int seq_count = 1;
	uint nrblks = inode->i_size / 4096;
	uint blksconsumed = 0;
	int segno = 0;

	print_extra_inode_info(inode, 1);
	printf("nr of blks: %u", nrblks);

	/* If inline flag is set, the data spans only this one
	 * blocks. We are not processing any directory entries
	 * in this path. Hence we just calculate the layout score
	 */
	if ((inode->i_inline & F2FS_INLINE_DATA) || 
			(inode->i_inline & F2FS_INLINE_DENTRY)) {
		printf("\n Inline data, Layout score for nid: %d is 1.0 \n\n", nid);
		return (1.0);
	}

	printf("\n----------------------------------------------------------------\n");
	prevnr = le32_to_cpu(inode->i_addr[0]);
	if (prevnr != 0) {
		printf("\n nid:%d %d block:%lu segno:%lu ", nid, total_blks, prevnr, GET_SEGNO(sbi, prevnr));
		total_blks++;
	}
	segno = (prevnr - sbi->raw_super->segment0_blkaddr) / 65536;
	for (i = 1; i < ADDRS_PER_INODE(inode); i++) {
		blknr = le32_to_cpu(inode->i_addr[i]);
		if (blknr == 0)
			continue;
		printf("\n nid:%d %d block:%lu segno:%lu ", nid, total_blks, blknr, GET_SEGNO(sbi, blknr));
		//DISP_u32(inode, i_addr[i]);	/* Pointers to data blocks */
		DBG(2, "\n direct blocks processing: i: %d prevnr: %d blknr: %d", i, prevnr, blknr);
		if ((prevnr+1) == blknr)
			seq_count++;
		prevnr = blknr;
		total_blks++;
	}
	blksconsumed = ADDRS_PER_INODE(inode);
	if (nrblks < blksconsumed)
		goto ret;

	process_blk(sbi, inode->i_nid[0], DIRECT, LAYOUT_SCORE, &seq_count, &total_blks, &prevnr, NULL, NULL);
	blksconsumed += ADDRS_PER_BLOCK;
	if (nrblks < blksconsumed)
		goto ret;

	process_blk(sbi, inode->i_nid[1], DIRECT, LAYOUT_SCORE, &seq_count, &total_blks, &prevnr, NULL, NULL);
	blksconsumed += ADDRS_PER_BLOCK;
	if (nrblks < blksconsumed)
		goto ret;

	process_blk(sbi, inode->i_nid[2], INDIRECT, LAYOUT_SCORE, &seq_count, &total_blks, &prevnr, NULL, NULL);
	blksconsumed += NIDS_PER_BLOCK * ADDRS_PER_BLOCK;
	if (nrblks < blksconsumed)
		goto ret;

	process_blk(sbi, inode->i_nid[3], INDIRECT, LAYOUT_SCORE, &seq_count, &total_blks, &prevnr, NULL, NULL);
	blksconsumed += NIDS_PER_BLOCK * ADDRS_PER_BLOCK;
	if (nrblks < blksconsumed)
		goto ret;

	process_blk(sbi, inode->i_nid[4], DINDIRECT, LAYOUT_SCORE, &seq_count, &total_blks, &prevnr, NULL, NULL);
ret:
	printf("\n Layout score for nid: %d is %2.5f, seq_count: %d, total_blks: %d ", nid, (float)((float) seq_count/ (float) total_blks), seq_count, total_blks);
	printf("\n----------------------------------------------------------------\n");
	return (float)((float) seq_count/ (float) total_blks);
}

void process_dentries(struct f2fs_sb_info * sbi, u8 *bitmap, __u8 (*filenames)[F2FS_SLOT_LEN],
			struct f2fs_dir_entry *dentry, u8 is_enc,
			int max, float *layout_score, int * total_files)
{
	int i;
	u16 name_len;
	u8 *name;
	char en[F2FS_PRINT_NAMELEN];
	nid_t nid;
	int ftype;

	ASSERT(bitmap != NULL);

	for (i = 0; i < max; i++) {
		if (!test_bit_le(i, bitmap))
			continue;
		name_len = le16_to_cpu(dentry[i].name_len);
		if (!name_len)
			continue;
		name = calloc(name_len + 1, 1);
		ASSERT(name);
		memcpy(name, filenames[i], name_len);
		//printf("\t %s ", name); 
		ftype = dentry[i].file_type;
		if (ftype == F2FS_FT_DIR) {
			if ((name[0] == '.' && name_len == 1) ||
				(name[0] == '.' && name[1] == '.' &&
					name_len == 2)) {
				continue;
			}
		}
		printf("\n");
		nid = le32_to_cpu(dentry[i].ino);
		printf("\n name_len: %d name: %s nid: %lu", name_len, name, nid);
		process_inode_num(sbi, nid, ftype, layout_score, total_files);
	}
}

/* 
 * TODO: You do not want to process the dentries belonging to . and ..
 */
static inline void process_dentries_in_block(struct f2fs_sb_info *sbi, block_t blkaddr, u8 is_enc, 
		float *layout_score, int * total_files)
{
	struct f2fs_dentry_block *de_blk;
	int ret;

	de_blk = (struct f2fs_dentry_block *)calloc(BLOCK_SZ, 1);
	ASSERT(de_blk != NULL);
	ret = dev_read_block(de_blk, blkaddr);
	ASSERT(ret >= 0);

	process_dentries(sbi, de_blk->dentry_bitmap, de_blk->filename,
				de_blk->dentry, is_enc, NR_DENTRY_IN_BLOCK,
				layout_score, total_files);
}

#define MAX_INLINE_DATA_I(inode) (sizeof(__le32) *                         \
                                (DEF_ADDRS_PER_INODE -                  \
                                get_inline_xattr_addrs(inode) -      \
                                __get_extra_isize(inode) -                 \
                                DEF_INLINE_RESERVED_SIZE))

#define NR_INLINE_DENTRY_I(inode)  (MAX_INLINE_DATA_I(inode) * BITS_PER_BYTE / \
                                ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * \
                                BITS_PER_BYTE + 1))

#define INLINE_DENTRY_BITMAP_SIZE_I(inode) ((NR_INLINE_DENTRY_I(inode) + \
                                        BITS_PER_BYTE - 1) / BITS_PER_BYTE)
#define INLINE_RESERVED_SIZE_I(inode)      (MAX_INLINE_DATA_I(inode) - \
                                ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * \
                                NR_INLINE_DENTRY_I(inode) + \
                                INLINE_DENTRY_BITMAP_SIZE_I(inode)))

/* 
 * TODO: dentries can be inline as well
 */
void process_all_dentries(struct f2fs_sb_info *sbi, struct f2fs_inode *inode, float * layout_score, int *total_files)
{
	block_t d_addr;
	int i, ofs;

	DBG(2, "\n addres_per_inode: %u", ADDRS_PER_INODE(inode));
	
	ofs = __get_extra_isize(inode);
	if(inode->i_inline & F2FS_INLINE_DENTRY) {
		DBG(4, "\n Dir is inlined!");
		/* TODO: Process inlined directory */
		void *inline_dentry;
		struct f2fs_dentry_ptr d;
		int entry_cnt, bitmap_size, reserved_size;

		inline_dentry = (void *)(&inode->i_addr[ofs + DEF_INLINE_RESERVED_SIZE]);
		ASSERT(inline_dentry != NULL);
		DBG(4, "\n ofs + DEF_INLINE_RESERVED_SIZE: %d", DEF_INLINE_RESERVED_SIZE);
		DBG(4, "\n inode->i_addr[1]: %x", inode->i_addr[1]);
		entry_cnt = NR_INLINE_DENTRY_I(inode);
		bitmap_size = INLINE_DENTRY_BITMAP_SIZE_I(inode);
		reserved_size = INLINE_RESERVED_SIZE_I(inode);

		d.max = entry_cnt;
		printf("\n d.max: %d ", d.max);
		printf("\n ");
		d.nr_bitmap = bitmap_size;
		d.bitmap = (u8 *)inline_dentry;
		DBG(3, "\n bitmap_size: %d, reserved_size: %d \n", bitmap_size, reserved_size);
		DBG(3, "\n inline_dentry: %x", (unsigned int) inline_dentry);
		d.dentry = (struct f2fs_dir_entry *)
                                ((char *)inline_dentry + bitmap_size + reserved_size);
		d.filename = (__u8 (*)[F2FS_SLOT_LEN])((char *) inline_dentry +
                                bitmap_size + reserved_size +
                                SIZE_OF_DIR_ENTRY * entry_cnt);
		process_dentries(sbi, d.bitmap, d.filename, d.dentry, file_is_encrypt(inode), d.max, layout_score, total_files);
		return;
	}
	DBG(2, "\n Directory is not inlined ");
	DBG(3, "\n ofs: %d ", ofs);
	for (i = ofs; i < ADDRS_PER_INODE(inode); i++) {
		d_addr = le32_to_cpu(inode->i_addr[i]);
		if (d_addr == NULL_ADDR)
			continue;
		if (d_addr == NEW_ADDR)
			continue;
		DBG(3, " \n %d %u - will process dentries here", i , d_addr);

		process_dentries_in_block(sbi, d_addr, file_is_encrypt(inode), layout_score, total_files);
	}

	/* The following function will call process_dentry */
	process_blk(sbi, inode->i_nid[0], DIRECT, DENTRY_PROCESS, NULL, NULL, NULL, layout_score, total_files);
	process_blk(sbi, inode->i_nid[1], DIRECT, DENTRY_PROCESS, NULL, NULL, NULL, layout_score, total_files);
	process_blk(sbi, inode->i_nid[2], INDIRECT, DENTRY_PROCESS, NULL, NULL, NULL, layout_score, total_files);
	process_blk(sbi, inode->i_nid[3], INDIRECT, DENTRY_PROCESS, NULL, NULL, NULL, layout_score, total_files);
	process_blk(sbi, inode->i_nid[4], DINDIRECT, DENTRY_PROCESS, NULL, NULL, NULL, layout_score, total_files);
}

#define BITS_IN_BYTE 8

/* Now you get the sequentiality ratio of all inodes
 * and then take an average of all those ratios.
 * This should improve after a number of segment cleaning
 * We use this to show, how just cleaning one segment
 * at a time, actually degrades the sequential segment
 * count - especially when the inode data is spread across
 * two segments at least.
 *
 * TODO:
 * Check if there are only two bits set: one for data
 * and one for metadata
 */
int process_bitmap(struct f2fs_sb_info *sbi)
{
	int i, nr_bytes;
	int curr = 0, prev = 0, seq_segs = 0;
	char byte;

	nr_bytes = (sbi->total_sections * sbi->segs_per_sec) / BITS_IN_BYTE;

	for(i=0; i < nr_bytes; i++) {
		byte = segbitmap[i];
		/* find continuous bits set in this byte
		 *
		 * eg: 01101101. If you come across
		 * a zero, then you stop adding.
		 */
		while (byte) {
			if (byte && 1) 
				curr ++;
			else {
				if (prev < curr) {
					prev = curr;
				}
				curr = 0;
				break;
			}
			byte = byte >> 1;
		}
	}
	if (prev < curr) {
		prev = curr;
	}
	/* prev contains the maximum number of sequential segments */
	seq_segs = prev;
	return ((sbi->total_sections * sbi->segs_per_sec)/ seq_segs);
}

static inline struct f2fs_node * containerof(struct f2fs_inode * inode)
{
	return (struct f2fs_node *) ((char *)inode - offsetof(struct f2fs_node, i));

}


/* This function does two things:
 * a) Print this inode's blocks
 * b) If this is a directory inode then process all the dentries
 */
static void process_inode_num(struct f2fs_sb_info *sbi, nid_t nid, 
		int ftype, float *layout_score, int * total_files)
{
	struct f2fs_inode *inode;
	float inode_score;

	inode = read_inode(sbi, nid);
	if (!inode) {
		printf("\n Could not read inode: %d ", nid);
		return;
	}
	/* Calculate the layout score of this inode */
	inode_score = process_inode_info(sbi, nid, inode);

	*layout_score += inode_score;
	(*total_files)++;
	
	if (ftype == F2FS_FT_DIR) {
		DBG(2, "\n Processing directory!");
		/* do a DFS of all the dentries in this inode */
		process_all_dentries(sbi, inode, layout_score, total_files);
	}

	free(containerof(inode));
}


static void process_root_inode(struct f2fs_sb_info *sbi)
{

	nid_t root_nid;
	int total_files=0;
	float layout_score=0.0;

	root_nid = sbi->root_ino_num;
	process_inode_num(sbi, root_nid, F2FS_FT_DIR, &layout_score, &total_files);

	printf("\n Average layout score: %2.5f, total_files: %d total_layout_score: %f", (float) (layout_score / (float) total_files), total_files, layout_score); 
}

int main(int argc, char **argv)
{
	struct f2fs_sb_info *sbi;
	int ret = 0;

	f2fs_init_configuration();
	c.dbg_lv = 1;

	/* Get device */
	if (argc < 2) {
		MSG(0, "\tError: Device not specified\n");
		exit(-1);	
	}
	c.devices[0].path = strdup(argv[1]);

	if (f2fs_devs_are_umounted() < 0) {
		MSG(0, "\tError: Not available on mounted device!\n");
		return -1;
	}

	if (f2fs_get_device_info() < 0) {
		printf("\n Could not get device information \n");
		return -1;
	}

	sbi = (struct f2fs_sb_info *) malloc(sizeof(struct f2fs_sb_info));
	if (!sbi) {
		MSG(0, "Malloc error for sbi");
		exit(-1);
	}
	memset(sbi, 0, sizeof(struct f2fs_sb_info));
	c.auto_fix = 0;
	c.preen_mode = 0;
	c.fix_on = 0;
	c.func = SEQ;

	ret = f2fs_do_mount(sbi);
	if (ret != 0) {
		if (ret == 1) {
			MSG(0, "Info: No error was reported\n");
			ret = 0;
		}
		goto out_err;
	}

	process_root_inode(sbi);

	f2fs_do_umount(sbi);

	printf("\nDone.\n");
	return 0;

out_err:
	if (sbi->ckpt)
		free(sbi->ckpt);
	if (sbi->raw_super)
		free(sbi->raw_super);
	if (sbi)
		free(sbi);
	return ret;
}
