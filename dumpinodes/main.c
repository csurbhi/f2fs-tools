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
	PRINT,
};

void get_nat_entry(struct f2fs_sb_info *sbi, nid_t nid,
                                struct f2fs_nat_entry *raw_nat);

static char * segbitmap;

static void process_inode_num(struct f2fs_sb_info *sbi, nid_t nid,
                int ftype);
static void process_dentries_in_block(struct f2fs_sb_info *sbi, block_t blkaddr);


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


void process_direct_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *node, int action,
				uint *min_segid, uint *max_segid)
{
	int idx;
	block_t blkaddr;
	printf("\t");
	for (idx = 0; idx < ADDRS_PER_BLOCK; idx++) {
		blkaddr = le32_to_cpu(node->dn.addr[idx]);
		if (blkaddr == 0)
			continue;
		if (action == PRINT) {
			set_min_max_segid(blkaddr, min_segid, max_segid);
			set_blknr(blkaddr);
			printf("\t %x ", blkaddr);
		}
		else if (action == F2FS_FT_DIR) {
			/* assert that the inode is a DIR */
			process_dentries_in_block(sbi, blkaddr);
		} else
			ASSERT(1);
	}
	printf("\n");
}

void process_indirect_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *node, int action,
				uint *min_segid, uint *max_segid)
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
		get_node_info_nat(sbi, nid, &ni);
		if (action == PRINT) {
			set_blknr(ni.blk_addr);
			set_min_max_segid(ni.blk_addr, min_segid, max_segid);
			printf("\n \t %x, that points to: \n", ni.blk_addr);
		}
		ret = dev_read_block(dnode, ni.blk_addr);
		ASSERT(ret >= 0);
		//process_direct_blocks(sbi, dnode, action, min_segid, max_segid);
	}
	free(dnode);
}

void process_dindirect_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *dindnode, int action,
				uint *min_segid, uint *max_segid)
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
		if (action == PRINT) {
			set_blknr(ni.blk_addr);
			set_min_max_segid(ni.blk_addr, min_segid, max_segid);
			printf("\n \t %x, that points to: \n", ni.blk_addr);
		}
		ret = dev_read_block(indnode, ni.blk_addr);
		ASSERT(ret >= 0);
		process_indirect_blocks(sbi, indnode, action, min_segid, max_segid);
	}
	free(indnode);
}

enum block_type {
	DIRECT,
	INDIRECT,
	DINDIRECT
};


void process_blk(struct f2fs_sb_info *sbi, nid_t nid, int level, int action,
			uint *min_segid, uint *max_segid)
{
	struct f2fs_node *node;
	struct node_info ni;
	int ret;

	if (nid == 0)
		return;

	node = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node != NULL);
	get_node_info_nat(sbi, nid, &ni);
	if (action == PRINT) {
		set_blknr(ni.blk_addr);
		set_min_max_segid(ni.blk_addr, min_segid, max_segid);
		printf(" %x points to: \n", ni.blk_addr);
	}
	ret = dev_read_block(node, ni.blk_addr);
	ASSERT(ret >= 0);
	switch(level) {
		case DIRECT:
			process_direct_blocks(sbi, node, action, min_segid, max_segid);
			break;
		case INDIRECT:
			process_indirect_blocks(sbi, node, action, min_segid, max_segid);
			break;
		case DINDIRECT:
			process_dindirect_blocks(sbi, node, action, min_segid, max_segid);
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
	ret = dev_read_block(node, ni.blk_addr);
	ASSERT(ret >= 0);
	ASSERT(node->footer.nid == node->footer.ino);
	ASSERT(node->footer.nid == nid);

	inode = &node->i;
	return inode;
}


void process_inode_info(struct f2fs_sb_info *sbi, nid_t nid, struct f2fs_inode *inode,
			uint *min_segid, uint *max_segid)
{
	struct node_info ni;
	unsigned int i = 0;
	block_t blknr;

	printf("\n Blk number of the inode: %x ", ni.blk_addr);

	print_extra_inode_info(inode, 1);

	/* If inline flag is set, do not show blk addresses*/
	if ((inode->i_inline && F2FS_INLINE_DATA) || 
			(inode->i_inline && F2FS_INLINE_DENTRY)) {
		return;
	}

	for (i = 0; i < ADDRS_PER_INODE(inode); i++) {
		blknr = le32_to_cpu(inode->i_addr[i]);
		if (blknr == 0)
			continue;
		set_blknr(blknr);
		set_min_max_segid(blknr, min_segid, max_segid);
		DISP_u32(inode, i_addr[i]);	/* Pointers to data blocks */
	}

	process_blk(sbi, inode->i_nid[1], DIRECT, PRINT, min_segid, max_segid);
	process_blk(sbi, inode->i_nid[2], DIRECT, PRINT, min_segid, max_segid);
	process_blk(sbi, inode->i_nid[3], INDIRECT, PRINT, min_segid, max_segid);
	/* process_blk(sbi, inode->i_nid[4], INDIRECT, PRINT, min_segid, max_segid);
	process_blk(sbi, inode->i_nid[5], DINDIRECT, PRINT, min_segid, max_segid); */
	printf("\n inode nr: %x, min_seg: %u, max_seg: %u", nid, *min_segid, *max_segid);
	printf("\n");
}

/* 
 * TODO: You do not want to process the dentries belonging to . and ..
 */
static void process_dentries_in_block(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct f2fs_dentry_block *de_blk;
	int ret, i, ftype;
	nid_t nid;
	struct f2fs_dir_entry *dentry;
	block_t blk_addr;
	u8 *bitmap;
	__u8 (*filenames)[F2FS_SLOT_LEN];
	u16 name_len;
	u8 *name;
	char en[F2FS_PRINT_NAMELEN];

	printf("\n Hellooooo!!");
	de_blk = (struct f2fs_dentry_block *)calloc(BLOCK_SZ, 1);
	ASSERT(de_blk != NULL);
	ret = dev_read_block(de_blk, blk_addr);
	ASSERT(ret >= 0);
	bitmap = de_blk->dentry_bitmap;
	filenames = de_blk->filename;
	dentry = de_blk->dentry;
	for (i = 0; i < NR_DENTRY_IN_BLOCK; i++) {
		if (test_bit_le(i, bitmap) == 0)
			continue;
		name_len = le16_to_cpu(dentry[i].name_len);
		name = calloc(name_len + 1, 1);
		ASSERT(name);
		memcpy(name, filenames[i], name_len);
		if ((name[0] == '.' && name_len == 1) ||
                	(name[0] == '.' && name[1] == '.' &&
                        	name_len == 2)) {
			continue;
		}
		nid = le32_to_cpu(dentry[i].ino);
		ftype = dentry[i].file_type;
		printf("\n %s , name");
		pretty_print_filename(name, name_len, en, 0);
		process_inode_num(sbi, nid, ftype);
	}
}

/* 
 * TODO: dentries can be inline as well
 */
void process_all_dentries(struct f2fs_sb_info *sbi, struct f2fs_inode *inode)
{
	block_t d_addr;
	int i;

	printf("\n addres_per_inode: %u", ADDRS_PER_INODE(inode));
	
	/*
	 * TODO: using ofs. Check fsck_chk_inode_blk()
	ofs = get_extra_isize(node_blk);
	*/
	for (i = 0; i < ADDRS_PER_INODE(inode); i++) {
		d_addr = le32_to_cpu(inode->i_addr[i]);
		if (d_addr == NULL_ADDR)
			continue;
		if (d_addr == NEW_ADDR)
			continue;

		process_dentries_in_block(sbi, d_addr);
	}

	/* The following function will call process_dentry */
	process_blk(sbi, inode->i_nid[0], DIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->i_nid[1], DIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->i_nid[2], INDIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->i_nid[3], INDIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->i_nid[4], DINDIRECT, F2FS_FT_DIR, NULL, NULL);
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
		int ftype)
{
	struct f2fs_inode *inode = read_inode(sbi, nid);
	uint min_segid, max_segid;
	min_segid = INT_MAX;
	max_segid = 0;
	uint nr_segs = sbi->total_sections * sbi->segs_per_sec;

	memset(segbitmap, 0, sizeof(nr_segs/BITS_IN_BYTE));
	process_inode_info(sbi, nid, inode, &min_segid, &max_segid);
	process_bitmap(sbi);
	
	if (ftype == F2FS_FT_DIR) {
		printf("\n Processing directory!");
		process_all_dentries(sbi, inode);
	}

	free(containerof(inode));
}


static void process_root_inode(struct f2fs_sb_info *sbi)
{

	nid_t root_nid;
	uint total_segs = sbi->total_sections * sbi->segs_per_sec;

	segbitmap = calloc(total_segs/8, 1);
	ASSERT(segbitmap != NULL);

	root_nid = sbi->root_ino_num;
	process_inode_num(sbi, root_nid, F2FS_FT_DIR);
}

int main(int argc, char **argv)
{
	struct f2fs_sb_info *sbi;
	int ret = 0;

	f2fs_init_configuration();

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
	memset(sbi, 0, sizeof(sbi));
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
