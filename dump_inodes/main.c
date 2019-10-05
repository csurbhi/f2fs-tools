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
#include "fsck.h"
#include <libgen.h>
#include <ctype.h>
#include <getopt.h>
#include "quotaio.h"

struct f2fs_fsck gfsck;

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
extern struct sparse_file *f2fs_sparse_file;
#endif

static char * segbitmap;

static int is_digits(char *optarg)
{
	unsigned int i;

	for (i = 0; i < strlen(optarg); i++)
		if (!isdigit(optarg[i]))
			break;
	return i == strlen(optarg);
}

void get_node_info_nat(struct f2fs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct f2fs_nat_entry raw_nat;

	ni->nid = nid;
	get_nat_entry(sbi, nid, &raw_nat);
	node_info_from_raw_nat(ni, &raw_nat);
}

void set_min_max_segid(blk_t blknr, uint *min_segid, uint *max_segid)
{
	uint segid;

	segid = blknr / BLKS_PER_SEG;
	if (segid < *min_segid)
		*min_segid = segid;
	if (segid > *max_segid)
		*max_segid = segid;

	return;
}

void set_blknr(blk_t blknr)
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
	int idx, ret;
	block_t blkaddr;
	printf("\t");
	for (idx = 0; idx < ADDRS_PER_BLOCK; idx++) {
		blkaddr = le32_to_cpu(node->dn.addr[idx]);
		if (action == PRINT) {
			set_min_max_segid(blknr, min_segid, max_segid);
			set_blknr(blknr);
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
		get_node_info_nat(sbi, nid, &ni);
		if (action == PRINT) {
			set_blknr(blknr);
			set_min_max_segid(blknr, min_segid, max_segid);
			printf("\n \t %x, that points to: \n", ni->blkaddr);
		}
		ret = dev_read_block(dnode, ni->blk_addr);
		ASSERT(ret >= 0);
		process_direct_blocks(sbi, dnode, action, min_segid, max_segid);
	}
	free(dnode);
}

void process_dindirect_blocks(struct f2fs_sb_info *sbi, struct f2fs_node *indnode, int action,
				uint *min_segid, uint *max_segid)
{
	int idx, ret;
	nid_t nid;
	struct f2fs_node *indnode;
	struct node_info ni;
	
	indnode = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(dnode != NULL);

	for (idx = 0; idx < NIDS_PER_BLOCK; idx++) {
		nid = le32_to_cpu(node->in.nid[idx]);
		get_node_info_nat(sbi, nid, &ni);
		if (action == PRINT) {
			set_blknr(blknr);
			set_min_max_segid(blknr, min_segid, max_segid);
			printf("\n \t %x, that points to: \n", ni->blkaddr);
		}
		ret = dev_read_block(indnode, ni->blk_addr);
		ASSERT(ret >= 0);
		process_indirect_blocks(sbi, indnode, action, min_segid, max_segid);
	}
	free(indnode);
}


blk_t process_blk(struct f2fs_sb_info *sbi, nid_t nid, int level, int action,
			uint *min_segid, uint *max_segid)
{
	struct f2fs_node *node;
	struct node_info ni;

	node = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node != NULL);
	get_node_info_nat(sbi, nid, &ni);
	if (action == PRINT) {
		set_blknr(blknr);
		set_min_max_segid(blknr, min_segid, max_segid);
		printf(" %x points to: \n", ni->blkaddr);
	}
	ret = dev_read_block(node, ni->blk_addr);
	ASSERT(ret >= 0);
	switch(level) {
		case DIRECT:
			process_direct_blocks(sbi, node, nid, action, min_segid, max_segid);
			break
		case INDIRECT:
			process_indirect_blocks(sbi, node, nid, action, min_segid, max_segid);
			break;
		case DINDIRECT:
			process_dindirect_blocks(sbi, node, nid, action, min_segid, max_segid);
			break;
		default:
			ASSERT(1);
	}
	free(node);
}

void print_extra_inode_info(struct f2fs_inode *inode, char flag)
{
	if (!flag)
		return;

	pretty_print_filename(inode->i_name, namelen, en, enc_name);
	if (name && en[0]) {
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

struct f2fs_inode * read_inode(nid_t nid)
{
	struct f2fs_node *node = NULL;
	node = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node_blk != NULL);

	get_node_info_nat(sbi, nid, &ni);
	ret = dev_read_block(node, ni->blk_addr);
	ASSERT(ret >= 0);
	ASSERT(node->footer.nid == node->footer.ino);
	ASSERT(node->footer.nid == nid);

	inode = node->i;
	return inode;
}

void process_inode_info(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
			uint min_segid, uint max_segid)
{
	struct f2fs_inode *inode;
	struct node_info ni;
	void *xattr_addr;
	struct f2fs_xattr_entry *ent;
	char en[F2FS_PRINT_NAMELEN];
	unsigned int i = 0;
	u32 namelen;
	int enc_name;
	int ofs;
	block_t blknr;


	namelen = le32_to_cpu(inode->i_namelen);
	enc_name = file_enc_name(inode);
	ofs = __get_extra_isize(inode);

	print("\n Blk number of the inode: %x ", ni.blk_addr);

	print_extra(inode, true);

	/* If inline flag is set, do not show blk addresses*/
	if ((inode->i_inline && F2FS_INLINE_DATA) || 
			(inode->i_inline && F2FS_INLINE_DENTRY)) {
		return 0;
	}

	for (i = ofs; i < ADDRS_PER_INODE(inode); i++) {
		blknr = le32_to_cpu(inode->i_addr[ofs]);
		set_blknr(blknr);
		set_min_max_segid(blknr, min_segid, max_segid);
		DISP_u32(inode, i_addr[ofs]);	/* Pointers to data blocks */
	}

	process_blk(inode->nid[1], DIRECT, PRINT, min_segid, max_segid);
	process_blk(inode->nid[2], DIRECT, PRINT, min_segid, max_segid);
	process_blk(inode->nid[3], INDIRECT, PRINT, min_segid, max_segid);
	process_blk(inode->nid[4], INDIRECT, PRINT, min_segid, max_segid);
	process_blk(inode->nid[5], DINDIRECT, PRINT, min_segid, max_segid);
	printf("\n inode nr: %x, min_seg: %x, max_seg: %x", inode->inum, *min_segid, *max_segid);
	printf("\n");
}

void process_dentries_in_block(struct f2fs_sb_info *sbi, blk_t blkaddr)
{
	struct f2fs_dentry_block *de_blk;
	int dentries, ret, i

	de_blk = (struct f2fs_dentry_block *)calloc(BLOCK_SZ, 1);
	ASSERT(de_blk != NULL);
	ret = dev_read_block(de_blk, blk_addr);
	ASSERT(ret >= 0);
	dentry = de_blk->dentry;
	for (i = 0; i < NR_DENTRY_IN_BLOCK; i++) {
		nid = le32_to_cpu(dentry[i].ino);
		ftype = dentry[i].file_type;
		process_inode_num(sbi, nid, ftype);
	}
}

void process_all_dentries(struct f2fs_sb_info *sbi, struct f2fs_inode *inode)
{
	for (i = 0; i < ADDRS_PER_BLOCK; i++) {
		d_addr = le32_to_cpu(inode->i_addr[ofs])
		process_dentries_in_block(sbi, d_addr);
	}
	/* The following function will call process_dentry */
	process_blk(sbi, inode->nid[1], DIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->nid[2], DIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->nid[3], INDIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->nid[4], INDIRECT, F2FS_FT_DIR, NULL, NULL);
	process_blk(sbi, inode->nid[5], DINDIRECT, F2FS_FT_DIR, NULL, NULL);
}

#define FIRST_BIT (1<<0)
#define SECOND_BIT (1<<1)
#define THIRD_BIT (1<<2)
#define FOURTH_BIT (1<<3)
#define FIFTH_BIT (1<<4)
#define SIXTH_BIT (1<<5)
#define SEVENTH_BIT (1<<6)
#define EIGHTH_BIT (1<<7)

/* Now you get the sequentiality ratio of all inodes
 * and then take an average of all those ratios.
 * This should improve after a number of segment cleaning
 * We use this to show, how just cleaning one segment
 * at a time, actually degrades the sequential segment
 * count - especially when the inode data is spread across
 * two segments at least.
 */
int process_bitmap(struct f2fs_sb_info *sbi)
{
	int i, nr_bytes = sbi->nr_segs / 8;
	int curr = 0, prev = 0, seq_segs = 0;
	char mask = ~0;

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
	return (sbi->nr_segs / seq_segs);
}

/* This function does two things:
 * a) Print this inode's blocks
 * b) If this is a directory inode then process all the dentries
 */
static void process_inode_num(struct f2fs_sb_info *sbi, nid_t nid, 
		int ftype)
{
	struct f2fs_inode *inode = read_inode(nid);
	uint min_segid, max_segid;
	mix_segid = INT_MAX;
	max_segid = 0;

	memset(segbitmap, 0, sizeof(sbi->nr_segs/8));
	process_inode_info(sbi, inode, min_segid, max_segid);
	process_bitmap(sbi);
	if (ftype == F2FS_FT_DIR)
		process_all_dentries(sbi, inode);
}


static void process_root_inode(struct f2fs_sb_info *sbi)
{

	nid_t root_nid;
	uint total_segs = sbi->nr_segs;

	segbitmap = calloc(total_segs/8);
	ASSERT(segbitmap != NULL);

	root_nid = get_root_nid(sbi);
	process_inode_num(root_nid, DIR_TYPE);
}

int main(int argc, char **argv)
{
	struct f2fs_sb_info *sbi;
	int ret = 0;

	f2fs_init_configuration();

	f2fs_parse_options(argc, argv);

	if (c.func != DUMP && f2fs_devs_are_umounted() < 0) {
		if (errno == EBUSY)
			return -1;
		if (!c.ro || c.func == DEFRAG) {
			MSG(0, "\tError: Not available on mounted device!\n");
			return -1;
		}

		/* allow ro-mounted partition */
		if (c.force) {
			MSG(0, "Info: Force to check/repair FS on RO mounted device\n");
		} else {
			MSG(0, "Info: Check FS only on RO mounted device\n");
			c.fix_on = 0;
			c.auto_fix = 0;
		}
	}

	/* Get device */
	if (f2fs_get_device_info() < 0)
		return -1;

	sbi = (struct f2fs_sb_info *) malloc(sizeof(struct fsfs_sb_info));
	if (!sbi) {
		MSG(0, "Malloc error for sbi");
		exit(-1);
	}
	memset(&sbi, 0, sizeof(sbi));
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
