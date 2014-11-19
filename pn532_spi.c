/*
 * Copyright (C) 2011 Instituto Nokia de Tecnologia
 * Copyright (C) 2012-2013 Tieto Poland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nfc.h>
#include <linux/netdevice.h>
#include <net/nfc/nfc.h>
#include <linux/spi/spi.h>
#include <linux/of.h>

#define VERSION "0.1"

#define PN532_ALL_PROTOCOLS (NFC_PROTO_JEWEL_MASK | NFC_PROTO_MIFARE_MASK |\
			     NFC_PROTO_FELICA_MASK | NFC_PROTO_ISO14443_MASK |\
			     NFC_PROTO_NFC_DEP_MASK |\
			     NFC_PROTO_ISO14443_B_MASK)

#define PN532_NO_TYPE_B_PROTOCOLS (NFC_PROTO_JEWEL_MASK | \
				   NFC_PROTO_MIFARE_MASK | \
				   NFC_PROTO_FELICA_MASK | \
				   NFC_PROTO_ISO14443_MASK | \
				   NFC_PROTO_NFC_DEP_MASK)

/* Standard pn532 frame definitions (standard and extended)*/
#define PN532_STD_FRAME_HEADER_LEN (sizeof(struct pn532_std_frame) + \
					+ 2) /* data[0] TFI, data[1] CC */
#define PN532_FRAME_TAIL_LEN 2 /* data[len] DCS, data[len + 1] postamble*/

#define PN532_EXT_FRAME_HEADER_LEN (sizeof(struct pn532_ext_frame) + \
					+ 2) /* data[0] TFI, data[1] CC */

#define PN532_MAX_FRAME_HEADER_LEN PN532_EXT_FRAME_HEADER_LEN

#define PN532_CMD_DATAEXCH_DATA_MAXLEN	262
#define PN532_CMD_DATAFRAME_MAXLEN	240	/* max data length (send) */
#define PN532_CMD_DATAEXCH_HEAD_LEN 1
#define PN532_CMD_SPI_FRAME_HEAD_LEN  1 /* SPI SR byte */

#define PN532_SPI_CMD_WRITE  0x01
#define PN532_SPI_CMD_READ   0x03
#define PN532_SPI_CMD_STATUS 0x02

#define PN532_SPI_READY  0x01

/*
 * Max extended frame payload len, excluding TFI and CC
 * which are already in PN532_FRAME_HEADER_LEN.
 */
#define PN532_MAX_FRAME_PAYLOAD_LEN 263

#define PN532_MAX_FRAME_LEN PN532_MAX_FRAME_HEADER_LEN + \
	PN532_MAX_FRAME_PAYLOAD_LEN + PN532_FRAME_TAIL_LEN

#define PN532_STD_FRAME_ACK_SIZE 6 /* Preamble (1), SoPC (2), ACK Code (2),
				  Postamble (1) */
#define PN532_STD_FRAME_CHECKSUM(f) (f->data[f->len])
#define PN532_STD_FRAME_POSTAMBLE(f) (f->data[f->len + 1])
/* Half start code (3), LEN (4) should be 0xffff for extended frame */
#define PN532_STD_IS_EXTENDED(hdr) ((hdr)->len == 0xFF \
					&& (hdr)->lcs == 0xFF)
#define PN532_EXT_FRAME_CHECKSUM(f) (f->data[be16_to_cpu(f->len)])


#define PN532_CMD_GET_FIRMWARE_VERSION 0x02
#define PN532_CMD_RF_CONFIGURATION 0x32
#define PN532_CMD_IN_DATA_EXCHANGE 0x40
#define PN532_CMD_IN_COMM_THRU     0x42
#define PN532_CMD_IN_LIST_PASSIVE_TARGET 0x4A
#define PN532_CMD_IN_ATR 0x50
#define PN532_CMD_IN_RELEASE 0x52
#define PN532_CMD_IN_JUMP_FOR_DEP 0x56

#define PN532_CMD_TG_INIT_AS_TARGET 0x8c
#define PN532_CMD_TG_GET_DATA 0x86
#define PN532_CMD_TG_SET_DATA 0x8e
#define PN532_CMD_TG_SET_META_DATA 0x94
#define PN532_CMD_UNDEF 0xff

/* custom cmd */
#define PN532_CMD_ACK 0x1fff
#define pn532_cmd_abort pn532_send_ack

#define PN532_MAX_CMD_TIMEOUT_MS 1000

/* PN532 Commands */
#define PN532_FRAME_CMD(f) (f->data[1])

#define PN532_CMD_RESPONSE(cmd) (cmd + 1)

/* Delay between each SPI status check (ms) */
#define PN532_STATUS_CHECK_INTERVAL 5
/* How much time we spend listening for initiators */
#define PN532_LISTEN_TIME 2
/* Delay between each poll frame (ms) */
#define PN532_POLL_INTERVAL 10

/* PN532 Return codes */
#define PN532_CMD_RET_MASK 0x3F
#define PN532_CMD_MI_MASK 0x40
#define PN532_CMD_RET_SUCCESS 0x00

struct pn532;

/* structs for pn532 commands */

/* PN532_CMD_GET_FIRMWARE_VERSION */
struct pn532_fw_version {
	u8 ic;
	u8 ver;
	u8 rev;
	u8 support;
};

/* PN532_CMD_RF_CONFIGURATION */
#define PN532_CFGITEM_RF_FIELD    0x01
#define PN532_CFGITEM_TIMING      0x02
#define PN532_CFGITEM_MAX_RETRIES 0x05

#define PN532_CFGITEM_RF_FIELD_AUTO_RFCA 0x2

#define PN532_CONFIG_TIMING_102 0xb
#define PN532_CONFIG_TIMING_204 0xc
#define PN532_CONFIG_TIMING_409 0xd
#define PN532_CONFIG_TIMING_819 0xe

#define PN532_CONFIG_MAX_RETRIES_NO_RETRY 0x00
#define PN532_CONFIG_MAX_RETRIES_ENDLESS 0xFF

struct pn532_config_max_retries {
	u8 mx_rty_atr;
	u8 mx_rty_psl;
	u8 mx_rty_passive_act;
} __packed;

struct pn532_config_timing {
	u8 rfu;
	u8 atr_res_timeout;
	u8 dep_timeout;
} __packed;

/* PN532_CMD_IN_LIST_PASSIVE_TARGET */

/* felica commands opcode */
#define PN532_FELICA_OPC_SENSF_REQ 0
#define PN532_FELICA_OPC_SENSF_RES 1
/* felica SENSF_REQ parameters */
#define PN532_FELICA_SENSF_SC_ALL 0xFFFF
#define PN532_FELICA_SENSF_RC_NO_SYSTEM_CODE 0
#define PN532_FELICA_SENSF_RC_SYSTEM_CODE 1
#define PN532_FELICA_SENSF_RC_ADVANCED_PROTOCOL 2

/* type B initiator_data values */
#define PN532_TYPE_B_AFI_ALL_FAMILIES 0
#define PN532_TYPE_B_POLL_METHOD_TIMESLOT 0
#define PN532_TYPE_B_POLL_METHOD_PROBABILISTIC 1

union pn532_cmd_poll_initdata {
	struct {
		u8 afi;
		u8 polling_method;
	} __packed type_b;
	struct {
		u8 opcode;
		__be16 sc;
		u8 rc;
		u8 tsn;
	} __packed felica;
};

/* Poll modulations */
enum {
	PN532_POLL_MOD_106KBPS_A,
	PN532_POLL_MOD_212KBPS_FELICA,
	PN532_POLL_MOD_424KBPS_FELICA,
	PN532_POLL_MOD_106KBPS_JEWEL,
	PN532_POLL_MOD_847KBPS_B,
	PN532_LISTEN_MOD,

	__PN532_POLL_MOD_AFTER_LAST,
};
#define PN532_POLL_MOD_MAX (__PN532_POLL_MOD_AFTER_LAST - 1)

struct pn532_poll_modulations {
	struct {
		u8 maxtg;
		u8 brty;
		union pn532_cmd_poll_initdata initiator_data;
	} __packed data;
	u8 len;
};

static const struct pn532_poll_modulations poll_mod[] = {
	[PN532_POLL_MOD_106KBPS_A] = {
		.data = {
			.maxtg = 1,
			.brty = 0,
		},
		.len = 2,
	},
	[PN532_POLL_MOD_212KBPS_FELICA] = {
		.data = {
			.maxtg = 1,
			.brty = 1,
			.initiator_data.felica = {
				.opcode = PN532_FELICA_OPC_SENSF_REQ,
				.sc = PN532_FELICA_SENSF_SC_ALL,
				.rc = PN532_FELICA_SENSF_RC_SYSTEM_CODE,
				.tsn = 0x03,
			},
		},
		.len = 7,
	},
	[PN532_POLL_MOD_424KBPS_FELICA] = {
		.data = {
			.maxtg = 1,
			.brty = 2,
			.initiator_data.felica = {
				.opcode = PN532_FELICA_OPC_SENSF_REQ,
				.sc = PN532_FELICA_SENSF_SC_ALL,
				.rc = PN532_FELICA_SENSF_RC_SYSTEM_CODE,
				.tsn = 0x03,
			},
		 },
		.len = 7,
	},
	[PN532_POLL_MOD_106KBPS_JEWEL] = {
		.data = {
			.maxtg = 1,
			.brty = 4,
		},
		.len = 2,
	},
	[PN532_POLL_MOD_847KBPS_B] = {
		.data = {
			.maxtg = 1,
			.brty = 8,
			.initiator_data.type_b = {
				.afi = PN532_TYPE_B_AFI_ALL_FAMILIES,
				.polling_method =
					PN532_TYPE_B_POLL_METHOD_TIMESLOT,
			},
		},
		.len = 3,
	},
	[PN532_LISTEN_MOD] = {
		.len = 0,
	},
};

/* PN532_CMD_IN_ATR */

struct pn532_cmd_activate_response {
	u8 status;
	u8 nfcid3t[10];
	u8 didt;
	u8 bst;
	u8 brt;
	u8 to;
	u8 ppt;
	/* optional */
	u8 gt[];
} __packed;

struct pn532_cmd_jump_dep_response {
	u8 status;
	u8 tg;
	u8 nfcid3t[10];
	u8 didt;
	u8 bst;
	u8 brt;
	u8 to;
	u8 ppt;
	/* optional */
	u8 gt[];
} __packed;


/* PN532_TG_INIT_AS_TARGET */
#define PN532_INIT_TARGET_PASSIVE 0x1
#define PN532_INIT_TARGET_DEP 0x2

#define PN532_INIT_TARGET_RESP_FRAME_MASK 0x3
#define PN532_INIT_TARGET_RESP_ACTIVE     0x1
#define PN532_INIT_TARGET_RESP_DEP        0x4


/* start of frame */
#define PN532_STD_FRAME_SOF 0x00FF

/* standard frame identifier: in/out/error */
#define PN532_STD_FRAME_DIR_OUT 0xD4
#define PN532_STD_FRAME_DIR_IN 0xD5

struct pn532_std_frame { /* Normal Information frame */
	u8 preamble;
	__be16 start_code; /*  2 bytes (0x00 and 0xFF) */
	u8 len; /* DATA length + TFI */
	u8 lcs; /* Packet Length Checksum: Lower byte of [LEN + LCS] = 0x00 */
	u8 data[];
} __packed;

struct pn532_ext_frame {	/* Extended Information frame */
	u8 preamble;
	__be16 start_code;
	__be16 eif_flag;	/* fixed to 0xFFFF */
	__be16 len;
	u8 lcs;
	u8 data[];
} __packed;

struct pn532_frame {
	union {
		struct pn532_std_frame std;
		struct pn532_ext_frame ext;
	} u;
};

typedef int (*pn532_send_async_complete_t) (struct pn532 *dev, void *arg,
					struct sk_buff *resp);

enum pn532_cmd_flag {
	CMD_INIT,
	CMD_WAIT_ACK,
	CMD_WAIT_RESP
};

struct pn532_cmd {
	struct list_head list;
	unsigned long flags;
	unsigned long timeout;
	u16 code;
	struct sk_buff *req;
	pn532_send_async_complete_t  complete_cb;
	void *complete_cb_context;
};

struct pn532_cmd_head {
	struct list_head list;
	spinlock_t lock;  /* protects cmd queue */
};

struct pn532 {
	struct nfc_dev *nfc_dev;
	struct spi_device *spi;
	bool lsb_support;

	int tx_headroom;
	int tx_tailroom;

	spinlock_t cmd_lock;  /* protects cmd */
	struct pn532_cmd *cmd;

	struct sk_buff_head resp_q;
	struct sk_buff_head fragment_skb;

	struct work_struct cmd_work;
	struct delayed_work spi_status_work;
	struct work_struct ack_work;
	struct work_struct response_work;

	struct delayed_work poll_work;
	struct work_struct mi_rx_work;
	struct work_struct mi_tx_work;
	struct work_struct mi_tm_rx_work;
	struct work_struct mi_tm_tx_work;
	struct work_struct tg_work;
	struct work_struct rf_work;

	struct workqueue_struct	*wq;
	struct workqueue_struct	*cmd_wq;
	struct workqueue_struct	*tr_wq;

	atomic_t cmd_cnt;
	struct pn532_cmd_head cmd_queue;

	struct pn532_poll_modulations *poll_mod_active[PN532_POLL_MOD_MAX + 1];
	u8 poll_mod_count;
	u8 poll_mod_curr;
	u8 poll_dep;
	u32 poll_protocols;
	u32 listen_protocols;
	struct timer_list listen_timer;
	int cancel_listen;

	u8 *gb;
	size_t gb_len;

	u8 tgt_available_prots;
	u8 tgt_active_prot;
	u8 tgt_mode;

	void *cmd_complete_mi_arg;
	void *cmd_complete_dep_arg;
};

static const u8 bit_reverse_table[256] =
{
#   define R2(n)     n,     n + 2*64,     n + 1*64,     n + 3*64
#   define R4(n) R2(n), R2(n + 2*16), R2(n + 1*16), R2(n + 3*16)
#   define R6(n) R4(n), R4(n + 2*4 ), R4(n + 1*4 ), R4(n + 3*4 )
    R6(0), R6(2), R6(1), R6(3)
};

#define ARRAY_BITS_REVERSE(d, l) \
{ \
	int i; \
	for (i = 0; i < (l); ++i) \
		(d)[i] = bit_reverse_table[(d)[i]]; \
}while(0)

#define BITS_REVERSE(x)  bit_reverse_table[(x)]

#define PN532_COMPLETE_CURRENT_CMD(dev, resp) \
{ \
	unsigned long flags; \
	struct pn532_cmd *cmd_; \
	spin_lock_irqsave(&dev->cmd_lock, flags); \
	cmd_ = dev->cmd; \
	dev->cmd = NULL; \
	spin_unlock_irqrestore(&dev->cmd_lock, flags); \
	if (cmd_->complete_cb != NULL) \
		cmd_->complete_cb(dev, cmd_->complete_cb_context,resp);\
	dev_kfree_skb(cmd_->req); \
	kfree(cmd_); \
}while(0)

#define PN532_CURRENT_CMD_IS_VALID(dev) \
({ \
	bool is_valid; \
	unsigned long flags; \
	spin_lock_irqsave(&dev->cmd_lock, flags); \
	is_valid = dev->cmd != NULL; \
	spin_unlock_irqrestore(&dev->cmd_lock, flags); \
	is_valid; \
})

static inline void cmd_queue_head_init(struct pn532_cmd_head *head)
{
	spin_lock_init(&head->lock);
	INIT_LIST_HEAD(&head->list);
}

static inline void cmd_queue_tail(struct pn532_cmd_head *head,
		struct pn532_cmd *cmd)
{
	unsigned long flags;

	INIT_LIST_HEAD(&cmd->list);

	spin_lock_irqsave(&head->lock, flags);
	list_add_tail(&cmd->list, &head->list);
	spin_unlock_irqrestore(&head->lock, flags);
}

static inline struct pn532_cmd * cmd_dequeue(struct pn532_cmd_head * head)
{
	unsigned long flags;
	struct pn532_cmd *cmd = NULL;

	spin_lock_irqsave(&head->lock, flags);

	if (list_empty(&head->list))
		goto out;

	cmd = list_first_entry(&head->list, struct pn532_cmd, list);

	list_del(&cmd->list);

 out:
	spin_unlock_irqrestore(&head->lock, flags);
	return cmd;
}

static inline void cmd_queue_purge(struct pn532_cmd_head * head)
{
	unsigned long flags;
	struct pn532_cmd *cmd, *n;

	spin_lock_irqsave(&head->lock, flags);

	list_for_each_entry_safe(cmd, n, &head->list, list) {
		list_del(&cmd->list);
		dev_kfree_skb(cmd->req);
		kfree(cmd);
	}
	spin_unlock_irqrestore(&head->lock, flags);
}

/* =============================================================== */

static inline struct sk_buff *pn532_alloc_skb(struct pn532 *dev,
		unsigned int len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len + dev->tx_headroom + dev->tx_tailroom, GFP_KERNEL);
	if (skb)
		skb_reserve(skb, dev->tx_headroom);

	return skb;
}

/* The rule: value(high byte) + value(low byte) + checksum = 0 */
static inline u8 pn532_ext_checksum(u16 value)
{
	return ~(u8)(((value & 0xFF00) >> 8) + (u8)(value & 0xFF)) + 1;
}

/* The rule: value + checksum = 0 */
static inline u8 pn532_std_checksum(u8 value)
{
	return ~value + 1;
}

/* The rule: sum(data elements) + checksum = 0 */
static u8 pn532_std_data_checksum(u8 *data, int datalen)
{
	u8 sum = 0;
	int i;

	for (i = 0; i < datalen; i++)
		sum += data[i];

	return pn532_std_checksum(sum);
}

static void pn532_build_cmd_frame(struct pn532 *dev, u8 cmd_code,
				  struct sk_buff *skb)
{
	int payload_len;
	/* Data Checksum - lower byte of [TFI + PD0 + PD1 + ... + PDn + DCS] = 0x00 */
	u8 dcs;

	struct pn532_std_frame * frame;

	/* Add Command code */
	*skb_push(skb, sizeof(u8)) = cmd_code;
	/* Add TFI Frame Identifier - Actual DATA starts here */
	*skb_push(skb, sizeof(u8)) = PN532_STD_FRAME_DIR_OUT;

	payload_len = skb->len;
	dcs = pn532_std_data_checksum(skb->data, skb->len);

	/* Fill Frame header */
	frame = (struct pn532_std_frame *)skb_push(skb, sizeof(struct pn532_std_frame));

	frame->preamble = 0;
	frame->start_code = cpu_to_be16(PN532_STD_FRAME_SOF);
	frame->len = payload_len;
	frame->lcs = pn532_std_checksum(frame->len);

	/* Add DCS */
	*skb_put(skb, sizeof(u8)) = dcs;

	/* Add POSTAMBLE */
	*skb_put(skb, sizeof(u8)) = 0;
}

static bool pn532_frame_is_ack(void *_frame)
{
	struct pn532_std_frame *frame = _frame;

	if (frame->start_code != cpu_to_be16(PN532_STD_FRAME_SOF))
		return false;

	if (frame->len != 0 || frame->lcs != 0xFF)
		return false;

	return true;
}

static bool pn532_frame_is_error(void *_frame)
{
	struct pn532_std_frame *frame = _frame;

	if (frame->start_code != cpu_to_be16(PN532_STD_FRAME_SOF))
		return false;

	if (frame->len != 1 ||
	    frame->lcs != 0xFF ||
	    frame->data[0] != 0x7F ||
	    PN532_STD_FRAME_CHECKSUM(frame) != 0x81)
		return false;

	return true;
}

static bool pn532_std_frame_is_valid(struct pn532 *dev,
		void *_frame)
{
	u8 checksum;
	struct pn532_std_frame *stdf = _frame;

	if (stdf->start_code != cpu_to_be16(PN532_STD_FRAME_SOF))
		return false;

	if (likely(PN532_STD_IS_EXTENDED(stdf)))
		return false;

	checksum = pn532_std_checksum(stdf->len);
	if (checksum != stdf->lcs)
		return false;

	checksum = pn532_std_data_checksum(stdf->data, stdf->len);
	if (checksum != PN532_STD_FRAME_CHECKSUM(stdf))
		return false;

	return true;
}

static bool pn532_ext_frame_is_valid(struct pn532 *dev,
		void *_frame)
{
	u8 checksum;
	/* Extended */
	struct pn532_ext_frame *eif = _frame;

	if (eif->start_code != cpu_to_be16(PN532_STD_FRAME_SOF))
		return false;

	if (likely(!PN532_STD_IS_EXTENDED(eif)))
		return false;

	checksum = pn532_ext_checksum(be16_to_cpu(eif->len));
	if (checksum != eif->lcs)
		return false;

	/* check data checksum */
	checksum = pn532_std_data_checksum(eif->data,
					   be16_to_cpu(eif->len));
	if (checksum != PN532_EXT_FRAME_CHECKSUM(eif))
		return false;

	return true;
}

/* ==================== TARGET ====================== */

struct pn532_target_type_a {
	__be16 sens_res;
	u8 sel_res;
	u8 nfcid_len;
	u8 nfcid_data[];
} __packed;


#define PN532_TYPE_A_SENS_RES_NFCID1(x) ((u8)((be16_to_cpu(x) & 0x00C0) >> 6))
#define PN532_TYPE_A_SENS_RES_SSD(x) ((u8)((be16_to_cpu(x) & 0x001F) >> 0))
#define PN532_TYPE_A_SENS_RES_PLATCONF(x) ((u8)((be16_to_cpu(x) & 0x0F00) >> 8))

#define PN532_TYPE_A_SENS_RES_SSD_JEWEL 0x00
#define PN532_TYPE_A_SENS_RES_PLATCONF_JEWEL 0x0C

#define PN532_TYPE_A_SEL_PROT(x) (((x) & 0x60) >> 5)
#define PN532_TYPE_A_SEL_CASCADE(x) (((x) & 0x04) >> 2)

#define PN532_TYPE_A_SEL_PROT_MIFARE 0
#define PN532_TYPE_A_SEL_PROT_ISO14443 1
#define PN532_TYPE_A_SEL_PROT_DEP 2
#define PN532_TYPE_A_SEL_PROT_ISO14443_DEP 3

static bool pn532_target_type_a_is_valid(struct pn532_target_type_a *type_a,
							int target_data_len)
{
	u8 ssd;
	u8 platconf;

	if (target_data_len < sizeof(struct pn532_target_type_a))
		return false;

	/* The lenght check of nfcid[] and ats[] are not being performed because
	   the values are not being used */

	/* Requirement 4.6.3.3 from NFC Forum Digital Spec */
	ssd = PN532_TYPE_A_SENS_RES_SSD(type_a->sens_res);
	platconf = PN532_TYPE_A_SENS_RES_PLATCONF(type_a->sens_res);

	if ((ssd == PN532_TYPE_A_SENS_RES_SSD_JEWEL &&
	     platconf != PN532_TYPE_A_SENS_RES_PLATCONF_JEWEL) ||
	    (ssd != PN532_TYPE_A_SENS_RES_SSD_JEWEL &&
	     platconf == PN532_TYPE_A_SENS_RES_PLATCONF_JEWEL))
		return false;

	/* Requirements 4.8.2.1, 4.8.2.3, 4.8.2.5 and 4.8.2.7 from NFC Forum */
	if (PN532_TYPE_A_SEL_CASCADE(type_a->sel_res) != 0)
		return false;

	return true;
}

static int pn532_target_found_type_a(struct nfc_target *nfc_tgt, u8 *tgt_data,
							int tgt_data_len)
{
	struct pn532_target_type_a *tgt_type_a;

	tgt_type_a = (struct pn532_target_type_a *)tgt_data;

	if (!pn532_target_type_a_is_valid(tgt_type_a, tgt_data_len))
		return -EPROTO;

	switch (PN532_TYPE_A_SEL_PROT(tgt_type_a->sel_res)) {
	case PN532_TYPE_A_SEL_PROT_MIFARE:
		nfc_tgt->supported_protocols = NFC_PROTO_MIFARE_MASK;
		break;
	case PN532_TYPE_A_SEL_PROT_ISO14443:
		nfc_tgt->supported_protocols = NFC_PROTO_ISO14443_MASK;
		break;
	case PN532_TYPE_A_SEL_PROT_DEP:
		nfc_tgt->supported_protocols = NFC_PROTO_NFC_DEP_MASK;
		break;
	case PN532_TYPE_A_SEL_PROT_ISO14443_DEP:
		nfc_tgt->supported_protocols = NFC_PROTO_ISO14443_MASK |
							NFC_PROTO_NFC_DEP_MASK;
		break;
	}

	nfc_tgt->sens_res = be16_to_cpu(tgt_type_a->sens_res);
	nfc_tgt->sel_res = tgt_type_a->sel_res;
	nfc_tgt->nfcid1_len = tgt_type_a->nfcid_len;
	memcpy(nfc_tgt->nfcid1, tgt_type_a->nfcid_data, nfc_tgt->nfcid1_len);

	return 0;
}

struct pn532_target_felica {
	u8 pol_res;
	u8 opcode;
	u8 nfcid2[NFC_NFCID2_MAXSIZE];
	u8 pad[8];
	/* optional */
	u8 syst_code[];
} __packed;

#define PN532_FELICA_SENSF_NFCID2_DEP_B1 0x01
#define PN532_FELICA_SENSF_NFCID2_DEP_B2 0xFE

static bool pn532_target_felica_is_valid(struct pn532_target_felica *felica,
							int target_data_len)
{
	if (target_data_len < sizeof(struct pn532_target_felica))
		return false;

	if (felica->opcode != PN532_FELICA_OPC_SENSF_RES)
		return false;

	return true;
}

static int pn532_target_found_felica(struct nfc_target *nfc_tgt, u8 *tgt_data,
							int tgt_data_len)
{
	struct pn532_target_felica *tgt_felica;

	tgt_felica = (struct pn532_target_felica *)tgt_data;

	if (!pn532_target_felica_is_valid(tgt_felica, tgt_data_len))
		return -EPROTO;

	if ((tgt_felica->nfcid2[0] == PN532_FELICA_SENSF_NFCID2_DEP_B1) &&
	    (tgt_felica->nfcid2[1] == PN532_FELICA_SENSF_NFCID2_DEP_B2))
		nfc_tgt->supported_protocols = NFC_PROTO_NFC_DEP_MASK;
	else
		nfc_tgt->supported_protocols = NFC_PROTO_FELICA_MASK;

	memcpy(nfc_tgt->sensf_res, &tgt_felica->opcode, 9);
	nfc_tgt->sensf_res_len = 9;

	memcpy(nfc_tgt->nfcid2, tgt_felica->nfcid2, NFC_NFCID2_MAXSIZE);
	nfc_tgt->nfcid2_len = NFC_NFCID2_MAXSIZE;

	return 0;
}

struct pn532_target_jewel {
	__be16 sens_res;
	u8 jewelid[4];
} __packed;

static bool pn532_target_jewel_is_valid(struct pn532_target_jewel *jewel,
							int target_data_len)
{
	u8 ssd;
	u8 platconf;

	if (target_data_len < sizeof(struct pn532_target_jewel))
		return false;

	/* Requirement 4.6.3.3 from NFC Forum Digital Spec */
	ssd = PN532_TYPE_A_SENS_RES_SSD(jewel->sens_res);
	platconf = PN532_TYPE_A_SENS_RES_PLATCONF(jewel->sens_res);

	if ((ssd == PN532_TYPE_A_SENS_RES_SSD_JEWEL &&
	     platconf != PN532_TYPE_A_SENS_RES_PLATCONF_JEWEL) ||
	    (ssd != PN532_TYPE_A_SENS_RES_SSD_JEWEL &&
	     platconf == PN532_TYPE_A_SENS_RES_PLATCONF_JEWEL))
		return false;

	return true;
}

static int pn532_target_found_jewel(struct nfc_target *nfc_tgt, u8 *tgt_data,
							int tgt_data_len)
{
	struct pn532_target_jewel *tgt_jewel;

	tgt_jewel = (struct pn532_target_jewel *)tgt_data;

	if (!pn532_target_jewel_is_valid(tgt_jewel, tgt_data_len))
		return -EPROTO;

	nfc_tgt->supported_protocols = NFC_PROTO_JEWEL_MASK;
	nfc_tgt->sens_res = be16_to_cpu(tgt_jewel->sens_res);
	nfc_tgt->nfcid1_len = 4;
	memcpy(nfc_tgt->nfcid1, tgt_jewel->jewelid, nfc_tgt->nfcid1_len);

	return 0;
}

struct pn532_type_b_prot_info {
	u8 bitrate;
	u8 fsci_type;
	u8 fwi_adc_fo;
} __packed;

#define PN532_TYPE_B_PROT_FCSI(x) (((x) & 0xF0) >> 4)
#define PN532_TYPE_B_PROT_TYPE(x) (((x) & 0x0F) >> 0)
#define PN532_TYPE_B_PROT_TYPE_RFU_MASK 0x8

struct pn532_type_b_sens_res {
	u8 opcode;
	u8 nfcid[4];
	u8 appdata[4];
	struct pn532_type_b_prot_info prot_info;
} __packed;

#define PN532_TYPE_B_OPC_SENSB_RES 0x50

struct pn532_target_type_b {
	struct pn532_type_b_sens_res sensb_res;
	u8 attrib_res_len;
	u8 attrib_res[];
} __packed;

static bool pn532_target_type_b_is_valid(struct pn532_target_type_b *type_b,
							int target_data_len)
{
	if (target_data_len < sizeof(struct pn532_target_type_b))
		return false;

	if (type_b->sensb_res.opcode != PN532_TYPE_B_OPC_SENSB_RES)
		return false;

	if (PN532_TYPE_B_PROT_TYPE(type_b->sensb_res.prot_info.fsci_type) &
						PN532_TYPE_B_PROT_TYPE_RFU_MASK)
		return false;

	return true;
}

static int pn532_target_found_type_b(struct nfc_target *nfc_tgt, u8 *tgt_data,
							int tgt_data_len)
{
	struct pn532_target_type_b *tgt_type_b;

	tgt_type_b = (struct pn532_target_type_b *)tgt_data;

	if (!pn532_target_type_b_is_valid(tgt_type_b, tgt_data_len))
		return -EPROTO;

	nfc_tgt->supported_protocols = NFC_PROTO_ISO14443_B_MASK;

	return 0;
}

/* =============================================================== */

static int pn532_spi_send_frame(struct pn532 *dev, struct sk_buff *skb)
{
	int rc;
	struct spi_message m;
	struct spi_transfer t;

	*skb_push(skb, sizeof(u8)) = PN532_SPI_CMD_WRITE;

	print_hex_dump_debug("PN532_SPI TX: ", DUMP_PREFIX_NONE, 16, 1,
			     skb->data, skb->len, false);

	if (!dev->lsb_support) {
		ARRAY_BITS_REVERSE(skb->data, skb->len);
		print_hex_dump_debug("PN532_SPI TX (converted): ",
				DUMP_PREFIX_NONE, 16, 1,
				skb->data, skb->len, false);
	}

	memset(&t, 0, sizeof(struct spi_transfer));
	t.tx_buf = skb->data;
	t.len = skb->len;

	spi_message_init(&m);

        spi_message_add_tail(&t, &m);

	rc = spi_sync(dev->spi, &m);

	return rc;
}

static int pn532_send_cmd_async(struct pn532 *dev, u8 cmd_code,
				 struct sk_buff *req,
				 pn532_send_async_complete_t complete_cb,
				 void *complete_cb_context)
{
	struct pn532_cmd *cmd;

	dev_dbg(&dev->spi->dev, "Sending command 0x%x\n", cmd_code);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->code = cmd_code;
	cmd->req = req;
	cmd->complete_cb = complete_cb;
	cmd->complete_cb_context = complete_cb_context;

	pn532_build_cmd_frame(dev, cmd_code, req);

	cmd_queue_tail(&dev->cmd_queue, cmd);
	atomic_inc(&dev->cmd_cnt);

	queue_work(dev->cmd_wq, &dev->cmd_work);

	return 0;
}

struct pn532_sync_cmd_response {
	struct sk_buff *resp;
	struct completion done;
};

static int pn532_send_sync_complete(struct pn532 *dev, void *_arg,
				    struct sk_buff *resp)
{
	struct pn532_sync_cmd_response *arg = _arg;

	dev_dbg(&dev->spi->dev, "Recv complete event: resp %p\n", resp);

	arg->resp = resp;
	complete(&arg->done);

	return 0;
}

/*  pn532_send_cmd_sync
 *
 *  Please note the req parameter is freed inside the function to
 *  limit a number of return value interpretations by the caller.
 *
 *  1. negative in case of error during TX path -> req should be freed
 *
 *  2. negative in case of error during RX path -> req should not be freed
 *     as it's been already freed at the begining of RX path by
 *     async_complete_cb.
 *
 *  3. valid pointer in case of succesfult RX path
 *
 *  A caller has to check a return value with IS_ERR macro. If the test pass,
 *  the returned pointer is valid.
 *
 * */
static struct sk_buff *pn532_send_cmd_sync(struct pn532 *dev, u8 cmd_code,
					       struct sk_buff *req)
{
	int rc;
	struct pn532_sync_cmd_response arg;

	init_completion(&arg.done);

	rc = pn532_send_cmd_async(dev, cmd_code, req,
				  pn532_send_sync_complete, &arg);
	if (rc) {
		dev_kfree_skb(req);
		return ERR_PTR(rc);
	}

	wait_for_completion(&arg.done);

	return arg.resp;
}

static int pn532_send_ack(struct pn532 *dev)
{
	/* spec 7.1.1.3:  Preamble, SoPC (2), ACK Code (2), Postamble */
	u8 ack[] = {0x00, 0x00, 0xff, 0x00, 0xff, 0x00};

	struct pn532_cmd *cmd;
	struct pn532_sync_cmd_response arg;

	dev_dbg(&dev->spi->dev, "%s", __func__);

	init_completion(&arg.done);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->code = PN532_CMD_ACK;
	cmd->complete_cb = pn532_send_sync_complete;
	cmd->complete_cb_context = &arg;
	cmd->req = pn532_alloc_skb(dev, sizeof(ack));
	memcpy(skb_put(cmd->req, sizeof(ack)), ack, sizeof(ack));

	cmd_queue_tail(&dev->cmd_queue, cmd);
	atomic_inc(&dev->cmd_cnt);

	queue_work(dev->cmd_wq, &dev->cmd_work);

	wait_for_completion(&arg.done);

	return 0;
}

/* ===================================================================== */

static void pn532_read_response(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, response_work);
	u8 read_cmd = PN532_SPI_CMD_READ;
	int rc;
	struct sk_buff *resp;
	unsigned int resp_len;

	struct spi_message m;
	struct spi_transfer t[2];


	dev_dbg(&dev->spi->dev, "%s", __func__);

	if (!PN532_CURRENT_CMD_IS_VALID(dev)) {
		dev_dbg(&dev->spi->dev, "%s there is no command being executed",
			__func__);
		return;
	}

	if (!dev->lsb_support)
		read_cmd = BITS_REVERSE(read_cmd);

	resp_len = PN532_MAX_FRAME_LEN;

	resp = alloc_skb(resp_len, GFP_KERNEL);
	if (!resp) {
		nfc_err(&dev->spi->dev, "Can't allocate memory for Normal Inf. response\n");
		resp = ERR_PTR(-ENOMEM);
		goto out;
	}

	memset(&t, 0, sizeof(t));
	t[0].tx_buf = &read_cmd;
	t[0].len = sizeof(read_cmd);
	t[0].cs_change = 0;
	t[1].rx_buf = resp->data;
	t[1].len = resp_len;
	t[1].cs_change = 1;

	spi_message_init(&m);

        spi_message_add_tail(&t[0], &m);
        spi_message_add_tail(&t[1], &m);

	rc = spi_sync(dev->spi, &m);
	if (rc < 0) {
		dev_kfree_skb(resp);
		resp = ERR_PTR(-EIO);
		goto out;
	}

	print_hex_dump_debug("PN532_SPI RESP: ", DUMP_PREFIX_NONE, 16, 1,
			     resp->data, resp_len, false);

	if (!dev->lsb_support) {
		ARRAY_BITS_REVERSE(resp->data, resp_len);
		print_hex_dump_debug("PN532_SPI RESP (converted): ",
				DUMP_PREFIX_NONE, 16, 1,
			        resp->data, resp_len, false);
	}

	if (pn532_frame_is_error(resp->data)) {
		dev_err(&dev->spi->dev, "Receive ERROR frame for 0x%d command\n",
				dev->cmd->code);
		dev_kfree_skb(resp);
		resp = ERR_PTR(-EINVAL);
		goto out;
	}

	if (pn532_std_frame_is_valid(dev, resp->data)){
		struct pn532_std_frame * frame = (void *)resp->data;
		dev_dbg(&dev->spi->dev, "%s is a STD frame", __func__);
		if (PN532_FRAME_CMD(frame) !=
				PN532_CMD_RESPONSE(dev->cmd->code)) {
			dev_err(&dev->spi->dev,
				"Wrong RESP cmd code 0x%x. Has to be 0x%x\n",
				PN532_FRAME_CMD(frame),
				PN532_CMD_RESPONSE(dev->cmd->code));
			dev_kfree_skb(resp);
			resp = ERR_PTR(-EINVAL);
			goto out;
		}

		skb_reserve(resp, PN532_STD_FRAME_HEADER_LEN);
		skb_put(resp, frame->len - 2); /* TFI + CC */
	}else if(pn532_ext_frame_is_valid(dev, resp->data)) {
		struct pn532_ext_frame * frame = (void *)resp->data;
		dev_dbg(&dev->spi->dev, "%s is a EXT frame", __func__);
		if (PN532_FRAME_CMD(frame) !=
				PN532_CMD_RESPONSE(dev->cmd->code)) {
			dev_err(&dev->spi->dev,
				"Wrong RESP cmd code %d. Has to be %d\n",
				PN532_FRAME_CMD(frame),
				PN532_CMD_RESPONSE(dev->cmd->code));
			dev_kfree_skb(resp);
			resp = ERR_PTR(-EINVAL);
			goto out;
		}
		skb_reserve(resp, PN532_EXT_FRAME_HEADER_LEN);
		skb_put(resp, frame->len - 2); /* TFI + CC */
	}else {
		dev_kfree_skb(resp);
		resp = ERR_PTR(-EINVAL);
		goto out;
	}

	print_hex_dump_debug("PN532_SPI RESP: ", DUMP_PREFIX_NONE, 16, 1,
			     resp->data, resp->len, false);

out:
	dev_dbg(&dev->spi->dev, "Complete cmd 0x%x\n",dev->cmd->code);
	PN532_COMPLETE_CURRENT_CMD(dev, resp);
	queue_work(dev->cmd_wq, &dev->cmd_work);
	return;

}

static void pn532_read_ack(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, ack_work);
	u8 ack[PN532_STD_FRAME_ACK_SIZE] = {0};
	u8 read_cmd = PN532_SPI_CMD_READ;
	int rc;

	dev_dbg(&dev->spi->dev, "%s", __func__);

	if (!dev->cmd)
		return;

	if (!dev->lsb_support)
		read_cmd = BITS_REVERSE(read_cmd);

	rc = spi_write_then_read(dev->spi, &read_cmd, sizeof(read_cmd),
			ack, PN532_STD_FRAME_ACK_SIZE);

	print_hex_dump_debug("PN532_SPI ACK: ", DUMP_PREFIX_NONE, 16, 1,
			     ack, PN532_STD_FRAME_ACK_SIZE, false);

	if (!dev->lsb_support) {
		ARRAY_BITS_REVERSE(ack, PN532_STD_FRAME_ACK_SIZE);
		print_hex_dump_debug("PN532_SPI ACK (converted): ",
				DUMP_PREFIX_NONE, 16, 1,
				ack, PN532_STD_FRAME_ACK_SIZE, false);
	}

	if (!pn532_frame_is_ack(ack)) {
		nfc_err(&dev->spi->dev, "Received an invalid ack\n");
		PN532_COMPLETE_CURRENT_CMD(dev, ERR_PTR(-EINVAL));
		queue_work(dev->cmd_wq, &dev->cmd_work);
		return;
	}

	set_bit(CMD_WAIT_RESP, &dev->cmd->flags);
	queue_delayed_work(dev->tr_wq, &dev->spi_status_work,
				msecs_to_jiffies(PN532_STATUS_CHECK_INTERVAL));
}

static void pn532_status_check(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532,
			spi_status_work.work);
	u8 status_cmd;
	u8 status = 0;
	int rc;

	status_cmd = PN532_SPI_CMD_STATUS;

	if (!dev->lsb_support)
		status_cmd = BITS_REVERSE(status_cmd);

	rc = spi_write_then_read(dev->spi, &status_cmd, sizeof(status_cmd),
				&status, sizeof(status));
	if (!dev->lsb_support)
		status = BITS_REVERSE(status);

	dev_dbg(&dev->spi->dev, "Status %d\n", status);

	if (status == PN532_SPI_READY) {
		if (dev->cmd && test_bit(CMD_WAIT_RESP, &dev->cmd->flags))
			queue_work(dev->tr_wq, &dev->response_work);
		else if (dev->cmd && test_bit(CMD_WAIT_ACK, &dev->cmd->flags))
			queue_work(dev->tr_wq, &dev->ack_work);

		return;
	}

	if (dev->cmd && time_before(jiffies, dev->cmd->timeout)) {
		queue_delayed_work(dev->wq, &dev->spi_status_work,
				msecs_to_jiffies(PN532_STATUS_CHECK_INTERVAL));
	} else {
		dev_dbg(&dev->spi->dev, "Status check timeout\n");
		PN532_COMPLETE_CURRENT_CMD(dev, ERR_PTR(-ETIMEDOUT));
	}
}

static void pn532_wq_cmd(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, cmd_work);
	struct pn532_cmd *cmd = NULL;
	unsigned long flags;
	int rc;

	dev_dbg(&dev->spi->dev, "cmd_cnt %d\n", atomic_read(&dev->cmd_cnt));

	if (PN532_CURRENT_CMD_IS_VALID(dev)) {
		return;
	}

next:
	if (atomic_read(&dev->cmd_cnt)) {
		cmd = cmd_dequeue(&dev->cmd_queue);
		if (!cmd)
			return;

		atomic_dec(&dev->cmd_cnt);

		rc = pn532_spi_send_frame(dev, cmd->req);
		if (rc < 0) {
			PN532_COMPLETE_CURRENT_CMD(dev, ERR_PTR(rc));
			return;
		}

		cmd->timeout = jiffies +
			msecs_to_jiffies(PN532_MAX_CMD_TIMEOUT_MS);

		spin_lock_irqsave(&dev->cmd_lock, flags);
		dev->cmd = cmd;
		spin_unlock_irqrestore(&dev->cmd_lock, flags);

		if (cmd->code > PN532_CMD_UNDEF) {
			/* this is custom command like ACK and NACK
			 * no need to wait response. just complete it */
			PN532_COMPLETE_CURRENT_CMD(dev, NULL);
			goto next;
		}

		set_bit(CMD_WAIT_ACK, &cmd->flags);
		if (!rc)
			queue_delayed_work(dev->tr_wq, &dev->spi_status_work,
					msecs_to_jiffies(PN532_STATUS_CHECK_INTERVAL));

	}
}

/* ===================================================================== */

struct pn532_data_exchange_arg {
	data_exchange_cb_t cb;
	void *cb_context;
};

static struct sk_buff *pn532_build_response(struct pn532 *dev)
{
	struct sk_buff *skb, *tmp, *t;
	unsigned int skb_len = 0, tmp_len = 0;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (skb_queue_empty(&dev->resp_q))
		return NULL;

	if (skb_queue_len(&dev->resp_q) == 1) {
		skb = skb_dequeue(&dev->resp_q);
		goto out;
	}

	skb_queue_walk_safe(&dev->resp_q, tmp, t)
		skb_len += tmp->len;

	dev_dbg(&dev->spi->dev, "%s total length %d\n",
		__func__, skb_len);

	skb = alloc_skb(skb_len, GFP_KERNEL);
	if (skb == NULL)
		goto out;

	skb_put(skb, skb_len);

	skb_queue_walk_safe(&dev->resp_q, tmp, t) {
		memcpy(skb->data + tmp_len, tmp->data, tmp->len);
		tmp_len += tmp->len;
	}

out:
	skb_queue_purge(&dev->resp_q);

	return skb;
}

static int pn532_data_exchange_complete(struct pn532 *dev, void *_arg,
					struct sk_buff *resp)
{
	struct pn532_data_exchange_arg *arg = _arg;
	struct sk_buff *skb;
	int rc = 0;
	u8 status, ret, mi;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (IS_ERR(resp)) {
		rc = PTR_ERR(resp);
		goto _error;
	}

	status = resp->data[0];
	ret = status & PN532_CMD_RET_MASK;
	mi = status & PN532_CMD_MI_MASK;

	skb_pull(resp, sizeof(status));

	if (ret != PN532_CMD_RET_SUCCESS) {
		nfc_err(&dev->spi->dev,
			"Exchanging data failed (error 0x%x)\n", ret);
		rc = -EIO;
		goto error;
	}

	skb_queue_tail(&dev->resp_q, resp);

	if (mi) {
		dev->cmd_complete_mi_arg = arg;
		queue_work(dev->wq, &dev->mi_rx_work);
		return -EINPROGRESS;
	}

	/* Prepare for the next round */
	if (skb_queue_len(&dev->fragment_skb) > 0) {
		dev->cmd_complete_dep_arg = arg;
		queue_work(dev->wq, &dev->mi_tx_work);

		return -EINPROGRESS;
	}

	skb = pn532_build_response(dev);
	if (!skb)
		goto error;

	arg->cb(arg->cb_context, skb, 0);
	kfree(arg);
	return 0;

error:
	dev_kfree_skb(resp);
_error:
	skb_queue_purge(&dev->resp_q);
	arg->cb(arg->cb_context, NULL, rc);
	kfree(arg);
	return rc;
}

static int pn532_tm_get_data_complete(struct pn532 *dev, void *arg,
				      struct sk_buff *resp)
{
	struct sk_buff *skb;
	u8 status, ret, mi;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (IS_ERR(resp)) {
		skb_queue_purge(&dev->resp_q);
		return PTR_ERR(resp);
	}

	status = resp->data[0];

	ret = status & PN532_CMD_RET_MASK;
	mi = status & PN532_CMD_MI_MASK;

	skb_pull(resp, sizeof(status));

	if (ret != PN532_CMD_RET_SUCCESS) {
		rc = -EIO;
		goto error;
	}

	skb_queue_tail(&dev->resp_q, resp);

	if (mi) {
		queue_work(dev->wq, &dev->mi_tm_rx_work);
		return -EINPROGRESS;
	}

	skb = pn532_build_response(dev);
	if (!skb) {
		rc = -EIO;
		goto error;
	}

	return nfc_tm_data_received(dev->nfc_dev, skb);

error:
	nfc_tm_deactivated(dev->nfc_dev);
	dev->tgt_mode = 0;
	skb_queue_purge(&dev->resp_q);
	dev_kfree_skb(resp);

	return rc;
}

static void pn532_wq_tm_mi_recv(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, mi_tm_rx_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb = pn532_alloc_skb(dev, 0);
	if (!skb)
		return;

	rc = pn532_send_cmd_async(dev, PN532_CMD_TG_GET_DATA, skb,
					pn532_tm_get_data_complete,
					NULL);

	if (rc < 0)
		dev_kfree_skb(skb);

	return;
}

static int pn532_tm_send_complete(struct pn532 *dev, void *arg,
				  struct sk_buff *resp)
{
	u8 status;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (IS_ERR(resp))
		return PTR_ERR(resp);

	status = resp->data[0];

	/* Prepare for the next round */
	if (skb_queue_len(&dev->fragment_skb) > 0) {
		queue_work(dev->wq, &dev->mi_tm_tx_work);
		return -EINPROGRESS;
	}
	dev_kfree_skb(resp);

	if (status != 0) {
		nfc_tm_deactivated(dev->nfc_dev);

		dev->tgt_mode = 0;

		return 0;
	}

	queue_work(dev->wq, &dev->tg_work);

	return 0;
}

static void pn532_wq_tm_mi_send(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, mi_tm_tx_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	/* Grab the first skb in the queue */
	skb = skb_dequeue(&dev->fragment_skb);
	if (skb == NULL) {	/* No more data */
		/* Reset the queue for future use */
		skb_queue_head_init(&dev->fragment_skb);
		goto error;
	}

	/* last entry - remove MI bit */
	if (skb_queue_len(&dev->fragment_skb) == 0) {
		rc = pn532_send_cmd_async(dev, PN532_CMD_TG_SET_DATA,
					skb, pn532_tm_send_complete, NULL);
	} else
		rc = pn532_send_cmd_async(dev,
					PN532_CMD_TG_SET_META_DATA,
					skb, pn532_tm_send_complete, NULL);

	if (rc == 0) /* success */
		return;

	dev_err(&dev->spi->dev,
		"Error %d when trying to perform set meta data_exchange", rc);

	dev_kfree_skb(skb);

error:
	pn532_send_ack(dev);
}

static void pn532_wq_mi_send(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, mi_tx_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	/* Grab the first skb in the queue */
	skb = skb_dequeue(&dev->fragment_skb);

	if (skb == NULL) {	/* No more data */
		/* Reset the queue for future use */
		skb_queue_head_init(&dev->fragment_skb);
		goto error;
	}

	/* Still some fragments? */
	rc = pn532_send_cmd_async(dev,PN532_CMD_IN_DATA_EXCHANGE,
					 skb,
					 pn532_data_exchange_complete,
					 dev->cmd_complete_dep_arg);

	if (rc == 0) /* success */
		return;

	nfc_err(&dev->spi->dev,
		"Error %d when trying to perform data_exchange\n", rc);

	dev_kfree_skb(skb);
	kfree(dev->cmd_complete_dep_arg);

error:
	pn532_send_ack(dev);
}

static void pn532_wq_mi_recv(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, mi_rx_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb = pn532_alloc_skb(dev, PN532_CMD_DATAEXCH_HEAD_LEN);
	if (!skb)
		goto error;

	*skb_put(skb, sizeof(u8)) =  1; /*TG*/

	rc = pn532_send_cmd_async(dev, PN532_CMD_IN_DATA_EXCHANGE, skb,
					 pn532_data_exchange_complete,
					 dev->cmd_complete_mi_arg);

	if (rc == 0) /* success */
		return;

	nfc_err(&dev->spi->dev,
		"Error %d when trying to perform data_exchange\n", rc);

	dev_kfree_skb(skb);
	kfree(dev->cmd_complete_mi_arg);

error:
	pn532_send_ack(dev);
}

/* ===================================================================== */

static int pn532_rf_complete(struct pn532 *dev, void *arg,
			     struct sk_buff *resp)
{
	int rc = 0;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (IS_ERR(resp)) {
		rc = PTR_ERR(resp);

		nfc_err(&dev->spi->dev, "RF setting error %d", rc);

		return rc;
	}

	queue_delayed_work(dev->wq, &dev->poll_work,
			   msecs_to_jiffies(PN532_POLL_INTERVAL));

	dev_kfree_skb(resp);
	return rc;
}

static void pn532_wq_rf(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, rf_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb = pn532_alloc_skb(dev, 2);
	if (!skb)
		return;

	*skb_put(skb, 1) = PN532_CFGITEM_RF_FIELD;
	*skb_put(skb, 1) = PN532_CFGITEM_RF_FIELD_AUTO_RFCA;

	rc = pn532_send_cmd_async(dev, PN532_CMD_RF_CONFIGURATION, skb,
				  pn532_rf_complete, NULL);
	if (rc < 0) {
		dev_kfree_skb(skb);
		nfc_err(&dev->spi->dev, "RF setting error %d\n", rc);
	}

	return;
}

/* ===================================================================== */

static int pn532_send_poll_frame(struct pn532 *dev);
static void pn532_wq_poll(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, poll_work.work);
	struct pn532_poll_modulations *cur_mod;
	int rc;

	cur_mod = dev->poll_mod_active[dev->poll_mod_curr];

	dev_dbg(&dev->spi->dev,
		"%s cancel_listen %d modulation len %d\n",
		__func__, dev->cancel_listen, cur_mod->len);

	if (dev->cancel_listen == 1) {
		dev->cancel_listen = 0;
		pn532_cmd_abort(dev);
	}

	rc = pn532_send_poll_frame(dev);
	if (rc)
		return;

	if (cur_mod->len == 0 && dev->poll_mod_count > 1)
		mod_timer(&dev->listen_timer, jiffies + PN532_LISTEN_TIME * HZ);

	return;
}

/* ===================================================================== */

static void pn532_wq_tg_get_data(struct work_struct *work)
{
	struct pn532 *dev = container_of(work, struct pn532, tg_work);
	struct sk_buff *skb;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb = pn532_alloc_skb(dev, 0);
	if (!skb)
		return;

	rc = pn532_send_cmd_async(dev, PN532_CMD_TG_GET_DATA, skb,
				   pn532_tm_get_data_complete, NULL);

	if (rc < 0)
		dev_kfree_skb(skb);

	return;
}

/* ===================================================================== */

static inline void pn532_poll_next_mod(struct pn532 *dev)
{
	dev->poll_mod_curr = (dev->poll_mod_curr + 1) % dev->poll_mod_count;
}

static void pn532_poll_reset_mod_list(struct pn532 *dev)
{
	dev->poll_mod_count = 0;
}

static void pn532_poll_add_mod(struct pn532 *dev, u8 mod_index)
{
	dev->poll_mod_active[dev->poll_mod_count] =
		(struct pn532_poll_modulations *)&poll_mod[mod_index];
	dev->poll_mod_count++;
}

static void pn532_poll_create_mod_list(struct pn532 *dev,
				       u32 im_protocols, u32 tm_protocols)
{
	pn532_poll_reset_mod_list(dev);

	if ((im_protocols & NFC_PROTO_MIFARE_MASK) ||
	    (im_protocols & NFC_PROTO_ISO14443_MASK) ||
	    (im_protocols & NFC_PROTO_NFC_DEP_MASK))
		pn532_poll_add_mod(dev, PN532_POLL_MOD_106KBPS_A);

	if (im_protocols & NFC_PROTO_FELICA_MASK ||
	    im_protocols & NFC_PROTO_NFC_DEP_MASK) {
		pn532_poll_add_mod(dev, PN532_POLL_MOD_212KBPS_FELICA);
		pn532_poll_add_mod(dev, PN532_POLL_MOD_424KBPS_FELICA);
	}

	if (im_protocols & NFC_PROTO_JEWEL_MASK)
		pn532_poll_add_mod(dev, PN532_POLL_MOD_106KBPS_JEWEL);

	/* TODO */
	//if (im_protocols & NFC_PROTO_ISO14443_B_MASK)
	//	pn532_poll_add_mod(dev, PN532_POLL_MOD_847KBPS_B);

	if (tm_protocols)
		pn532_poll_add_mod(dev, PN532_LISTEN_MOD);
}

static struct sk_buff *pn532_alloc_poll_in_frame(struct pn532 *dev,
					struct pn532_poll_modulations *mod)
{
	struct sk_buff *skb;

	skb = pn532_alloc_skb(dev, mod->len);
	if (!skb)
		return NULL;

	memcpy(skb_put(skb, mod->len), &mod->data, mod->len);

	return skb;
}

static struct sk_buff *pn532_alloc_poll_tg_frame(struct pn532 *dev)
{
	struct sk_buff *skb;
	u8 *felica, *nfcid3, *gb;

	u8 *gbytes = dev->gb;
	size_t gbytes_len = dev->gb_len;

	u8 felica_params[18] = {0x1, 0xfe, /* DEP */
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, /* random */
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0xff, 0xff}; /* System code */

	u8 mifare_params[6] = {0x1, 0x1, /* SENS_RES */
			       0x0, 0x0, 0x0,
			       0x40}; /* SEL_RES for DEP */

	unsigned int skb_len = 36 + /* mode (1), mifare (6),
				       felica (18), nfcid3 (10), gb_len (1) */
			       gbytes_len +
			       1;  /* len Tk*/

	skb = pn532_alloc_skb(dev, skb_len);
	if (!skb)
		return NULL;

	/* DEP support only */
	*skb_put(skb, 1) = PN532_INIT_TARGET_DEP;

	/* MIFARE params */
	memcpy(skb_put(skb, 6), mifare_params, 6);

	/* Felica params */
	felica = skb_put(skb, 18);
	memcpy(felica, felica_params, 18);
	get_random_bytes(felica + 2, 6);

	/* NFCID3 */
	nfcid3 = skb_put(skb, 10);
	memset(nfcid3, 0, 10);
	memcpy(nfcid3, felica, 8);

	/* General bytes */
	*skb_put(skb, 1) = gbytes_len;

	gb = skb_put(skb, gbytes_len);
	memcpy(gb, gbytes, gbytes_len);

	/* Len Tk */
	*skb_put(skb, 1) = 0;

	return skb;
}

#define ATR_REQ_GB_OFFSET 17
static int pn532_init_target_complete(struct pn532 *dev, struct sk_buff *resp)
{
	u8 mode, *cmd, comm_mode = NFC_COMM_PASSIVE, *gb;
	size_t gb_len;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (resp->len < ATR_REQ_GB_OFFSET + 1)
		return -EINVAL;

	mode = resp->data[0];
	cmd = &resp->data[1];

	dev_dbg(&dev->spi->dev, "Target mode 0x%x len %d\n",
		mode, resp->len);

	if ((mode & PN532_INIT_TARGET_RESP_FRAME_MASK) ==
	    PN532_INIT_TARGET_RESP_ACTIVE)
		comm_mode = NFC_COMM_ACTIVE;

	if ((mode & PN532_INIT_TARGET_RESP_DEP) == 0)  /* Only DEP supported */
		return -EOPNOTSUPP;

	gb = cmd + ATR_REQ_GB_OFFSET;
	gb_len = resp->len - (ATR_REQ_GB_OFFSET + 1);

	rc = nfc_tm_activated(dev->nfc_dev, NFC_PROTO_NFC_DEP_MASK,
			      comm_mode, gb, gb_len);
	if (rc < 0) {
		nfc_err(&dev->spi->dev,
			"Error when signaling target activation\n");
		return rc;
	}

	dev->tgt_mode = 1;
	queue_work(dev->wq, &dev->tg_work);

	return 0;
}

static int pn532_target_found(struct pn532 *dev, u8 tg, u8 *tgdata,
			      int tgdata_len)
{
	struct nfc_target nfc_tgt;
	int rc;

	dev_dbg(&dev->spi->dev, "%s: modulation=%d\n",
		__func__, dev->poll_mod_curr);

	if (tg != 1)
		return -EPROTO;

	memset(&nfc_tgt, 0, sizeof(struct nfc_target));

	switch (dev->poll_mod_curr) {
	case PN532_POLL_MOD_106KBPS_A:
		rc = pn532_target_found_type_a(&nfc_tgt, tgdata, tgdata_len);
		break;
	case PN532_POLL_MOD_212KBPS_FELICA:
	case PN532_POLL_MOD_424KBPS_FELICA:
		rc = pn532_target_found_felica(&nfc_tgt, tgdata, tgdata_len);
		break;
	case PN532_POLL_MOD_106KBPS_JEWEL:
		rc = pn532_target_found_jewel(&nfc_tgt, tgdata, tgdata_len);
		break;
	case PN532_POLL_MOD_847KBPS_B:
		rc = pn532_target_found_type_b(&nfc_tgt, tgdata, tgdata_len);
		break;
	default:
		nfc_err(&dev->spi->dev,
			"Unknown current poll modulation\n");
		return -EPROTO;
	}

	if (rc)
		return rc;

	if (!(nfc_tgt.supported_protocols & dev->poll_protocols)) {
		dev_dbg(&dev->spi->dev,
			"The Tg found doesn't have the desired protocol\n");
		return -EAGAIN;
	}

	dev_dbg(&dev->spi->dev,
		"Target found - supported protocols: 0x%x\n",
		nfc_tgt.supported_protocols);

	dev->tgt_available_prots = nfc_tgt.supported_protocols;

	nfc_targets_found(dev->nfc_dev, &nfc_tgt, 1);

	return 0;
}

static int pn532_start_poll_complete(struct pn532 *dev, struct sk_buff *resp)
{
	u8 nbtg, tg, *tgdata;
	int rc, tgdata_len;

	/* Toggle the DEP polling */
	dev->poll_dep = 1;

	nbtg = resp->data[0];
	tg = resp->data[1];
	tgdata = &resp->data[2];
	tgdata_len = resp->len - 2;  /* nbtg + tg */

	if (nbtg) {
		rc = pn532_target_found(dev, tg, tgdata, tgdata_len);

		/* We must stop the poll after a valid target found */
		if (rc == 0) {
			pn532_poll_reset_mod_list(dev);
			return 0;
		}
	}

	return -EAGAIN;
}

static int pn532_poll_complete(struct pn532 *dev, void *arg,
			       struct sk_buff *resp)
{
	struct pn532_poll_modulations *cur_mod;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (IS_ERR(resp)) {
		rc = PTR_ERR(resp);

		nfc_err(&dev->spi->dev, "%s  Poll complete error %d\n",
			__func__, rc);

		if (rc == -ENOENT) {
			if (dev->poll_mod_count != 0)
				return rc;
			else
				goto stop_poll;
		} else if (rc < 0) {
			nfc_err(&dev->spi->dev,
				"Error %d when running poll\n", rc);
			goto stop_poll;
		}
	}

	cur_mod = dev->poll_mod_active[dev->poll_mod_curr];

	if (cur_mod->len == 0) { /* Target mode */
		del_timer(&dev->listen_timer);
		rc = pn532_init_target_complete(dev, resp);
		goto done;
	}

	/* Initiator mode */
	rc = pn532_start_poll_complete(dev, resp);
	if (!rc)
		goto done;

	if (!dev->poll_mod_count) {
		dev_dbg(&dev->spi->dev, "Polling has been stopped\n");
		goto done;
	}

	pn532_poll_next_mod(dev);
	/* Not target found, turn radio off */
	queue_work(dev->wq, &dev->rf_work);

done:
	dev_kfree_skb(resp);
	return rc;

stop_poll:
	nfc_err(&dev->spi->dev, "Polling operation has been stopped\n");

	pn532_poll_reset_mod_list(dev);
	dev->poll_protocols = 0;
	return rc;
}

static int pn532_poll_dep_complete(struct pn532 *dev, void *arg,
				   struct sk_buff *resp)
{
	struct pn532_cmd_jump_dep_response *rsp;
	struct nfc_target nfc_target;
	u8 target_gt_len;
	int rc;

	if (IS_ERR(resp))
		return PTR_ERR(resp);

	rsp = (struct pn532_cmd_jump_dep_response *)resp->data;

	rc = rsp->status & PN532_CMD_RET_MASK;
	if (rc != PN532_CMD_RET_SUCCESS) {
		/* Not target found, turn radio off */
		queue_work(dev->wq, &dev->rf_work);

		dev_kfree_skb(resp);
		return 0;
	}

	dev_dbg(&dev->spi->dev, "Creating new target");

	nfc_target.supported_protocols = NFC_PROTO_NFC_DEP_MASK;
	nfc_target.nfcid1_len = 10;
	memcpy(nfc_target.nfcid1, rsp->nfcid3t, nfc_target.nfcid1_len);
	rc = nfc_targets_found(dev->nfc_dev, &nfc_target, 1);
	if (rc)
		goto error;

	dev->tgt_available_prots = 0;
	dev->tgt_active_prot = NFC_PROTO_NFC_DEP;

	/* ATR_RES general bytes are located at offset 17 */
	target_gt_len = resp->len - 17;
	rc = nfc_set_remote_general_bytes(dev->nfc_dev,
					  rsp->gt, target_gt_len);
	if (!rc) {
		rc = nfc_dep_link_is_up(dev->nfc_dev,
					dev->nfc_dev->targets[0].idx,
					0, NFC_RF_INITIATOR);

		if (!rc)
			pn532_poll_reset_mod_list(dev);
	}
error:
	dev_kfree_skb(resp);
	return rc;
}

#define PASSIVE_DATA_LEN 5
static int pn532_poll_dep(struct nfc_dev *nfc_dev)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	struct sk_buff *skb;
	int rc, skb_len;
	u8 *next, nfcid3[NFC_NFCID3_MAXSIZE];
	u8 passive_data[PASSIVE_DATA_LEN] = {0x00, 0xff, 0xff, 0x00, 0x3};

	dev_dbg(&dev->spi->dev, "%s", __func__);

	if (!dev->gb) {
		dev->gb = nfc_get_local_general_bytes(nfc_dev, &dev->gb_len);

		if (!dev->gb || !dev->gb_len) {
			dev->poll_dep = 0;
			queue_work(dev->wq, &dev->rf_work);
		}
	}

	skb_len = 3 + dev->gb_len; /* ActPass + BR + Next */
	skb_len += PASSIVE_DATA_LEN;

	/* NFCID3 */
	skb_len += NFC_NFCID3_MAXSIZE;
	nfcid3[0] = 0x1;
	nfcid3[1] = 0xfe;
	get_random_bytes(nfcid3 + 2, 6);

	skb = pn532_alloc_skb(dev, skb_len);
	if (!skb)
		return -ENOMEM;

	*skb_put(skb, 1) = 0x01;  /* Active */
	*skb_put(skb, 1) = 0x02;  /* 424 kbps */

	next = skb_put(skb, 1);  /* Next */
	*next = 0;

	/* Copy passive data */
	memcpy(skb_put(skb, PASSIVE_DATA_LEN), passive_data, PASSIVE_DATA_LEN);
	*next |= 1;

	/* Copy NFCID3 (which is NFCID2 from SENSF_RES) */
	memcpy(skb_put(skb, NFC_NFCID3_MAXSIZE), nfcid3,
	       NFC_NFCID3_MAXSIZE);
	*next |= 2;

	memcpy(skb_put(skb, dev->gb_len), dev->gb, dev->gb_len);
	*next |= 4; /* We have some Gi */

	rc = pn532_send_cmd_async(dev, PN532_CMD_IN_JUMP_FOR_DEP, skb,
				  pn532_poll_dep_complete, NULL);

	if (rc < 0)
		dev_kfree_skb(skb);

	return rc;
}

static int pn532_send_poll_frame(struct pn532 *dev)
{
	struct pn532_poll_modulations *mod;
	struct sk_buff *skb;
	int rc;
	u8 cmd_code;

	mod = dev->poll_mod_active[dev->poll_mod_curr];

	dev_dbg(&dev->spi->dev, "mod len %d\n", mod->len);

	if (dev->poll_dep)  {
		dev->poll_dep = 0;
		return pn532_poll_dep(dev->nfc_dev);
	}

	if (mod->len == 0) {  /* Listen mode */
		cmd_code = PN532_CMD_TG_INIT_AS_TARGET;
		skb = pn532_alloc_poll_tg_frame(dev);
	} else {  /* Polling mode */
		cmd_code =  PN532_CMD_IN_LIST_PASSIVE_TARGET;
		skb = pn532_alloc_poll_in_frame(dev, mod);
	}

	if (!skb) {
		nfc_err(&dev->spi->dev, "Failed to allocate skb\n");
		return -ENOMEM;
	}

	rc = pn532_send_cmd_async(dev, cmd_code, skb, pn532_poll_complete,
				  NULL);
	if (rc < 0) {
		dev_kfree_skb(skb);
		nfc_err(&dev->spi->dev, "Polling loop error %d\n", rc);
	}

	return rc;
}

static void pn532_listen_mode_timer(unsigned long data)
{
	struct pn532 *dev = (struct pn532 *)data;

	dev_dbg(&dev->spi->dev, "Listen mode timeout\n");

	dev->cancel_listen = 1;

	pn532_poll_next_mod(dev);

	queue_delayed_work(dev->wq, &dev->poll_work,
			   msecs_to_jiffies(PN532_POLL_INTERVAL));
}

/* ===================================================================== */

static int pn532_set_configuration(struct pn532 *dev, u8 cfgitem, u8 *cfgdata,
								u8 cfgdata_len)
{
	struct sk_buff *skb;
	struct sk_buff *resp;
	int skb_len;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb_len = sizeof(cfgitem) + cfgdata_len; /* cfgitem + cfgdata */

	skb = pn532_alloc_skb(dev, skb_len);
	if (!skb)
		return -ENOMEM;

	*skb_put(skb, sizeof(cfgitem)) = cfgitem;
	memcpy(skb_put(skb, cfgdata_len), cfgdata, cfgdata_len);

	resp = pn532_send_cmd_sync(dev, PN532_CMD_RF_CONFIGURATION, skb);
	if (IS_ERR(resp))
		return PTR_ERR(resp);

	dev_dbg(&dev->spi->dev, "%s done.\n", __func__);
	dev_kfree_skb(resp);
	return 0;
}

static int pn532_get_firmware_version(struct pn532 *dev,
				      struct pn532_fw_version *fv)
{
	struct sk_buff *skb;
	struct sk_buff *resp;

	skb = pn532_alloc_skb(dev, 0);
	if (!skb)
		return -ENOMEM;

	resp = pn532_send_cmd_sync(dev, PN532_CMD_GET_FIRMWARE_VERSION, skb);
	if (IS_ERR(resp))
		return PTR_ERR(resp);

	fv->ic = resp->data[0];
	fv->ver = resp->data[1];
	fv->rev = resp->data[2];
	fv->support = resp->data[3];

	dev_kfree_skb(resp);
	dev_dbg(&dev->spi->dev, "%s done.\n", __func__);
	return 0;
}

static int pn532_rf_field(struct nfc_dev *nfc_dev, u8 rf)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	u8 rf_field = !!rf;
	int rc;

	rf_field |= PN532_CFGITEM_RF_FIELD_AUTO_RFCA;

	rc = pn532_set_configuration(dev, PN532_CFGITEM_RF_FIELD,
				     (u8 *)&rf_field, 1);
	if (rc) {
		nfc_err(&dev->spi->dev, "Error on setting RF field\n");
		return rc;
	}

	return rc;
}

static int pn532_in_dep_link_up_complete(struct pn532 *dev, void *arg,
					 struct sk_buff *resp)
{
	struct pn532_cmd_jump_dep_response *rsp;
	u8 target_gt_len;
	int rc;
	u8 active = *(u8 *)arg;

	kfree(arg);

	if (IS_ERR(resp))
		return PTR_ERR(resp);

	if (dev->tgt_available_prots &&
	    !(dev->tgt_available_prots & (1 << NFC_PROTO_NFC_DEP))) {
		nfc_err(&dev->spi->dev,
			"The target does not support DEP\n");
		rc =  -EINVAL;
		goto error;
	}

	rsp = (struct pn532_cmd_jump_dep_response *)resp->data;

	rc = rsp->status & PN532_CMD_RET_MASK;
	if (rc != PN532_CMD_RET_SUCCESS) {
		nfc_err(&dev->spi->dev,
			"Bringing DEP link up failed (error 0x%x)\n", rc);
		goto error;
	}

	if (!dev->tgt_available_prots) {
		struct nfc_target nfc_target;

		dev_dbg(&dev->spi->dev, "Creating new target\n");

		nfc_target.supported_protocols = NFC_PROTO_NFC_DEP_MASK;
		nfc_target.nfcid1_len = 10;
		memcpy(nfc_target.nfcid1, rsp->nfcid3t, nfc_target.nfcid1_len);
		rc = nfc_targets_found(dev->nfc_dev, &nfc_target, 1);
		if (rc)
			goto error;

		dev->tgt_available_prots = 0;
	}

	dev->tgt_active_prot = NFC_PROTO_NFC_DEP;

	/* ATR_RES general bytes are located at offset 17 */
	target_gt_len = resp->len - 17;
	rc = nfc_set_remote_general_bytes(dev->nfc_dev,
					  rsp->gt, target_gt_len);
	if (rc == 0)
		rc = nfc_dep_link_is_up(dev->nfc_dev,
					dev->nfc_dev->targets[0].idx,
					!active, NFC_RF_INITIATOR);

error:
	dev_kfree_skb(resp);
	return rc;
}

static int pn532_activate_target_nfcdep(struct pn532 *dev)
{
	struct pn532_cmd_activate_response *rsp;
	u16 gt_len;
	int rc;
	struct sk_buff *skb;
	struct sk_buff *resp;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	skb = pn532_alloc_skb(dev, sizeof(u8) * 2); /*TG + Next*/
	if (!skb)
		return -ENOMEM;

	*skb_put(skb, sizeof(u8)) = 1; /* TG */
	*skb_put(skb, sizeof(u8)) = 0; /* Next */

	resp = pn532_send_cmd_sync(dev, PN532_CMD_IN_ATR, skb);
	if (IS_ERR(resp))
		return PTR_ERR(resp);

	rsp = (struct pn532_cmd_activate_response *)resp->data;
	rc = rsp->status & PN532_CMD_RET_MASK;
	if (rc != PN532_CMD_RET_SUCCESS) {
		nfc_err(&dev->spi->dev,
			"Target activation failed (error 0x%x)\n", rc);
		dev_kfree_skb(resp);
		return -EIO;
	}

	/* ATR_RES general bytes are located at offset 16 */
	gt_len = resp->len - 16;
	rc = nfc_set_remote_general_bytes(dev->nfc_dev, rsp->gt, gt_len);

	dev_kfree_skb(resp);
	return rc;
}

/* Split the Tx skb into small chunks */
static int pn532_fill_fragment_skbs(struct pn532 *dev, struct sk_buff *skb)
{
	struct sk_buff *frag;
	int  frag_size;

	do {
		/* Remaining size */
		if (skb->len > PN532_CMD_DATAFRAME_MAXLEN)
			frag_size = PN532_CMD_DATAFRAME_MAXLEN;
		else
			frag_size = skb->len;

		/* Allocate and reserve */
		frag = pn532_alloc_skb(dev, frag_size);
		if (!frag) {
			skb_queue_purge(&dev->fragment_skb);
			break;
		}

		if (!dev->tgt_mode) {
			/* Reserve the TG/MI byte */
			skb_reserve(frag, 1);

			/* MI + TG */
			if (frag_size  == PN532_CMD_DATAFRAME_MAXLEN)
				*skb_push(frag, sizeof(u8)) =
							(PN532_CMD_MI_MASK | 1);
			else
				*skb_push(frag, sizeof(u8)) =  1; /* TG */
		}

		memcpy(skb_put(frag, frag_size), skb->data, frag_size);

		/* Reduce the size of incoming buffer */
		skb_pull(skb, frag_size);

		/* Add this to skb_queue */
		skb_queue_tail(&dev->fragment_skb, frag);

	} while (skb->len > 0);

	dev_kfree_skb(skb);

	return skb_queue_len(&dev->fragment_skb);
}

/* ============================== NFC OPS ========================== */

static int pn532_dev_up(struct nfc_dev *nfc_dev)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	return pn532_rf_field(nfc_dev, 1);
}

static int pn532_dev_down(struct nfc_dev *nfc_dev)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	return pn532_rf_field(nfc_dev, 0);
}

static int pn532_dep_link_up(struct nfc_dev *nfc_dev, struct nfc_target *target,
			     u8 comm_mode, u8 * gb, size_t gb_len)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	struct sk_buff *skb;
	int rc, skb_len;
	u8 *next, *arg, nfcid3[NFC_NFCID3_MAXSIZE];
	u8 passive_data[PASSIVE_DATA_LEN] = {0x00, 0xff, 0xff, 0x00, 0x3};

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (dev->poll_mod_count) {
		nfc_err(&dev->spi->dev,
			"Cannot bring the DEP link up while polling\n");
		return -EBUSY;
	}

	if (dev->tgt_active_prot) {
		nfc_err(&dev->spi->dev,
			"There is already an active target\n");
		return -EBUSY;
	}

	skb_len = 3 + gb_len; /* ActPass + BR + Next */
	skb_len += PASSIVE_DATA_LEN;

	/* NFCID3 */
	skb_len += NFC_NFCID3_MAXSIZE;
	if (target && !target->nfcid2_len) {
		nfcid3[0] = 0x1;
		nfcid3[1] = 0xfe;
		get_random_bytes(nfcid3 + 2, 6);
	}

	skb = pn532_alloc_skb(dev, skb_len);
	if (!skb)
		return -ENOMEM;

	*skb_put(skb, 1) = !comm_mode;  /* ActPass */
	*skb_put(skb, 1) = 0x02;  /* 424 kbps */

	next = skb_put(skb, 1);  /* Next */
	*next = 0;

	/* Copy passive data */
	memcpy(skb_put(skb, PASSIVE_DATA_LEN), passive_data, PASSIVE_DATA_LEN);
	*next |= 1;

	/* Copy NFCID3 (which is NFCID2 from SENSF_RES) */
	if (target && target->nfcid2_len)
		memcpy(skb_put(skb, NFC_NFCID3_MAXSIZE), target->nfcid2,
		       target->nfcid2_len);
	else
		memcpy(skb_put(skb, NFC_NFCID3_MAXSIZE), nfcid3,
		       NFC_NFCID3_MAXSIZE);
	*next |= 2;

	if (gb != NULL && gb_len > 0) {
		memcpy(skb_put(skb, gb_len), gb, gb_len);
		*next |= 4; /* We have some Gi */
	} else {
		*next = 0;
	}

	arg = kmalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg) {
		dev_kfree_skb(skb);
		return -ENOMEM;
	}

	*arg = !comm_mode;

	pn532_rf_field(dev->nfc_dev, 0);

	rc = pn532_send_cmd_async(dev, PN532_CMD_IN_JUMP_FOR_DEP, skb,
				  pn532_in_dep_link_up_complete, arg);

	if (rc < 0) {
		dev_kfree_skb(skb);
		kfree(arg);
	}

	return rc;
}

static int pn532_dep_link_down(struct nfc_dev *nfc_dev)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	pn532_poll_reset_mod_list(dev);

	if (dev->tgt_mode || dev->tgt_active_prot)
		pn532_cmd_abort(dev);

	dev->tgt_active_prot = 0;
	dev->tgt_mode = 0;

	skb_queue_purge(&dev->resp_q);

	return 0;

}

static int pn532_start_poll(struct nfc_dev *nfc_dev,
			    u32 im_protocols, u32 tm_protocols)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	struct pn532_poll_modulations *cur_mod;
	u8 rand_mod;
	int rc;

	dev_dbg(&dev->spi->dev,
		"%s: im protocols 0x%x tm protocols 0x%x\n",
		__func__, im_protocols, tm_protocols);

	if (dev->tgt_active_prot) {
		nfc_err(&dev->spi->dev,
			"Cannot poll with a target already activated\n");
		return -EBUSY;
	}

	if (dev->tgt_mode) {
		nfc_err(&dev->spi->dev,
			"Cannot poll while already being activated\n");
		return -EBUSY;
	}

	if (tm_protocols) {
		dev->gb = nfc_get_local_general_bytes(nfc_dev, &dev->gb_len);
		if (dev->gb == NULL)
			tm_protocols = 0;
	}

	pn532_poll_create_mod_list(dev, im_protocols, tm_protocols);
	dev->poll_protocols = im_protocols;
	dev->listen_protocols = tm_protocols;

	/* Do not always start polling from the same modulation */
	get_random_bytes(&rand_mod, sizeof(rand_mod));
	rand_mod %= dev->poll_mod_count;
	dev->poll_mod_curr = rand_mod;

	cur_mod = dev->poll_mod_active[dev->poll_mod_curr];

	rc = pn532_send_poll_frame(dev);

	/* Start listen timer */
	if (!rc && cur_mod->len == 0 && dev->poll_mod_count > 1)
		mod_timer(&dev->listen_timer, jiffies + PN532_LISTEN_TIME * HZ);

	return rc;
}

static void pn532_stop_poll(struct nfc_dev *nfc_dev)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);

	del_timer(&dev->listen_timer);

	if (!dev->poll_mod_count) {
		dev_dbg(&dev->spi->dev,
			"Polling operation was not running\n");
		return;
	}

	pn532_cmd_abort(dev);
	flush_delayed_work(&dev->poll_work);
	pn532_poll_reset_mod_list(dev);
}

static int pn532_activate_target(struct nfc_dev *nfc_dev,
				 struct nfc_target *target, u32 protocol)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	int rc;

	dev_dbg(&dev->spi->dev, "%s: protocol=%u\n", __func__, protocol);

	if (dev->poll_mod_count) {
		nfc_err(&dev->spi->dev,
			"Cannot activate while polling\n");
		return -EBUSY;
	}

	if (dev->tgt_active_prot) {
		nfc_err(&dev->spi->dev,
			"There is already an active target\n");
		return -EBUSY;
	}

	if (!dev->tgt_available_prots) {
		nfc_err(&dev->spi->dev,
			"There is no available target to activate\n");
		return -EINVAL;
	}

	if (!(dev->tgt_available_prots & (1 << protocol))) {
		nfc_err(&dev->spi->dev,
			"Target doesn't support requested proto %u\n",
			protocol);
		return -EINVAL;
	}

	if (protocol == NFC_PROTO_NFC_DEP) {
		rc = pn532_activate_target_nfcdep(dev);
		if (rc) {
			nfc_err(&dev->spi->dev,
				"Activating target with DEP failed %d\n", rc);
			return rc;
		}
	}

	dev->tgt_active_prot = protocol;
	dev->tgt_available_prots = 0;

	return 0;
}

static void pn532_deactivate_target(struct nfc_dev *nfc_dev,
				    struct nfc_target *target)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	struct sk_buff *skb;
	struct sk_buff *resp;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (!dev->tgt_active_prot) {
		nfc_err(&dev->spi->dev, "There is no active target\n");
		return;
	}

	dev->tgt_active_prot = 0;
	skb_queue_purge(&dev->resp_q);

	skb = pn532_alloc_skb(dev, sizeof(u8));
	if (!skb)
		return;

	*skb_put(skb, 1) = 1; /* TG*/

	resp = pn532_send_cmd_sync(dev, PN532_CMD_IN_RELEASE, skb);
	if (IS_ERR(resp))
		return;

	rc = resp->data[0] & PN532_CMD_RET_MASK;
	if (rc != PN532_CMD_RET_SUCCESS)
		nfc_err(&dev->spi->dev,
			"Error 0x%x when releasing the target\n", rc);

	dev_kfree_skb(resp);
	return;
}

static int pn532_transceive(struct nfc_dev *nfc_dev,
			    struct nfc_target *target, struct sk_buff *skb,
			    data_exchange_cb_t cb, void *cb_context)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	struct pn532_data_exchange_arg *arg = NULL;
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	if (!dev->tgt_active_prot) {
		nfc_err(&dev->spi->dev,
			"Can't exchange data if there is no active target\n");
		rc = -EINVAL;
		goto error;
	}

	arg = kmalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg) {
		rc = -ENOMEM;
		goto error;
	}

	arg->cb = cb;
	arg->cb_context = cb_context;

	/* jumbo frame ? */
	if (skb->len > PN532_CMD_DATAEXCH_DATA_MAXLEN) {
		rc = pn532_fill_fragment_skbs(dev, skb);
		if (rc <= 0)
			goto error;

		skb = skb_dequeue(&dev->fragment_skb);
		if (!skb) {
			rc = -EIO;
			goto error;
		}
	} else {
		*skb_push(skb, sizeof(u8)) =  1; /* TG */
	}

	rc = pn532_send_cmd_async(dev, PN532_CMD_IN_DATA_EXCHANGE,
				   skb, pn532_data_exchange_complete,
				   arg);


	if (rc < 0) /* rc from send_async */
		goto error;

	return 0;

error:
	kfree(arg);
	dev_kfree_skb(skb);
	return rc;
}

static int pn532_tm_send(struct nfc_dev *nfc_dev, struct sk_buff *skb)
{
	struct pn532 *dev = nfc_get_drvdata(nfc_dev);
	int rc;

	dev_dbg(&dev->spi->dev, "%s\n", __func__);

	/* let's split in multiple chunks if size's too big */
	if (skb->len > PN532_CMD_DATAEXCH_DATA_MAXLEN) {
		rc = pn532_fill_fragment_skbs(dev, skb);
		if (rc <= 0)
			goto error;

		/* get the first skb */
		skb = skb_dequeue(&dev->fragment_skb);
		if (!skb) {
			rc = -EIO;
			goto error;
		}

		rc = pn532_send_cmd_async(dev, PN532_CMD_TG_SET_META_DATA, skb,
						pn532_tm_send_complete, NULL);
	} else {
		/* Send th skb */
		rc = pn532_send_cmd_async(dev, PN532_CMD_TG_SET_DATA, skb,
						pn532_tm_send_complete, NULL);
	}

error:
	if (rc < 0) {
		dev_kfree_skb(skb);
		skb_queue_purge(&dev->fragment_skb);
	}

	return rc;
}

static struct nfc_ops pn532_nfc_ops = {
	.dev_up = pn532_dev_up,
	.dev_down = pn532_dev_down,
	.dep_link_up = pn532_dep_link_up,
	.dep_link_down = pn532_dep_link_down,
	.start_poll = pn532_start_poll,
	.stop_poll = pn532_stop_poll,
	.activate_target = pn532_activate_target,
	.deactivate_target = pn532_deactivate_target,
	.im_transceive = pn532_transceive,
	.tm_send = pn532_tm_send,
};

/* ==================================================================== */
static int pn532_setup(struct pn532 *dev)
{
	struct pn532_config_max_retries max_retries;
	struct pn532_config_timing timing;
	int rc;

	max_retries.mx_rty_atr = 0x2;
	max_retries.mx_rty_psl = 0x1;
	max_retries.mx_rty_passive_act = PN532_CONFIG_MAX_RETRIES_NO_RETRY;

	timing.rfu = PN532_CONFIG_TIMING_102;
	timing.atr_res_timeout = PN532_CONFIG_TIMING_102;
	timing.dep_timeout = PN532_CONFIG_TIMING_204;

	rc = pn532_set_configuration(dev, PN532_CFGITEM_MAX_RETRIES,
				     (u8 *) & max_retries, sizeof(max_retries));
	if (rc) {
		nfc_err(&dev->spi->dev,
			"Error on setting MAX_RETRIES config\n");
		return rc;
	}

	rc = pn532_set_configuration(dev, PN532_CFGITEM_TIMING,
				     (u8 *) & timing, sizeof(timing));
	if (rc) {
		nfc_err(&dev->spi->dev, "Error on setting RF timings\n");
		return rc;
	}

	return 0;
}


static int pn532_probe(struct spi_device *spi)
{
	struct pn532_fw_version fw_ver;
	struct pn532 *dev;
	int rc = -ENOMEM;

	dev_dbg(&spi->dev, "%s\n", __func__);
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->spi = spi;

	spi_set_drvdata(spi, dev);

	/* PN532 support only LSB mode */
	spi->mode |= SPI_LSB_FIRST;
	dev->lsb_support = true;
	if (spi_setup(spi)){
		dev_dbg(&spi->dev, "SPI master is not supported LSB mode.\n");
		dev->lsb_support = false;
	}

	dev->tx_headroom = PN532_MAX_FRAME_HEADER_LEN +
			   PN532_CMD_SPI_FRAME_HEAD_LEN +
			   PN532_CMD_DATAEXCH_HEAD_LEN;
	dev->tx_tailroom = PN532_FRAME_TAIL_LEN;

	dev_dbg(&spi->dev, "headroom %d, tailroom %d\n", dev->tx_headroom,
			dev->tx_tailroom);

	spin_lock_init(&dev->cmd_lock);
	dev->cmd = NULL;

	skb_queue_head_init(&dev->resp_q);
	skb_queue_head_init(&dev->fragment_skb);

	INIT_WORK(&dev->cmd_work, pn532_wq_cmd);
	INIT_DELAYED_WORK(&dev->spi_status_work, pn532_status_check);
	INIT_WORK(&dev->ack_work, pn532_read_ack);
	INIT_WORK(&dev->response_work, pn532_read_response);
	INIT_WORK(&dev->mi_rx_work, pn532_wq_mi_recv);
	INIT_WORK(&dev->mi_tx_work, pn532_wq_mi_send);
	INIT_WORK(&dev->tg_work, pn532_wq_tg_get_data);
	INIT_WORK(&dev->mi_tm_rx_work, pn532_wq_tm_mi_recv);
	INIT_WORK(&dev->mi_tm_tx_work, pn532_wq_tm_mi_send);
	INIT_WORK(&dev->rf_work, pn532_wq_rf);
	INIT_DELAYED_WORK(&dev->poll_work, pn532_wq_poll);
	dev->wq = alloc_ordered_workqueue("pn532_wq", 0);
	if (!dev->wq)
		goto error;

	dev->cmd_wq = alloc_ordered_workqueue("pn532_cmd_wq", 0);
	if (!dev->cmd_wq)
		goto destroy_wq;

	dev->tr_wq = alloc_ordered_workqueue("pn532_tr_wq", 0);
	if (!dev->tr_wq)
		goto destroy_cmd_wq;

	init_timer(&dev->listen_timer);
	dev->listen_timer.data = (unsigned long) dev;
	dev->listen_timer.function = pn532_listen_mode_timer;

	cmd_queue_head_init(&dev->cmd_queue);

	memset(&fw_ver, 0, sizeof(fw_ver));
	rc = pn532_get_firmware_version(dev, &fw_ver);
	if (rc < 0)
		goto destroy_tr_wq;

	nfc_info(&dev->spi->dev,
		 "NXP PN5%02X firmware ver %d.%d now attached\n",
		 fw_ver.ic, fw_ver.ver, fw_ver.rev);

	dev->nfc_dev = nfc_allocate_device(&pn532_nfc_ops, PN532_ALL_PROTOCOLS,
					   dev->tx_headroom,
					   dev->tx_tailroom);
	if (!dev->nfc_dev) {
		rc = -ENOMEM;
		goto destroy_tr_wq;
	}

	dev_dbg(&spi->dev, "%s\n", __func__);
	nfc_set_parent_dev(dev->nfc_dev, &spi->dev);
	nfc_set_drvdata(dev->nfc_dev, dev);

	rc = nfc_register_device(dev->nfc_dev);
	if (rc)
		goto free_nfc_dev;

	rc = pn532_setup(dev);
	if (rc)
		goto unregister_nfc_dev;

	return 0;

 unregister_nfc_dev:
	nfc_unregister_device(dev->nfc_dev);

 free_nfc_dev:
	nfc_free_device(dev->nfc_dev);

 destroy_tr_wq:
	destroy_workqueue(dev->tr_wq);

 destroy_cmd_wq:
	destroy_workqueue(dev->cmd_wq);

 destroy_wq:
	destroy_workqueue(dev->wq);

 error:
	kfree(dev);
	return rc;
}

static int pn532_remove(struct spi_device *spi)
{
	struct pn532 *dev;

	dev = spi_get_drvdata(spi);
	spi_set_drvdata(spi, NULL);

	nfc_unregister_device(dev->nfc_dev);
	nfc_free_device(dev->nfc_dev);

	flush_delayed_work(&dev->poll_work);
	destroy_workqueue(dev->wq);

	flush_delayed_work(&dev->spi_status_work);
	destroy_workqueue(dev->tr_wq);

	destroy_workqueue(dev->cmd_wq);

	del_timer(&dev->listen_timer);

	cmd_queue_purge(&dev->cmd_queue);

	if (dev->cmd != NULL) {
		dev_kfree_skb(dev->cmd->req);
		kfree(dev->cmd);
	}

	kfree(dev);

	nfc_info(&spi->dev, "NXP PN532 NFC SPI device disconnected\n");

	return 0;
}

static const struct of_device_id dt_ids[] = {
	{.compatible = "nxp,pn533"},
	{},
};

MODULE_DEVICE_TABLE(of, dt_ids);

static struct spi_driver pn532_spi_driver = {
	.driver = {
		   .name = "pn532_spi",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(dt_ids),
		   },
	.probe = pn532_probe,
	.remove = pn532_remove,
};

module_spi_driver(pn532_spi_driver);

MODULE_AUTHOR("Dzmitry Yatsushkevich <dmitry.yatsushkevich@gmail.com>");
MODULE_DESCRIPTION("PN532 SPI driver ver " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
