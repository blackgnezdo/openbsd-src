/* $OpenBSD: bwfmreg.h,v 1.6 2017/10/18 15:45:38 patrick Exp $ */
/*
 * Copyright (c) 2010-2016 Broadcom Corporation
 * Copyright (c) 2016,2017 Patrick Wildt <patrick@blueri.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* SDIO registers */
#define BWFM_SDIO_FUNC1_SBADDRLOW		0x1000A
#define BWFM_SDIO_FUNC1_SBADDRMID		0x1000B
#define BWFM_SDIO_FUNC1_SBADDRHIGH		0x1000C
#define BWFM_SDIO_FUNC1_CHIPCLKCSR		0x1000E
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_FORCE_ALP			0x01
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HT			0x02
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_FORCE_ILP			0x04
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL_REQ		0x08
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_HT_AVAIL_REQ		0x10
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HW_CLKREQ_OFF		0x20
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL			0x40
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_HT_AVAIL			0x80
#define  BWFM_SDIO_FUNC1_CHIPCLKCSR_CSR_MASK			0x1F
#define BWFM_SDIO_FUNC1_SDIOPULLUP		0x1000F

#define BWFM_SDIO_SB_OFT_ADDR_MASK		0x07FFF
#define BWFM_SDIO_SB_ACCESS_2_4B_FLAG		0x08000

/* Chip registers */
#define BWFM_CHIP_BASE				0x18000000
#define BWFM_CHIP_REG_CHIPID			0x00000000
#define  BWFM_CHIP_CHIPID_ID(x)				(((x) >> 0) & 0xffff)
#define  BWFM_CHIP_CHIPID_REV(x)			(((x) >> 16) & 0xf)
#define  BWFM_CHIP_CHIPID_PKG(x)			(((x) >> 20) & 0xf)
#define  BWFM_CHIP_CHIPID_CC(x)				(((x) >> 24) & 0xf)
#define  BWFM_CHIP_CHIPID_TYPE(x)			(((x) >> 28) & 0xf)
#define  BWFM_CHIP_CHIPID_TYPE_SOCI_SB			0
#define  BWFM_CHIP_CHIPID_TYPE_SOCI_AI			1
#define BWFM_CHIP_REG_CAPABILITIES		0x00000004
#define  BWFM_CHIP_REG_CAPABILITIES_PMU			0x10000000
#define BWFM_CHIP_REG_CAPABILITIES_EXT		0x000000AC
#define  BWFM_CHIP_REG_CAPABILITIES_EXT_AOB_PRESENT	0x00000040
#define BWFM_CHIP_REG_EROMPTR			0x000000FC
#define BWFM_CHIP_REG_PMUCONTROL		0x00000600
#define  BWFM_CHIP_REG_PMUCONTROL_RES_MASK		0x00006000
#define  BWFM_CHIP_REG_PMUCONTROL_RES_SHIFT		13
#define  BWFM_CHIP_REG_PMUCONTROL_RES_RELOAD		0x2
#define BWFM_CHIP_REG_PMUCAPABILITIES		0x00000604
#define  BWFM_CHIP_REG_PMUCAPABILITIES_REV_MASK		0x000000ff

/* Agent registers */
#define BWFM_AGENT_IOCTL			0x0408
#define  BWFM_AGENT_IOCTL_CLK				0x0001
#define  BWFM_AGENT_IOCTL_FGC				0x0002
#define  BWFM_AGENT_IOCTL_CORE_BITS			0x3FFC
#define  BWFM_AGENT_IOCTL_PME_EN			0x4000
#define  BWFM_AGENT_IOCTL_BIST_EN			0x8000
#define BWFM_AGENT_RESET_CTL			0x0800
#define  BWFM_AGENT_RESET_CTL_RESET			0x0001

/* Agent Core-IDs */
#define BWFM_AGENT_CORE_CHIPCOMMON		0x800
#define BWFM_AGENT_INTERNAL_MEM			0x80E
#define BWFM_AGENT_CORE_80211			0x812
#define BWFM_AGENT_CORE_PMU			0x827
#define BWFM_AGENT_CORE_SDIO_DEV		0x829
#define BWFM_AGENT_CORE_ARM_CM3			0x82A
#define BWFM_AGENT_CORE_ARM_CR4			0x83E
#define BWFM_AGENT_CORE_ARM_CA7			0x847

/* Specific Core Bits */
#define BWFM_AGENT_ARMCR4_IOCTL_CPUHALT		0x0020
#define BWFM_AGENT_D11_IOCTL_PHYCLOCKEN		0x0004
#define BWFM_AGENT_D11_IOCTL_PHYRESET		0x0008

/* SOCRAM registers */
#define BWFM_SOCRAM_BANKIDX			0x0010
#define BWFM_SOCRAM_BANKPDA			0x0044

/* SDPCMD registers */
#define BWFM_SDPCMD_INTSTATUS			0x0020

/* DMP descriptor */
#define BWFM_DMP_DESC_MASK			0x0000000F
#define BWFM_DMP_DESC_EMPTY			0x00000000
#define BWFM_DMP_DESC_VALID			0x00000001
#define BWFM_DMP_DESC_COMPONENT			0x00000001
#define BWFM_DMP_DESC_MASTER_PORT		0x00000003
#define BWFM_DMP_DESC_ADDRESS			0x00000005
#define BWFM_DMP_DESC_ADDRSIZE_GT32		0x00000008
#define BWFM_DMP_DESC_EOT			0x0000000F
#define BWFM_DMP_COMP_DESIGNER			0xFFF00000
#define BWFM_DMP_COMP_DESIGNER_S		20
#define BWFM_DMP_COMP_PARTNUM			0x000FFF00
#define BWFM_DMP_COMP_PARTNUM_S			8
#define BWFM_DMP_COMP_CLASS			0x000000F0
#define BWFM_DMP_COMP_CLASS_S			4
#define BWFM_DMP_COMP_REVISION			0xFF000000
#define BWFM_DMP_COMP_REVISION_S		24
#define BWFM_DMP_COMP_NUM_SWRAP			0x00F80000
#define BWFM_DMP_COMP_NUM_SWRAP_S		19
#define BWFM_DMP_COMP_NUM_MWRAP			0x0007C000
#define BWFM_DMP_COMP_NUM_MWRAP_S		14
#define BWFM_DMP_COMP_NUM_SPORT			0x00003E00
#define BWFM_DMP_COMP_NUM_SPORT_S		9
#define BWFM_DMP_COMP_NUM_MPORT			0x000001F0
#define BWFM_DMP_COMP_NUM_MPORT_S		4
#define BWFM_DMP_MASTER_PORT_UID		0x0000FF00
#define BWFM_DMP_MASTER_PORT_UID_S		8
#define BWFM_DMP_MASTER_PORT_NUM		0x000000F0
#define BWFM_DMP_MASTER_PORT_NUM_S		4
#define BWFM_DMP_SLAVE_ADDR_BASE		0xFFFFF000
#define BWFM_DMP_SLAVE_ADDR_BASE_S		12
#define BWFM_DMP_SLAVE_PORT_NUM			0x00000F00
#define BWFM_DMP_SLAVE_PORT_NUM_S		8
#define BWFM_DMP_SLAVE_TYPE			0x000000C0
#define BWFM_DMP_SLAVE_TYPE_S			6
#define  BWFM_DMP_SLAVE_TYPE_SLAVE		0
#define  BWFM_DMP_SLAVE_TYPE_BRIDGE		1
#define  BWFM_DMP_SLAVE_TYPE_SWRAP		2
#define  BWFM_DMP_SLAVE_TYPE_MWRAP		3
#define BWFM_DMP_SLAVE_SIZE_TYPE		0x00000030
#define BWFM_DMP_SLAVE_SIZE_TYPE_S		4
#define  BWFM_DMP_SLAVE_SIZE_4K			0
#define  BWFM_DMP_SLAVE_SIZE_8K			1
#define  BWFM_DMP_SLAVE_SIZE_16K		2
#define  BWFM_DMP_SLAVE_SIZE_DESC		3

/* Security Parameters */
#define BWFM_AUTH_OPEN				0
#define BWFM_AUTH_SHARED_KEY			1
#define BWFM_AUTH_AUTO				2
#define BWFM_MFP_NONE				0
#define BWFM_MFP_CAPABLE			1
#define BWFM_MFP_REQUIRED			2
#define BWFM_WPA_AUTH_DISABLED			(0 << 0)
#define BWFM_WPA_AUTH_NONE			(1 << 0)
#define BWFM_WPA_AUTH_WPA_UNSPECIFIED		(1 << 1)
#define BWFM_WPA_AUTH_WPA_PSK			(1 << 2)
#define BWFM_WPA_AUTH_WPA2_UNSPECIFIED		(1 << 6)
#define BWFM_WPA_AUTH_WPA2_PSK			(1 << 7)
#define BWFM_WPA_AUTH_WPA2_1X_SHA256		(1 << 12)
#define BWFM_WPA_AUTH_WPA2_PSK_SHA256		(1 << 15)
#define BWFM_WSEC_NONE				(0 << 0)
#define BWFM_WSEC_WEP				(1 << 0)
#define BWFM_WSEC_TKIP				(1 << 1)
#define BWFM_WSEC_AES				(1 << 2)

/* Channel Parameters */
#define BWFM_BAND_AUTO				0
#define BWFM_BAND_5G				1
#define BWFM_BAND_2G				2
#define BWFM_BAND_ALL				3

/* DCMD commands */
#define BWFM_C_GET_VERSION			1
#define BWFM_C_UP				2
#define BWFM_C_DOWN				3
#define BWFM_C_SET_PROMISC			10
#define BWFM_C_GET_RATE				12
#define BWFM_C_GET_INFRA			19
#define BWFM_C_SET_INFRA			20
#define BWFM_C_GET_AUTH				21
#define BWFM_C_SET_AUTH				22
#define BWFM_C_GET_BSSID			23
#define BWFM_C_GET_SSID				25
#define BWFM_C_SET_SSID				26
#define BWFM_C_TERMINATED			28
#define BWFM_C_GET_CHANNEL			29
#define BWFM_C_SET_CHANNEL			30
#define BWFM_C_GET_SRL				31
#define BWFM_C_SET_SRL				32
#define BWFM_C_GET_LRL				33
#define BWFM_C_SET_LRL				34
#define BWFM_C_GET_RADIO			37
#define BWFM_C_SET_RADIO			38
#define BWFM_C_GET_PHYTYPE			39
#define BWFM_C_SET_KEY				45
#define BWFM_C_GET_REGULATORY			46
#define BWFM_C_SET_REGULATORY			47
#define BWFM_C_SET_PASSIVE_SCAN			49
#define BWFM_C_SCAN				50
#define BWFM_C_SCAN_RESULTS			51
#define BWFM_C_DISASSOC				52
#define BWFM_C_REASSOC				53
#define BWFM_C_SET_ROAM_TRIGGER			55
#define BWFM_C_SET_ROAM_DELTA			57
#define BWFM_C_GET_BCNPRD			75
#define BWFM_C_SET_BCNPRD			76
#define BWFM_C_GET_DTIMPRD			77
#define BWFM_C_SET_DTIMPRD			78
#define BWFM_C_SET_COUNTRY			84
#define BWFM_C_GET_PM				85
#define BWFM_C_SET_PM				86
#define BWFM_C_GET_REVINFO			98
#define BWFM_C_GET_CURR_RATESET			114
#define BWFM_C_GET_AP				117
#define BWFM_C_SET_AP				118
#define BWFM_C_SET_SCB_AUTHORIZE		121
#define BWFM_C_SET_SCB_DEAUTHORIZE		122
#define BWFM_C_GET_RSSI				127
#define BWFM_C_GET_WSEC				133
#define BWFM_C_SET_WSEC				134
#define BWFM_C_GET_PHY_NOISE			135
#define BWFM_C_GET_BSS_INFO			136
#define BWFM_C_GET_GET_PKTCNTS			137
#define BWFM_C_GET_BANDLIST			140
#define BWFM_C_SET_SCB_TIMEOUT			158
#define BWFM_C_GET_ASSOCLIST			159
#define BWFM_C_GET_PHYLIST			180
#define BWFM_C_SET_SCAN_CHANNEL_TIME		185
#define BWFM_C_SET_SCAN_UNASSOC_TIME		187
#define BWFM_C_SCB_DEAUTHENTICATE_FOR_REASON	201
#define BWFM_C_SET_ASSOC_PREFER			205
#define BWFM_C_GET_VALID_CHANNELS		217
#define BWFM_C_GET_KEY_PRIMARY			235
#define BWFM_C_SET_KEY_PRIMARY			236
#define BWFM_C_SET_SCAN_PASSIVE_TIME		258
#define BWFM_C_GET_VAR				262
#define BWFM_C_SET_VAR				263
#define BWFM_C_SET_WSEC_PMK			268

struct bwfm_proto_bcdc_dcmd {
	struct {
		uint32_t cmd;
		uint32_t len;
		uint32_t flags;
#define BWFM_BCDC_DCMD_ERROR		(1 << 0)
#define BWFM_BCDC_DCMD_GET		(0 << 1)
#define BWFM_BCDC_DCMD_SET		(1 << 1)
#define BWFM_BCDC_DCMD_IF_GET(x)	(((x) >> 12) & 0xf)
#define BWFM_BCDC_DCMD_IF_SET(x)	(((x) & 0xf) << 12)
#define BWFM_BCDC_DCMD_ID_GET(x)	(((x) >> 16) & 0xffff)
#define BWFM_BCDC_DCMD_ID_SET(x)	(((x) & 0xffff) << 16)
		uint32_t status;
	} hdr;
	char buf[8192];
};

struct bwfm_proto_bcdc_hdr {
	uint8_t flags;
#define BWFM_BCDC_FLAG_PROTO_VER	2
#define BWFM_BCDC_FLAG_VER(x)		(((x) & 0xf) << 4)
#define BWFM_BCDC_FLAG_SUM_GOOD		(1 << 2) /* rx */
#define BWFM_BCDC_FLAG_SUM_NEEDED	(1 << 3) /* tx */
	uint8_t priority;
#define BWFM_BCDC_PRIORITY_MASK		0x7
	uint8_t flags2;
#define BWFM_BCDC_FLAG2_IF_MASK		0xf
	uint8_t data_offset;
};

#define BWFM_MCSSET_LEN				16
#define BWFM_MAX_SSID_LEN			32
struct bwfm_bss_info {
	uint32_t version;
	uint32_t length;
	uint8_t bssid[ETHER_ADDR_LEN];
	uint16_t beacon_period;
	uint16_t capability;
	uint8_t ssid_len;
	uint8_t ssid[BWFM_MAX_SSID_LEN];
	uint32_t nrates;
	uint8_t rates[16];
	uint16_t chanspec;
	uint16_t atim_window;
	uint8_t dtim_period;
	uint16_t rssi;
	uint8_t phy_noise;
	uint8_t n_cap;
	uint32_t nbss_cap;
	uint8_t ctl_ch;
	uint32_t reserved32[1];
	uint8_t flags;
	uint8_t reserved[3];
	uint8_t basic_mcs[BWFM_MCSSET_LEN];
	uint16_t ie_offset;
	uint32_t ie_length;
	uint16_t snr;
};

struct bwfm_ssid {
	uint32_t len;
	uint8_t ssid[BWFM_MAX_SSID_LEN];
};

struct bwfm_scan_params {
	struct bwfm_ssid ssid;
	uint8_t bssid[ETHER_ADDR_LEN];
	uint8_t bss_type;
#define DOT11_BSSTYPE_ANY		2
	uint8_t scan_type;
	uint32_t nprobes;
	uint32_t active_time;
	uint32_t passive_time;
	uint32_t home_time;
	uint32_t channel_num;
	uint16_t channel_list[];
};

struct bwfm_scan_results {
	uint32_t buflen;
	uint32_t version;
	uint32_t count;
	struct bwfm_bss_info bss_info[];
};

struct bwfm_escan_params {
	uint32_t version;
#define BWFM_ESCAN_REQ_VERSION		1
	uint16_t action;
#define WL_ESCAN_ACTION_START		1
#define WL_ESCAN_ACTION_CONTINUE	2
#define WL_ESCAN_ACTION_ABORT		3
	uint16_t sync_id;
	struct bwfm_scan_params scan_params;
};

struct bwfm_escan_results {
	uint32_t buflen;
	uint32_t version;
	uint16_t sync_id;
	uint16_t bss_count;
	struct bwfm_bss_info bss_info[];
};

struct bwfm_assoc_params {
	uint8_t bssid[ETHER_ADDR_LEN];
	uint32_t chanspec_num;
	uint16_t chanspec_list[];
};

struct bwfm_join_pref_params {
	uint8_t type;
#define BWFM_JOIN_PREF_RSSI		1
#define BWFM_JOIN_PREF_WPA		2
#define BWFM_JOIN_PREF_BAND		3
#define BWFM_JOIN_PREF_RSSI_DELTA	4
	uint8_t len;
	uint8_t rssi_gain;
#define BWFM_JOIN_PREF_RSSI_BOOST	8
	uint8_t band;
#define BWFM_JOIN_PREF_BAND_AUTO	0
#define BWFM_JOIN_PREF_BAND_5G		1
#define BWFM_JOIN_PREF_BAND_2G		2
#define BWFM_JOIN_PREF_BAND_ALL		3
};

struct bwfm_join_params {
	struct bwfm_ssid ssid;
	struct bwfm_assoc_params assoc;
};

struct bwfm_join_scan_params {
	uint8_t scan_type;
	uint32_t nprobes;
	uint32_t active_time;
	uint32_t passive_time;
	uint32_t home_time;
};

struct bwfm_ext_join_params {
	struct bwfm_ssid ssid;
	struct bwfm_join_scan_params scan;
	struct bwfm_assoc_params assoc;
};

struct bwfm_wsec_pmk {
	uint16_t key_len;
#define BWFM_WSEC_MAX_PSK_LEN		32
	uint16_t flags;
#define BWFM_WSEC_PASSPHRASE		(1 << 0)
	uint8_t key[2 * BWFM_WSEC_MAX_PSK_LEN + 1];
};

/* Event handling */
enum bwfm_fweh_event_code {
	BWFM_E_SET_SSID = 0,
	BWFM_E_JOIN = 1,
	BWFM_E_START = 2,
	BWFM_E_AUTH = 3,
	BWFM_E_AUTH_IND = 4,
	BWFM_E_DEAUTH = 5,
	BWFM_E_DEAUTH_IND = 6,
	BWFM_E_ASSOC = 7,
	BWFM_E_ASSOC_IND = 8,
	BWFM_E_REASSOC = 9,
	BWFM_E_REASSOC_IND = 10,
	BWFM_E_DISASSOC = 11,
	BWFM_E_DISASSOC_IND = 12,
	BWFM_E_QUIET_START = 13,
	BWFM_E_QUIET_END = 14,
	BWFM_E_BEACON_RX = 15,
	BWFM_E_LINK = 16,
	BWFM_E_MIC_ERROR = 17,
	BWFM_E_NDIS_LINK = 18,
	BWFM_E_ROAM = 19,
	BWFM_E_TXFAIL = 20,
	BWFM_E_PMKID_CACHE = 21,
	BWFM_E_RETROGRADE_TSF = 22,
	BWFM_E_PRUNE = 23,
	BWFM_E_AUTOAUTH = 24,
	BWFM_E_EAPOL_MSG = 25,
	BWFM_E_SCAN_COMPLETE = 26,
	BWFM_E_ADDTS_IND = 27,
	BWFM_E_DELTS_IND = 28,
	BWFM_E_BCNSENT_IND = 29,
	BWFM_E_BCNRX_MSG = 30,
	BWFM_E_BCNLOST_MSG = 31,
	BWFM_E_ROAM_PREP = 32,
	BWFM_E_PFN_NET_FOUND = 33,
	BWFM_E_PFN_NET_LOST = 34,
	BWFM_E_RESET_COMPLETE = 35,
	BWFM_E_JOIN_START = 36,
	BWFM_E_ROAM_START = 37,
	BWFM_E_ASSOC_START = 38,
	BWFM_E_IBSS_ASSOC = 39,
	BWFM_E_RADIO = 40,
	BWFM_E_PSM_WATCHDOG = 41,
	BWFM_E_PROBREQ_MSG = 44,
	BWFM_E_SCAN_CONFIRM_IND = 45,
	BWFM_E_PSK_SUP = 46,
	BWFM_E_COUNTRY_CODE_CHANGED = 47,
	BWFM_E_EXCEEDED_MEDIUM_TIME = 48,
	BWFM_E_ICV_ERROR = 49,
	BWFM_E_UNICAST_DECODE_ERROR = 50,
	BWFM_E_MULTICAST_DECODE_ERROR = 51,
	BWFM_E_TRACE = 52,
	BWFM_E_IF = 54,
	BWFM_E_P2P_DISC_LISTEN_COMPLETE = 55,
	BWFM_E_RSSI = 56,
	BWFM_E_EXTLOG_MSG = 58,
	BWFM_E_ACTION_FRAME = 59,
	BWFM_E_ACTION_FRAME_COMPLETE = 60,
	BWFM_E_PRE_ASSOC_IND = 61,
	BWFM_E_PRE_REASSOC_IND = 62,
	BWFM_E_CHANNEL_ADOPTED = 63,
	BWFM_E_AP_STARTED = 64,
	BWFM_E_DFS_AP_STOP = 65,
	BWFM_E_DFS_AP_RESUME = 66,
	BWFM_E_ESCAN_RESULT = 69,
	BWFM_E_ACTION_FRAME_OFF_CHAN_COMPLETE = 70,
	BWFM_E_PROBERESP_MSG = 71,
	BWFM_E_P2P_PROBEREQ_MSG = 72,
	BWFM_E_DCS_REQUEST = 73,
	BWFM_E_FIFO_CREDIT_MAP = 74,
	BWFM_E_ACTION_FRAME_RX = 75,
	BWFM_E_TDLS_PEER_EVENT = 92,
	BWFM_E_BCMC_CREDIT_SUPPORT = 127,
	BWFM_E_LAST = 139
};
#define BWFM_EVENT_MASK_LEN		(roundup(BWFM_E_LAST, 8) / 8)

enum bwfm_fweh_event_status {
	BWFM_E_STATUS_SUCCESS = 0,
	BWFM_E_STATUS_FAIL = 1,
	BWFM_E_STATUS_TIMEOUT = 2,
	BWFM_E_STATUS_NO_NETWORKS = 3,
	BWFM_E_STATUS_ABORT = 4,
	BWFM_E_STATUS_NO_ACK = 5,
	BWFM_E_STATUS_UNSOLICITED = 6,
	BWFM_E_STATUS_ATTEMPT = 7,
	BWFM_E_STATUS_PARTIAL = 8,
	BWFM_E_STATUS_NEWSCAN = 9,
	BWFM_E_STATUS_NEWASSOC = 10,
	BWFM_E_STATUS_11HQUIET = 11,
	BWFM_E_STATUS_SUPPRESS = 12,
	BWFM_E_STATUS_NOCHANS = 13,
	BWFM_E_STATUS_CS_ABORT = 15,
	BWFM_E_STATUS_ERROR = 16,
};

struct bwfm_ethhdr {
	uint16_t subtype;
	uint16_t length;
	uint8_t version;
	uint8_t oui[3];
#define	BWFM_BRCM_OUI			"\x00\x10\x18"
	uint16_t usr_subtype;
#define	BWFM_BRCM_SUBTYPE_EVENT		1
} __packed;

struct bwfm_event_msg {
	uint16_t version;
	uint16_t flags;
	uint32_t event_type;
	uint32_t status;
	uint32_t reason;
	uint32_t auth_type;
	uint32_t datalen;
	struct ether_addr addr;
	char ifname[IFNAMSIZ];
	uint8_t ifidx;
	uint8_t bsscfgidx;
} __packed;

struct bwfm_event {
	struct ether_header ehdr;
#define BWFM_ETHERTYPE_LINK_CTL			0x886c
	struct bwfm_ethhdr hdr;
	struct bwfm_event_msg msg;
} __packed;
