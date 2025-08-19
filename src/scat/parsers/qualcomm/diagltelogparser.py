#!/usr/bin/env python3

from collections import namedtuple
from packaging import version
import binascii
import bitstring
import calendar
import logging
import struct

bitstring_ver = version.parse(bitstring.__version__)
if bitstring_ver >= version.parse('4.2.0'):
    bitstring.options.lsb0 = True
elif bitstring_ver >= version.parse('4.0.0'):
    bitstring.lsb0 = True
elif bitstring_ver >= version.parse('3.1.7'):
    bitstring.set_lsb0(True)
else:
    raise Exception("SCAT requires bitstring>=3.1.7, recommends bitstring>=4.0.0")

import scat.parsers.qualcomm.diagcmd as diagcmd
import scat.util as util

class DiagLteLogParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        self.rrc_segments = dict()
        self.first_segment_item = None

        self.no_process = {
        }

        i = diagcmd.diag_log_get_lte_item_id
        c = diagcmd.diag_log_code_lte
        self.process = {
            # ML1
            # i(c.LOG_LTE_ML1_MAC_RAR_MSG1_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_RAR_MSG2_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_CONNECTED_MODE_INTRA_FREQ_MEAS): lambda x, y, z: self.parse_lte_ml1_connected_intra_freq_meas(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL): lambda x, y, z: self.parse_lte_ml1_scell_meas(x, y, z),
            i(c.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS): lambda x, y, z: self.parse_lte_ml1_ncell_meas(x, y, z),
            # i(c.LOG_LTE_ML1_INTRA_FREQ_CELL_RESELECTION)
            # i(c.LOG_LTE_ML1_NEIGHBOR_CELL_MEAS_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_ncell_meas_rr(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE): lambda x, y, z: self.parse_lte_ml1_scell_meas_response(x, y, z),
            # i(c.LOG_LTE_ML1_SEARCH_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_search_rr(x, y, z),
            # i(c.LOG_LTE_ML1_CONNECTED_MODE_NEIGHBOR_MEAS_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_connected_ncell_meas_rr(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_INFO): lambda x, y, z: self.parse_lte_ml1_cell_info(x, y, z),

            # MAC
            i(c.LOG_LTE_MAC_RACH_TRIGGER): lambda x, y, z: self.parse_lte_mac_rach_trigger(x, y, z),
            i(c.LOG_LTE_MAC_RACH_RESPONSE): lambda x, y, z: self.parse_lte_mac_rach_response(x, y, z),
            i(c.LOG_LTE_MAC_DL_TRANSPORT_BLOCK): lambda x, y, z: self.parse_lte_mac_dl_block(x, y, z),
            i(c.LOG_LTE_MAC_UL_TRANSPORT_BLOCK): lambda x, y, z: self.parse_lte_mac_ul_block(x, y, z),

            # RLC

            # PDCP
            # i(c.LOG_LTE_PDCP_DL_CONFIG): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_CONFIG): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_DL_DATA_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_DATA_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_DL_CONTROL_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_CONTROL_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            i(c.LOG_LTE_PDCP_DL_CIPHER_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_dl_cip(x, y, z),
            i(c.LOG_LTE_PDCP_UL_CIPHER_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_ul_cip(x, y, z),
            i(c.LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_dl_srb_int(x, y, z),
            i(c.LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_ul_srb_int(x, y, z),

            # RRC
            i(c.LOG_LTE_RRC_OTA_MESSAGE): lambda x, y, z: self.parse_lte_rrc(x, y, z),
            i(c.LOG_LTE_RRC_MIB_MESSAGE): lambda x, y, z: self.parse_lte_mib(x, y, z),
            i(c.LOG_LTE_RRC_SERVING_CELL_INFO): lambda x, y, z: self.parse_lte_rrc_cell_info(x, y, z),

            # CA COMBOS
            i(c.LOG_LTE_RRC_SUPPORTED_CA_COMBOS): lambda x, y, z: self.parse_lte_cacombos(x, y, z),

            # NAS
            i(c.LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    # def parse_lte_dummy(self, pkt_header, pkt_body, args):
    #     return {'stdout': 'LTE Dummy 0x{:04x}: {}'.format(pkt_header.log_id, binascii.hexlify(pkt_body).decode())}

    def parse_rsrp(self, rsrp):
        return -180 + rsrp * 0.0625

    def parse_rsrq(self, rsrq):
        return -30 + rsrq * 0.0625

    def parse_rssi(self, rssi):
        return -110 + rssi * 0.0625

    # ML1
    def parse_lte_ml1_scell_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_version = pkt_body[0]

        item_struct = namedtuple('QcDiagLteMl1ScellMeas', 'rrc_rel reserved1 earfcn pci_serv_layer_prio meas_rsrp avg_rsrp rsrq rssi rxlev s_search')
        if pkt_version == 4:
            item = item_struct._make(struct.unpack('<BHHHLLLLLL', pkt_body[1:32]))
        elif pkt_version == 5:
            item = item_struct._make(struct.unpack('<BHLH2xLLLLLL', pkt_body[1:36]))
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet version 0x{:02x}'.format(pkt_version))
            return None

        pci_serv_layer_prio_bits = bitstring.Bits(uint=item.pci_serv_layer_prio, length=16)
        pci = pci_serv_layer_prio_bits[0:9].uint

        meas_rsrp = item.meas_rsrp & 0xfff
        avg_rsrp = item.avg_rsrp & 0xfff

        rsrq_bits = bitstring.Bits(uint=item.rsrq, length=32)
        meas_rsrq = rsrq_bits[0:10].uint
        avg_rsrq = rsrq_bits[20:30].uint

        rssi_bits = bitstring.Bits(uint=item.rssi, length=32)
        meas_rssi = rssi_bits[10:21].uint

        rxlev_bits = bitstring.Bits(uint=item.rxlev, length=32)
        q_rxlevmin = rxlev_bits[0:6].uint
        p_max = rxlev_bits[6:13].uint
        max_ue_tx_pwr = rxlev_bits[13:19].uint
        s_rxlev = rxlev_bits[19:26].uint
        num_drx_s_fail = rxlev_bits[26:32].uint

        stdout = 'LTE SCell: EARFCN: {}, PCI: {}, Measured RSRP: {:.2f}, Measured RSSI: {:.2f}, Measured RSRQ: {:.2f}'.format(item.earfcn,
            pci, self.parse_rsrp(meas_rsrp), self.parse_rssi(meas_rssi), self.parse_rsrq(meas_rsrq))

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_lte_ml1_ncell_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_version = pkt_body[0]
        stdout = ''

        item_struct = namedtuple('QcDiagLteMl1NcellMeas', 'rrc_rel reserved1 earfcn q_rxlevmin_n_cells')
        n_cell_struct = namedtuple('QcDiagLteMl1NcellMeasNcell', 'val0 val1 val2 val3 n_freq_offset val5 ant0_offset ant1_offset')

        pos = 0
        if pkt_version == 4: # Version 4
            # Version, RRC standard release, EARFCN, Q_rxlevmin, Num Cells, Cell Info
            # Cell Info - PCI, Measured RSSI, Measured RSRP, Average RSRP
            #    Measured RSRQ, Average RSRQ, S_rxlev, Freq Offset
            #    Ant0 Frame Offset, Ant0 Sample Offset, Ant1 Frame Offset, Ant1 Sample Offset
            #    S_qual
            item = item_struct._make(struct.unpack('<BHHH', pkt_body[1:8]))
            pos = 8
        elif pkt_version == 5: # Version 5
            # EARFCN -> 4 bytes
            item = item_struct._make(struct.unpack('<BHLL', pkt_body[1:12]))
            pos = 12
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Meas packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        q_rxlevmin = item.q_rxlevmin_n_cells & 0x3f
        n_cells = item.q_rxlevmin_n_cells >> 6
        stdout += 'LTE NCell: EARFCN: {}, number of cells: {}\n'.format(item.earfcn, n_cells)

        for i in range(n_cells):
            n_cell_pkt = pkt_body[pos + 32 * i:pos + 32 * (i + 1)]
            n_cell = n_cell_struct._make(struct.unpack('<LLLLHHLL', n_cell_pkt[0:28]))

            val0_bits = bitstring.Bits(uint=n_cell.val0, length=32)
            n_pci = val0_bits[0:9].uint
            n_meas_rssi = val0_bits[9:20].uint
            n_meas_rsrp = val0_bits[20:32].uint
            n_avg_rsrp = (n_cell.val1 >> 12) & 0xfff
            n_meas_rsrq = (n_cell.val2 >> 12) & 0x3ff
            n_avg_rsrq = n_cell.val3 & 0x3ff
            n_s_rxlev = (n_cell.val3 >> 20) & 0x3f
            n_ant0_frame_offset = n_cell.ant0_offset & 0x7ff
            n_ant0_sample_offset = (n_cell.ant0_offset >> 11)
            n_ant1_frame_offset = n_cell.ant1_offset & 0x7ff
            n_ant1_sample_offset = (n_cell.ant1_offset >> 11)

            if item.rrc_rel == 1: # Rel 9
                r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                n_s_qual = r9_info_interim[0]
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Cell Meas packet - RRC version {}'.format(item.rrc_rel))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

            n_real_rsrp = self.parse_rsrp(n_meas_rsrp)
            n_real_rssi = self.parse_rssi(n_meas_rssi)
            n_real_rsrq = self.parse_rsrq(n_meas_rsrq)

            stdout += '└── Neighbor cell {}: PCI: {:3d}, RSRP: {:.2f}, RSSI: {:.2f}, RSRQ: {:.2f}\n'.format(i, n_pci, n_real_rsrp, n_real_rssi, n_real_rsrq)
        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def _parse_scell_meas_response_cell(self, cell_bytes, snr_offset=80):
        """Helper to parse a single cell's data from a measurement response packet."""
        try:
            val0_bits = bitstring.Bits(uint=struct.unpack('<H', cell_bytes[0:2])[0], length=16)
            pci = val0_bits[0:9].uint

            interim = struct.unpack('<LL', cell_bytes[snr_offset:snr_offset+8])
            val_bits = bitstring.Bits().join([bitstring.Bits(uint=x, length=32) for x in interim][::-1])
            # We use snr0 as the primary SNR value
            snr = round(val_bits[0:9].uint * 0.1 - 20.0, 2)

            return {'pci': pci, 'snr': snr}
        except Exception:
            return None