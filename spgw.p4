/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors:
 *     Carmelo Cascone <carmelo@opennetworking.org>
 */

#include <core.p4>
#include <v1model.p4>

#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define ETH_TYPE_IPV4 0x0800
#define IP_VERSION_4 0x4
#define IPV4_MIN_IHL 0x5
#define IPV4_MAX_TTL 64
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17

#define UDP_PORT_GTPU 2152
#define GTP_GPDU 0xff
#define GTPU_VERSION 0x01
#define GTP_PROTOCOL_TYPE_GTP 0x01

typedef bit direction_t;
typedef bit pcc_gate_status_t;
typedef bit<32> sdf_rule_id_t;
typedef bit<32> pcc_rule_id_t;

const sdf_rule_id_t DEFAULT_SDF_RULE_ID = 0;
const pcc_rule_id_t DEFAULT_PCC_RULE_ID = 0;

const direction_t DIR_UPLINK = 1w0;
const direction_t DIR_DOWNLINK = 1w1;

const pcc_gate_status_t PCC_GATE_OPEN = 1w0;
const pcc_gate_status_t PCC_GATE_CLOSED = 1w1;

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

// GTPU v1
header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32> teid;       /* tunnel endpoint id */
}

/* These optional fields exist if any of the ex, seq, or pdn flags are on */
// UNUSED
// header gtpu_opt_t {
//     bit<16> seq_no;   /* Sequence number */
//     bit<8>  npdu_no;  /* N-PDU number*/
//     bit<8>  ex_type;  /* Next extension header type */
// }

struct spgw_meta_t {
    bit<16>           l4_src_port;
    bit<16>           l4_dst_port;
    direction_t       direction;
    pcc_gate_status_t pcc_gate_status;
    sdf_rule_id_t     sdf_rule_id;
    pcc_rule_id_t     pcc_rule_id;
    bit<32>           dl_sess_teid;
    bit<32>           dl_sess_enb_addr;
    bit<32>           dl_sess_s1u_addr;

}

struct spgw_headers_t {
    ethernet_t ethernet;
    ipv4_t     gtpu_ipv4;
    udp_t      gtpu_udp;
    gtpu_t     gtpu;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser spgw_parser_impl(packet_in packet,
                        out spgw_headers_t hdr,
                        inout spgw_meta_t spgw_meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        spgw_meta.l4_src_port = hdr.tcp.src_port;
        spgw_meta.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        spgw_meta.l4_src_port = hdr.udp.src_port;
        spgw_meta.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.udp.dst_port) {
            UDP_PORT_GTPU: parse_gtpu;
            default: accept;
        }
    }

    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition parse_ipv4_inner;
    }

    state parse_ipv4_inner {
        hdr.gtpu_ipv4 = hdr.ipv4;
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp_inner;
            default: accept;
        }
    }

    state parse_udp_inner {
        hdr.gtpu_udp = hdr.udp;
        packet.extract(hdr.udp);
        spgw_meta.l4_src_port = hdr.udp.src_port;
        spgw_meta.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

/**
 * Check if a packet has to be processed by the SPGW pipeline (do_spgw) and sets
 * the direction of processing (spgw_meta.direction).
 */
control spgw_checkin(in spgw_headers_t hdr,
                     inout spgw_meta_t spgw_meta,
                     out bool do_spgw) {

    table ue_filter_table {
        key = {
            /**
             * IP prefixes of the UEs managed by this switch.
             */
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {  }
    }

    table s1u_filter_table {
        key = {
            /**
             * IP addresses of the S1U interfaces embodied by this switch.
             */
            hdr.gtpu_ipv4.dst_addr : exact;
        }
        actions = {  }
    }

    apply {
        do_spgw = false;
        if (hdr.gtpu.isValid() && hdr.gtpu.msgtype == GTP_GPDU) {
            spgw_meta.direction = DIR_UPLINK;
            if (s1u_filter_table.apply().hit) {
                do_spgw = true;
            }
        } else {
            if (ue_filter_table.apply().hit) {
                do_spgw = true;
            }
        }
    }
}

/**
 * SPGW pipeline processing.
 */
control spgw_pipeline(inout spgw_headers_t hdr,
                      inout spgw_meta_t spgw_meta,
                      in standard_metadata_t std_meta) {

    direct_counter(CounterType.packets_and_bytes) ue_counter;

    action gtpu_encap() {
        hdr.gtpu.setValid();
        hdr.gtpu.version = GTPU_VERSION;
        hdr.gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.gtpu.spare = 0; 
        hdr.gtpu.ex_flag = 0;
        hdr.gtpu.seq_flag = 0;
        hdr.gtpu.npdu_flag = 0;
        hdr.gtpu.msgtype = GTP_GPDU;
        hdr.gtpu.msglen = (bit<16>) (std_meta.packet_length - ETH_HDR_SIZE);
        hdr.gtpu.teid = spgw_meta.dl_sess_teid;

        hdr.gtpu_ipv4.setValid();
        hdr.gtpu_ipv4.version = IP_VERSION_4;
        hdr.gtpu_ipv4.ihl = IPV4_MIN_IHL;
        hdr.gtpu_ipv4.diffserv = 0;
        hdr.gtpu_ipv4.total_len = (bit<16>) (std_meta.packet_length
            - ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE);
        hdr.gtpu_ipv4.identification = 0x1513; /* From NGIC */
        hdr.gtpu_ipv4.flags = 0;
        hdr.gtpu_ipv4.frag_offset = 0;
        hdr.gtpu_ipv4.ttl = IPV4_MAX_TTL;
        hdr.gtpu_ipv4.protocol = IP_PROTO_UDP;
        hdr.gtpu_ipv4.dst_addr = spgw_meta.dl_sess_enb_addr;
        hdr.gtpu_ipv4.src_addr = spgw_meta.dl_sess_s1u_addr;
        hdr.gtpu_ipv4.hdr_checksum = 0; /* Updated later */

        hdr.gtpu_udp.setValid();
        hdr.gtpu_udp.src_port = UDP_PORT_GTPU;
        hdr.gtpu_udp.dst_port = UDP_PORT_GTPU;
        hdr.gtpu_udp.len = (bit<16>) (std_meta.packet_length
            - ETH_HDR_SIZE + UDP_HDR_SIZE);
        hdr.gtpu_udp.checksum = 0; /* Ignore, won't be updated */
    }

    action gtpu_decap() {
        hdr.gtpu_ipv4.setInvalid();
        hdr.gtpu_udp.setInvalid();
        hdr.gtpu.setInvalid();
    }

    action set_sdf_rule_id(sdf_rule_id_t id) {
        spgw_meta.sdf_rule_id = id;
    }

    action set_pcc_rule_id(pcc_rule_id_t id) {
        spgw_meta.pcc_rule_id = id;
    }

    action set_pcc_info(pcc_gate_status_t gate_status) {
        spgw_meta.pcc_gate_status = gate_status;
    }

    action set_dl_sess_info(bit<32> dl_sess_teid,
                            bit<32> dl_sess_enb_addr,
                            bit<32> dl_sess_s1u_addr) {
        spgw_meta.dl_sess_teid = dl_sess_teid;
        spgw_meta.dl_sess_enb_addr = dl_sess_enb_addr;
        spgw_meta.dl_sess_s1u_addr = dl_sess_s1u_addr;
    }

    action update_ue_cdr() {
        ue_counter.count();
    }

    table sdf_rule_lookup {
        key = {
            spgw_meta.direction   : exact;
            hdr.ipv4.src_addr     : ternary;
            hdr.ipv4.dst_addr     : ternary;
            hdr.ipv4.protocol     : ternary;
            spgw_meta.l4_src_port : ternary;
            spgw_meta.l4_dst_port : ternary;
        }
        actions = {
            set_sdf_rule_id();
        }
        const default_action = set_sdf_rule_id(DEFAULT_SDF_RULE_ID);
    }

    table pcc_rule_lookup {
        key = {
            spgw_meta.sdf_rule_id : exact;
        }
        actions = {
            set_pcc_rule_id();
        }
        const default_action = set_pcc_rule_id(DEFAULT_PCC_RULE_ID);
    }

    table pcc_info_lookup {
        key = {
            spgw_meta.pcc_rule_id : exact;
        }
        actions = {
            set_pcc_info();
        }
        const default_action = set_pcc_info(PCC_GATE_OPEN);
    }

    table dl_sess_lookup {
        key = {
            hdr.ipv4.dst_addr : exact; /* UE addr for downlink */
        }
        actions = {
            set_dl_sess_info();
        }
    }

    table ue_cdr_table {
        key = {
            hdr.ipv4.dst_addr : exact; /* UE addr for downlink */
        }
        actions = {
            update_ue_cdr();
        }
        counters = ue_counter;
    }

    apply {

        if (spgw_meta.direction == DIR_UPLINK) {
            gtpu_decap();
        }
        
        // Allow all traffic by default.
        spgw_meta.pcc_gate_status = PCC_GATE_OPEN;

        sdf_rule_lookup.apply();
        pcc_rule_lookup.apply();
        pcc_info_lookup.apply();

        if (spgw_meta.pcc_gate_status == PCC_GATE_CLOSED) {
            mark_to_drop();
            exit;
        }

        if (spgw_meta.direction == DIR_DOWNLINK) {
            if (!dl_sess_lookup.apply().hit) {
                /* We have no other choice than drop, as we miss the session
                   info necessary to properly GTPU encap the packet. */
                mark_to_drop();
                exit;
            }
            ue_cdr_table.apply();
            gtpu_encap();
        }
    }
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

/**
 * Verifies outer GTPU IPv4 checksum.
 */
control verify_gtpu_checksum(inout spgw_headers_t hdr) {
    apply {
        verify_checksum(hdr.gtpu_ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.gtpu_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

/**
 * Updates outer GTPU IPv4 checksum.
 */
control compute_gtpu_checksum(inout spgw_headers_t hdr) {
    apply {
        // Compute outer IPv4 checksum.
        update_checksum(hdr.gtpu_ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.gtpu_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

/**
 * Emits packet L2-L4 headers, including the GTPU ones.
 */
control spgw_deparser(packet_out packet, in spgw_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.gtpu_ipv4);
        packet.emit(hdr.gtpu_udp);
        packet.emit(hdr.gtpu);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
