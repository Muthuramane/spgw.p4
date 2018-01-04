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
 */

#include <core.p4>
#include <v1model.p4>

#define ETH_TYPE_IPV4 0x0800
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define UDP_PORT_GTPU 2152

typedef bit<9> port_t;

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

/* GTPU v1: https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol#GTP_version_1 */
header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extersion hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32> teid;       /* tunnel endpoint id */
}

/* These optional fields exist if any of the ex, seq, or pdn flags are on */
// UNUSED
header gtpu_opt_t {
    bit<16> seq_no;   /* Sequence number */
    bit<8>  npdu_no;    /* N-PDU number*/
    bit<8>  ex_type;    /* Next extension header type */
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    bit<16>       l4_inner_src_port;
    bit<16>       l4_inner_dst_port;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    gtpu_t gtpu;
    ipv4_t ipv4_inner;
    tcp_t tcp_inner;
    udp_t udp_inner;
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser parser_impl(packet_in packet,
                  out headers_t hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {

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
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
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
        packet.extract(hdr.ipv4_inner);
        transition select(hdr.ipv4_inner.protocol) {
            IP_PROTO_TCP: parse_tcp_inner;
            IP_PROTO_UDP: parse_udp_inner;
            default: accept;
        }
    }

    state parse_tcp_inner {
        packet.extract(hdr.tcp_inner);
        local_metadata.l4_inner_src_port = hdr.tcp_inner.src_port;
        local_metadata.l4_inner_dst_port = hdr.tcp_inner.dst_port;
        transition accept;
    }

    state parse_udp_inner {
        packet.extract(hdr.udp_inner);
        local_metadata.l4_inner_src_port = hdr.udp_inner.src_port;
        local_metadata.l4_inner_dst_port = hdr.udp_inner.dst_port;
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control ingress_impl(inout headers_t hdr,
                     inout local_metadata_t local_metadata,
                     inout standard_metadata_t standard_metadata) {

    apply { /* TODO */ }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control egress_impl(inout headers_t hdr,
                    inout local_metadata_t local_metadata,
                    inout standard_metadata_t standard_metadata) {
    apply {
        /*
        Nothing to do on the egress pipeline.
        */
    }
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control verify_checksum_impl(inout headers_t hdr,
                             inout local_metadata_t local_metadata) {
    apply {
        /*
        Nothing to do here, we assume checksum is always correct.
        */
    }
}

control compute_checksum_impl(inout headers_t hdr,
                              inout local_metadata_t local_metadata) {
    apply {
        /*
        Nothing to do here, as we do not modify packet headers.
        */
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control deparser_impl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtpu);
        packet.emit(hdr.ipv4_inner);
        packet.emit(hdr.udp_inner);
        packet.emit(hdr.tcp_inner);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(parser_impl(),
         verify_checksum_impl(),
         ingress_impl(),
         egress_impl(),
         compute_checksum_impl(),
         deparser_impl()) main;
