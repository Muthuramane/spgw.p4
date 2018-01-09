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

#include "common.p4"
#include "spgw.p4"

// In this example headers and metadata are the same as in the SPGW case.
typedef spgw_headers_t headers_t;
typedef spgw_meta_t local_metadata_t;

parser parser_impl(packet_in packet,
                   out headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata) {

	spgw_parser_impl() spgw_parser;

	state start {
		spgw_parser.apply(packet, hdr, local_metadata);
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control ingress_impl(inout headers_t hdr,
                     inout local_metadata_t local_metadata,
                     inout standard_metadata_t standard_metadata) {

    apply {
        bool do_spgw = false;
        spgw_checkin.apply(hdr, local_metadata, do_spgw);
        if (do_spgw) {
        	spgw_pipeline.apply(hdr, local_metadata, standard_metadata);
        }
    }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control egress_impl(inout headers_t hdr,
                    inout local_metadata_t local_metadata,
                    inout standard_metadata_t standard_metadata) {
    apply { /* Nothing to do */ }
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control verify_checksum_impl(inout headers_t hdr,
                             inout local_metadata_t local_metadata) {
    apply {
        verify_gtpu_checksum.apply(hdr);
    }
}

control compute_checksum_impl(inout headers_t hdr,
                              inout local_metadata_t local_metadata) {
    apply {
        compute_gtpu_checksum.apply(hdr);
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control deparser_impl(packet_out packet, in headers_t hdr) {
    apply {
        spgw_deparser.apply(packet, hdr);
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
