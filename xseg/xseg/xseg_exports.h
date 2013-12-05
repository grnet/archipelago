/*
 * Copyright 2012 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

EXPORT_SYMBOL(xseg_initialize);
EXPORT_SYMBOL(xseg_finalize);
EXPORT_SYMBOL(xseg_parse_spec);
EXPORT_SYMBOL(xseg_register_type);
EXPORT_SYMBOL(xseg_unregister_type);
EXPORT_SYMBOL(xseg_register_peer);
EXPORT_SYMBOL(xseg_unregister_peer);
EXPORT_SYMBOL(xseg_report_peer_types);
EXPORT_SYMBOL(xseg_enable_driver);
EXPORT_SYMBOL(xseg_disable_driver);
EXPORT_SYMBOL(xseg_create);
EXPORT_SYMBOL(xseg_destroy);
EXPORT_SYMBOL(xseg_join);
EXPORT_SYMBOL(xseg_leave);
EXPORT_SYMBOL(xseg_bind_port);
EXPORT_SYMBOL(xseg_alloc_requests);
EXPORT_SYMBOL(xseg_free_requests);
EXPORT_SYMBOL(xseg_get_request);
EXPORT_SYMBOL(xseg_put_request);
EXPORT_SYMBOL(xseg_prep_request);
EXPORT_SYMBOL(xseg_submit);
EXPORT_SYMBOL(xseg_receive);
EXPORT_SYMBOL(xseg_accept);
EXPORT_SYMBOL(xseg_respond);
EXPORT_SYMBOL(xseg_prepare_wait);
EXPORT_SYMBOL(xseg_cancel_wait);
EXPORT_SYMBOL(xseg_wait_signal);
EXPORT_SYMBOL(xseg_signal);
EXPORT_SYMBOL(xseg_get_port);
EXPORT_SYMBOL(xseg_set_req_data);
EXPORT_SYMBOL(xseg_get_req_data);
EXPORT_SYMBOL(xseg_set_path_next);
EXPORT_SYMBOL(xseg_forward);
EXPORT_SYMBOL(xseg_init_local_signal);
EXPORT_SYMBOL(xseg_quit_local_signal);
EXPORT_SYMBOL(xseg_resize_request);
EXPORT_SYMBOL(xseg_get_objh);
EXPORT_SYMBOL(xseg_put_objh);
EXPORT_SYMBOL(xseg_set_max_requests);
EXPORT_SYMBOL(xseg_get_max_requests);
EXPORT_SYMBOL(xseg_get_allocated_requests);
EXPORT_SYMBOL(xseg_set_freequeue_size);
EXPORT_SYMBOL(xseg_get_data_nonstatic);
EXPORT_SYMBOL(xseg_get_target_nonstatic);
EXPORT_SYMBOL(xseg_get_signal_desc_nonstatic);
EXPORT_SYMBOL(xseg_bind_dynport);
EXPORT_SYMBOL(xseg_leave_dynport);
EXPORT_SYMBOL(xseg_portno_nonstatic);

EXPORT_SYMBOL(xseg_snprintf);
EXPORT_SYMBOL(__xseg_errbuf);
EXPORT_SYMBOL(__xseg_log);
EXPORT_SYMBOL(init_logctx);
EXPORT_SYMBOL(renew_logctx);
EXPORT_SYMBOL(__xseg_log2);
EXPORT_SYMBOL(xseg_printtrace);
