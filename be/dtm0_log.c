/* -*- C -*- */
/*
 * Copyright (c) 2013-2020 Seagate Technology LLC and/or its Affiliates
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
 * For any questions about this software or licensing,
 * please email opensource@seagate.com or cortx-questions@seagate.com.
 *
 */

#include "be/dtm0_log.h"
#include "be/list.h"
#include "lib/errno.h"  /* ENOENT */
#include "lib/memory.h" /* M0_ALLOC */

M0_INTERNAL void m0_be_dtm0_log_init(struct m0_be_dtm0_log *log)
{
	m0_mutex_init(&log->dl_lock);
	m0_list_init(log->dl_vlist);
}

M0_INTERNAL void m0_be_dtm0_log_fini(struct m0_be_dtm0_log *log)
{
	m0_mutex_fini(&log->dl_lock);
	m0_list_fini(log->dl_vlist);
}

M0_INTERNAL void m0_be_dtm0_log_credit(enum m0_be_dtm0_log_credit_op op,
                                       struct m0_be_tx              *tx,
                                       struct m0_be_seg             *seg,
                                       struct m0_be_tx_credit       *accum)
{
	switch (op) {
	case M0_DTML_CREATE:
		//dtm0log_be_list_credit(M0_BLO_CREATE, 1, accum);
		break;
	case M0_DTML_SENT:
	case M0_DTML_EXECUTED:
	case M0_DTML_PERSISTENT:
	case M0_DTML_REDO:
	default:
		M0_IMPOSSIBLE("");
	}
}

M0_INTERNAL void m0_be_dtm0_log_create(struct m0_be_tx        *tx,
                                       struct m0_be_seg       *seg,
                                       struct m0_be_dtm0_log **out)
{
	struct m0_be_dtm0_log *log = NULL;

#if 0
	M0_PRE(tx);
	M0_PRE(seg);
	M0_PRE(m0_be_tx__invariant(tx));

	M0_BE_ALLOC_PTR_SYNC(log, seg, tx);
	M0_ASSERT(log);
	M0_BE_ALLOC_PTR_SYNC(log->dl_list, seg, tx);
	M0_ASSERT(log->dl_list);

	dtm0_log_be_list_create(log->dl_list, tx);
#endif
	M0_ALLOC_PTR(log);
	M0_ASSERT(log);
	M0_ALLOC_PTR(log->dl_vlist);
	M0_ASSERT(log->dl_vlist);

	*out = log;
}

M0_INTERNAL void m0_be_dtm0_log_destroy(struct m0_be_dtm0_log **log,
                                        struct m0_be_tx        *tx)
{
	struct m0_be_dtm0_log *plog = *log;

	M0_PRE(plog);
	M0_PRE(plog->dl_vlist);

	m0_free(plog->dl_vlist);
	m0_free(plog);
	*log = NULL;
}

M0_INTERNAL int m0_dtm0_dtx_id_cmp(const struct m0_dtm0_dtx_id *left,
                                   const struct m0_dtm0_dtx_id *right)
{
	return memcmp(left, right, sizeof(*left));
}

M0_INTERNAL int m0_be_dtm0_log_find(struct m0_be_dtm0_log       *log,
                                    const struct m0_dtm0_dtx_id *id,
                                    struct m0_dtm0_log_record  **out)
{
	struct m0_dtm0_log_record *rec = NULL;

	M0_PRE(log);
	M0_PRE(id);
	M0_PRE(out != NULL);

	M0_PRE(m0_mutex_is_locked(&log->dl_lock));
	m0_list_for_each_entry(log->dl_vlist, rec,
                               struct m0_dtm0_log_record, dlr_tlink) {
		if (!m0_dtm0_dtx_id_cmp(&rec->dlr_txr.dt_tid, id)) {
			*out = rec;
			return 0;;
		}
	}

	return -ENOENT;
}

static void m0_be_dtm0_log__insert(struct m0_be_dtm0_log *log,
                                   struct m0_be_tx       *tx,
                                   struct m0_dtm0_txr    *txr)
{
	struct m0_dtm0_log_record *rec = NULL;

	M0_ALLOC_PTR(rec);
	M0_ASSERT(rec);
	memcpy(rec, txr, sizeof(*txr));
	if (txr->dt_txr_payload.b_nob) {
		m0_buf_copy(&rec->dlr_txr.dt_txr_payload,
                            &txr->dt_txr_payload);
	}

	m0_list_link_init(&rec->dlr_tlink);
	m0_list_add_tail(log->dl_vlist, &rec->dlr_tlink);
}

static void m0_be_dtm0_log__set(struct m0_be_dtm0_log     *log,
                                struct m0_be_tx           *tx,
                                struct m0_dtm0_txr        *txr,
                                struct m0_dtm0_log_record *rec)
{
	int                 pa_id;
	struct m0_dtm0_txr *ltxr = &rec->dlr_txr;

	M0_PRE(ltxr->dt_participants_nr);

	/* Attach payload to log if it is not attached */
	if (!ltxr->dt_txr_payload.b_nob && txr->dt_txr_payload.b_nob) {
		m0_buf_copy(&ltxr->dt_txr_payload, &txr->dt_txr_payload);
	}

	/* Update participant state if changed */
	for (pa_id = 0; pa_id < ltxr->dt_participants_nr; ++pa_id) {
		if (ltxr->dt_participants[pa_id].pstate <
                    txr->dt_participants[pa_id].pstate) {
			ltxr->dt_participants[pa_id].pstate =
			txr->dt_participants[pa_id].pstate;
		}
	}
}

M0_INTERNAL void m0_be_dtm0_log_update(struct m0_be_dtm0_log *log,
                                       struct m0_be_tx       *tx,
                                       struct m0_dtm0_txr    *txr)
{
	struct m0_dtm0_log_record *rec = NULL;

	M0_PRE(log);
	M0_PRE(tx);
	M0_PRE(txr);
	M0_PRE(m0_mutex_is_locked(&log->dl_lock));

	if (m0_be_dtm0_log_find(log, &txr->dt_tid, &rec) == -ENOENT) {
		m0_be_dtm0_log__insert(log, tx, txr);
	} else {
		M0_ASSERT(rec);
		m0_be_dtm0_log__set(log, tx, txr, rec);
	}
}
