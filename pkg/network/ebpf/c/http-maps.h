#ifndef __HTTP_MAPS_H
#define __HTTP_MAPS_H

#include "tracer.h"
#include "bpf_helpers.h"
#include "http-types.h"
#include "map-defs.h"

/* This map is used to keep track of in-flight HTTP transactions for each TCP connection */
BPF_HASH_MAP(http_in_flight, conn_tuple_t, http_transaction_t, 1)
    
/* This map used for notifying userspace that a HTTP batch is ready to be consumed */
BPF_PERF_EVENT_ARRAY_MAP(http_notifications, __u32, 0)

/* This map stores finished HTTP transactions in batches so they can be consumed by userspace*/
BPF_HASH_MAP(http_batches, http_batch_key_t, http_batch_t, 1024)

/* This map holds one entry per CPU storing state associated to current http batch*/
BPF_HASH_MAP(http_batch_state, __u32, http_batch_state_t, 1024)
    
BPF_HASH_MAP(ssl_sock_by_ctx, void *, ssl_sock_t, 1)

BPF_HASH_MAP(ssl_read_args, u64, ssl_read_args_t, 1024)
    
BPF_HASH_MAP(bio_new_socket_args, __u64, __u32, 1024)
    
BPF_HASH_MAP(fd_by_ssl_bio, __u32, void *, 1024)
    
BPF_HASH_MAP(ssl_ctx_by_pid_tgid, __u64, void *, 1024)
    
BPF_HASH_MAP(open_at_args, __u64, lib_path_t, 1024)
    
/* This map used for notifying userspace of a shared library being loaded */
BPF_PERF_EVENT_ARRAY_MAP(shared_libraries, __u32, 0)
    
#endif
