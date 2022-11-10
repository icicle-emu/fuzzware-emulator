#ifndef FUZZWARE_NATIVE_TRACING
#define FUZZWARE_NATIVE_TRACING

#include "native_hooks.h"
#include "state_snapshotting.h"

uc_err init_tracing(uc_engine *uc, char *p_bbl_set_trace_path, char *p_bbl_hash_path, char *p_mmio_set_trace_path, size_t num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends);

#endif