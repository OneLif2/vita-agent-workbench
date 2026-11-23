#include "wb_payload.h"

#include "wb_ver.h"

bool wb_payload_ok(const wb_payload_v1 *table) {
    if (!table) return false;
    if (table->magic != WB_PAYLOAD_MAGIC) return false;
    if (table->abi != WB_PAYLOAD_ABI) return false;
    if (table->size < sizeof(wb_payload_v1)) return false;
    if (!table->version || !*table->version) return false;
    if (!table->dispatch) return false;
    return true;
}
