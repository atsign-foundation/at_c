#include "atclient/atsign.h"
#include "atclient/atutils.h"

void atsign_init(atsign* atsign, const char* atsign_str) {
    // Check if input_at_sign is null or empty
    if (atsign_str == NULL || strlen(atsign_str) == 0) {
        fprintf(stderr, "Error: atsign cannot be null or empty\n");
        exit(EXIT_FAILURE);
    }

    atsign->atsign = with_prefix(atsign_str);
    atsign->without_prefix_str = without_prefix(atsign_str);
}

void free_atsign(atsign* atsign) {
    free(atsign->atsign);
    free(atsign->without_prefix_str);
}