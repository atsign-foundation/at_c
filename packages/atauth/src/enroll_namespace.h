#ifndef ATAUTH_ENROLL_NAMESPACE_H
#define ATAUTH_ENROLL_NAMESPACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

struct enroll_namespace {
  size_t len;
  char **namespaces; // array of strings
  enum namespace_permissions *permissions;
};

// read bit 1
// write bit 2
enum namespace_permissions {
  np_readonly = 0b01,
  np_read_write = 0b11,
};

void enroll_namespace_init(struct enroll_namespace *ns);
void enroll_namespace_free(struct enroll_namespace *ns);
int parse_enroll_namespace(const char *input, struct enroll_namespace *output);
int enroll_namespace_to_json_string(struct enroll_namespace *ns, char **json_string);

#ifdef __cplusplus
}
#endif

#endif
