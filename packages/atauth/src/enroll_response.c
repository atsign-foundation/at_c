#include "enroll_response.h"
#include "atclient/json.h"
#include "atlogger/atlogger.h"
#include "cJSON.h"
#include <string.h>
// enroll:request:{"appName":"foo","deviceName":"bar", "apkamPublicKey":"baz"}
// data:{"enrollmentId":"4450e479-e1e2-4916-9e1f-a9cfdbdf25b8","status":"pending"}

#define TAG "atauth_enroll_response"

#define ENROLLMENT_ID "enrollmentId"
#define STATUS "status"

#ifdef ATCOMMONS_JSON_PROVIDER_CJSON
int parse_enrollment_response(const char *buffer, struct enroll_response *response) {
  char *enrollment_id = NULL;
  char *status = NULL;

  int ret = strncmp(buffer, "data:", 5);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Did not receive data response from enroll request\n");
    return 1;
  }

  cJSON *json = cJSON_Parse(buffer + 5);
  if (json == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse json from enroll response\n");
    return 1;
  }

  if (cJSON_HasObjectItem(json, ENROLLMENT_ID)) {
    char *temp = cJSON_GetStringValue(cJSON_GetObjectItem(json, ENROLLMENT_ID));
    size_t temp_len = strlen(temp);
    enrollment_id = malloc(sizeof(char) * (temp_len + 1));
    if (enrollment_id == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enrollment_id\n");
      cJSON_Delete(json);
      return 1;
    }
    memcpy(enrollment_id, temp, temp_len);
    enrollment_id[temp_len] = 0;
  }

  if (cJSON_HasObjectItem(json, STATUS)) {
    char *temp = cJSON_GetStringValue(cJSON_GetObjectItem(json, STATUS));
    size_t temp_len = strlen(temp);
    status = malloc(sizeof(char) * (temp_len + 1));
    if (status == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for status\n");
      cJSON_Delete(json);
      if (enrollment_id != NULL) {
        free(enrollment_id);
      }
      return 1;
    }
    memcpy(status, temp, temp_len);
    status[temp_len] = 0;
  }

  cJSON_Delete(json);
  *response = (struct enroll_response){
      .enrollment_id = enrollment_id,
      .status = status,
  };
  return 0;
}
#else
#error no json implementation
#endif

void free_enroll_response(struct enroll_response *res) {
  if (res->enrollment_id != NULL) {
    free((char *)res->enrollment_id);
  }
  if (res->status != NULL) {
    free((char *)res->status);
  }
}
