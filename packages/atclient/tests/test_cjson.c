#include <cJSON/cJSON.h>
#include <stddef.h> // IWYU pragma: keep
#include <stdio.h>

int main() {
  int ret = 1; // error by default

  /**
   * Create this JSON and print
   * {
   *    "name": "bob",
   *    "age": 5,
   *    "stats": {
   *        "defense": 4,
   *        "hp": 10.0
   *    }
   * }
   *
   */

  cJSON *root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "name", cJSON_CreateString("bob"));
  cJSON_AddItemToObject(root, "age", cJSON_CreateNumber(5));
  cJSON *stats = cJSON_CreateObject();
  cJSON_AddItemToObject(stats, "defense", cJSON_CreateNumber(4));
  cJSON_AddItemToObject(stats, "hp", cJSON_CreateNumber(10.01));
  cJSON_AddItemToObject(root, "stats", stats);
  printf("%s\n", cJSON_Print(root));

  ret = 0;

  goto exit;

exit: {
  cJSON_Delete(root);
  return ret;
}
}
