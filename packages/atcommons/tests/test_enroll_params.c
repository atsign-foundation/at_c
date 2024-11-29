#include "atcommons/enroll_params.h"
#include "atlogger/atlogger.h"

#include "at_expect.c"
#include <stdlib.h>

#define TAG "test_enroll_params"

// this test case has all params populated e.g. app-name, deice-name, ...
int test_case_1() {
  // create an enroll_namespace
  atcommons_enroll_namespace_t namespace;
  namespace.name = "namespace1";
  namespace.access = "rw";

  // another way to create an enroll namespace
  atcommons_enroll_namespace_t namespace2 = {"namespace2", "r"};

  atcommons_enroll_namespace_list_t *ns_list = malloc(sizeof(atcommons_enroll_namespace_list_t));
  atcommons_enroll_namespace_list_append(&ns_list, &namespace);
  atcommons_enroll_namespace_list_append(&ns_list, &namespace2);

  atcommons_enroll_params_t *enroll_params = malloc(sizeof(atcommons_enroll_params_t));
  atcommons_enroll_params_init(enroll_params);
  enroll_params->app_name = "test-app";
  enroll_params->device_name = "test-device";
  enroll_params->otp = "XYZABC";
  enroll_params->ns_list = ns_list;
  char *expected_json = "{\"appName\":\"test-app\",\"deviceName\":\"test-device\",\"otp\":\"XYZABC\",\"namespaces\":{"
                        "\"namespace1\":\"rw\",\"namespace2\":\"r\"}}";

  size_t params_json_len = 0;
  char *params_json = NULL;
  int ret = atcommons_enroll_params_to_json(&params_json, &params_json_len, enroll_params);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_params_to_json returned: %d\n", ret);
    return ret;
  }

  ret = atcommons_string_expect(params_json, expected_json);
  return ret;
}

// this test case tries to serialize an enroll_params struct that has some null values
int test_case_2() {
  char *expected_json =
      "{\"appName\":\"app1\",\"deviceName\":\"rhaegar\",\"namespaces\":{\"test01\":\"rw\"},\"apkamPublicKey\":"
      "\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1THrbmEpXMDXUtci4GBNaARF2ghWYz6tC5PcO8oyjqioDwlp7lVZcufhgZGD2Dd5"
      "j124vyx8t0qlTP/LObK8WvgvLOY5NqUCOgYBv0VufVzOr6xrsNKVEKC9GzMkMbUfFwBVYHeeIg3IKeGTyxB+qHQIAa2gLZCBKX8EsLTGliQmkv2J"
      "96umaFTsS/juwxw9nSVpsMIwCcg6hA3njVbjR1p5o9mZ3lVw57GOHzkdyGXXBgKzNvBRXBSDOkNCulxoixrydqWD8sLc8AERQoWCUwSWITTS0YE/"
      "jFL8fH2zWupjJ510JmoIf2L2MJsiFFUCtRIRTWSIHs1/cXZiIEvhQIDAQAB\","
      "\"encryptedDefaultEncryptionPrivateKey\":\"Ksq6db1VpgDFiT2E39TLyt/"
      "NvvRFwlTHLRZIwPZF+RBREODSgqVmLrK5neYNQ+WFQ51h6cYtoSkaAbCpPJH8dAmbVuZGqP5LdrXBbflw0zwaJ+F/"
      "qc1eP5uvE60tEko80qeDQoh15tpCny8RwhbWRxCOMaj3+n3AKOFixsz/"
      "3Ka4wQxc2zwYTVoiKbrOLnsWdZnV3laEgoP56+Xd891jb3zicw50LICxU9Oj74wR1E+VyzerGTnUH+"
      "CXVx7WJ0V5mkGHpac0FsXIC52cmqVQ5sI0AuiyZEV5lg2hefQZSi9Zpu/"
      "B5fmxLf7WEbELRjjVUaVoDvOO7fZVFH9MCByXwJeunVzmLGXYm0YngINsA2n4uqPFY+5ku6fmVfWCr+6JLfguKUPIcdVg/OtzdC0Mv/"
      "eTjg8YenazHOMPnsfIWK/Ng8aLSX3dyo3ib3BnCbwyYFlgikPv435joYlmAqrkeTYPK8Dg94wG5u/"
      "1cSuqmYmKwRSEYcHAQ6Dud2o2t1jCqPhq5s+4FRTbMotUPaGiLITZKJGzDHdJB5nBdhRcjPICvsLEwq10J1lBe/b9qn47Oz3Oq8/"
      "pl6ML1ZedW5MCsyjREZJZ/5/"
      "oOSdbuWpB9AJNFDHS6KDUXmDWSdmtlrkjNwwmvJmxcpfIO29h+lpmVCg7ot0EYWChdqywnd9YJ+tKuRYCVvBxh+"
      "LOAnEZEQiONx53EjSppCxBOyB4ZJzeCyTuGjqYP4SqGvJsCNIL5U2DPLKU2g6dVIFMQHmGzEDW4WcvGbSz62FQOSeD+"
      "m5cIdPeejmTAWxl1JSXIWqMBZA6XKNUFh2L/RpYjyXuHURGiyTFv1flwB7/"
      "71po1wqPrjMjiaRbRIYKcm1xLcBIvsXqPQDw0FuPYwrhzUkO0hbE+GZlBU8dnzEcP66iccbV3zJcF3mhE3OsBquRSPaqEv/"
      "N5yEf8rWbREramAA0oBPwIJUaDv77JyUYaRw5wB2R3rIRgv6l1QhZAbfvaBn9bzsFL1pAoxMKLPS5x20PRHS3KUKJL7oMuAMzeYQZf4XnSW"
      "mfe9YrwTRTL2beRQFqTB8wPS0n3QRWrzeTTQGg5pgVyuW/"
      "2pj5zWf8C1Vm2X84rM7hB1+oy2PQxxCQCPxMNWzDkCgHzwefkB+rYhgzP2dGkRqcQUo7JGfEMgNJJ1RfW7/"
      "hfr9NGXYnSREH7FTIDdXBOh6pTcG8V+BpAV7f9kknwLTqAGKGsIjw9yGd/"
      "M742z1Rpq+VoeVFqXk+aZb3nellRplosO8HQrUWBRfQP2uiqO7ri0/"
      "c+0McybH79yDuTyYYbMdmoU77asHsdTxgv1q9PHvcVoijysBtxT+"
      "7lD0HZULe7L64V4kyRBjp5qOUiQzkcVK8XkQaCiRIlvlxeIx08FhuU9E70gOpWzyjl4esPGfHx9GWynwvXPhhQ/"
      "ws8HbcXMm4rjbFfdkgs3LB6ORACXNqZDhqK1DjzOInH8SBadw4ns7YeT++1WAaPPA/"
      "lAmXcZOzrvt2b6pRv6RttkMGJZhQf1PIEA2+GhTJ8ItxGnwlRpceWsuB4RRuroQZNeHD8zqbLDT7Evjcwm3EMoiMm+"
      "MtNxP5hUciCZTzrNLKDIOQ00PNxSZW+yYNSHr1fx3SxJaEW4bbqZs2KyF246TOtCwSgbM+dpSrFzTh+/"
      "Y6MW5dUWA36bL+HnyHuMSaIWXyj6YCgXe3fLTuEhEUmPYqAxswSkkVtxyn1PFY+L51aXXs0uzWkr00IJ3EB8tpXg4Jku+GfDZ+"
      "2wdO7rDy63VHpyG9savIefXSfM8NLmYb6tEw60/"
      "FznmO9G90nrXEfzo9KyfbEZ1qvDuy1d7A0GFTSuOLTFvzKzEytVfTayznpd5n3QqeU9V8uVUOwQ2We9sJ2U5ULHxMJ1gKlWpZ2mUB/"
      "P3M93PUwTYp4roD147auy+3quhyIyTy3eXwqHYucFeEJ22jINov3JYus8vUWRjuU7/"
      "3q3WUTGiz7fEUcr3eaPDMkSOQvUImzXWaOyJCxSC6CHpYMyyQGAW6hn35N5bYO0XyoJxQFhRwsCRa3wi9eQNSE9LizyXeLb980enIzG+"
      "P44x3cd8xtpe4ABM3HkiKZAGiJ7Hz0nzs5g5wyd0mLw181nz3RBS/"
      "7OvpQ22KzhohHrP6OwzXOnrRvZu62PJ4qe29ODMtecSKYFuMRTJg\",\"encryptedDefaultSelfEncryptionKey\":\"EdHYR+"
      "Rol3v1pAigsuSSkOTAkcse3wHXIX9b4tZd7SBrHLXJnZt2EqLur5pIKKjD\"}";

  // another way to create an enroll namespace
  atcommons_enroll_namespace_t namespace = {"test01", "rw"};

  atcommons_enroll_namespace_list_t *ns_list = malloc(sizeof(atcommons_enroll_namespace_list_t));
  atcommons_enroll_namespace_list_append(&ns_list, &namespace);

  atcommons_enroll_params_t *enroll_params = malloc(sizeof(atcommons_enroll_params_t));
  atcommons_enroll_params_init(enroll_params);
  enroll_params->app_name = "app1";
  enroll_params->device_name = "rhaegar";
  // enroll_params->otp = "XYZABC";
  enroll_params->ns_list = ns_list;
  enroll_params->encrypted_default_encryption_private_key =
      "Ksq6db1VpgDFiT2E39TLyt/NvvRFwlTHLRZIwPZF+RBREODSgqVmLrK5neYNQ+WFQ51h6cYtoSkaAbCpPJH8dAmbVuZGqP5LdrXBbflw0zwaJ+F/"
      "qc1eP5uvE60tEko80qeDQoh15tpCny8RwhbWRxCOMaj3+n3AKOFixsz/"
      "3Ka4wQxc2zwYTVoiKbrOLnsWdZnV3laEgoP56+Xd891jb3zicw50LICxU9Oj74wR1E+VyzerGTnUH+"
      "CXVx7WJ0V5mkGHpac0FsXIC52cmqVQ5sI0AuiyZEV5lg2hefQZSi9Zpu/"
      "B5fmxLf7WEbELRjjVUaVoDvOO7fZVFH9MCByXwJeunVzmLGXYm0YngINsA2n4uqPFY+5ku6fmVfWCr+6JLfguKUPIcdVg/OtzdC0Mv/"
      "eTjg8YenazHOMPnsfIWK/Ng8aLSX3dyo3ib3BnCbwyYFlgikPv435joYlmAqrkeTYPK8Dg94wG5u/"
      "1cSuqmYmKwRSEYcHAQ6Dud2o2t1jCqPhq5s+4FRTbMotUPaGiLITZKJGzDHdJB5nBdhRcjPICvsLEwq10J1lBe/b9qn47Oz3Oq8/"
      "pl6ML1ZedW5MCsyjREZJZ/5/"
      "oOSdbuWpB9AJNFDHS6KDUXmDWSdmtlrkjNwwmvJmxcpfIO29h+lpmVCg7ot0EYWChdqywnd9YJ+tKuRYCVvBxh+"
      "LOAnEZEQiONx53EjSppCxBOyB4ZJzeCyTuGjqYP4SqGvJsCNIL5U2DPLKU2g6dVIFMQHmGzEDW4WcvGbSz62FQOSeD+"
      "m5cIdPeejmTAWxl1JSXIWqMBZA6XKNUFh2L/RpYjyXuHURGiyTFv1flwB7/"
      "71po1wqPrjMjiaRbRIYKcm1xLcBIvsXqPQDw0FuPYwrhzUkO0hbE+GZlBU8dnzEcP66iccbV3zJcF3mhE3OsBquRSPaqEv/"
      "N5yEf8rWbREramAA0oBPwIJUaDv77JyUYaRw5wB2R3rIRgv6l1QhZAbfvaBn9bzsFL1pAoxMKLPS5x20PRHS3KUKJL7oMuAMzeYQZf4XnSWmfe9Y"
      "rwTRTL2beRQFqTB8wPS0n3QRWrzeTTQGg5pgVyuW/"
      "2pj5zWf8C1Vm2X84rM7hB1+oy2PQxxCQCPxMNWzDkCgHzwefkB+rYhgzP2dGkRqcQUo7JGfEMgNJJ1RfW7/"
      "hfr9NGXYnSREH7FTIDdXBOh6pTcG8V+BpAV7f9kknwLTqAGKGsIjw9yGd/M742z1Rpq+VoeVFqXk+aZb3nellRplosO8HQrUWBRfQP2uiqO7ri0/"
      "c+0McybH79yDuTyYYbMdmoU77asHsdTxgv1q9PHvcVoijysBtxT+"
      "7lD0HZULe7L64V4kyRBjp5qOUiQzkcVK8XkQaCiRIlvlxeIx08FhuU9E70gOpWzyjl4esPGfHx9GWynwvXPhhQ/"
      "ws8HbcXMm4rjbFfdkgs3LB6ORACXNqZDhqK1DjzOInH8SBadw4ns7YeT++1WAaPPA/"
      "lAmXcZOzrvt2b6pRv6RttkMGJZhQf1PIEA2+GhTJ8ItxGnwlRpceWsuB4RRuroQZNeHD8zqbLDT7Evjcwm3EMoiMm+"
      "MtNxP5hUciCZTzrNLKDIOQ00PNxSZW+yYNSHr1fx3SxJaEW4bbqZs2KyF246TOtCwSgbM+dpSrFzTh+/"
      "Y6MW5dUWA36bL+HnyHuMSaIWXyj6YCgXe3fLTuEhEUmPYqAxswSkkVtxyn1PFY+L51aXXs0uzWkr00IJ3EB8tpXg4Jku+GfDZ+"
      "2wdO7rDy63VHpyG9savIefXSfM8NLmYb6tEw60/"
      "FznmO9G90nrXEfzo9KyfbEZ1qvDuy1d7A0GFTSuOLTFvzKzEytVfTayznpd5n3QqeU9V8uVUOwQ2We9sJ2U5ULHxMJ1gKlWpZ2mUB/"
      "P3M93PUwTYp4roD147auy+3quhyIyTy3eXwqHYucFeEJ22jINov3JYus8vUWRjuU7/"
      "3q3WUTGiz7fEUcr3eaPDMkSOQvUImzXWaOyJCxSC6CHpYMyyQGAW6hn35N5bYO0XyoJxQFhRwsCRa3wi9eQNSE9LizyXeLb980enIzG+"
      "P44x3cd8xtpe4ABM3HkiKZAGiJ7Hz0nzs5g5wyd0mLw181nz3RBS/7OvpQ22KzhohHrP6OwzXOnrRvZu62PJ4qe29ODMtecSKYFuMRTJg";
  enroll_params->encrypted_self_encryption_key = "EdHYR+Rol3v1pAigsuSSkOTAkcse3wHXIX9b4tZd7SBrHLXJnZt2EqLur5pIKKjD";
  enroll_params->apkam_public_key =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1THrbmEpXMDXUtci4GBNaARF2ghWYz6tC5PcO8oyjqioDwlp7lVZcufhgZGD2Dd5"
      "j124vyx8t0qlTP/LObK8WvgvLOY5NqUCOgYBv0VufVzOr6xrsNKVEKC9GzMkMbUfFwBVYHeeIg3IKeGTyxB+qHQIAa2gLZCBKX8EsLTGliQmkv2J"
      "96umaFTsS/juwxw9nSVpsMIwCcg6hA3njVbjR1p5o9mZ3lVw57GOHzkdyGXXBgKzNvBRXBSDOkNCulxoixrydqWD8sLc8AERQoWCUwSWITTS0YE/"
      "jFL8fH2zWupjJ510JmoIf2L2MJsiFFUCtRIRTWSIHs1/cXZiIEvhQIDAQAB";

  size_t params_json_len = 0;
  char *params_json = NULL;
  int ret = atcommons_enroll_params_to_json(&params_json, &params_json_len, enroll_params);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_params_to_json returned: %d\n", ret);
    return ret;
  }

  ret = atcommons_string_expect(params_json, expected_json);
  return ret;
}

int main() {
  int ret = test_case_1();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test case 1| ret: %d\n", ret);
    return ret;
  }
  ret = test_case_2();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test case 2| ret: %d\n", ret);
    return ret;
  }
  return ret;
}
