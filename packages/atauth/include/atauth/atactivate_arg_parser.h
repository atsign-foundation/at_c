#ifndef ATACTIVATE_ARG_PARSER_H
#define ATACTIVATE_ARG_PARSER_H

/**
 * @brief Parses command-line arguments to initialize the atactivate
 * configuration
 *
 * Note: Memory need not be preallocated for atsign, cram_secret, atkeys_fp, first_app_name, first_device_name,
 * root_host and root_port. Caller needs to free the above mentioned variables
 * after use
 *
 * @param argc The number of arguments
 * @param argv The array of arguments
 * @param atsign pointer to store the parsed atsign value
 * @param cram_secret pointer to store the parsed cram_secret value
 * @param otp OTP pointer to store the parsed OTP/SPP value (accepts OTP fetched from OTP verb)
 * @param atkeys_fp pointer to store the parsed file path of the atkeys
 * @param app_name pointer to store the parsed app_name for current enrollment
 * @param device_name pointer to store the parsed device_name for current enrollment
 * @param namespaces pointert to store the parsed namespaces list for current enrollment
 * @param root_host pointer to store the parsed root server host
 * @param root_port pointer to store the parsed root server port
 * @return int 0 on success, non-zero on error
 */
int atactivate_parse_args(int argc, char *argv[], char **atsign, char **cram_secret, char **otp, char **atkeys_fp,
                          char **app_name, char **device_name, char **namespaces, char **root_host, int *root_port);

#endif // ATACTIVATE_ARG_PARSER_H
