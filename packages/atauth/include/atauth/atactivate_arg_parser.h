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
 * @param atsign pointer to store the atsign value
 * @param cram_secret pointer to store the cram_secret value
 * @param otp OTP fetched from otp verb handler
 * @param atkeys_fp pointer to store the file path of the atkeys
 * @param app_name
 * @param device_name
 * @param namespaces
 * @param root_host pointer to store the root host server address
 * @return int 0 on success, non-zero on error
 */
int atactivate_parse_args(int argc, char *argv[], char **atsign, char **cram_secret, char **otp, char **atkeys_fp,
                          char **app_name, char **device_name, char **namespaces, char **root_host);

#endif // ATACTIVATE_ARG_PARSER_H
