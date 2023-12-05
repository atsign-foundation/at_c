#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/atsign.h"
#include "atclient/atkeysfile.h"
#include "atclient/atkeys.h"

char* concatenate_with_prefix(const char* initial_prefix, const char* strings[], int num_strings) {
    // Calculate the total length required to store the result
    size_t total_length = strlen(initial_prefix);

    for (int i = 0; i < num_strings; i++) {
        total_length += strlen(strings[i]);
    }

    // Allocate dynamic memory to store the result
    char* result = (char*)malloc(total_length + 1); // +1 for the null character '\0'

    // Check if memory allocation was successful
    if (result == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory.\n");
        exit(EXIT_FAILURE);
    }

    // Copy the initial prefix to the result string
    strcpy(result, initial_prefix);

    // Concatenate each string to the result using pointers and dynamic memory
    char* ptr = result + strlen(initial_prefix);

    for (int i = 0; i < num_strings; i++) {
        strcpy(ptr, strings[i]);
        ptr += strlen(strings[i]);
    }

    return result;
}

char *trim(char *s) {
    char *ptr;
    if (!s)
        return NULL;   // handle NULL string
    if (!*s)
        return s;      // handle empty string
    for (ptr = s + strlen(s) - 1; (ptr >= s) && isspace(*ptr); --ptr);
    ptr[1] = '\0';
    return s;
}

int starts_with(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

int ends_with(const char *suffix, const char *str) 
{
  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);

  return (str_len >= suffix_len) &&
         (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

char* without_prefix(char* atsign) {
    if (atsign[0] == '@') {
        return atsign + 1;
    } else {
        return atsign;
    }
}

char* with_prefix(char* atsign) {
    if (atsign[0] == '@') {
        return atsign;
    } else {
        size_t len = strlen(atsign) + 2;
        char* result = (char*)malloc(len);
        sprintf(result, "@%s", atsign);
        return result;
    }
}

atclient_atkeys load_keys(atsign *atsign) {
    int ret = 1;

    // Get the home directory path
    const char *home_dir = getenv("HOME");

    if (home_dir == NULL) {
        fprintf(stderr, "Failed to retrieve HOME environment variable.\n");
        // return -1;
        // return NULL;
    }
    
    // Calculate the necessary size for the complete path
    size_t path_size = strlen(home_dir) + strlen("/.atsign/keys/") + strlen(atsign->atsign) + strlen("_key.atKeys") + 1;

    // Allocate dynamic memory for the path
    char *file_path = malloc(path_size);

    if (file_path == NULL) {
        fprintf(stderr, "Error allocating memory for the file path.\n");
        //return -2;
        // return NULL;
    }

    // Build the complete path to the file
    snprintf(file_path, path_size, "%s/.atsign/keys/%s_key.atKeys", home_dir, atsign->atsign);

    // 1a. read `atkeysfile` struct
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    ret = atclient_atkeysfile_read(&atkeysfile, file_path);
    if (ret != 0) {
        free(file_path);
        // return -3;
        // return NULL;
    }

    // atclient_atkeys *atkeys_tmp;

    // atclient_atkeys *atkeys = malloc(sizeof(atclient_atkeys));
    atclient_atkeys atkeys;
    // 1b. populate `atkeys` struct
    atclient_atkeys_init(&atkeys);
    ret = atclient_atkeys_populate(&atkeys, atkeysfile);

    if (ret != 0) {
        free(file_path);
        // return -4;
        // return NULL;
    }
    
    // memcpy(&atkeys, &atkeys_tmp, sizeof(atclient_atkeys));
    // free(atkeys_tmp);
    free(file_path);
    
    return atkeys;
    //return 0; 
}

