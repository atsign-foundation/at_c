#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//could us cJSON.h maybe
#include "atkeys_filereader.h"

int atclient_atkeysfile_read(const char* path, const size_t pathlen, atclient_atkeysfile* atsign){
    /*readAtKeys creates a struct to store AtKeys, reads .atKeys file contents,
    and saves into the struct. The function returns a pointer to the new struct.
    */

   //open file to read
    FILE* file = fopen(path, "r");
    if(file == NULL){
        perror("Error opening the file to read");
        return -1;
    }

    //save contents into a string
    char* line = NULL;
    size_t len = 0;
    char* token; //to parse the string with tokenization

    if(getline(&line, &len, file) != -1){
        printf("Line saved\n");

        token = strtok(line, ","); //start tokenization
        if(token == NULL){
            perror("Invalid file format to create token");
            fclose(file);
            free(line);
            return -1;
        }

        //population time: save all values in atclient_atkeys_file
        token = save(token, atsign->aesPkamPublicKey);
        token = save(token, atsign->aesPkamPrivateKey);
        token = save(token, atsign->aesEncryptPublicKey);
        token = save(token, atsign->aesEncryptPrivateKey);
        token = save(token, atsign->selfEncryptionKey);
        token = save(token, atsign->atSign);
    } else{
        perror("Line not saved\n");
        return -1;
    }

    fclose(file);
    free(line);

    return 0;
}

void atclient_atkeysfile_init(atclient_atkeysfile** atkeysfile){
    *atkeysfile = malloc(sizeof(atclient_atkeysfile));
    if (*atkeysfile == NULL) {
        perror("Error allocating memory for atclient_atkeysfile_init");
        return;
    }

    (*atkeysfile)->aesPkamPublicKey = malloc(sizeof(atclient_atkeysfile_entry));
    (*atkeysfile)->aesPkamPrivateKey = malloc(sizeof(atclient_atkeysfile_entry));
    (*atkeysfile)->aesEncryptPublicKey = malloc(sizeof(atclient_atkeysfile_entry));
    (*atkeysfile)->aesEncryptPrivateKey = malloc(sizeof(atclient_atkeysfile_entry));
    (*atkeysfile)->selfEncryptionKey = malloc(sizeof(atclient_atkeysfile_entry));
    (*atkeysfile)->atSign = malloc(sizeof(atclient_atkeysfile_entry));
}

char* save(char* token, atclient_atkeysfile_entry* attribute){
    /*save assumes tokenization has begun. The function will save to a specified 
    struct attribute and returns a new token which contains the substring*/

    if (token != NULL) {
        char* temp = strdup(token); //saves temporary substring
        if(temp == NULL){
            perror("Error allocating memory for temp");
            return NULL;
        }

        //find starting index
        char* splitter = strchr(temp, ':'); //find first occurrence of ':'
        if(splitter == NULL){
            perror("Invalid token format");
            free(temp);
            return NULL;
        }

        int start = splitter - temp + 2; //change index to the key
        int length = strlen(temp) - start; //length of actual key
        char* subKey = (char*)malloc((length + 1)*sizeof(char)); //alloc string for actual key
        if(subKey == NULL){
            perror("subKey alloc failed in save\n");
            free(temp);
            return NULL;
        }

        //save the actual key
        if(strchr(temp, '}') == NULL){
            strncpy(subKey, temp+start, length - 1); //strncpy(dest, source at new start position, correct size excluding last")
        }else{
            strncpy(subKey, temp+start, length - 2); //strncpy(dest, source at new start position, correct size excluding last")
        }
        
        subKey[length] = '\0';    
        
        //save to struct
        attribute->key = subKey; 
        attribute->len = strlen(subKey);
        //printf("Saved key OFFICIAL is %s\n", attribute->key);

        free(temp);
    }else{
        perror("save function did not run");
        return NULL;
    }

    return token = strtok(NULL, ",");
}

int atclient_atkeysfile_write(const char *path, const size_t len, atclient_atkeysfile *atsign)
{
    //writeAtKeys writes a string from a fully populated struct at the given path

    //open file for writing
    FILE* file = fopen(path, "w");
    if(file == NULL){
        perror("Couldn't open file for writing\n");
        return -1;
    }

    //char* line = malloc(sizeof(char)); //for {}
    char* line = malloc(sizeof(char)*3); //for {}
    if(line == NULL){
        perror("Error allocating memory for line");
        fclose(file);
        return -1;
    }

    strcpy(line, "{");

    //get Atsign string
    char* pathCpy = (char*)malloc((strlen(path) + 1) * sizeof(char));
    if(pathCpy == NULL){
        perror("Error allocating memory for pathCpy");
        fclose(file);
        return -1;
    }

    strcpy(pathCpy, path);
    char* sign = strtok(pathCpy, "_"); 
    printf("The atsign is %s\n", sign);

    updateFileLine(&line, "aesPkamPublicKey", atsign->aesPkamPublicKey, 0);
    updateFileLine(&line, "aesPkamPrivateKey", atsign->aesPkamPrivateKey, 0);
    updateFileLine(&line, "aesEncryptPublicKey", atsign->aesEncryptPublicKey, 0);
    updateFileLine(&line, "aesEncryptPrivateKey", atsign->aesEncryptPrivateKey, 0);
    updateFileLine(&line, "selfEncryptionKey", atsign->selfEncryptionKey, 0);
    updateFileLine(&line, sign, atsign->atSign, -1);
    //line = realloc(line, (strlen(line) + 2)*sizeof(char));
    //strcat(line, newType);
    strcat(line, "}");

    //printf("FINAL LINE IS %s\n", line);

    fprintf(file, "%s", line); //write line to file
    printf("Data written to file\n");

    free(line);
    free(pathCpy);
    fclose(file);

    return 0;
}

void updateFileLine(char** line, char* type, atclient_atkeysfile_entry* attribute, int comma){
    
    //save type in format: "type":
    char* newType = (char*)malloc((strlen(type) + 3) * sizeof(char));
    if(newType == NULL){
        perror("Error allocating memory for newType");
        return;
    }
    strcpy(newType, "\"");
    strcat(newType, type);
    strcat(newType, "\":");
    //printf("The newType is %s\n", newType);

    //update line with type
    *line = realloc(*line, (strlen(*line) + strlen(newType) + 1)*sizeof(char));
    strcat(*line, newType);

    //save key in format: "key"
    char* newKey = (char*)malloc((strlen(attribute->key) + 3) * sizeof(char));
    if(newKey == NULL){
        perror("Error allocating memory for newKey");
        return;
    }
    strcpy(newKey, "\"");
    strcat(newKey, attribute->key);
    strcat(newKey, "\"");
    if(comma == 0){
        strcat(newKey, ",");
    }

    //printf("The newType is %s\n", newKey);

    //update line with key
    *line = realloc(*line, (strlen(*line) + attribute->len + 1)*sizeof(char));
    strcat(*line, newKey);

    //printf("Updated Line to %s\n", *line);
}

/* Main function to demonstrate
int main()
{
    char* filepath = "@17shiny_key.atKeys";

    //create struct & allocate
    atclient_atkeysfile* atsign = malloc(sizeof(atclient_atkeysfile));
    atclient_atkeysfile_init(&atsign);

    //read to populate struct
    if(atclient_atkeysfile_read(filepath, strlen(filepath), atsign) != 0){
        perror("Error reading into a struct");
        return -1;
    } else{
        printf("Struct is fully populated\n");
    }

    printf("STRUCT SAVED %s for the AtSign\n", atsign->atSign->key);

    //write populated struct into a txt file
    if(atclient_atkeysfile_write("@17shinyCopy_key.atKeys", strlen("@17shinyCopy_key.atKeys"), atsign) != 0){
        perror("Error writing into a struct");
        return -1;
    } else{
        printf("Written to file\n");
    }

    return 0;
}*/