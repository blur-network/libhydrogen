#include "hydrogen.h"

#include <string>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <list>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#define CONTEXT "password"
#define OPSLIMIT 10000
#define MEMLIMIT 0
#define THREADS  1
#define MEMLIMIT_MAX  0
#define THREADS_MAX 1
#define OPSLIMIT_MAX 50000


char *userinput(FILE* fp, size_t size) {
  char *in; int buf;
  size_t len = 0;

  try {
    in = (char*)(realloc(NULL, sizeof(char) * size));
    if(!in)
      return in;
    while (EOF != (buf = fgetc(fp)) && buf != '\n') {
      in[len++] = buf;
      if (len == size) {
        if (len >= 65) {
          throw len;
          break;
        } else {
          in = (char*)(realloc(in, sizeof(char) * (size += 1)));
          if(!in)
           return in;
        }
      }
    }
    in[len++]='\0';
    return (char*)(realloc(in, sizeof(char)*len));
  } catch(size_t &len) {
    printf("Error! Password cannot be longer than 64 characters. Please try again. \n");
    return NULL;
  }
}


int main()
{

hydro_init();

void hydro_memzero(void *pnt, size_t len);
uint8_t new_master_key[hydro_pwhash_MASTERKEYBYTES];
hydro_pwhash_keygen(new_master_key);


    uint8_t            h[64];
    uint8_t            static_key[128];
    char               h_hex[129]; // byte for each char + 1 null term byte

printf("Enter a password for key derivation: \t");

char *in = userinput(stdin, sizeof(stdin));
  if (in == NULL) {
    hydro_memzero((void*)(stdin), sizeof(stdin));
    return -1;
  }
const char *input = in;

    memset(new_master_key, 'x', sizeof new_master_key);
    hydro_pwhash_deterministic(h, sizeof h, input, sizeof (input - 1), CONTEXT, new_master_key, OPSLIMIT, 0, 1);
    hydro_bin2hex(h_hex, sizeof h_hex, h, sizeof h);


uint8_t derived_key[32];
char de_hex[65];
hydro_pwhash_deterministic(derived_key, sizeof derived_key, input, sizeof (input-1),
                           CONTEXT, new_master_key, OPSLIMIT, MEMLIMIT, THREADS);

uint8_t stored[hydro_pwhash_STOREDBYTES];
hydro_pwhash_create(stored, h_hex, sizeof h_hex, new_master_key,
                    OPSLIMIT, MEMLIMIT, THREADS);

hydro_bin2hex(h_hex, sizeof h_hex, h, sizeof h);
hydro_bin2hex(de_hex, sizeof de_hex, derived_key, sizeof derived_key);

printf("Stored Representation: \t%s\n", h_hex);
printf("Derived key: \t%s\n", de_hex);

hydro_memzero((void*)(input), sizeof(input));
hydro_memzero((void*)(in), sizeof(in));

printf("Please re-type your password to verify: \t"); // working

    uint8_t            htwo[64];
    char               htwo_hex[129]; // byte for each char + 1 null term byte

char *intwo = userinput(stdin, sizeof(stdin));
  if (intwo == NULL)
    return -1;
const char *inputtwo = intwo;

hydro_pwhash_deterministic(htwo, sizeof htwo, inputtwo, sizeof (inputtwo - 1), CONTEXT, new_master_key, OPSLIMIT, 0, 1);
hydro_bin2hex(htwo_hex, sizeof htwo_hex, htwo, sizeof htwo);


if (hydro_pwhash_verify(stored, htwo_hex, sizeof htwo_hex, new_master_key,
                        OPSLIMIT_MAX, MEMLIMIT_MAX, THREADS_MAX) != 0) {
  printf("Incorrect password. \n");
}

else {
  printf("Verification Passed. \n");
}

return 0;

}
