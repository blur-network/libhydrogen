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


int main()
{

hydro_init();

uint8_t new_master_key[hydro_pwhash_MASTERKEYBYTES];
hydro_pwhash_keygen(new_master_key);


    uint8_t            h[64];
    uint8_t            static_key[128];
    char               h_hex[129]; // byte for each char + 1 null term byte


std::cout << "Please enter a password for key generation: ";
char in[64];
memset(in, 'x', sizeof in);
std::cin >> in;
const char* input = in;


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


std::cout << "Stored Representation: " << hydro_bin2hex(h_hex, sizeof h_hex, h, sizeof h) << std::endl;
std::cout << "Derived key: " << hydro_bin2hex(de_hex, sizeof de_hex, derived_key, sizeof derived_key) << std::endl;

std::cout << "Please re-type your password to verify: "; // working

    uint8_t            htwo[64];
//    uint8_t            static_key[128];
    char               htwo_hex[129]; // byte for each char + 1 null term byte 

char intwo[64];
memset(intwo, 'x', sizeof intwo);
std::cin >> intwo;
const char* inputtwo = intwo;

hydro_pwhash_deterministic(htwo, sizeof htwo, inputtwo, sizeof (inputtwo - 1), CONTEXT, new_master_key, OPSLIMIT, 0, 1);
hydro_bin2hex(htwo_hex, sizeof htwo_hex, htwo, sizeof htwo);


if (hydro_pwhash_verify(stored, htwo_hex, sizeof htwo_hex, new_master_key,
                        OPSLIMIT_MAX, MEMLIMIT_MAX, THREADS_MAX) != 0) {
  std::cout << "Incorrect password." << std::endl;
}

else {
  std::cout << "Verification Passed." << std::endl;
}
return 0;

}
