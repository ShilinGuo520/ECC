#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>


int main()
{
	EC_KEY *b;
	b = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
	EC_KEY_generate_key(b);
	EC_KEY_get0_public_key(b);
	EC_KEY_get0_private_key(b);

	printf("hello\n");
}
