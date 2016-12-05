#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#  define EXIT(n) exit(n)

# define ABORT do { \
        fflush(stdout); \
        fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
        ERR_print_errors_fp(stderr); \
        EXIT(1); \
} while (0)

/* test multiplication with group order, long and negative scalars */
static void group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1, *n2, *order;
    EC_POINT *P = EC_POINT_new(group);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT *S = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();
    int i;

    n1 = BN_new();
    n2 = BN_new();
    order = BN_new();
    fprintf(stdout, "verify group order ...");
    fflush(stdout);
    if (!EC_GROUP_get_order(group, order, ctx))
        ABORT;
    if (!EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!EC_POINT_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);
    if (!EC_GROUP_precompute_mult(group, ctx))
        ABORT;
    if (!EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!EC_POINT_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, " ok\n");
    fprintf(stdout, "long/negative scalar tests ");
    for (i = 1; i <= 2; i++) {
        const BIGNUM *scalars[6];
        const EC_POINT *points[6];

        fprintf(stdout, i == 1 ?
                "allowing precomputation ... " :
                "without precomputation ... ");
        if (!BN_set_word(n1, i))
            ABORT;
        /*
         * If i == 1, P will be the predefined generator for which
         * EC_GROUP_precompute_mult has set up precomputation.
         */
        if (!EC_POINT_mul(group, P, n1, NULL, NULL, ctx))
            ABORT;

        if (!BN_one(n1))
            ABORT;
        /* n1 = 1 - order */
        if (!BN_sub(n1, n1, order))
            ABORT;
        if (!EC_POINT_mul(group, Q, NULL, P, n1, ctx))
            ABORT;
        if (0 != EC_POINT_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = 1 + order */
        if (!BN_add(n2, order, BN_value_one()))
            ABORT;
        if (!EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != EC_POINT_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
        if (!BN_mul(n2, n1, n2, ctx))
            ABORT;
        if (!EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != EC_POINT_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        /* Add P to verify the result. */
        if (!EC_POINT_add(group, Q, Q, P, ctx))
            ABORT;
        if (!EC_POINT_is_at_infinity(group, Q))
            ABORT;

        /* Exercise EC_POINTs_mul, including corner cases. */
        if (EC_POINT_is_at_infinity(group, P))
            ABORT;

        scalars[0] = scalars[1] = BN_value_one();
        points[0]  = points[1]  = P;

        if (!EC_POINTs_mul(group, R, NULL, 2, points, scalars, ctx))
            ABORT;
        if (!EC_POINT_dbl(group, S, points[0], ctx))
            ABORT;
        if (0 != EC_POINT_cmp(group, R, S, ctx))
            ABORT;

        scalars[0] = n1;
        points[0] = Q;          /* => infinity */
        scalars[1] = n2;
        points[1] = P;          /* => -P */
        scalars[2] = n1;
        points[2] = Q;          /* => infinity */
        scalars[3] = n2;
        points[3] = Q;          /* => infinity */
        scalars[4] = n1;
        points[4] = P;          /* => P */
        scalars[5] = n2;
        points[5] = Q;          /* => infinity */
        if (!EC_POINTs_mul(group, P, NULL, 6, points, scalars, ctx))
            ABORT;
        if (!EC_POINT_is_at_infinity(group, P))
            ABORT;
    }
    fprintf(stdout, "ok\n");

    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
}


int main()
{
    BN_CTX *ctx = NULL;
    BIGNUM *p, *a, *b;
    EC_GROUP *group;
    EC_GROUP *P_160 = NULL, *P_192 = NULL, *P_224 = NULL, *P_256 =
        NULL, *P_384 = NULL, *P_521 = NULL;
    EC_POINT *P, *Q, *R;
    BIGNUM *x, *y, *z, *yplusone;
    unsigned char buf[100];
    size_t i, len;
    int k;

    if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"))
        ABORT;
    if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        ABORT;
    if (!BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"))
        ABORT;
    if (!BN_hex2bn(&b, "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"))
        ABORT;
    if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        ABORT;

    if (!BN_hex2bn(&x, "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"))
        ABORT;
    if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1, ctx))
        ABORT;
    if (EC_POINT_is_on_curve(group, P, ctx) <= 0)
        ABORT;
    if (!BN_hex2bn(&z, "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"))
        ABORT;
    if (!EC_GROUP_set_generator(group, P, z, BN_value_one()))
        ABORT;

    if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx))
        ABORT;
    fprintf(stdout, "\nNIST curve P-192 -- Generator:\n     x = 0x");
    BN_print_fp(stdout, x);
    fprintf(stdout, "\n     y = 0x");
    BN_print_fp(stdout, y);
    fprintf(stdout, "\n");
    /* G_y value taken from the standard: */
    if (!BN_hex2bn(&z, "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"))
        ABORT;
    if (0 != BN_cmp(y, z))
        ABORT;

    if (!BN_add(yplusone, y, BN_value_one()))
        ABORT;
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (EC_POINT_set_affine_coordinates_GFp(group, P, x, yplusone, ctx))
        ABORT;

    fprintf(stdout, "verify degree ...");
    if (EC_GROUP_get_degree(group) != 192)
        ABORT;
    fprintf(stdout, " ok\n");

    group_order_tests(group);

    if ((P_192 = EC_GROUP_new(EC_GROUP_method_of(group))) == NULL)
        ABORT;
    if (!EC_GROUP_copy(P_192, group))
        ABORT;
}




/*
int main()
{
	EC_KEY *b;
	EC_POINT *pk;
	BIGNUM *sk = NULL;
	BIGNUM *sk2;

	unsigned char num[] = "ASDFGHJKL";
	int i;
	EC_GROUP *group1,*group2; 
	b = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
	if(b == 0) {
		printf("error\n");
	}

	BN_bin2bn(num ,16 ,sk);

	EC_KEY_generate_key(b);
	EC_KEY_set_private_key(b ,sk);

	EC_GROUP_set_generator();

	pk = EC_KEY_get0_public_key(b);
	sk2 = EC_KEY_get0_private_key(b);
	printf("top = %d \n" ,sk2->top);
	
	for (i = 0 ;i < 6; i++) {
		printf("%x",sk2->d[i]);
	}
	
	printf("\nend\n");
}*/
