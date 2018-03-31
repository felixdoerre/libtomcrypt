/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

static int _ecc_cmp_hex_bn(const char *left_hex, void *right_bn)
{
   void *bn;
   int match = 0;
   if (mp_init(&bn) != CRYPT_OK)                    return 0;
   if (mp_read_radix(bn, left_hex, 16) != CRYPT_OK) goto error;
   if (mp_cmp(bn, right_bn) != LTC_MP_EQ)           goto error;
   match = 1;
error:
   mp_clear(bn);
   return match;
}

static void _ecc_oid_lookup(ecc_key *key)
{
   const ltc_ecc_curve *curve;

   key->dp.oidlen = 0;
   for (curve = ltc_ecc_curves; curve->prime != NULL; curve++) {
      if (_ecc_cmp_hex_bn(curve->prime, key->dp.prime)  != 1) continue;
      if (_ecc_cmp_hex_bn(curve->order, key->dp.order)  != 1) continue;
      if (_ecc_cmp_hex_bn(curve->A,     key->dp.A)      != 1) continue;
      if (_ecc_cmp_hex_bn(curve->B,     key->dp.B)      != 1) continue;
      if (_ecc_cmp_hex_bn(curve->Gx,    key->dp.base.x) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->Gy,    key->dp.base.y) != 1) continue;
      if (key->dp.cofactor != curve->cofactor)                continue;
      break; /* found */
   }
   if (curve->prime && curve->OID) {
      key->dp.oidlen = 16; /* size of key->dp.oid */
      pk_oid_str_to_num(curve->OID, key->dp.oid, &key->dp.oidlen);
   }
}

int ecc_set_dp_by_oid(unsigned long *oid, unsigned long oidlen, ecc_key *key)
{
   int err;
   char OID[256];
   unsigned long outlen;
   const ltc_ecc_curve *curve;

   LTC_ARGCHK(oid != NULL);
   LTC_ARGCHK(oidlen > 0);

   outlen = sizeof(OID);
   if ((err = pk_oid_num_to_str(oid, oidlen, OID, &outlen)) != CRYPT_OK) return err;
   if ((err = ecc_get_curve_by_name(OID, &curve)) != CRYPT_OK)           return err;

   return ecc_set_dp(curve, key);
}

int ecc_copy_dp(const ecc_key *srckey, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(srckey != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(srckey->dp.prime,  key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.order,  key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.A,      key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.B,      key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_ecc_copy_point(&srckey->dp.base, &key->dp.base)) != CRYPT_OK) { goto error; }
   /* cofactor & size */
   key->dp.cofactor = srckey->dp.cofactor;
   key->dp.size     = srckey->dp.size;
   /* OID */
   if (srckey->dp.oidlen > 0) {
     key->dp.oidlen = srckey->dp.oidlen;
     for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = srckey->dp.oid[i];
   }
   else {
     _ecc_oid_lookup(key); /* try to find OID in ltc_ecc_curves */
   }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_dp_from_mpis(void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor, ecc_key *key)
{
   int err;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(a     != NULL);
   LTC_ARGCHK(b     != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(order != NULL);
   LTC_ARGCHK(gx    != NULL);
   LTC_ARGCHK(gy    != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(prime, key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(order, key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(a,     key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(b,     key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gx,    key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gy,    key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)      { goto error; }
   /* cofactor & size */
   key->dp.cofactor = cofactor;
   key->dp.size = mp_unsigned_bin_size(prime);
   /* try to find OID in ltc_ecc_curves */
   _ecc_oid_lookup(key);
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
