#ifndef __ec_wei_h__
#define __ec_wei_h__

#include "ec_common.h"

typedef struct _ec_wei_def
{
 bigint_t p;
 bigint_t a;
 bigint_t b;
 int am3_flag; /* a = -3 ? */
} ec_wei_def_t;

#ifdef __cplusplus
extern "C"
{
#endif

void ec_wei_def_init(ec_wei_def_t *def, bigint_t p, bigint_t a, bigint_t b); /* b may be NULL */
void ec_wei_def_init_small_a(ec_wei_def_t *def, bigint_t p, int a, bigint_t b);
void ec_wei_def_destroy(ec_wei_def_t *def);

void ec_wei_point_init(ec_point_t *a, const ec_wei_def_t *def);
void ec_wei_point_init_values(ec_point_t *a, const ec_wei_def_t *def, bigint_t x, bigint_t y);
void ec_wei_point_destroy(ec_point_t *a);
int  ec_wei_point_check(const bigint_t x, const bigint_t y, const ec_wei_def_t *def, ec_scratch_t *s);
void ec_wei_point_copy(ec_point_t *res, const ec_point_t *a);
void ec_wei_point_move(ec_point_t *res, ec_point_t *a);
void ec_wei_point_neg(ec_point_t *a);

void ec_wei_scratch_init(ec_scratch_t *s, const ec_wei_def_t *def);
void ec_wei_scratch_destroy(ec_scratch_t *s);

#ifdef __cplusplus
}
#endif

#endif
