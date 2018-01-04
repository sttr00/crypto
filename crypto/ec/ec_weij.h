#ifndef __ec_weij_h__
#define __ec_weij_h__

#include "ec_wei.h"

/*
  Short Weierstrass curves, Jacobian coordinates
    y^2 = x^3 + a*x + b
  Identity: (1:1:0)
  Negation: -(X:Y:Z) = (X:-Y:Z)
 */

#ifdef __cplusplus
extern "C"
{
#endif

void ec_weij_point_dbl(ec_point_t *res, const ec_point_t *a,
                       const ec_wei_def_t *def, ec_scratch_t *s);
void ec_weij_point_add(ec_point_t *res, const ec_point_t *a, const ec_point_t *b,
                       const ec_wei_def_t *def, ec_scratch_t *s);
void ec_weij_point_madd(ec_point_t *res, const ec_point_t *a,
                        const bigint_t bx, const bigint_t by,
                        const ec_wei_def_t *def, ec_scratch_t *s);

int ec_weij_point_affine_xy(bigint_t x, bigint_t y, const ec_point_t *a,
                            const ec_wei_def_t *def, ec_scratch_t *s);
int ec_weij_point_affine_x(bigint_t x, const ec_point_t *a,
                           const ec_wei_def_t *def, ec_scratch_t *s);
int ec_weij_point_normalize(ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s);

void ec_weij_point_mul(ec_point_t *res, const ec_point_t *a,
                       const ec_wei_def_t *def, const bigint_t k, ec_scratch_t *s);

#ifdef __cplusplus
}
#endif

#endif
