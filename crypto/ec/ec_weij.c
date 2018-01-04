#include "ec_weij.h"
#include <assert.h>

/* dbl-2007-bl: 1M + 8S + 1m(a) + 1m(3) */
void ec_weij_point_dbl(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 bigint_mmul(s->v[0], a->x, a->x, def->p);       /* 1S: v0 = XX = x^2                  */
 bigint_mmul(s->v[1], a->y, a->y, def->p);       /* 2S: v1 = YY = y^2                  */
 bigint_mmul(s->v[2], s->v[1], s->v[1], def->p); /* 3S: v2 = y^4                       */
 bigint_mmul(s->v[3], a->z, a->z, def->p);       /* 4S: v3 = ZZ = z^2                  */
 bigint_add(s->v[4], a->x, s->v[1]);             /*     v4 = x + YY                    */
 bigint_mmul(s->v[5], s->v[4], s->v[4], def->p); /* 5S: v4 = (x+YY)^2                  */
 bigint_sub(s->v[5], s->v[5], s->v[0]);          /*     v5 = (x+YY)^2 - XX             */
 bigint_sub(s->v[5], s->v[5], s->v[2]);          /*     v5 = (x+YY)^2 - XX - y^4       */
 bigint_lshift(s->v[5], s->v[5], 1);             /*     v5 = S = 2*(x+YY)^2 - XX - y^4 */
 bigint_mmul(s->v[4], s->v[3], s->v[3], def->p); /* 6S: v4 = z^4                       */
 bigint_mmul(s->v[6], s->v[4], def->a, def->p);  /* 1m: v6 = a*z^4                     */
 bigint_mulw(s->v[4], s->v[0], 3);               /* 2m: v4 = 3*XX                      */
 bigint_add(s->v[0], s->v[4], s->v[6]);          /*     v0 = M = 3*XX + a*z^4          */
 bigint_mmul(s->v[4], s->v[0], s->v[0], def->p); /* 7S: v4 = M^2                       */
 bigint_lshift(s->v[6], s->v[5], 1);             /*     v6 = 2*S                       */
 bigint_msub(res->x, s->v[4], s->v[6], def->p);  /*     x' = T = M^2 - 2*S             */
 bigint_sub(s->v[4], s->v[5], res->x);           /*     v4 = S - T                     */
 bigint_mmul(s->v[5], s->v[0], s->v[4], def->p); /* 1M: v5 = M*(S-T)                   */
 bigint_lshift(s->v[6], s->v[2], 3);             /*     v6 = 8*y^4                     */
 bigint_add(s->v[4], a->y, a->z);                /*     v4 = y + z                     */
 bigint_msub(res->y, s->v[5], s->v[6], def->p);  /*     y' = M*(S-T) - 8*y^4           */
 bigint_mmul(s->v[0], s->v[4], s->v[4], def->p); /* 8S: v0 = (y+z)^2                   */
 bigint_sub(s->v[0], s->v[0], s->v[1]);          /*     v0 = (y+z)^2 - YY              */
 bigint_msub(res->z, s->v[0], s->v[3], def->p);  /*     z' = (y+z)^2 - YY - ZZ         */
}

/* dbl-2001-b: 3M + 5S * 1m(3) */
void ec_weij_point_dbl3(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 bigint_mmul(s->v[0], a->z, a->z, def->p);       /* 1S: v0 = delta = z^2                   */
 bigint_mmul(s->v[1], a->y, a->y, def->p);       /* 2S: v1 = gamma = y^2                   */
 bigint_mmul(s->v[2], a->x, s->v[1], def->p);    /* 1M: v2 = beta = x*gamma                */
 bigint_add(s->v[3], a->x, s->v[0]);             /*     v3 = x + delta                     */
 bigint_sub(s->v[4], a->x, s->v[0]);             /*     v4 = x - delta                     */
 bigint_mulw(s->v[3], s->v[3], 3);               /* 1m: v3 = 3*(x+delta)                   */
 bigint_mmul(s->v[5], s->v[3], s->v[4], def->p); /* 2M: v5 = alpha = 3*(x+delta)*(x-delta) */
 bigint_add(s->v[3], a->y, a->z);                /*     v3 = y + z                         */
 bigint_add(s->v[0], s->v[0], s->v[1]);          /*     v0 = delta + gamma                 */
 bigint_mmul(s->v[4], s->v[3], s->v[3], def->p); /* 3S: v4 = (y+z)^2                       */
 bigint_msub(res->z, s->v[4], s->v[0], def->p);  /*     z' = (y+z)^2 - delta - gamma       */
 bigint_mmul(s->v[0], s->v[5], s->v[5], def->p); /* 4S: v0 = alpha^2                       */
 bigint_lshift(s->v[3], s->v[2], 3);             /*     v3 = 8*beta                        */
 bigint_msub(res->x, s->v[0], s->v[3], def->p);  /*     x' = alpha^2 - 8*beta              */
 bigint_mmul(s->v[4], s->v[1], s->v[1], def->p); /* 5S: v4 = gamma^2                       */
 bigint_lshift(s->v[2], s->v[2], 2);             /*     v2 = 4*beta                        */
 bigint_lshift(s->v[4], s->v[4], 3);             /*     v4 = 8*gamma^2                     */
 bigint_sub(s->v[2], s->v[2], res->x);           /*     v2 = 4*beta - x'                   */
 bigint_mmul(s->v[3], s->v[5], s->v[2], def->p); /* 3M: v3 = alpha*(4*beta-x')             */
 bigint_msub(res->y, s->v[3], s->v[4], def->p);  /*     y' = alpha*(4*beta-x') - 8*gamma^2 */
}

/* add-2007-bl: 11M + 5S */
void ec_weij_point_add(ec_point_t *res, const ec_point_t *a, const ec_point_t *b, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(b->z, 0))
 {
  bigint_copy(res->x, a->x);
  bigint_copy(res->y, a->y);
  bigint_copy(res->z, a->z);
  return;
 }
 if (bigint_eq_word(a->z, 0))
 {
  bigint_copy(res->x, b->x);
  bigint_copy(res->y, b->y);
  bigint_copy(res->z, b->z);
  return;
 }
 bigint_mmul(s->v[0], a->z, a->z, def->p);       /*  1S: v0 = z1^2                    */
 bigint_mmul(s->v[1], b->z, b->z, def->p);       /*  2S: v1 = z2^2                    */
 bigint_mmul(s->v[2], a->x, s->v[1], def->p);    /*  1M: v2 = U1 = x1*z2^2            */
 bigint_mmul(s->v[3], b->x, s->v[0], def->p);    /*  2M: v3 = U2 = x2*z1^2            */
 bigint_mmul(s->v[4], s->v[1], b->z, def->p);    /*  3M: v4 = z2^3                    */
 bigint_mmul(s->v[5], s->v[0], a->z, def->p);    /*  4M: v5 = z1^3                    */
 bigint_mmul(s->v[6], a->y, s->v[4], def->p);    /*  5M: v6 = S1 = y1*z2^3            */
 bigint_mmul(s->v[7], b->y, s->v[5], def->p);    /*  6M: v7 = S2 = y2*z1^3            */
 bigint_sub(s->v[3], s->v[3], s->v[2]);          /*      v3 = H = U2 - U1             */
 bigint_sub(s->v[7], s->v[7], s->v[6]);          /*      v7 = S2 - S1                 */
 if (bigint_eq_word(s->v[3], 0))
 {
  if (bigint_eq_word(s->v[7], 0))
  {
   ec_weij_point_dbl(res, a, def, s);   
  } else
  {
   bigint_set_word(res->x, 1);
   bigint_set_word(res->y, 1);
   bigint_set_word(res->z, 0);
  }
  return;
 }
 bigint_add(s->v[0], s->v[0], s->v[1]);          /*      v0 = z1^2 + z2^2             */
 bigint_lshift(s->v[4], s->v[3], 1);             /*      v4 = 2*H                     */
 bigint_mmul(s->v[5], s->v[4], s->v[4], def->p); /*  3S: v5 = I = (2*H)^2             */
 bigint_mmul(s->v[1], s->v[3], s->v[5], def->p); /*  7M: v1 = J = H*I                 */
 bigint_mmul(s->v[4], s->v[2], s->v[5], def->p); /*  8M: v4 = V = U1*I                */
 bigint_lshift(s->v[7], s->v[7], 1);             /*      v7 = r = 2*(S2-S1)           */
 bigint_mmul(s->v[5], s->v[7], s->v[7], def->p); /*  4S: v5 = r^2                     */
 bigint_sub(s->v[5], s->v[5], s->v[1]);          /*      v5 = r^2 - J                 */
 bigint_lshift(s->v[2], s->v[4], 1);             /*      v2 = 2*V                     */
 bigint_msub(res->x, s->v[5], s->v[2], def->p);  /*      x' = r^2 - J - 2*V           */
 bigint_sub(s->v[4], s->v[4], res->x);           /*      v4 = V - x'                  */
 bigint_mmul(s->v[5], s->v[7], s->v[4], def->p); /*  9M: v5 = r*(V-x')                */
 bigint_lshift(s->v[6], s->v[6], 1);             /*      v6 = 2*S1                    */
 bigint_mmul(s->v[4], s->v[6], s->v[1], def->p); /* 10M: v4 = 2*S1*J                  */
 bigint_msub(res->y, s->v[5], s->v[4], def->p);  /*      y' = r*(V-x') - 2*S1*J       */
 bigint_add(s->v[5], a->z, b->z);                /*      v5 = z1 + z2                 */
 bigint_mmul(s->v[6], s->v[5], s->v[5], def->p); /*  5S: v6 = (z1+z2)^2               */
 bigint_sub(s->v[6], s->v[6], s->v[0]);          /*      v6 = (z1+z2)^2 - z1^2 - z2^2 */ 
 bigint_mmul(res->z, s->v[6], s->v[3], def->p);  /* 11M: z' = v6*H                    */
}

/* madd-2007-bl: 7M + 4S */
void ec_weij_point_madd(ec_point_t *res, const ec_point_t *a, const bigint_t bx, const bigint_t by, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0))
 {
  bigint_copy(res->x, bx);
  bigint_copy(res->y, by);
  bigint_set_word(res->z, 1);
  return;
 }
 bigint_mmul(s->v[0], a->z, a->z, def->p);       /* 1S: v0 = z1^2                    */
 bigint_mmul(s->v[1], bx, s->v[0], def->p);      /* 1M: v1 = U2 = x2*z1^2            */
 bigint_mmul(s->v[2], s->v[0], a->z, def->p);    /* 2M: v2 = z1^3                    */
 bigint_mmul(s->v[3], by, s->v[2], def->p);      /* 3M: v3 = S2 = y2*z1^3            */
 bigint_sub(s->v[4], s->v[1], a->x);             /*     v4 = H = U2 - x1             */
 bigint_sub(s->v[2], s->v[3], a->y);             /*     v2 = S2 - y1                 */
 if (bigint_eq_word(s->v[4], 0))
 {
  if (bigint_eq_word(s->v[2], 0))
  {
   ec_weij_point_dbl(res, a, def, s); /* TODO: doubling with z=1 */
  } else
  {
   bigint_set_word(res->x, 1);
   bigint_set_word(res->y, 1);
   bigint_set_word(res->z, 0);
  }
  return;
 }
 bigint_mmul(s->v[5], s->v[4], s->v[4], def->p); /* 2S: v5 = H^2                     */
 bigint_lshift(s->v[6], s->v[5], 2);             /*     v6 = I = 4*H^2               */
 bigint_lshift(s->v[2], s->v[2], 1);             /*     v2 = r = 2*(S2 - y1)         */
 bigint_add(s->v[0], s->v[0], s->v[5]);          /*     v0 = z1^2 + H^2              */
 bigint_mmul(s->v[3], s->v[4], s->v[6], def->p); /* 4M: v3 = J = H*I                 */
 bigint_mmul(s->v[5], a->x, s->v[6], def->p);    /* 5M: v5 = V = x1*I                */
 bigint_mmul(s->v[6], s->v[2], s->v[2], def->p); /* 3S: v6 = r^2                     */
 bigint_sub(s->v[6], s->v[6], s->v[3]);          /*     v6 = r^2 - J                 */
 bigint_lshift(s->v[7], s->v[5], 1);             /*     v7 = 2*V                     */
 bigint_msub(res->x, s->v[6], s->v[7], def->p);  /*     x' = r^2 - J - 2*V           */
 bigint_sub(s->v[5], s->v[5], res->x);           /*     v5 = V - x'                  */
 bigint_mmul(s->v[6], s->v[2], s->v[5], def->p); /* 6M: v6 = r*(V - x')              */
 bigint_lshift(s->v[5], a->y, 1);                /*     v5 = 2*y1                    */
 bigint_mmul(s->v[2], s->v[5], s->v[3], def->p); /* 7M: v2 = 2*y1*J                  */
 bigint_msub(res->y, s->v[6], s->v[2], def->p);  /*     y' = r*(V - x') -  2*y1*J    */
 bigint_add(s->v[3], a->z, s->v[4]);             /*     v3 = z1 + H                  */
 bigint_mmul(s->v[6], s->v[3], s->v[3], def->p); /* 4S: v6 = (z1 + H)^2              */
 bigint_msub(res->z, s->v[6], s->v[0], def->p);  /*     z' = (z1 + H)^2 - z1^2 - H^2 */
}

int ec_weij_point_normalize(ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0) || !bigint_minv(s->v[0], a->z, def->p))
 {
  bigint_set_word(a->x, 1);
  bigint_set_word(a->y, 1);
  return 0;
 }
 bigint_mmul(s->v[1], s->v[0], s->v[0], def->p);
 bigint_mmul(a->x, a->x, s->v[1], def->p);
 bigint_mmul(s->v[2], s->v[1], s->v[0], def->p);
 bigint_mmul(a->y, a->y, s->v[2], def->p);
 bigint_set_word(a->z, 1);
 return 1;
}

int ec_weij_point_affine_xy(bigint_t x, bigint_t y, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0)) return 0;
 if (!bigint_minv(s->v[0], a->z, def->p)) return 0;
 bigint_mmul(s->v[1], s->v[0], s->v[0], def->p);
 bigint_mmul(x, a->x, s->v[1], def->p);
 bigint_mmul(s->v[2], s->v[1], s->v[0], def->p);
 bigint_mmul(y, a->y, s->v[2], def->p);
 return 1;
}

int ec_weij_point_affine_x(bigint_t x, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0)) return 0;
 if (!bigint_minv(s->v[0], a->z, def->p)) return 0;
 bigint_mmul(s->v[1], s->v[0], s->v[0], def->p);
 bigint_mmul(x, a->x, s->v[1], def->p);
 return 1;
}

void ec_weij_point_mul(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, const bigint_t k, ec_scratch_t *s)
{
 int i, n = bigint_get_bit_count(k);
 bigint_set_word(res->x, 1);
 bigint_set_word(res->y, 1);
 bigint_set_word(res->z, 0); 
 #if 1
 if (ec_weij_point_affine_xy(s->v[8], s->v[9], a, def, s))
 {
  if (def->am3_flag)
   for (i = n-1; i >= 0; i--)
   {
    ec_weij_point_dbl3(res, res, def, s);
    if (bigint_get_bit(k, i)) ec_weij_point_madd(res, res, s->v[8], s->v[9], def, s); 
   }
  else
   for (i = n-1; i >= 0; i--)
   {
    ec_weij_point_dbl(res, res, def, s);
    if (bigint_get_bit(k, i)) ec_weij_point_madd(res, res, s->v[8], s->v[9], def, s); 
   }
 }
 #else
 assert(res != a);
 for (i = n-1; i >= 0; i--)
 {
  ec_weij_point_dbl(res, res, def, s);
  if (bigint_get_bit(k, i))
   ec_weij_point_add(res, res, a, def, s); 
 }
 #endif
 if (bigint_get_sign(k)) ec_wei_point_neg(res);
}
