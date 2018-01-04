#include "ec_weip.h"
#include <assert.h>

/* dbl-2007-bl: 5M + 6S + 1m(a) + 1m(3) */
void ec_weip_point_dbl(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 bigint_mmul(s->v[0], a->x, a->x, def->p);       /* 1S: v0 = XX = x^2            */
 bigint_mmul(s->v[1], a->z, a->z, def->p);       /* 2S: v1 = ZZ = z^2            */
 bigint_mul(s->v[2], s->v[1], def->a);           /* 1m: v2 = a*ZZ                */
 bigint_mulw(s->v[4], s->v[0], 3);               /* 2m: v4 = 3*XX                */
 bigint_madd(s->v[2], s->v[2], s->v[4], def->p); /*     v2 = w = a*ZZ + 3*XX     */
 bigint_lshift(s->v[5], a->y, 1);                /*     v5 = 2*y                 */
 bigint_mmul(s->v[5], s->v[5], a->z, def->p);    /* 1M: v5 = s = 2*y*z           */
 bigint_mmul(s->v[1], s->v[5], s->v[5], def->p); /* 3S: v1 = ss = s^2            */
 bigint_mmul(res->z, s->v[1], s->v[5], def->p);  /* 2M: z' = s^3                 */
 bigint_mmul(s->v[4], a->y, s->v[5], def->p);    /* 3M: v4 = R = y*s             */
 bigint_mmul(s->v[3], s->v[4], s->v[4], def->p); /* 4S: v3 = RR = R^2            */
 bigint_add(s->v[4], s->v[4], a->x);             /*     v4 = x + R               */
 bigint_mmul(s->v[6], s->v[4], s->v[4], def->p); /* 5S: v6 = (x + R)^2           */
 bigint_sub(s->v[6], s->v[6], s->v[0]);          /*     v6 = (x + R)^2-XX        */
 bigint_sub(s->v[6], s->v[6], s->v[3]);          /*     v6 = B = (x + R)^2-XX-RR */
 bigint_lshift(s->v[0], s->v[6], 1);             /*     v0 = 2*B                 */
 bigint_mmul(s->v[1], s->v[2], s->v[2], def->p); /* 6S: v1 = w^2                 */
 bigint_sub(s->v[1], s->v[1], s->v[0]);          /*     v1 = h = w^2 - 2*B       */
 bigint_mmul(res->x, s->v[1], s->v[5], def->p);  /* 4M: x' = h*s                 */
 bigint_sub(s->v[6], s->v[6], s->v[1]);          /*     v6 = B - h               */
 bigint_mmul(res->y, s->v[6], s->v[2], def->p);  /* 5M: y' = w*(B - h)           */
 bigint_lshift(s->v[3], s->v[3], 1);             /*     v3 = 2*RR                */
 bigint_msub(res->y, res->y, s->v[3], def->p);   /*     y' = w*(B - h) - 2*RR    */
}

/* dbl-2007-bl-2: 7M + 3S + 1m(3) */
void ec_weip_point_dbl3(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 bigint_sub(s->v[0], a->x, a->z);                /*     v0 = x - z               */
 bigint_add(s->v[1], a->x, a->z);                /*     v1 = x + z               */
 bigint_mmul(s->v[2], s->v[0], s->v[1], def->p); /* 1M: v2 = (x-z)*(x+z)         */
 bigint_mulw(s->v[2], s->v[2], 3);               /* 1m: v2 = w = 3*(x-z)*(x+z)   */
 bigint_mmul(s->v[3], a->y, a->z, def->p);       /* 2M: v3 = y*z                 */
 bigint_lshift(s->v[3], s->v[3], 1);             /*     v3 = s = 2*y*z           */
 bigint_mmul(s->v[0], s->v[3], s->v[3], def->p); /* 1S: v0 = s^2                 */
 bigint_mmul(res->z, s->v[0], s->v[3], def->p);  /* 3M: z' = s^3                 */
 bigint_mmul(s->v[1], a->y, s->v[3], def->p);    /* 4M: v1 = R = y*s             */
 bigint_mmul(s->v[7], s->v[1], s->v[1], def->p); /* 2S: v7 = RR = R^2            */
 bigint_mmul(s->v[4], a->x, s->v[1], def->p);    /* 5M: v4 = x*R                 */
 bigint_lshift(s->v[4], s->v[4], 1);             /*     v4 = B = 2*x*R           */
 bigint_lshift(s->v[5], s->v[4], 1);             /*     v5 = 2*B                 */
 bigint_mmul(s->v[6], s->v[2], s->v[2], def->p); /* 3S: v6 = w^2                 */
 bigint_sub(s->v[6], s->v[6], s->v[5]);          /*     v6 = h = w^2 - 2*B       */
 bigint_mmul(res->x, s->v[6], s->v[3], def->p);  /* 6M: x' = h*s                 */
 bigint_sub(s->v[4], s->v[4], s->v[6]);          /*     v4 = B - h               */
 bigint_mul(s->v[5], s->v[4], s->v[2]);          /* 7M: v5 = w*(B-h)             */
 bigint_lshift(s->v[7], s->v[7], 1);             /*     v7 = 2*RR                */
 bigint_msub(res->y, s->v[5], s->v[7], def->p);  /*     y' = w*(B-h) - 2*RR      */
}

/* add-1998-cmo-2: 12M + 2S */
void ec_weip_point_add(ec_point_t *res, const ec_point_t *a, const ec_point_t *b, const ec_wei_def_t *def, ec_scratch_t *s)
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
 bigint_mmul(s->v[0], a->y, b->z, def->p);       /*  1M: v0 = y1z2 = y1*z2             */
 bigint_mmul(s->v[1], a->x, b->z, def->p);       /*  2M: v1 = x1z2 = x1*z2             */
 bigint_mmul(s->v[3], b->y, a->z, def->p);       /*  3M: v3 = y2*z1                    */
 bigint_mmul(s->v[5], b->x, a->z, def->p);       /*  4M: v5 = x2*z1                    */
 bigint_sub(s->v[3], s->v[3], s->v[0]);          /*      v3 = u = y2*z1 - y1z2         */
 bigint_sub(s->v[5], s->v[5], s->v[1]);          /*      v5 = v = x2*z1 - x1z2         */
 if (bigint_eq_word(s->v[5], 0))
 {
  if (bigint_eq_word(s->v[3], 0))
  {
   ec_weip_point_dbl(res, a, def, s);   
  } else
  {
   bigint_set_word(res->x, 0);
   bigint_set_word(res->y, 1);
   bigint_set_word(res->z, 0);
  }
  return;
 }
 bigint_mmul(s->v[2], a->z, b->z, def->p);       /*  5M: v2 = z1z2 = z1*z2             */
 bigint_mmul(s->v[4], s->v[3], s->v[3], def->p); /*  1S: v4 = u^2                      */
 bigint_mmul(s->v[6], s->v[5], s->v[5], def->p); /*  2S: v6 = v^2                      */
 bigint_mmul(s->v[7], s->v[6], s->v[5], def->p); /*  6M: v7 = v^3                      */
 bigint_mmul(s->v[6], s->v[6], s->v[1], def->p); /*  7M: v6 = R = v^2*x1z2             */
 bigint_mmul(s->v[4], s->v[4], s->v[2], def->p); /*  8M: v4 = u^2*z1z2                 */
 bigint_mmul(res->z, s->v[7], s->v[2], def->p);  /*  9M: z' = v^3*z1z2                 */
 bigint_lshift(s->v[2], s->v[6], 1);             /*      v2 = 2*R                      */
 bigint_sub(s->v[4], s->v[4], s->v[7]);          /*      v4 = u^2*z1z2 - v^3           */
 bigint_sub(s->v[4], s->v[4], s->v[2]);          /*      v4 = A = u^2*z1z2 - v^3 - 2*R */
 bigint_mmul(res->x, s->v[5], s->v[4], def->p);  /* 10M: x' = v*A                      */
 bigint_sub(s->v[6], s->v[6], s->v[4]);          /*      v6 = R - A                    */
 bigint_mmul(s->v[5], s->v[3], s->v[6], def->p); /* 11M: v5 = u*(R - A)                */
 bigint_mmul(s->v[6], s->v[7], s->v[0], def->p); /* 12M: v6 = v^3*y1z2                 */
 bigint_msub(res->y, s->v[5], s->v[6], def->p);  /*      y' = u*(R - A) - v^3*y1z2     */
}

/* madd-1998-cmo: 9M + 2S */
void ec_weip_point_madd(ec_point_t *res, const ec_point_t *a, const bigint_t bx, const bigint_t by, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0))
 {
  bigint_copy(res->x, bx);
  bigint_copy(res->y, by);
  bigint_set_word(res->z, 1);
  return;
 }
 bigint_mmul(s->v[0], by, a->z, def->p);        /* 1M: v0 = y2*z1               */
 bigint_sub(s->v[0], s->v[0], a->y);            /*     v0 = u = y2*z1 - y1      */
 bigint_mmul(s->v[1], bx, a->z, def->p);        /* 2M: v1 = x2*z1               */
 bigint_sub(s->v[1], s->v[1], a->x);            /*     v1 = v = x2*z1 - x1      */
 if (bigint_eq_word(s->v[1], 0))
 {
  if (bigint_eq_word(s->v[0], 0))
  {
   ec_point_t tmp;
   tmp.x = bx;
   tmp.y = by;
   tmp.z = bigint_create_word(1);
   ec_weip_point_dbl(res, &tmp, def, s); /* TODO: doubling with z=1 */
   bigint_destroy(tmp.z);
  } else
  {
   bigint_set_word(res->x, 0);
   bigint_set_word(res->y, 1);
   bigint_set_word(res->z, 0);
  }
  return;
 }
 bigint_mmul(s->v[2], s->v[0], s->v[0], def->p); /* 1S: v2 = u^2                */
 bigint_mmul(s->v[3], s->v[1], s->v[1], def->p); /* 2S: v3 = v^2                */
 bigint_mmul(s->v[4], s->v[3], s->v[1], def->p); /* 3M: v4 = v^3                */
 bigint_mmul(s->v[5], s->v[3], a->x, def->p);    /* 4M: v5 = R = v^2*x1         */
 bigint_mmul(s->v[6], s->v[2], a->z, def->p);    /* 5M: v6 = u^2*z1             */
 bigint_lshift(s->v[7], s->v[5], 1);             /*     v7 = 2*R                */
 bigint_sub(s->v[6], s->v[6], s->v[4]);          /*     v6 = u^2*z1 - v^3       */
 bigint_sub(s->v[6], s->v[6], s->v[7]);          /*     v6 = A = u^2*z1-v^3-2*R */
 bigint_mmul(res->x, s->v[1], s->v[6], def->p);  /* 6M: x' = v*A                */
 bigint_sub(s->v[5], s->v[5], s->v[6]);          /*     v5 = R - A              */
 bigint_mul(s->v[3], s->v[0], s->v[5]);          /* 7M: v3 = u*(R-A)            */
 bigint_mul(s->v[1], s->v[4], a->y);             /* 8M: v1 = v^3*y1             */
 bigint_msub(res->y, s->v[3], s->v[1], def->p);  /*     y' = u*(R-A) - v^3*y1   */
 bigint_mmul(res->z, s->v[4], a->z, def->p);     /* 9M: z' = v^3*z1             */
}

int ec_weip_point_normalize(ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0) || !bigint_minv(s->v[0], a->z, def->p))
 {
  bigint_set_word(a->x, 0);
  bigint_set_word(a->y, 1);
  return 0;
 }
 bigint_mmul(a->x, a->x, s->v[0], def->p);
 bigint_mmul(a->y, a->y, s->v[0], def->p);
 bigint_set_word(a->z, 1);
 return 1;
}

int ec_weip_point_affine_xy(bigint_t x, bigint_t y, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0)) return 0;
 if (!bigint_minv(s->v[0], a->z, def->p)) return 0;
 bigint_mmul(x, a->x, s->v[0], def->p);
 bigint_mmul(y, a->y, s->v[0], def->p);
 return 1;
}

int ec_weip_point_affine_x(bigint_t x, const ec_point_t *a, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (bigint_eq_word(a->z, 0)) return 0;
 if (!bigint_minv(s->v[0], a->z, def->p)) return 0;
 bigint_mmul(x, a->x, s->v[0], def->p);
 return 1;
}

void ec_weip_point_mul(ec_point_t *res, const ec_point_t *a, const ec_wei_def_t *def, const bigint_t k, ec_scratch_t *s)
{
 int i, n = bigint_get_bit_count(k);
 bigint_set_word(res->x, 0);
 bigint_set_word(res->y, 1);
 bigint_set_word(res->z, 0); 
 #if 1
 if (ec_weip_point_affine_xy(s->v[8], s->v[9], a, def, s))
 {
  if (def->am3_flag)
   for (i = n-1; i >= 0; i--)
   {
    ec_weip_point_dbl3(res, res, def, s);
    if (bigint_get_bit(k, i)) ec_weip_point_madd(res, res, s->v[8], s->v[9], def, s); 
   }
  else
   for (i = n-1; i >= 0; i--)
   {
    ec_weip_point_dbl(res, res, def, s);
    if (bigint_get_bit(k, i)) ec_weip_point_madd(res, res, s->v[8], s->v[9], def, s); 
   }
 }
 #else
 assert(res != a);
 for (i = n-1; i >= 0; i--)
 {
  ec_weip_point_dbl(res, res, def, s);
  if (bigint_get_bit(k, i))
   ec_weip_point_add(res, res, a, def, s); 
 }
 #endif
 if (bigint_get_sign(k)) ec_wei_point_neg(res);
}
