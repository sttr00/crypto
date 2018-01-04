#include "ec_wei.h"
#include <limits.h>
#include <assert.h>

void ec_wei_def_init(ec_wei_def_t *def, bigint_t p, bigint_t a, bigint_t b)
{
 def->p = p;
 def->a = a;
 def->b = b;
 def->am3_flag = 0;
}

void ec_wei_def_init_small_a(ec_wei_def_t *def, bigint_t p, int a, bigint_t b)
{
 def->p = p;
 def->b = b;
 if (a < 0)
 {
  assert(a != INT_MIN);
  def->a = bigint_create(0);
  bigint_subw(def->a, def->p, -a);
  def->am3_flag = a == -3;
 } else
 {
  def->a = bigint_create_word(a);
  def->am3_flag = 0;
 }
}

void ec_wei_def_destroy(ec_wei_def_t *def)
{
 bigint_destroy(def->p);
 bigint_destroy(def->a);
 bigint_destroy(def->b);
}

void ec_wei_point_init(ec_point_t *a, const ec_wei_def_t *def)
{
 int n = bigint_get_word_count(def->p);
 a->x = bigint_create(n);
 a->y = bigint_create(n);
 a->z = bigint_create(n);
}

void ec_wei_point_init_values(ec_point_t *a, const ec_wei_def_t *def, bigint_t x, bigint_t y)
{
 a->x = x;
 a->y = y;
 a->z = bigint_create_word(1);
}

void ec_wei_point_destroy(ec_point_t *a)
{
 bigint_destroy(a->x);
 bigint_destroy(a->y);
 bigint_destroy(a->z);
}

int ec_wei_point_check(const bigint_t x, const bigint_t y, const ec_wei_def_t *def, ec_scratch_t *s)
{
 if (!def->b) return -1;
 bigint_mmul(s->v[0], x, x, def->p);
 bigint_add(s->v[0], s->v[0], def->a);
 bigint_mmul(s->v[1], s->v[0], x, def->p);
 bigint_madd(s->v[1], s->v[1], def->b, def->p);
 bigint_mmul(s->v[2], y, y, def->p);
 return bigint_cmp(s->v[1], s->v[2]);
}

void ec_wei_point_copy(ec_point_t *res, const ec_point_t *a)
{
 bigint_copy(res->x, a->x);
 bigint_copy(res->y, a->y);
 bigint_copy(res->z, a->z);
}

void ec_wei_point_move(ec_point_t *res, ec_point_t *a)
{
 bigint_move(res->x, a->x);
 bigint_move(res->y, a->y);
 bigint_move(res->z, a->z);
}

void ec_wei_point_neg(ec_point_t *a)
{
 bigint_set_sign(a->y, !bigint_get_sign(a->y));
}

void ec_wei_scratch_init(ec_scratch_t *s, const ec_wei_def_t *def)
{
 int n = bigint_get_word_count(def->p) << 1;
 int i;
 for (i = 0; i < 10; i++) s->v[i] = bigint_create(n);
 #ifndef NDEBUG
 s->max_alloc = 10;
 #endif
}

void ec_wei_scratch_destroy(ec_scratch_t *s)
{
 int i;
 #ifndef NDEBUG
 assert(s->max_alloc == 10);
 #endif
 for (i = 0; i < 10; i++) bigint_destroy(s->v[i]);
}
