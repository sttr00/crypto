#ifndef __curves_wei_h__
#define __curves_wei_h__

#include "ec_wei.h"

struct curve_wei
{
 const char *name;
 int id;
 int bits;
 size_t size;
 const uint8_t *p;
 int a_small;
 const uint8_t *a;
 const uint8_t *x;
 const uint8_t *y;
 const uint8_t *n;
 size_t b_size;
 const uint8_t *b;
};

const curve_wei *get_wei_curve_by_id(int id);
const curve_wei *get_wei_curve_by_name(const char *name);

void init_curve(ec_wei_def_t *def, ec_point_t *g, bigint_t *pn, const curve_wei *params);

#endif
