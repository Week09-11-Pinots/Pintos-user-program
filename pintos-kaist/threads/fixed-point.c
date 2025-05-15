// fixed-point.c

#include "fixed-point.h"
#include <stdint.h> // int64_t 사용

// 변환
fixed_t int_to_fp(int n)
{
    return n * F;
}

int fp_to_int(int x)
{
    return x / F;
}

int fp_to_int_round(int x)
{
    return (x >= 0) ? (x + F / 2) / F : (x - F / 2) / F;
}

// 기본 연산
fixed_t add_fp(int x, int y)
{
    return x + y;
}

fixed_t sub_fp(int x, int y)
{
    return x - y;
}

fixed_t add_fp_int(int x, int n)
{
    return x + n * F;
}

fixed_t sub_fp_int(int x, int n)
{
    return x - n * F;
}

// 곱셈 / 나눗셈
fixed_t mul_fp(int x, int y)
{
    return ((int64_t)x) * y / F;
}

fixed_t mul_fp_int(int x, int n)
{
    return x * n;
}

fixed_t div_fp(int x, int y)
{
    return ((int64_t)x) * F / y;
}

fixed_t div_fp_int(int x, int n)
{
    return x / n;
}
