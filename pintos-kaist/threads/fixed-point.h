#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define F (1 << 14) // 17.14 고정소수점 포맷의 스케일 팩터

typedef int fixed_t;

// 변환
fixed_t int_to_fp(int n);       // 정수 -> 고정소수점
int fp_to_int(fixed_t x);       // 고정소수점 -> 정수 (내림)
int fp_to_int_round(fixed_t x); // 고정소수점 -> 정수 (반올림)

// 기본 연산
fixed_t add_fp(fixed_t x, fixed_t y); // x + y
fixed_t sub_fp(fixed_t x, fixed_t y); // x - y
fixed_t add_fp_int(fixed_t x, int n); // x + n
fixed_t sub_fp_int(fixed_t x, int n); // x - n

// 곱셈/나눗셈
fixed_t mul_fp(fixed_t x, fixed_t y); // x * y
fixed_t mul_fp_int(fixed_t x, int n); // x * n
fixed_t div_fp(fixed_t x, fixed_t y); // x / y
fixed_t div_fp_int(fixed_t x, int n); // x / n

#endif
