#ifndef THREADS_PTE_H
#define THREADS_PTE_H

#include "threads/vaddr.h"

/* x86 하드웨어 페이지 테이블을 다루는 함수와 매크로입니다.
 * 보다 일반적인 가상 주소 함수와 매크로는 vaddr.h를 참고하세요.
 *
 * 가상 주소는 다음과 같이 구성됩니다:
 *  63          48 47            39 38            30 29            21 20         12 11         0
 * +-------------+----------------+----------------+----------------+-------------+------------+
 * | 부호 확장   | 페이지 맵      | 페이지 디렉터리| 페이지 디렉터리| 페이지 테이블|  물리 오프셋|
 * |             | 레벨-4 오프셋  | 포인터         | 오프셋         | 오프셋       |   오프셋    |
 * +-------------+----------------+----------------+----------------+-------------+------------+
 *               |                |                |                |             |
 *               +------- 9 ------+------- 9 ------+------- 9 ------+----- 9 -----+---- 12 ----+
 *                                         가상 주소
 */

/*
 * x86-64 가상 주소에서 각 페이지 테이블 인덱스를 추출하는 매크로 정의
 *
 * PML4SHIFT, PDPESHIFT, PDXSHIFT, PTXSHIFT:
 *   - 각각 PML4, PDPE, PD, PT 인덱스를 얻기 위해 비트를 쉬프트하는 값
 *   - x86-64 가상 주소 체계에서 각 레벨의 인덱스 위치를 정의
 *
 * PML4(la):
 *   - 가상 주소 la에서 PML4 인덱스를 추출 (39~47비트)
 *
 * PDPE(la):
 *   - 가상 주소 la에서 PDPE 인덱스를 추출 (30~38비트)
 *
 * PDX(la):
 *   - 가상 주소 la에서 PD 인덱스를 추출 (21~29비트)
 *
 * PTX(la):
 *   - 가상 주소 la에서 PT 인덱스를 추출 (12~20비트)
 *
 * PTE_ADDR(pte):
 *   - 페이지 테이블 엔트리(pte)에서 물리 주소 부분만 추출 (하위 12비트 마스킹)
 */
#define PML4SHIFT 39UL
#define PDPESHIFT 30UL
#define PDXSHIFT 21UL
#define PTXSHIFT 12UL

#define PML4(la) ((((uint64_t)(la)) >> PML4SHIFT) & 0x1FF)
#define PDPE(la) ((((uint64_t)(la)) >> PDPESHIFT) & 0x1FF)
#define PDX(la) ((((uint64_t)(la)) >> PDXSHIFT) & 0x1FF)
#define PTX(la) ((((uint64_t)(la)) >> PTXSHIFT) & 0x1FF)
#define PTE_ADDR(pte) ((uint64_t)(pte) & ~0xFFF)

/* 아래에 중요한 플래그들이 나열되어 있습니다.
   PDE 또는 PTE가 "present" 상태가 아니면, 다른 플래그들은 무시됩니다.
   0으로 초기화된 PDE 또는 PTE는 "not present"로 해석되며, 이는 문제가 되지 않습니다. */
#define PTE_FLAGS 0x00000000000000fffUL     /* Flag bits. */
#define PTE_ADDR_MASK 0xffffffffffffff000UL /* Address bits. */
#define PTE_AVL 0x00000e00                  /* Bits available for OS use. */
#define PTE_P 0x1                           /* 1=present, 0=not present. */
#define PTE_W 0x2                           /* 1=read/write, 0=read-only. */
#define PTE_U 0x4                           /* 1=user/kernel, 0=kernel only. */
#define PTE_A 0x20                          /* 1=accessed, 0=not acccessed. */
#define PTE_D 0x40                          /* 1=dirty, 0=not dirty (PTEs only). */

#endif /* threads/pte.h */
