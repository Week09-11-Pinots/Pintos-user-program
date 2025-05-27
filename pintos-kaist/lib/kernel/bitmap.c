#include "bitmap.h"
#include <debug.h>
#include <limits.h>
#include <round.h>
#include <stdio.h>
#include "threads/malloc.h"
#ifdef FILESYS
#include "filesys/file.h"
#endif

/* 요소 타입.

	이는 int보다 적어도 넓은 비트 폭을 가진 부호 없는 정수 타입이어야 합니다.

	각 비트는 비트맵의 하나의 비트를 나타냅니다.
	만약 요소의 비트 0이 비트맵에서 비트 K를 나타낸다면,
	요소의 비트 1은 비트맵에서 비트 K+1을 나타내며, 계속해서 이어집니다. */
typedef unsigned long elem_type;

/* Number of bits in an element. */
#define ELEM_BITS (sizeof (elem_type) * CHAR_BIT)
/* 외부에서 보면, 비트맵은 비트들의 배열입니다. 내부적으로는, 
	비트들의 배열을 시뮬레이션하는 elem_type(위에서 정의됨)의 배열입니다. */
struct bitmap {
	size_t bit_cnt;     /* Number of bits. */
	elem_type *bits;    /* Elements that represent bits. */
};

/* BIT_IDX 번호의 비트를 포함하는 요소의 인덱스를 반환합니다. */
static inline size_t
elem_idx (size_t bit_idx) {
	return bit_idx / ELEM_BITS;
}

/* BIT_IDX에 해당하는 비트만 켜져 있는 elem_type을 반환합니다. */
static inline elem_type
bit_mask (size_t bit_idx) {
	return (elem_type) 1 << (bit_idx % ELEM_BITS);
}

/* Returns the number of elements required for BIT_CNT bits. */
static inline size_t
elem_cnt (size_t bit_cnt) {
	return DIV_ROUND_UP (bit_cnt, ELEM_BITS);
}

/* Returns the number of bytes required for BIT_CNT bits. */
static inline size_t
byte_cnt (size_t bit_cnt) {
	return sizeof (elem_type) * elem_cnt (bit_cnt);
}

/* B의 비트들 중 마지막 요소에서 실제로 사용된 비트들이 1로 설정되고,
	나머지 비트들은 0으로 설정된 비트 마스크를 반환합니다. */
static inline elem_type
last_mask (const struct bitmap *b) {
	int last_bits = b->bit_cnt % ELEM_BITS;
	return last_bits ? ((elem_type) 1 << last_bits) - 1 : (elem_type) -1;
}

/* 생성 및 소멸. */

/* B를 BIT_CNT 비트의 비트맵으로 초기화하고
	모든 비트를 false로 설정합니다.
	성공하면 true를 반환하고, 메모리 할당에 실패하면
	false를 반환합니다. */
struct bitmap *
bitmap_create (size_t bit_cnt) {
	struct bitmap *b = malloc (sizeof *b);
	if (b != NULL) {
		b->bit_cnt = bit_cnt;
		b->bits = malloc (byte_cnt (bit_cnt));
		if (b->bits != NULL || bit_cnt == 0) {
			bitmap_set_all (b, false);
			return b;
		}
		free (b);
	}
	return NULL;
}

/* BIT_CNT 비트를 가진 비트맵을 생성하고 반환합니다.
	BLOCK에 미리 할당된 BLOCK_SIZE 바이트의 저장소를 사용합니다.
	BLOCK_SIZE는 적어도 bitmap_needed_bytes(BIT_CNT) 이상이어야 합니다. */
struct bitmap *
bitmap_create_in_buf (size_t bit_cnt, void *block, size_t block_size UNUSED) {
	struct bitmap *b = block;

	ASSERT (block_size >= bitmap_buf_size (bit_cnt));

	b->bit_cnt = bit_cnt;
	b->bits = (elem_type *) (b + 1);
	bitmap_set_all (b, false);
	return b;
}

/* BIT_CNT 비트를 가진 비트맵을 수용하는 데 필요한 바이트 수를 반환합니다.
	(bitmap_create_in_buf()에서 사용하기 위해). */
size_t
bitmap_buf_size (size_t bit_cnt) {
	return sizeof (struct bitmap) + byte_cnt (bit_cnt);
}

/* 비트맵 B를 소멸시키고, 그 저장소를 해제합니다.
	bitmap_create_preallocated()에 의해 생성된 비트맵에는 사용하지 마십시오. */
void
bitmap_destroy (struct bitmap *b) {
	if (b != NULL) {
		free (b->bits);
		free (b);
	}
}

/* Bitmap size. */

/* Returns the number of bits in B. */
size_t
bitmap_size (const struct bitmap *b) {
	return b->bit_cnt;
}

/* Setting and testing single bits. */

/* Atomically sets the bit numbered IDX in B to VALUE. */
void
bitmap_set (struct bitmap *b, size_t idx, bool value) {
	ASSERT (b != NULL);
	ASSERT (idx < b->bit_cnt);
	if (value)
		bitmap_mark (b, idx);
	else
		bitmap_reset (b, idx);
}

/* BIT_IDX 번호의 비트를 B에서 true로 원자적으로 설정합니다. */
void
bitmap_mark (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* 이는 `b->bits[idx] |= mask`와 동등하지만, 단일 프로세서 머신에서 원자성을 보장합니다.
	   [IA32-v2b]의 OR 명령어 설명을 참조하십시오. */
	asm ("lock orq %1, %0" : "=m" (b->bits[idx]) : "r" (mask) : "cc");
}

/* BIT_IDX 번호의 비트를 B에서 false로 원자적으로 설정합니다. */
void
bitmap_reset (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* 이는 `b->bits[idx] &= ~mask`와 동등하지만, 단일 프로세서 머신에서 원자성을 보장합니다.
	   [IA32-v2a]의 AND 명령어 설명을 참조하십시오. */
	asm ("lock andq %1, %0" : "=m" (b->bits[idx]) : "r" (~mask) : "cc");
}

/* Atomically toggles the bit numbered IDX in B;
   that is, if it is true, makes it false,
   and if it is false, makes it true. */
void
bitmap_flip (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* 이는 `b->bits[idx] ^= mask`와 동등하지만, 단일 프로세서 머신에서 원자성을 보장합니다.
	   [IA32-v2b]의 XOR 명령어 설명을 참조하십시오. */
	asm ("lock xorq %1, %0" : "=m" (b->bits[idx]) : "r" (mask) : "cc");
}

/* Returns the value of the bit numbered IDX in B. */
bool
bitmap_test (const struct bitmap *b, size_t idx) {
	ASSERT (b != NULL);
	ASSERT (idx < b->bit_cnt);
	return (b->bits[elem_idx (idx)] & bit_mask (idx)) != 0;
}

/* Setting and testing multiple bits. */

/* Sets all bits in B to VALUE. */
void
bitmap_set_all (struct bitmap *b, bool value) {
	ASSERT (b != NULL);

	bitmap_set_multiple (b, 0, bitmap_size (b), value);
}

/* Sets the CNT bits starting at START in B to VALUE. */
void
bitmap_set_multiple (struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		bitmap_set (b, start + i, value);
}

/* B에서 START와 START + CNT 사이(START 포함, START + CNT 제외)의 비트 중
	VALUE로 설정된 비트의 수를 반환합니다. */
size_t
bitmap_count (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i, value_cnt;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	value_cnt = 0;
	for (i = 0; i < cnt; i++)
		if (bitmap_test (b, start + i) == value)
			value_cnt++;
	return value_cnt;
}

/* B에서 START와 START + CNT 사이(START 포함, START + CNT 제외)의 비트 중
	VALUE로 설정된 비트가 하나라도 있으면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool
bitmap_contains (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		if (bitmap_test (b, start + i) == value)
			return true;
	return false;
}

/* B에서 START와 START + CNT 사이(START 포함, START + CNT 제외)의 비트 중
	하나라도 true로 설정된 비트가 있으면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool
bitmap_any (const struct bitmap *b, size_t start, size_t cnt) {
	return bitmap_contains (b, start, cnt, true);
}

/* B에서 START와 START + CNT 사이(START 포함, START + CNT 제외)의 비트 중
	하나라도 true로 설정된 비트가 없으면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool
bitmap_none (const struct bitmap *b, size_t start, size_t cnt) {
	return !bitmap_contains (b, start, cnt, true);
}

/* START와 START + CNT 사이(START 포함, START + CNT 제외)의 모든 비트가
	true로 설정되어 있으면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool
bitmap_all (const struct bitmap *b, size_t start, size_t cnt) {
	return !bitmap_contains (b, start, cnt, false);
}

/* 설정되거나 해제된 비트를 찾기. */

/* B에서 START 이후 CNT개의 연속된 비트가 모두 VALUE로 설정된
	첫 번째 그룹의 시작 인덱스를 찾아 반환합니다.
	그러한 그룹이 없으면 BITMAP_ERROR를 반환합니다. */
size_t
bitmap_scan (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);

	if (cnt <= b->bit_cnt) {
		size_t last = b->bit_cnt - cnt;
		size_t i;
		for (i = start; i <= last; i++)
			if (!bitmap_contains (b, i, cnt, !value))
				return i;
	}
	return BITMAP_ERROR;
}

/* B에서 START 이후 CNT개의 연속된 비트가 모두 VALUE로 설정된
	첫 번째 그룹의 시작 인덱스를 찾아, 모든 비트를 !VALUE로 뒤집고,
	그룹의 첫 번째 비트의 인덱스를 반환합니다.
	그러한 그룹이 없으면 BITMAP_ERROR를 반환합니다.
	CNT가 0이면 0을 반환합니다.
	비트 설정은 원자적으로 수행되지만, 비트 테스트는 설정과 원자적으로 수행되지 않습니다. */
size_t
bitmap_scan_and_flip (struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t idx = bitmap_scan (b, start, cnt, value);
	if (idx != BITMAP_ERROR)
		bitmap_set_multiple (b, idx, cnt, !value);
	return idx;
}

/* File input and output. */

#ifdef FILESYS
/* Returns the number of bytes needed to store B in a file. */
size_t
bitmap_file_size (const struct bitmap *b) {
	return byte_cnt (b->bit_cnt);
}

/* Reads B from FILE.  Returns true if successful, false
   otherwise. */
bool
bitmap_read (struct bitmap *b, struct file *file) {
	bool success = true;
	if (b->bit_cnt > 0) {
		off_t size = byte_cnt (b->bit_cnt);
		success = file_read_at (file, b->bits, size, 0) == size;
		b->bits[elem_cnt (b->bit_cnt) - 1] &= last_mask (b);
	}
	return success;
}

/* Writes B to FILE.  Return true if successful, false
   otherwise. */
bool
bitmap_write (const struct bitmap *b, struct file *file) {
	off_t size = byte_cnt (b->bit_cnt);
	return file_write_at (file, b->bits, size, 0) == size;
}
#endif /* FILESYS */

/* Debugging. */

/* Dumps the contents of B to the console as hexadecimal. */
void
bitmap_dump (const struct bitmap *b) {
	hex_dump (0, b->bits, byte_cnt (b->bit_cnt), false);
}

