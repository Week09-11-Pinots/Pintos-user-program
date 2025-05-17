#include <string.h>
#include <debug.h>

/* Copies SIZE bytes from SRC to DST, which must not overlap.
   Returns DST. */
void *
memcpy(void *dst_, const void *src_, size_t size)
{
	unsigned char *dst = dst_;
	const unsigned char *src = src_;

	ASSERT(dst != NULL || size == 0);
	ASSERT(src != NULL || size == 0);

	while (size-- > 0)
		*dst++ = *src++;

	return dst_;
}

/* Copies SIZE bytes from SRC to DST, which are allowed to
   overlap.  Returns DST. */
void *
memmove(void *dst_, const void *src_, size_t size)
{
	unsigned char *dst = dst_;
	const unsigned char *src = src_;

	ASSERT(dst != NULL || size == 0);
	ASSERT(src != NULL || size == 0);

	if (dst < src)
	{
		while (size-- > 0)
			*dst++ = *src++;
	}
	else
	{
		dst += size;
		src += size;
		while (size-- > 0)
			*--dst = *--src;
	}

	return dst;
}

/* Find the first differing byte in the two blocks of SIZE bytes
   at A and B.  Returns a positive value if the byte in A is
   greater, a negative value if the byte in B is greater, or zero
   if blocks A and B are equal. */
int memcmp(const void *a_, const void *b_, size_t size)
{
	const unsigned char *a = a_;
	const unsigned char *b = b_;

	ASSERT(a != NULL || size == 0);
	ASSERT(b != NULL || size == 0);

	for (; size-- > 0; a++, b++)
		if (*a != *b)
			return *a > *b ? +1 : -1;
	return 0;
}

/* Finds the first differing characters in strings A and B.
   Returns a positive value if the character in A (as an unsigned
   char) is greater, a negative value if the character in B (as
   an unsigned char) is greater, or zero if strings A and B are
   equal. */
int strcmp(const char *a_, const char *b_)
{
	const unsigned char *a = (const unsigned char *)a_;
	const unsigned char *b = (const unsigned char *)b_;

	ASSERT(a != NULL);
	ASSERT(b != NULL);

	while (*a != '\0' && *a == *b)
	{
		a++;
		b++;
	}

	return *a < *b ? -1 : *a > *b;
}

/* Returns a pointer to the first occurrence of CH in the first
   SIZE bytes starting at BLOCK.  Returns a null pointer if CH
   does not occur in BLOCK. */
void *
memchr(const void *block_, int ch_, size_t size)
{
	const unsigned char *block = block_;
	unsigned char ch = ch_;

	ASSERT(block != NULL || size == 0);

	for (; size-- > 0; block++)
		if (*block == ch)
			return (void *)block;

	return NULL;
}

/* Finds and returns the first occurrence of C in STRING, or a
   null pointer if C does not appear in STRING.  If C == '\0'
   then returns a pointer to the null terminator at the end of
   STRING. */
char *
strchr(const char *string, int c_)
{
	char c = c_;

	ASSERT(string);

	for (;;)
		if (*string == c)
			return (char *)string;
		else if (*string == '\0')
			return NULL;
		else
			string++;
}

/* Returns the length of the initial substring of STRING that
   consists of characters that are not in STOP. */
size_t
strcspn(const char *string, const char *stop)
{
	size_t length;

	for (length = 0; string[length] != '\0'; length++)
		if (strchr(stop, string[length]) != NULL)
			break;
	return length;
}

/* Returns a pointer to the first character in STRING that is
   also in STOP.  If no character in STRING is in STOP, returns a
   null pointer. */
char *
strpbrk(const char *string, const char *stop)
{
	for (; *string != '\0'; string++)
		if (strchr(stop, *string) != NULL)
			return (char *)string;
	return NULL;
}

/* Returns a pointer to the last occurrence of C in STRING.
   Returns a null pointer if C does not occur in STRING. */
char *
strrchr(const char *string, int c_)
{
	char c = c_;
	const char *p = NULL;

	for (; *string != '\0'; string++)
		if (*string == c)
			p = string;
	return (char *)p;
}

/* Returns the length of the initial substring of STRING that
   consists of characters in SKIP. */
size_t
strspn(const char *string, const char *skip)
{
	size_t length;

	for (length = 0; string[length] != '\0'; length++)
		if (strchr(skip, string[length]) == NULL)
			break;
	return length;
}

/* Returns a pointer to the first occurrence of NEEDLE within
   HAYSTACK.  Returns a null pointer if NEEDLE does not exist
   within HAYSTACK. */
char *
strstr(const char *haystack, const char *needle)
{
	size_t haystack_len = strlen(haystack);
	size_t needle_len = strlen(needle);

	if (haystack_len >= needle_len)
	{
		size_t i;

		for (i = 0; i <= haystack_len - needle_len; i++)
			if (!memcmp(haystack + i, needle, needle_len))
				return (char *)haystack + i;
	}

	return NULL;
}

/* 문자열을 DELIMITERS(구분자)로 분할합니다.
	이 함수를 처음 호출할 때 S에는 토큰화할 문자열을 전달해야 하며,
	이후 호출에서는 반드시 NULL 포인터를 전달해야 합니다.
	SAVE_PTR는 토크나이저의 위치를 추적하는 데 사용되는 `char *` 변수의 주소입니다.
	각 호출 시 반환값은 문자열의 다음 토큰이며, 더 이상 토큰이 없으면 NULL 포인터를 반환합니다.

	이 함수는 여러 개의 인접한 구분자를 하나의 구분자로 처리합니다.
	반환되는 토큰의 길이는 0이 될 수 없습니다.
	DELIMITERS는 한 문자열 내에서 호출마다 변경될 수 있습니다.

	strtok_r()는 문자열 S를 수정하여 구분자를 널 바이트로 변경합니다.
	따라서 S는 수정 가능한 문자열이어야 합니다.
	특히 문자열 리터럴은 C에서 수정이 불가능하므로 사용하면 안 됩니다.
	(호환성 때문에 const가 아니지만, 실제로는 수정 불가)

	사용 예시:

	char s[] = "  String to  tokenize. ";
	char *token, *save_ptr;

	for (token = strtok_r (s, " ", &save_ptr); token != NULL;
		  token = strtok_r (NULL, " ", &save_ptr))
	  printf ("'%s'\n", token);

	출력 결과:

	'String'
	'to'
	'tokenize.'
*/
char *
strtok_r(char *s, const char *delimiters, char **save_ptr)
{
	char *token;

	ASSERT(delimiters != NULL);
	ASSERT(save_ptr != NULL);

	/* S가 NULL이 아니면 S에서 시작합니다.
	   S가 NULL이면 저장된 위치에서 시작합니다. */
	if (s == NULL)
		s = *save_ptr;
	ASSERT(s != NULL);

	/* 현재 위치에서 모든 DELIMITERS(구분자)를 건너뜁니다. */
	while (strchr(delimiters, *s) != NULL)
	{
		/* 만약 null 바이트('\0')를 찾고 있다면, 모든 문자열은 끝에 null 바이트를
		   포함하므로 strchr()는 항상 NULL이 아닌 값을 반환합니다. */
		if (*s == '\0')
		{
			*save_ptr = s;
			return NULL;
		}

		s++;
	}

	/* 문자열 끝까지 DELIMITERS가 아닌 문자를 건너뜁니다. */
	token = s;
	while (strchr(delimiters, *s) == NULL)
		s++;
	if (*s != '\0')
	{
		*s = '\0';
		*save_ptr = s + 1;
	}
	else
		*save_ptr = s;
	return token;
}

/* Sets the SIZE bytes in DST to VALUE. */
void *
memset(void *dst_, int value, size_t size)
{
	unsigned char *dst = dst_;

	ASSERT(dst != NULL || size == 0);

	while (size-- > 0)
		*dst++ = value;

	return dst_;
}

/* Returns the length of STRING. */
size_t
strlen(const char *string)
{
	const char *p;

	ASSERT(string);

	for (p = string; *p != '\0'; p++)
		continue;
	return p - string;
}

/* If STRING is less than MAXLEN characters in length, returns
   its actual length.  Otherwise, returns MAXLEN. */
size_t
strnlen(const char *string, size_t maxlen)
{
	size_t length;

	for (length = 0; string[length] != '\0' && length < maxlen; length++)
		continue;
	return length;
}

/* Copies string SRC to DST.  If SRC is longer than SIZE - 1
   characters, only SIZE - 1 characters are copied.  A null
   terminator is always written to DST, unless SIZE is 0.
   Returns the length of SRC, not including the null terminator.

   strlcpy() is not in the standard C library, but it is an
   increasingly popular extension.  See
http://www.courtesan.com/todd/papers/strlcpy.html for
information on strlcpy(). */
size_t
strlcpy(char *dst, const char *src, size_t size)
{
	size_t src_len;

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	src_len = strlen(src);
	if (size > 0)
	{
		size_t dst_len = size - 1;
		if (src_len < dst_len)
			dst_len = src_len;
		memcpy(dst, src, dst_len);
		dst[dst_len] = '\0';
	}
	return src_len;
}

/* Concatenates string SRC to DST.  The concatenated string is
   limited to SIZE - 1 characters.  A null terminator is always
   written to DST, unless SIZE is 0.  Returns the length that the
   concatenated string would have assuming that there was
   sufficient space, not including a null terminator.

   strlcat() is not in the standard C library, but it is an
   increasingly popular extension.  See
http://www.courtesan.com/todd/papers/strlcpy.html for
information on strlcpy(). */
size_t
strlcat(char *dst, const char *src, size_t size)
{
	size_t src_len, dst_len;

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	src_len = strlen(src);
	dst_len = strlen(dst);
	if (size > 0 && dst_len < size)
	{
		size_t copy_cnt = size - dst_len - 1;
		if (src_len < copy_cnt)
			copy_cnt = src_len;
		memcpy(dst + dst_len, src, copy_cnt);
		dst[dst_len + copy_cnt] = '\0';
	}
	return src_len + dst_len;
}
