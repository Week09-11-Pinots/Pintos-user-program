#ifndef __LIB_KERNEL_LIST_H
#define __LIB_KERNEL_LIST_H

/* 이중 연결 리스트.
 *
 * 이 이중 연결 리스트 구현은 동적으로 할당된 메모리를 필요로 하지 않습니다.
 * 대신, 잠재적인 리스트 요소가 될 각 구조체는 struct list_elem 멤버를 포함해야 합니다.
 * 모든 리스트 함수는 이러한 `struct list_elem`을 기반으로 작동합니다.
 *
 * list_entry 매크로를 사용하면 struct list_elem에서 이를 포함하는 구조체 객체로 변환할 수 있습니다.
 *
 * 예를 들어, `struct foo`의 리스트가 필요하다고 가정해 봅시다.
 * `struct foo`는 다음과 같이 `struct list_elem` 멤버를 포함해야 합니다:
 *
 * struct foo {
 *   struct list_elem elem;
 *   int bar;
 *   ...다른 멤버들...
 * };
 *
 * 그런 다음 `struct foo`의 리스트를 선언하고 초기화할 수 있습니다:
 *
 * struct list foo_list;
 *
 * list_init (&foo_list);
 *
 * 반복(iteration)은 struct list_elem에서 이를 포함하는 구조체로 변환해야 하는 일반적인 상황입니다.
 * 다음은 foo_list를 사용하는 예제입니다:
 *
 * struct list_elem *e;
 *
 * for (e = list_begin (&foo_list); e != list_end (&foo_list);
 * e = list_next (e)) {
 *   struct foo *f = list_entry (e, struct foo, elem);
 *   ...f를 사용하여 작업 수행...
 * }
 *
 * 소스 코드 전체에서 리스트 사용의 실제 예제를 찾을 수 있습니다.
 * 예를 들어, threads 디렉토리의 malloc.c, palloc.c, thread.c 등이 리스트를 사용합니다.
 *
 * 이 리스트의 인터페이스는 C++ STL의 list<> 템플릿에서 영감을 받았습니다.
 * list<>에 익숙하다면 이를 사용하는 것이 쉽습니다.
 * 그러나 이 리스트는 *타입 검사*를 수행하지 않으며 많은 올바름 검사를 수행할 수 없습니다.
 * 실수를 하면 문제가 발생할 수 있습니다.
 *
 * 리스트 용어의 용어집:
 *
 * - "front": 리스트의 첫 번째 요소. 빈 리스트에서는 정의되지 않음. list_front()로 반환됨.
 *
 * - "back": 리스트의 마지막 요소. 빈 리스트에서는 정의되지 않음. list_back()로 반환됨.
 *
 * - "tail": 리스트의 마지막 요소 바로 뒤에 있는 요소. 빈 리스트에서도 잘 정의됨.
 * list_end()로 반환됨. 앞에서 뒤로의 반복(iteration)에서 끝 센티넬로 사용됨.
 *
 * - "beginning": 비어 있지 않은 리스트에서는 front. 빈 리스트에서는 tail.
 * list_begin()으로 반환됨. 앞에서 뒤로의 반복(iteration)의 시작점으로 사용됨.
 *
 * - "head": 리스트의 첫 번째 요소 바로 앞에 있는 요소. 빈 리스트에서도 잘 정의됨.
 * list_rend()로 반환됨. 뒤에서 앞으로의 반복(iteration)에서 끝 센티넬로 사용됨.
 *
 * - "reverse beginning": 비어 있지 않은 리스트에서는 back. 빈 리스트에서는 head.
 * list_rbegin()으로 반환됨. 뒤에서 앞으로의 반복(iteration)의 시작점으로 사용됨.
 *
 * - "interior element": head나 tail이 아닌 요소, 즉 실제 리스트 요소. 빈 리스트에는 내부 요소가 없음.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* List element. */
struct list_elem
{
   struct list_elem *prev; /* Previous list element. */
   struct list_elem *next; /* Next list element. */
};

/* List. */
struct list
{
   struct list_elem head; /* List head. */
   struct list_elem tail; /* List tail. */
};

/* Converts pointer to list element LIST_ELEM into a pointer to
   the structure that LIST_ELEM is embedded inside.  Supply the
   name of the outer structure STRUCT and the member name MEMBER
   of the list element.  See the big comment at the top of the
   file for an example. */
#define list_entry(LIST_ELEM, STRUCT, MEMBER) \
   ((STRUCT *)((uint8_t *)&(LIST_ELEM)->next - offsetof(STRUCT, MEMBER.next)))

void list_init(struct list *);

/* List traversal. */
struct list_elem *list_begin(struct list *);
struct list_elem *list_next(struct list_elem *);
struct list_elem *list_end(struct list *);

struct list_elem *list_rbegin(struct list *);
struct list_elem *list_prev(struct list_elem *);
struct list_elem *list_rend(struct list *);

struct list_elem *list_head(struct list *);
struct list_elem *list_tail(struct list *);

/* List insertion. */
void list_insert(struct list_elem *, struct list_elem *);
void list_splice(struct list_elem *before,
                 struct list_elem *first, struct list_elem *last);
void list_push_front(struct list *, struct list_elem *);
void list_push_back(struct list *, struct list_elem *);

/* List removal. */
struct list_elem *list_remove(struct list_elem *);
struct list_elem *list_pop_front(struct list *);
struct list_elem *list_pop_back(struct list *);

/* List elements. */
struct list_elem *list_front(struct list *);
struct list_elem *list_back(struct list *);

/* List properties. */
size_t list_size(struct list *);
bool list_empty(struct list *);

/* Miscellaneous. */
void list_reverse(struct list *);

/* Compares the value of two list elements A and B, given
   auxiliary data AUX.  Returns true if A is less than B, or
   false if A is greater than or equal to B. */
typedef bool list_less_func(const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux);

/* Operations on lists with ordered elements. */
void list_sort(struct list *,
               list_less_func *, void *aux);
void list_insert_ordered(struct list *, struct list_elem *,
                         list_less_func *, void *aux);
void list_unique(struct list *, struct list *duplicates,
                 list_less_func *, void *aux);

/* Max and min. */
struct list_elem *list_max(struct list *, list_less_func *, void *aux);
struct list_elem *list_min(struct list *, list_less_func *, void *aux);

#endif /* lib/kernel/list.h */
