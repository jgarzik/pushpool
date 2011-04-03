#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct elist_head {
	struct elist_head *next, *prev;
};

#define ELIST_HEAD_INIT(name) { &(name), &(name) }

#define ELIST_HEAD(name) \
	struct elist_head name = ELIST_HEAD_INIT(name)

#define INIT_ELIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct elist_head *new,
			      struct elist_head *prev,
			      struct elist_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * elist_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void elist_add(struct elist_head *new, struct elist_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * elist_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void elist_add_tail(struct elist_head *new, struct elist_head *head)
{
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct elist_head *prev, struct elist_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * elist_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: elist_empty on entry does not return true after this, the entry is in an undefined state.
 */
static inline void elist_del(struct elist_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (void *) 0;
	entry->prev = (void *) 0;
}

/**
 * elist_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void elist_del_init(struct elist_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_ELIST_HEAD(entry);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void list_move(struct elist_head *list, struct elist_head *head)
{
        __list_del(list->prev, list->next);
        elist_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct elist_head *list,
				  struct elist_head *head)
{
        __list_del(list->prev, list->next);
        elist_add_tail(list, head);
}

/**
 * elist_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int elist_empty(struct elist_head *head)
{
	return head->next == head;
}

static inline void __list_splice(struct elist_head *list,
				 struct elist_head *head)
{
	struct elist_head *first = list->next;
	struct elist_head *last = list->prev;
	struct elist_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(struct elist_head *list, struct elist_head *head)
{
	if (!elist_empty(list))
		__list_splice(list, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct elist_head *list,
				    struct elist_head *head)
{
	if (!elist_empty(list)) {
		__list_splice(list, head);
		INIT_ELIST_HEAD(list);
	}
}

/**
 * elist_entry - get the struct for this entry
 * @ptr:	the &struct elist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define elist_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * elist_for_each	-	iterate over a list
 * @pos:	the &struct elist_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define elist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next)
/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct elist_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
        	pos = pos->prev)

/**
 * list_for_each_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct elist_head to use as a loop counter.
 * @n:		another &struct elist_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * elist_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define elist_for_each_entry(pos, head, member)				\
	for (pos = elist_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = elist_entry(pos->member.next, typeof(*pos), member))

/**
 * elist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define elist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = elist_entry((head)->next, typeof(*pos), member),	\
		n = elist_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = elist_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_continue -       iterate over list of given type
 *                      continuing after existing point
 * @pos:        the type * to use as a loop counter.
 * @head:       the head for your list.
 * @member:     the name of the list_struct within the struct.
 */
#define list_for_each_entry_continue(pos, head, member)			\
	for (pos = elist_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head);					\
	     pos = elist_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))

#endif
