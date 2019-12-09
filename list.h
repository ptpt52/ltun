/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <stddef.h>

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

struct dlist_head {
	struct dlist_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

/*
 * Simple doubly linked dlist implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole dlists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

#define DLIST_HEAD_INIT(name) { &(name), &(name) }

#define DLIST_HEAD(name) \
	struct dlist_head name = DLIST_HEAD_INIT(name)

static inline void INIT_DLIST_HEAD(struct dlist_head *dlist)
{
	dlist->next = dlist;
	dlist->prev = dlist;
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal dlist manipulation where we know
 * the prev/next entries already!
 */
static inline void __dlist_add(struct dlist_head *new,
			      struct dlist_head *prev,
			      struct dlist_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * dlist_add - add a new entry
 * @new: new entry to be added
 * @head: dlist head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void dlist_add(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head, head->next);
}


/**
 * dlist_add_tail - add a new entry
 * @new: new entry to be added
 * @head: dlist head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void dlist_add_tail(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head->prev, head);
}

/*
 * Delete a dlist entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal dlist manipulation where we know
 * the prev/next entries already!
 */
static inline void __dlist_del(struct dlist_head * prev, struct dlist_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * dlist_del - deletes entry from dlist.
 * @entry: the element to delete from the dlist.
 * Note: dlist_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __dlist_del_entry(struct dlist_head *entry)
{
	__dlist_del(entry->prev, entry->next);
}

static inline void dlist_del(struct dlist_head *entry)
{
	__dlist_del_entry(entry);
	entry->next = NULL;
	entry->prev = NULL;
}

/**
 * dlist_replace - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void dlist_replace(struct dlist_head *old,
				struct dlist_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
}

static inline void dlist_replace_init(struct dlist_head *old,
					struct dlist_head *new)
{
	dlist_replace(old, new);
	INIT_DLIST_HEAD(old);
}

/**
 * dlist_swap - replace entry1 with entry2 and re-add entry1 at entry2's position
 * @entry1: the location to place entry2
 * @entry2: the location to place entry1
 */
static inline void dlist_swap(struct dlist_head *entry1,
			     struct dlist_head *entry2)
{
	struct dlist_head *pos = entry2->prev;

	dlist_del(entry2);
	dlist_replace(entry1, entry2);
	if (pos == entry1)
		pos = entry2;
	dlist_add(entry1, pos);
}

/**
 * dlist_del_init - deletes entry from dlist and reinitialize it.
 * @entry: the element to delete from the dlist.
 */
static inline void dlist_del_init(struct dlist_head *entry)
{
	__dlist_del_entry(entry);
	INIT_DLIST_HEAD(entry);
}

/**
 * dlist_move - delete from one dlist and add as another's head
 * @dlist: the entry to move
 * @head: the head that will precede our entry
 */
static inline void dlist_move(struct dlist_head *dlist, struct dlist_head *head)
{
	__dlist_del_entry(dlist);
	dlist_add(dlist, head);
}

/**
 * dlist_move_tail - delete from one dlist and add as another's tail
 * @dlist: the entry to move
 * @head: the head that will follow our entry
 */
static inline void dlist_move_tail(struct dlist_head *dlist,
				  struct dlist_head *head)
{
	__dlist_del_entry(dlist);
	dlist_add_tail(dlist, head);
}

/**
 * dlist_bulk_move_tail - move a subsection of a dlist to its tail
 * @head: the head that will follow our entry
 * @first: first entry to move
 * @last: last entry to move, can be the same as first
 *
 * Move all entries between @first and including @last before @head.
 * All three entries must belong to the same linked dlist.
 */
static inline void dlist_bulk_move_tail(struct dlist_head *head,
				       struct dlist_head *first,
				       struct dlist_head *last)
{
	first->prev->next = last->next;
	last->next->prev = first->prev;

	head->prev->next = first;
	first->prev = head->prev;

	last->next = head;
	head->prev = last;
}

/**
 * dlist_is_first -- tests whether @dlist is the first entry in dlist @head
 * @dlist: the entry to test
 * @head: the head of the dlist
 */
static inline int dlist_is_first(const struct dlist_head *dlist,
					const struct dlist_head *head)
{
	return dlist->prev == head;
}

/**
 * dlist_is_last - tests whether @dlist is the last entry in dlist @head
 * @dlist: the entry to test
 * @head: the head of the dlist
 */
static inline int dlist_is_last(const struct dlist_head *dlist,
				const struct dlist_head *head)
{
	return dlist->next == head;
}

/**
 * dlist_empty - tests whether a dlist is empty
 * @head: the dlist to test.
 */
static inline int dlist_empty(const struct dlist_head *head)
{
	return head->next == head;
}

/**
 * dlist_empty_careful - tests whether a dlist is empty and not being modified
 * @head: the dlist to test
 *
 * Description:
 * tests whether a dlist is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using dlist_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the dlist entry is dlist_del_init(). Eg. it cannot be used
 * if another CPU could re-dlist_add() it.
 */
static inline int dlist_empty_careful(const struct dlist_head *head)
{
	struct dlist_head *next = head->next;
	return (next == head) && (next == head->prev);
}

/**
 * dlist_rotate_left - rotate the dlist to the left
 * @head: the head of the dlist
 */
static inline void dlist_rotate_left(struct dlist_head *head)
{
	struct dlist_head *first;

	if (!dlist_empty(head)) {
		first = head->next;
		dlist_move_tail(first, head);
	}
}

/**
 * dlist_rotate_to_front() - Rotate dlist to specific item.
 * @dlist: The desired new front of the dlist.
 * @head: The head of the dlist.
 *
 * Rotates dlist so that @dlist becomes the new front of the dlist.
 */
static inline void dlist_rotate_to_front(struct dlist_head *dlist,
					struct dlist_head *head)
{
	/*
	 * Deletes the dlist head from the dlist denoted by @head and
	 * places it as the tail of @dlist, this effectively rotates the
	 * dlist so that @dlist is at the front.
	 */
	dlist_move_tail(head, dlist);
}

/**
 * dlist_is_singular - tests whether a dlist has just one entry.
 * @head: the dlist to test.
 */
static inline int dlist_is_singular(const struct dlist_head *head)
{
	return !dlist_empty(head) && (head->next == head->prev);
}

static inline void __dlist_cut_position(struct dlist_head *dlist,
		struct dlist_head *head, struct dlist_head *entry)
{
	struct dlist_head *new_first = entry->next;
	dlist->next = head->next;
	dlist->next->prev = dlist;
	dlist->prev = entry;
	entry->next = dlist;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * dlist_cut_position - cut a dlist into two
 * @dlist: a new dlist to add all removed entries
 * @head: a dlist with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the dlist
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @dlist. You should
 * pass on @entry an element you know is on @head. @dlist
 * should be an empty dlist or a dlist you do not care about
 * losing its data.
 *
 */
static inline void dlist_cut_position(struct dlist_head *dlist,
		struct dlist_head *head, struct dlist_head *entry)
{
	if (dlist_empty(head))
		return;
	if (dlist_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_DLIST_HEAD(dlist);
	else
		__dlist_cut_position(dlist, head, entry);
}

/**
 * dlist_cut_before - cut a dlist into two, before given entry
 * @dlist: a new dlist to add all removed entries
 * @head: a dlist with entries
 * @entry: an entry within head, could be the head itself
 *
 * This helper moves the initial part of @head, up to but
 * excluding @entry, from @head to @dlist.  You should pass
 * in @entry an element you know is on @head.  @dlist should
 * be an empty dlist or a dlist you do not care about losing
 * its data.
 * If @entry == @head, all entries on @head are moved to
 * @dlist.
 */
static inline void dlist_cut_before(struct dlist_head *dlist,
				   struct dlist_head *head,
				   struct dlist_head *entry)
{
	if (head->next == entry) {
		INIT_DLIST_HEAD(dlist);
		return;
	}
	dlist->next = head->next;
	dlist->next->prev = dlist;
	dlist->prev = entry->prev;
	dlist->prev->next = dlist;
	head->next = entry;
	entry->prev = head;
}

static inline void __dlist_splice(const struct dlist_head *dlist,
				 struct dlist_head *prev,
				 struct dlist_head *next)
{
	struct dlist_head *first = dlist->next;
	struct dlist_head *last = dlist->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * dlist_splice - join two dlists, this is designed for stacks
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 */
static inline void dlist_splice(const struct dlist_head *dlist,
				struct dlist_head *head)
{
	if (!dlist_empty(dlist))
		__dlist_splice(dlist, head, head->next);
}

/**
 * dlist_splice_tail - join two dlists, each dlist being a queue
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 */
static inline void dlist_splice_tail(struct dlist_head *dlist,
				struct dlist_head *head)
{
	if (!dlist_empty(dlist))
		__dlist_splice(dlist, head->prev, head);
}

/**
 * dlist_splice_init - join two dlists and reinitialise the emptied dlist.
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 *
 * The dlist at @dlist is reinitialised
 */
static inline void dlist_splice_init(struct dlist_head *dlist,
				    struct dlist_head *head)
{
	if (!dlist_empty(dlist)) {
		__dlist_splice(dlist, head, head->next);
		INIT_DLIST_HEAD(dlist);
	}
}

/**
 * dlist_splice_tail_init - join two dlists and reinitialise the emptied dlist
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 *
 * Each of the dlists is a queue.
 * The dlist at @dlist is reinitialised
 */
static inline void dlist_splice_tail_init(struct dlist_head *dlist,
					 struct dlist_head *head)
{
	if (!dlist_empty(dlist)) {
		__dlist_splice(dlist, head->prev, head);
		INIT_DLIST_HEAD(dlist);
	}
}

/**
 * dlist_entry - get the struct for this entry
 * @ptr:	the &struct dlist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * dlist_first_entry - get the first element from a dlist
 * @ptr:	the dlist head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the dlist_head within the struct.
 *
 * Note, that dlist is expected to be not empty.
 */
#define dlist_first_entry(ptr, type, member) \
	dlist_entry((ptr)->next, type, member)

/**
 * dlist_last_entry - get the last element from a dlist
 * @ptr:	the dlist head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the dlist_head within the struct.
 *
 * Note, that dlist is expected to be not empty.
 */
#define dlist_last_entry(ptr, type, member) \
	dlist_entry((ptr)->prev, type, member)

/**
 * dlist_first_entry_or_null - get the first element from a dlist
 * @ptr:	the dlist head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the dlist_head within the struct.
 *
 * Note that if the dlist is empty, it returns NULL.
 */
#define dlist_first_entry_or_null(ptr, type, member) ({ \
	struct dlist_head *head__ = (ptr); \
	struct dlist_head *pos__ = head__->next; \
	pos__ != head__ ? dlist_entry(pos__, type, member) : NULL; \
})

/**
 * dlist_next_entry - get the next element in dlist
 * @pos:	the type * to cursor
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_next_entry(pos, member) \
	dlist_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * dlist_prev_entry - get the prev element in dlist
 * @pos:	the type * to cursor
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_prev_entry(pos, member) \
	dlist_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * dlist_for_each	-	iterate over a dlist
 * @pos:	the &struct dlist_head to use as a loop cursor.
 * @head:	the head for your dlist.
 */
#define dlist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * dlist_for_each_prev	-	iterate over a dlist backwards
 * @pos:	the &struct dlist_head to use as a loop cursor.
 * @head:	the head for your dlist.
 */
#define dlist_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * dlist_for_each_safe - iterate over a dlist safe against removal of dlist entry
 * @pos:	the &struct dlist_head to use as a loop cursor.
 * @n:		another &struct dlist_head to use as temporary storage
 * @head:	the head for your dlist.
 */
#define dlist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * dlist_for_each_prev_safe - iterate over a dlist backwards safe against removal of dlist entry
 * @pos:	the &struct dlist_head to use as a loop cursor.
 * @n:		another &struct dlist_head to use as temporary storage
 * @head:	the head for your dlist.
 */
#define dlist_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)

/**
 * dlist_for_each_entry	-	iterate over dlist of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_for_each_entry(pos, head, member)				\
	for (pos = dlist_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = dlist_next_entry(pos, member))

/**
 * dlist_for_each_entry_reverse - iterate backwards over dlist of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_for_each_entry_reverse(pos, head, member)			\
	for (pos = dlist_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = dlist_prev_entry(pos, member))

/**
 * dlist_prepare_entry - prepare a pos entry for use in dlist_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the dlist
 * @member:	the name of the dlist_head within the struct.
 *
 * Prepares a pos entry for use as a start point in dlist_for_each_entry_continue().
 */
#define dlist_prepare_entry(pos, head, member) \
	((pos) ? : dlist_entry(head, typeof(*pos), member))

/**
 * dlist_for_each_entry_continue - continue iteration over dlist of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Continue to iterate over dlist of given type, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue(pos, head, member) 		\
	for (pos = dlist_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = dlist_next_entry(pos, member))

/**
 * dlist_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Start to iterate over dlist of given type backwards, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = dlist_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = dlist_prev_entry(pos, member))

/**
 * dlist_for_each_entry_from - iterate over dlist of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Iterate over dlist of given type, continuing from current position.
 */
#define dlist_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = dlist_next_entry(pos, member))

/**
 * dlist_for_each_entry_from_reverse - iterate backwards over dlist of given type
 *                                    from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Iterate backwards over dlist of given type, continuing from current position.
 */
#define dlist_for_each_entry_from_reverse(pos, head, member)		\
	for (; &pos->member != (head);					\
	     pos = dlist_prev_entry(pos, member))

/**
 * dlist_for_each_entry_safe - iterate over dlist of given type safe against removal of dlist entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 */
#define dlist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = dlist_first_entry(head, typeof(*pos), member),	\
		n = dlist_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_next_entry(n, member))

/**
 * dlist_for_each_entry_safe_continue - continue dlist iteration safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Iterate over dlist of given type, continuing after current point,
 * safe against removal of dlist entry.
 */
#define dlist_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = dlist_next_entry(pos, member), 				\
		n = dlist_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = dlist_next_entry(n, member))

/**
 * dlist_for_each_entry_safe_from - iterate over dlist from current point safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Iterate over dlist of given type from current point, safe against
 * removal of dlist entry.
 */
#define dlist_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = dlist_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = dlist_next_entry(n, member))

/**
 * dlist_for_each_entry_safe_reverse - iterate backwards over dlist safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_head within the struct.
 *
 * Iterate backwards over dlist of given type, safe against removal
 * of dlist entry.
 */
#define dlist_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = dlist_last_entry(head, typeof(*pos), member),		\
		n = dlist_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_prev_entry(n, member))

/**
 * dlist_safe_reset_next - reset a stale dlist_for_each_entry_safe loop
 * @pos:	the loop cursor used in the dlist_for_each_entry_safe loop
 * @n:		temporary storage used in dlist_for_each_entry_safe
 * @member:	the name of the dlist_head within the struct.
 *
 * dlist_safe_reset_next is not safe to use in general if the dlist may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the dlist,
 * and dlist_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define dlist_safe_reset_next(pos, n, member)				\
	n = dlist_next_entry(pos, member)

/*
 * Double linked dlists with a single pointer dlist head.
 * Mostly useful for hash tables where the two pointer dlist head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = NULL;
	n->pprev = NULL;
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_behind(struct hlist_node *n,
				    struct hlist_node *prev)
{
	n->next = prev->next;
	prev->next = n;
	n->pprev = &prev->next;

	if (n->next)
		n->next->pprev  = &n->next;
}

/* after that we'll appear to be on some hlist and hlist_del will work */
static inline void hlist_add_fake(struct hlist_node *n)
{
	n->pprev = &n->next;
}

static inline int hlist_fake(struct hlist_node *h)
{
	return h->pprev == &h->next;
}

/*
 * Check whether the node is the only node of the head without
 * accessing head:
 */
static inline int
hlist_is_singular_node(struct hlist_node *n, struct hlist_head *h)
{
	return !n->next && n->pprev == &h->first;
}

/*
 * Move a dlist from one dlist head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(struct hlist_head *old,
				   struct hlist_head *new)
{
	new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over dlist of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your dlist.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_safe - iterate over dlist of given type safe against removal of dlist entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#endif
