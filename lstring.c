/*
** $Id: lstring.c,v 1.48 2000/12/28 12:55:41 roberto Exp roberto $
** String table (keeps all strings handled by Lua)
** See Copyright Notice in lua.h
*/


#include <string.h>

#include "lua.h"

#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"


#define lmod(s,size)	((int)((s) & ((size)-1)))


void luaS_init (lua_State *L) {
  luaS_resize(L, &L->strt, MINPOWER2);
  luaS_resize(L, &L->udt, MINPOWER2);
}


void luaS_freeall (lua_State *L) {
  LUA_ASSERT(L->strt.nuse==0, "non-empty string table");
  luaM_freearray(L, L->strt.hash, L->strt.size, TString *);
  LUA_ASSERT(L->udt.nuse==0, "non-empty udata table");
  luaM_freearray(L, L->udt.hash, L->udt.size, TString *);
}


void luaS_resize (lua_State *L, stringtable *tb, int newsize) {
  TString **newhash = luaM_newvector(L, newsize, TString *);
  int i;
  for (i=0; i<newsize; i++) newhash[i] = NULL;
  /* rehash */
  for (i=0; i<tb->size; i++) {
    TString *p = tb->hash[i];
    while (p) {  /* for each node in the list */
      TString *next = p->nexthash;  /* save next */
      luint32 h = (tb == &L->strt) ? p->u.s.hash : IntPoint(p->u.d.value);
      int h1 = lmod(h, newsize);  /* new position */
      LUA_ASSERT(h%newsize == lmod(h, newsize),
                    "a&(x-1) == a%x, for x power of 2");
      p->nexthash = newhash[h1];  /* chain it in new position */
      newhash[h1] = p;
      p = next;
    }
  }
  luaM_freearray(L, tb->hash, tb->size, TString *);
  tb->size = newsize;
  tb->hash = newhash;
}


static void newentry (lua_State *L, stringtable *tb, TString *ts, int h) {
  ts->nexthash = tb->hash[h];  /* chain new entry */
  tb->hash[h] = ts;
  tb->nuse++;
  if (tb->nuse > (luint32)tb->size && tb->size < MAX_INT/2)  /* too crowded? */
    luaS_resize(L, tb, tb->size*2);
}



TString *luaS_newlstr (lua_State *L, const char *str, size_t l) {
  TString *ts;
  luint32 h = l;  /* seed */
  size_t step = (l>>5)+1;  /* if string is too long, don't hash all its chars */
  size_t l1;
  for (l1=l; l1>=step; l1-=step)  /* compute hash */
    h = h ^ ((h<<5)+(h>>2)+(unsigned char)str[l1-1]);
  for (ts = L->strt.hash[lmod(h, L->strt.size)]; ts; ts = ts->nexthash) {
    if (ts->len == l && (memcmp(str, ts->str, l) == 0))
      return ts;
  }
  /* not found */
  ts = (TString *)luaM_malloc(L, sizestring(l));
  ts->marked = 0;
  ts->nexthash = NULL;
  ts->len = l;
  ts->u.s.hash = h;
  ts->u.s.constindex = 0;
  memcpy(ts->str, str, l);
  ts->str[l] = 0;  /* ending 0 */
  newentry(L, &L->strt, ts, lmod(h, L->strt.size));  /* insert it on table */
  return ts;
}


TString *luaS_newudata (lua_State *L, size_t s, void *udata) {
  union L_UTString *uts = (union L_UTString *)luaM_malloc(L, sizeudata(s));
  TString *ts = &uts->ts;
  ts->marked = 0;
  ts->nexthash = NULL;
  ts->len = s;
  ts->u.d.tag = 0;
  ts->u.d.value = (udata == NULL) ? uts+1 : udata;
  /* insert it on table */
  newentry(L, &L->udt, ts, lmod(IntPoint(ts->u.d.value), L->udt.size));
  return ts;
}


TString *luaS_createudata (lua_State *L, void *udata, int tag) {
  int h1 = lmod(IntPoint(udata), L->udt.size);
  TString *ts;
  for (ts = L->udt.hash[h1]; ts; ts = ts->nexthash) {
    if (udata == ts->u.d.value && (tag == ts->u.d.tag || tag == LUA_ANYTAG))
      return ts;
  }
  /* not found */
  ts = luaS_newudata(L, 0, udata);
  if (tag != LUA_ANYTAG)
    ts->u.d.tag = tag;
  return ts;
}

