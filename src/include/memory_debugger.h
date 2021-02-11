#ifndef __MEMORY_DEBUGGER_H__
#define __MEMORY_DEBUGGER_H__



#ifndef NDEBUG
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#define WARN_MEMCPY_TO_UNKNOWN 1
#define WARN_MEMCPY_FROM_UNKNOWN 1
#define WARN_MEMCPY_SAME_POINTER 1
#define OVERRIDE_RETURN 1
#if OVERRIDE_RETURN
#define _return_0() \
	do{ \
		_mem_check_allocated_(__FILE__,__LINE__,__func__); \
		return; \
	} while(0)
#define _return_1(r) \
	do{ \
		_mem_check_allocated_(__FILE__,__LINE__,__func__); \
		return (r); \
	} while(0)
#endif



void _mem_check_allocated_(const char* f,unsigned int ln,const char* fn);



void* _mem_malloc_(size_t sz,const char* f,unsigned int ln,const char* fn);



void* _mem_calloc_(size_t ln_,size_t sz,const char* f,unsigned int ln,const char* fn);



void* _mem_realloc_(void* s,size_t sz,const char* f,unsigned int ln,const char* fn);



void* _mem_memcpy_(void* o,void* s,size_t sz,const char* f,unsigned int ln,const char* fn);



void _mem_free_(void* p,const char* f,unsigned int ln,const char* fn);



void _mem_trace_(void* p,const char* p_nm,const char* f,unsigned int ln,const char* fn);



#define malloc(sz) _mem_malloc_((sz),__FILE__,__LINE__,__func__)
#define calloc(ln,sz) _mem_calloc_((ln),(sz),__FILE__,__LINE__,__func__)
#define realloc(s,sz) _mem_realloc_((s),(sz),__FILE__,__LINE__,__func__)
#define memcpy(o,s,sz) _mem_memcpy_((o),(s),(sz),__FILE__,__LINE__,__func__)
#define free(p) _mem_free_((p),__FILE__,__LINE__,__func__)
#define mem_trace(p) _mem_trace_((p),#p,__FILE__,__LINE__,__func__)
#define mem_check_allocated() _mem_check_allocated_(__FILE__,__LINE__,__func__)
#if OVERRIDE_RETURN
#define _concat(a,b) a##b
#define _arg_c_l(...) _,__VA_ARGS__
#define _arg_c_exp(x) x
#define _arg_c_c(_0,_1,N,...) N
#define _arg_c_exp_va(...) _arg_c_exp(_arg_c_c(__VA_ARGS__,1,0))
#define _arg_c(...)  _arg_c_exp_va(_arg_c_l(__VA_ARGS__))
#define _ret_c(t,...) _concat(_return_,t)(__VA_ARGS__)
#define return(...) _ret_c(_arg_c(__VA_ARGS__),__VA_ARGS__)
#endif
#else
#include <stdlib.h>
#define mem_trace(p)
#define mem_check_allocated()
#endif
#endif
