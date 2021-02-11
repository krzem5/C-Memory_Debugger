#include <memory_debugger.h>
#undef return
#undef malloc
#undef calloc
#undef realloc
#undef memcpy
#undef free
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>



#define assert(ex) \
	do{ \
		if (!(ex)){ \
			printf("%s:%d (%s): Assertion Failed: %s\n",__FILE__,__LINE__,__func__,#ex); \
			raise(SIGABRT); \
		} \
	} while (0)



const char* _s_sig="XYXYXYXY";
const char* _e_sig="ZWZWZWZW";
struct _Node{
	struct _Node* p;
	struct _Node* n;
	void* ptr;
	size_t sz;
	const char* f;
	unsigned int ln;
	const char* fn;
	uint8_t t;
	const char* t_nm;
	void* t_v;
	const char* f_f;
	unsigned int f_ln;
	const char* f_fn;
	void* f_dt;
} _head={
	NULL,
	NULL,
	NULL,
	0,
	NULL,
	0,
	NULL,
	0,
	NULL,
	NULL,
	NULL,
	0,
	NULL,
	NULL
};
uint8_t _er=0;
uint8_t _m_err=0;



void _mem_abrt_(int p){
	_m_err=1;
	signal(SIGABRT,SIG_DFL);
	raise(SIGABRT);
}



void _dump(void* s,size_t sz){
	printf("Memory Dump Of Address 0x%016llx - 0x%016llx (+ %llu):\n",(unsigned long long int)s,(unsigned long long int)s+sz,sz);
	size_t mx_n=8*(((sz+7)>>3)-1);
	unsigned char mx=1;
	while (mx_n>10){
		mx++;
		mx_n/=10;
	}
	char* f=malloc(mx+20);
	sprintf_s(f,mx+20,"0x%%016llx + %% %ullu: ",mx);
	for (size_t i=0;i<sz;i+=8){
		printf(f,(uintptr_t)s,(uintptr_t)i);
		unsigned char j;
		for (j=0;j<8;j++){
			if (i+j>=sz){
				break;
			}
			printf("%02x",*((unsigned char*)s+i+j));
			printf(" ");
		}
		if (j==0){
			break;
		}
		while (j<8){
			printf("   ");
			j++;
		}
		printf("| ");
		for (j=0;j<8;j++){
			if (i+j>=sz){
				break;
			}
			unsigned char c=*((unsigned char*)s+i+j);
			if (c>0x1f&&c!=0x7f){
				printf("%c  ",(char)c);
			}
			else{
				printf("%02x ",c);
			}
		}
		printf("\n");
	}
	free(f);
}



void _check_heap(const char* f,unsigned int ln,const char* fn){
	struct _Node* n=&_head;
	while (1){
		if (n->ptr!=NULL){
			for (unsigned char i=0;i<8;i++){
				if (*((char*)n->ptr+i)!=*(_s_sig+i)){
					if (f==NULL){
						printf("ERROR: Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx-%u)!\n",((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),8-i);
					}
					else{
						printf("ERROR: %s:%u (%s): Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx-%u)!\n",f,ln,fn,((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),8-i);
					}
					_dump(n->ptr,n->sz+16);
					_m_err=1;
					raise(SIGABRT);
					return;
				}
			}
			for (unsigned char i=0;i<8;i++){
				if (*((char*)n->ptr+n->sz+i+8)!=*(_e_sig+i)){
					if (f==NULL){
						printf("ERROR: Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx+%llu+%u)!\n",((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),n->sz,i+1);
					}
					else{
						printf("ERROR: %s:%u (%s): Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx+%llu+%u)!\n",f,ln,fn,((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),n->sz,i+1);
					}
					_dump(n->ptr,n->sz+16);
					_m_err=1;
					raise(SIGABRT);
					return;
				}
			}
			if (n->t==1){
				uint8_t ch=0;
				for (size_t i=0;i<n->sz;i++){
					if (*((char*)n->ptr+i+8)!=*((char*)n->t_v+i)){
						if (ch==0){
							printf("TRACE: %s:%u (%s): %s (0x%016llx): Detected Memory Change:",f,ln,fn,n->t_nm,(unsigned long long int)n->ptr);
							ch=1;
						}
						else{
							printf(";");
						}
						printf(" +%llu (%02x -> %02x)",i,*((unsigned char*)n->t_v+i),*((unsigned char*)n->ptr+i+8));
						*((char*)n->t_v+i)=*((char*)n->ptr+i+8);
					}
				}
				if (ch==1){
					printf("\n");
				}
			}
			if (n->f_dt!=NULL){
				uint8_t ch=0;
				for (size_t i=0;i<n->sz;i++){
					if (*((char*)n->ptr+i+8)!=*((char*)n->f_dt+i)){
						if (ch==0){
							printf("TRACE: %s:%u (%s): Pointer allocated at %s:%u (%s) and freed at %s:%u (%s) (0x%016llx) has been written to",f,ln,fn,n->f,n->ln,n->fn,n->f_f,n->f_ln,n->f_fn,(unsigned long long int)n->ptr);
							ch=1;
						}
						else{
							printf(";");
						}
						printf(" +%llu (%02x -> %02x)",i,*((unsigned char*)n->f_dt+i),*((unsigned char*)n->ptr+i+8));
						*((char*)n->f_dt+i)=*((char*)n->ptr+i+8);
					}
				}
				if (ch==1){
					printf("\n");
					_dump((char*)n->ptr+8,n->sz);
					_m_err=1;
					raise(SIGABRT);
					return;
				}
			}
		}
		if (n->n==NULL){
			break;
		}
		n=n->n;
	}
}



void* _get(void* p,const char* msg,uint8_t wu,const char* f,unsigned int ln,const char* fn){
	if (p==NULL){
		printf("ERROR: %s:%u (%s): %s Null Pointer!\n",f,ln,fn,msg);
		_m_err=1;
		raise(SIGABRT);
		return NULL;
	}
	struct _Node* n=&_head;
	while (n->ptr!=(char*)p-8){
		if (n->n==NULL){
			if (wu==1){
				printf("WARN:  %s:%u (%s): %s Unknown Pointer!\n",f,ln,fn,msg);
			}
			return p;
		}
		n=n->n;
	}
	for (unsigned char i=0;i<8;i++){
		if (*((char*)n->ptr+i)!=*(_s_sig+i)){
			printf("ERROR: %s:%u (%s): Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx-%u)!\n",f,ln,fn,((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),8-i);
			_dump(n->ptr,n->sz+16);
			_m_err=1;
			raise(SIGABRT);
			return NULL;
		}
	}
	for (unsigned char i=0;i<8;i++){
		if (*((char*)n->ptr+n->sz+i+8)!=*(_e_sig+i)){
			printf("ERROR: %s:%u (%s): Address 0x%016llx Allocated at %s:%u (%s) has been Corrupted (0x%016llx+%llu+%u)!\n",f,ln,fn,((unsigned long long int)n->ptr+8),n->f,n->ln,n->fn,((unsigned long long int)n->ptr+8),n->sz,i+1);
			_dump(n->ptr,n->sz+16);
			_m_err=1;
			raise(SIGABRT);
			return NULL;
		}
	}
	return n;
}



void _mem_check_all_allocated_(void){
	if (_m_err==1){
		return;
	}
	_check_heap(NULL,0,NULL);
	unsigned long pc=0;
	unsigned long long int bc=0;
	struct _Node* n=&_head;
	while (n->n!=NULL){
		if (n->ptr!=NULL){
			pc++;
			bc+=n->sz;
			if (n->t==1){
				printf("%s (0x%016llx): Pointer not Freed at The End of Program! (%s:%u (%s))\n",n->t_nm,(unsigned long long int)n->ptr,n->f,n->ln,n->fn);
			}
			else{
				printf("0x%016llx: Pointer not Freed at The End of Program! (%s:%u (%s))\n",(unsigned long long int)n->ptr,n->f,n->ln,n->fn);
			}
			_dump((unsigned char*)n->ptr+8,n->sz);
		}
		n=n->n;
	}
	if (pc>0){
		printf("%lu Pointer(s) (%llu byte(s)) Not Freed, Aborting.\n",pc,bc);
	}
	else{
		printf("Everything Freed!");
	}
}



void _mem_check_allocated_(const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
}



void* _mem_malloc_(size_t sz,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
	struct _Node* n=&_head;
	while (n->ptr!=NULL){
		if (n->n==NULL){
			n->n=malloc(sizeof(struct _Node));
			n->n->p=NULL;
			n->n->n=NULL;
			n->n->ptr=NULL;
			n->n->sz=0;
			n->n->f=NULL;
			n->n->ln=0;
			n->n->fn=NULL;
			n->n->t=0;
			n->n->t_nm=NULL;
			n->n->t_v=NULL;
			n->n->f_f=NULL;
			n->n->f_ln=0;
			n->n->f_fn=NULL;
			n->n->f_dt=NULL;
		}
		n=n->n;
	}
	n->ptr=malloc(sz+16);
	if (n->ptr==NULL){
		printf("ERROR: %s: %s(%u): Out of Memory!\n",f,fn,ln);
		_m_err=1;
		raise(SIGABRT);
		return NULL;
	}
	for (uint8_t i=0;i<8;i++){
		*((char*)n->ptr+i)=*(_s_sig+i);
		*((char*)n->ptr+sz+i+8)=*(_e_sig+i);
	}
	n->sz=sz;
	n->f=f;
	n->ln=ln;
	n->fn=fn;
	n->t=0;
	n->t_nm=NULL;
	n->t_v=NULL;
	n->f_f=NULL;
	n->f_ln=0;
	n->f_fn=NULL;
	n->f_dt=NULL;
	return (void*)((uintptr_t)n->ptr+8);
}



void* _mem_calloc_(size_t ln_,size_t sz,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
	sz*=ln_;
	struct _Node* n=&_head;
	while (n->ptr!=NULL){
		if (n->n==NULL){
			n->n=malloc(sizeof(struct _Node));
			n->n->p=n;
			n->n->n=NULL;
			n->n->ptr=NULL;
			n->n->sz=0;
			n->n->f=NULL;
			n->n->ln=0;
			n->n->fn=NULL;
			n->n->t=0;
			n->n->t_nm=NULL;
			n->n->t_v=NULL;
			n->n->f_f=NULL;
			n->n->f_ln=0;
			n->n->f_fn=NULL;
			n->n->f_dt=NULL;
		}
		n=n->n;
	}
	n->ptr=malloc(sz+16);
	if (n->ptr==NULL){
		printf("ERROR: %s:%u (%s): Out of Memory!\n",f,ln,fn);
		_m_err=1;
		raise(SIGABRT);
		return NULL;
	}
	for (size_t i=0;i<8;i++){
		*((char*)n->ptr+i)=*(_s_sig+i);
		*((char*)n->ptr+sz+i+8)=*(_e_sig+i);
	}
	for (size_t i=0;i<sz;i++){
		*((char*)n->ptr+i+8)=0;
	}
	n->sz=sz;
	n->f=f;
	n->ln=ln;
	n->fn=fn;
	n->t=0;
	n->t_nm=NULL;
	n->t_v=NULL;
	n->f_f=NULL;
	n->f_ln=0;
	n->f_fn=NULL;
	n->f_dt=NULL;
	return (void*)((uintptr_t)n->ptr+8);
}



void* _mem_realloc_(void* s,size_t sz,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
	if (s==NULL){
		return _mem_malloc_(sz,f,ln,fn);
	}
	void* sn=_get(s,"Reallocating",1,f,ln,fn);
	struct _Node* n;
	if (sn==s){
		n=&_head;
		while (n->n==NULL){
			n=n->n;
		}
		n->n=malloc(sizeof(struct _Node));
		n->ptr=s;
	}
	else{
		n=(struct _Node*)sn;
	}
	if (n->t==1){
		printf("TRACE: %s:%u (%s): %s (0x%016llx): Reallocating Memory on Line %s:%u (%s): %llu -> %llu\n",f,ln,fn,n->t_nm,(unsigned long long int)n->ptr,f,ln,fn,n->sz,sz);
	}
	if (n->f_dt!=NULL){
		printf("ERROR: %s:%u (%s): Reallocating Pointer Allocated at %s:%u (%s), which has already been freed at %s:%u (%s)!\n",f,ln,fn,n->f,n->ln,n->fn,n->f_f,n->f_ln,n->f_fn);
		_m_err=1;
		raise(SIGABRT);
		return NULL;
	}
	n->ptr=realloc(n->ptr,sz+16);
	if (n->ptr==NULL){
		printf("ERROR: %s:%u (%s): Out of Memory!\n",f,ln,fn);
		_m_err=1;
		raise(SIGABRT);
		return NULL;
	}
	for (size_t i=0;i<8;i++){
		*((char*)n->ptr+i)=*(_s_sig+i);
		*((char*)n->ptr+sz+i+8)=*(_e_sig+i);
	}
	n->sz=sz;
	n->f=f;
	n->ln=ln;
	n->fn=fn;
	return (void*)((uintptr_t)n->ptr+8);
}



void* _mem_memcpy_(void* o,void* s,size_t sz,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	if (WARN_MEMCPY_SAME_POINTER&&o==s){
		printf("WARN: %s:%u (%s): Copying Between Same Pointer!\n",__FILE__,__LINE__,__func__);
	}
	assert(o!=s);
	_check_heap(f,ln,fn);
	void* on=_get(o,"Memcpy To",WARN_MEMCPY_TO_UNKNOWN,f,ln,fn);
	if (on!=o){
		if (((struct _Node*)on)->t==1){
			printf("TRACE: %s:%u (%s): %s (0x%016llx): Memory Copy To Self on Line %s:%u (%s)\n",f,ln,fn,((struct _Node*)on)->t_nm,(unsigned long long int)((struct _Node*)on)->ptr,f,ln,fn);
		}
		o=(char*)((struct _Node*)on)->ptr+8;
	}
	void* sn=_get(s,"Memcpy From",WARN_MEMCPY_FROM_UNKNOWN,f,ln,fn);
	if (sn!=s){
		if (((struct _Node*)sn)->t==1){
			printf("TRACE: %s:%u (%s): %s (0x%016llx): Memory Copy From Self on Line %s:%u (%s)\n",f,ln,fn,((struct _Node*)sn)->t_nm,(unsigned long long int)((struct _Node*)sn)->ptr,f,ln,fn);
		}
		s=(char*)((struct _Node*)sn)->ptr+8;
	}
	for (size_t i=0;i<sz;i++){
		*((char*)o+i)=*((char*)s+i);
	}
	return o;
}



void _mem_free_(void* p,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
	struct _Node* n=_get(p,"Freeing",0,f,ln,fn);
	if (n==p){
		printf("ERROR: %s:%u (%s): Freeing Unknown Pointer!\n",f,ln,fn);
		_m_err=1;
		raise(SIGABRT);
		return;
	}
	if (n->t==1){
		printf("TRACE: %s:%u (%s): %s (0x%016llx): Freeing Pointer on Line %s:%u (%s)\n",f,ln,fn,n->t_nm,(unsigned long long int)n->ptr,f,ln,fn);
	}
	if (n->f_dt!=NULL){
		printf("ERROR: %s:%u (%s): Pointer Allocated at %s:%u (%s) has already been freed at %s:%u (%s)!\n",f,ln,fn,n->f,n->ln,n->fn,n->f_f,n->f_ln,n->f_fn);
		_m_err=1;
		raise(SIGABRT);
		return;
	}
	n->t=0;
	if (n->t_v!=NULL){
		free(n->t_v);
		n->t_v=NULL;
	}
	n->f_f=f;
	n->f_ln=ln;
	n->f_fn=fn;
	n->f_dt=malloc(n->sz);
	memcpy(n->f_dt,(char*)n->ptr+8,n->sz);
}



void _mem_trace_(void* p,const char* p_nm,const char* f,unsigned int ln,const char* fn){
	if (_er==0){
		atexit(_mem_check_all_allocated_);
		signal(SIGABRT,_mem_abrt_);
		_er=1;
	}
	_check_heap(f,ln,fn);
	struct _Node* n=_get(p,"Tracing",0,f,ln,fn);
	if (n==p){
		printf("ERROR: %s:%u (%s): Tracing Unknown Pointer!\n",f,ln,fn);
		_m_err=1;
		raise(SIGABRT);
		return;
	}
	printf("TRACE: %s:%u (%s): Started Tracing Pointer %s (0x%016llx)\n",f,ln,fn,p_nm,(unsigned long long int)n->ptr);
	n->t=1;
	n->t_v=malloc(n->sz);
	n->t_nm=p_nm;
	for (size_t i=0;i<n->sz;i++){
		*((char*)n->t_v+i)=*((char*)n->ptr+i+8);
	}
}
