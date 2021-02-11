#include <memory_debugger.h>



int main(int argc,const char** argv){
	(void)argc;
	(void)argv;
	char* dt=malloc(32);
	mem_trace(dt);
	*dt=5;
	free(dt);
	*(dt+31)=5;
	realloc(dt,45);
	return (0);
}
