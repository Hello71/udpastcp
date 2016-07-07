#ifdef DEBUG
#define DBG(...) do { fprintf(stderr, __VA_ARGS__); putc('\n', stderr); } while (0)
#else
#define DBG(...)
#endif

#define IN_ADDR_PORT(addr) (((struct sockaddr_in *)addr)->sin_port)

extern int free_mem_on_exit;
