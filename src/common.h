#ifdef DEBUG
#define DBG(...) do { fprintf(stderr, __VA_ARGS__); putc('\n', stderr); } while (0)
#else
#define DBG(...)
#endif
