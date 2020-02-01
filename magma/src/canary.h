#ifdef __cplusplus
extern "C" {
#endif

#define MAGMA_LOG(b,c) do{magma_log((b),(int)(c));}while(0)

extern void magma_log(int bug, int condition);

#ifdef __cplusplus
}
#endif
