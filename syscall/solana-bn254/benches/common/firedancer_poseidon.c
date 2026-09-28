/* Benchmark-only adapter: keep Firedancer's context layout on the C side. */
#include "src/ballet/bn254/fd_poseidon.h"

int
bn254_bench_poseidon( unsigned char out[32], unsigned char const * inputs,
                     unsigned long count ) {
  fd_poseidon_t context;
  fd_poseidon_t * pos = fd_poseidon_init( &context, 0 );
  for( unsigned long i=0; i<count && pos; i++ )
    pos = fd_poseidon_append( pos, inputs + 32*i, 32 );
  return fd_poseidon_fini( pos, out ) != NULL;
}
