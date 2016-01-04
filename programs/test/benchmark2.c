#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_exit       exit
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#define mbedtls_free       free
#endif

#if !defined(MBEDTLS_TIMING_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_TIMING_C not defined.\n");
    return( 0 );
}
#else

#include <string.h>
#include <stdlib.h>

#include "mbedtls/timing.h"

#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/havege.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 16)  // 64k

#define BUFSIZE         1024
#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define OPTIONS                                                         \
    "md4, md5, ripemd160, sha1, sha256, sha512,\n"                      \
    "arc4, des3, des, aes_cbc, aes_gcm, aes_ccm, camellia, blowfish,\n" \
    "havege, ctr_drbg, hmac_drbg\n"                                     \
    "rsa, dhm, ecdsa, ecdh.\n"

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
        mbedtls_strerror( ret, ( char * )tmp, sizeof( tmp ) );         \
        mbedtls_printf( "FAILED: %s\n", tmp );
#else
#define PRINT_ERROR                                                     \
        mbedtls_printf( "FAILED: -0x%04x\n", -ret );
#endif
#define TIME_AND_TSC( TITLE, CODE )                                     \
do {                                                                    \
    unsigned long ii, jj, tsc;                                          \
                                                                        \
    mbedtls_printf( HEADER_FORMAT, TITLE );                             \
    fflush( stdout );                                                   \
                                                                        \
    mbedtls_set_alarm( 1 );                                             \
    for( ii = 1; ! mbedtls_timing_alarmed; ii++ )                       \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    tsc = mbedtls_timing_hardclock();                                   \
    for( jj = 0; jj < 1024; jj++ )                                      \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    mbedtls_printf( "%9lu Kb/s,  %9lu cycles/byte\n",                   \
                     ii * BUFSIZE / 1024,                               \
                     ( mbedtls_timing_hardclock() - tsc ) / ( jj * BUFSIZE ) );         \
} while( 0 )

#define TIME_AND_TSC2( TITLE, BUF2_SIZE, CODE )                         \
do {                                                                    \
    unsigned long ii, jj, tsc;                                          \
                                                                        \
    mbedtls_printf( HEADER_FORMAT, TITLE );                             \
    fflush( stdout );                                                   \
                                                                        \
    mbedtls_set_alarm( 1 );                                             \
    for( ii = 1; ! mbedtls_timing_alarmed; ii++ )                       \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    tsc = mbedtls_timing_hardclock();                                   \
    for( jj = 0; jj < 1024; jj++ )                                      \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    mbedtls_printf( "%9lu Kb/s,  %9lu cycles/byte\n",                   \
                     ii * BUF2_SIZE / 1024,                             \
                     ( mbedtls_timing_hardclock() - tsc ) / ( jj * BUF2_SIZE ) );         \
} while( 0 )

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
        mbedtls_strerror( ret, ( char * )tmp, sizeof( tmp ) );          \
        mbedtls_printf( "FAILED: %s\n", tmp );
#else
#define PRINT_ERROR                                                     \
        mbedtls_printf( "FAILED: -0x%04x\n", -ret );
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)

#define MEMORY_MEASURE_INIT                                             \
    size_t max_used, max_blocks, max_bytes;                             \
    size_t prv_used, prv_blocks;                                        \
    mbedtls_memory_buffer_alloc_cur_get( &prv_used, &prv_blocks );      \
    mbedtls_memory_buffer_alloc_max_reset( );

#define MEMORY_MEASURE_PRINT( title_len )                               \
    mbedtls_memory_buffer_alloc_max_get( &max_used, &max_blocks );      \
    for( ii = 12 - title_len; ii != 0; ii-- ) mbedtls_printf( " " );    \
    max_used -= prv_used;                                               \
    max_blocks -= prv_blocks;                                           \
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;             \
    mbedtls_printf( "%6u heap bytes", (unsigned) max_bytes );

#else
#define MEMORY_MEASURE_INIT
#define MEMORY_MEASURE_PRINT( title_len )
#endif

#define TIME_PUBLIC( TITLE, TYPE, CODE )                                \
do {                                                                    \
    unsigned long ii;                                                   \
    int ret;                                                            \
    MEMORY_MEASURE_INIT;                                                \
                                                                        \
    mbedtls_printf( HEADER_FORMAT, TITLE );                             \
    fflush( stdout );                                                   \
    mbedtls_set_alarm( 3 );                                             \
                                                                        \
    ret = 0;                                                            \
    for( ii = 1; ! mbedtls_timing_alarmed && ! ret ; ii++ )             \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    if( ret != 0 )                                                      \
    {                                                                   \
        PRINT_ERROR;                                                    \
    }                                                                   \
    else                                                                \
    {                                                                   \
        mbedtls_printf( "%6lu " TYPE "/s", ii / 3 );                    \
        MEMORY_MEASURE_PRINT( sizeof( TYPE ) + 1 );                     \
        mbedtls_printf( "\n" );                                         \
    }                                                                   \
} while( 0 )

unsigned char buf[BUFSIZE];

typedef struct {
    char md4, md5, ripemd160, sha1, sha256, sha512,
         arc4, des3, des, aes_cbc, aes_gcm, aes_ccm, camellia, blowfish,
         havege, ctr_drbg, hmac_drbg,
         rsa, dhm, ecdsa, ecdh;
} todo_list;

int main( int argc, char *argv[] )
{
    int i;
    unsigned char tmp[200];
    char title[TITLE_LEN];
    todo_list todo;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[HEAP_SIZE] = { 0 };
#endif

    if( argc <= 1 )
    {
        memset( &todo, 1, sizeof( todo ) );
    }
    else
    {
        memset( &todo, 0, sizeof( todo ) );

        for( i = 1; i < argc; i++ )
        {
            if( strcmp( argv[i], "md4" ) == 0 )
                todo.md4 = 1;
            else if( strcmp( argv[i], "md5" ) == 0 )
                todo.md5 = 1;
            else if( strcmp( argv[i], "ripemd160" ) == 0 )
                todo.ripemd160 = 1;
            else if( strcmp( argv[i], "sha1" ) == 0 )
                todo.sha1 = 1;
            else if( strcmp( argv[i], "sha256" ) == 0 )
                todo.sha256 = 1;
            else if( strcmp( argv[i], "sha512" ) == 0 )
                todo.sha512 = 1;
            else if( strcmp( argv[i], "arc4" ) == 0 )
                todo.arc4 = 1;
            else if( strcmp( argv[i], "des3" ) == 0 )
                todo.des3 = 1;
            else if( strcmp( argv[i], "des" ) == 0 )
                todo.des = 1;
            else if( strcmp( argv[i], "aes_cbc" ) == 0 )
                todo.aes_cbc = 1;
            else if( strcmp( argv[i], "aes_gcm" ) == 0 )
                todo.aes_gcm = 1;
            else if( strcmp( argv[i], "aes_ccm" ) == 0 )
                todo.aes_ccm = 1;
            else if( strcmp( argv[i], "camellia" ) == 0 )
                todo.camellia = 1;
            else if( strcmp( argv[i], "blowfish" ) == 0 )
                todo.blowfish = 1;
            else if( strcmp( argv[i], "havege" ) == 0 )
                todo.havege = 1;
            else if( strcmp( argv[i], "ctr_drbg" ) == 0 )
                todo.ctr_drbg = 1;
            else if( strcmp( argv[i], "hmac_drbg" ) == 0 )
                todo.hmac_drbg = 1;
            else if( strcmp( argv[i], "rsa" ) == 0 )
                todo.rsa = 1;
            else if( strcmp( argv[i], "dhm" ) == 0 )
                todo.dhm = 1;
            else if( strcmp( argv[i], "ecdsa" ) == 0 )
                todo.ecdsa = 1;
            else if( strcmp( argv[i], "ecdh" ) == 0 )
                todo.ecdh = 1;
            else
            {
                mbedtls_printf( "Unrecognized option: %s\n", argv[i] );
                mbedtls_printf( "Available options: " OPTIONS );
            }
        }
    }

    mbedtls_printf( "\n" );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif
    memset( buf, 0xAA, sizeof( buf ) );
    memset( tmp, 0xBB, sizeof( tmp ) );

#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( todo.aes_cbc )
    {
        int keysize;
        mbedtls_aes_context aes;
        mbedtls_aes_init( &aes );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-CBC-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_aes_setkey_enc( &aes, tmp, keysize );

            TIME_AND_TSC( title,
                mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, BUFSIZE, tmp, buf, buf ) );
        }
        mbedtls_aes_free( &aes );
    }
#endif
#endif

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if( todo.blowfish )
    {
        int keysize;
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "BLOWFISH-CBC-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_blowfish_crypt_cbc( &blowfish, MBEDTLS_BLOWFISH_ENCRYPT, BUFSIZE,
                        tmp, buf, buf ) );
        }

        mbedtls_blowfish_free( &blowfish );
    }
#endif

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CTR)
    if( todo.blowfish )
    {
        int keysize;
        unsigned char tmp2[200];
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            size_t nc_off = 0;

            mbedtls_snprintf( title, sizeof( title ), "BLOWFISH-CTR-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            memset( tmp2, 0, sizeof( tmp2 ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_blowfish_crypt_ctr( &blowfish, BUFSIZE, &nc_off, tmp, tmp2,
                        buf, buf ) );
        }

        mbedtls_blowfish_free( &blowfish );
    }
#endif

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CTR) && defined(MBEDTLS_BLOWFISH_CTR2)
    if( todo.blowfish )
    {
        int keysize;
        unsigned char tmp2[200];
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            size_t nc_off = 0;

            mbedtls_snprintf( title, sizeof( title ), "BLOWFISH-CTR2-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            memset( tmp2, 0, sizeof( tmp2 ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_blowfish_crypt_ctr2( &blowfish, BUFSIZE, &nc_off, tmp, tmp2,
                        buf, buf ) );
        }

        mbedtls_blowfish_free( &blowfish );
    }
#endif

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CTR) && defined(MBEDTLS_BLOWFISH_CTR_OMP)
    if( todo.blowfish )
    {
        int keysize;
        unsigned char tmp2[200];
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            size_t nc_off = 0;

            mbedtls_snprintf( title, sizeof( title ), "BLOWFISH-CTR-OMP-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            memset( tmp2, 0, sizeof( tmp2 ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_blowfish_crypt_ctr_omp( &blowfish, BUFSIZE, &nc_off, tmp, tmp2,
                        buf, buf ) );
        }

        mbedtls_blowfish_free( &blowfish );
    }

    if( todo.blowfish )
    {
        #define MAX_BUF2_SIZE 65536
        int keysize;
        unsigned char tmp2[200];
        unsigned char buf2[MAX_BUF2_SIZE];
        int buf2_size_list[6] = {1<<11, 1<<12, 1<<13, 1<<14, 1<<15, 65536};
        int idx;
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        /* ctr_omp for each plaintext size */
        for( idx = 0; idx < 6; idx++ )
        {
            int buf2_size;
            size_t nc_off = 0;

            keysize = 256;
            buf2_size = buf2_size_list[idx];
            mbedtls_snprintf( title, sizeof( title ), "BF-CTR-OMP-%d-S%d", keysize, buf2_size );

            memset( buf2, 0, sizeof( buf2 ) );
            memset( tmp, 0, sizeof( tmp ) );
            memset( tmp2, 0, sizeof( tmp2 ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC2( title, buf2_size, 
                    mbedtls_blowfish_crypt_ctr_omp( &blowfish, buf2_size, &nc_off, tmp, tmp2,
                        buf2, buf2 ) );

            keysize = 256;
            buf2_size = buf2_size_list[idx];
            mbedtls_snprintf( title, sizeof( title ), "BF-CTR-OMP-%d-S%d", keysize, buf2_size );

        }

        /* origin ctr for each plaintext size */
        for( idx = 0; idx < 6; idx++ )
        {
            int buf2_size;
            size_t nc_off = 0;

            keysize = 256;
            buf2_size = buf2_size_list[idx];
            mbedtls_snprintf( title, sizeof( title ), "BF-CTR-%d-S%d", keysize, buf2_size );

            memset( buf2, 0, sizeof( buf2 ) );
            memset( tmp, 0, sizeof( tmp ) );
            memset( tmp2, 0, sizeof( tmp2 ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC2( title, buf2_size, 
                    mbedtls_blowfish_crypt_ctr( &blowfish, buf2_size, &nc_off, tmp, tmp2,
                        buf2, buf2 ) );

            keysize = 256;
            buf2_size = buf2_size_list[idx];
            mbedtls_snprintf( title, sizeof( title ), "BF-CTR-OMP-%d-S%d", keysize, buf2_size );

        }

        mbedtls_blowfish_free( &blowfish );
    }
#endif
    mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_TIMING_C */
