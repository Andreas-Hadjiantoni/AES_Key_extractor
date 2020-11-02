/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"

typedef uint8_t aes_gf28_t;
typedef uint16_t aes_poly_t;

#define AES_ENC_RND_KEY_STEP(a,b,c,d) { \
  s[ a ] = s[ a ] ^ rk[ a ]; \
  s[ b ] = s[ b ] ^ rk[ b ]; \
  s[ c ] = s[ c ] ^ rk[ c ]; \
  s[ d ] = s[ d ] ^ rk[ d ]; \
}

# define AES_ENC_RND_SUB_STEP(a,b,c,d) { \
  s[ a ] = aes_enc_sbox ( s[ a ] );\
  s[ b ] = aes_enc_sbox ( s[ b ] );\
  s[ c ] = aes_enc_sbox ( s[ c ] );\
  s[ d ] = aes_enc_sbox ( s[ d ] );\
}

# define AES_ENC_RND_ROW_STEP(a,b,c,d,e,f,g,h) { \
  aes_gf28_t __a1 = s[ a ]; \
  aes_gf28_t __b1 = s[ b ]; \
  aes_gf28_t __c1 = s[ c ]; \
  aes_gf28_t __d1 = s[ d ]; \
                            \
  s[ e ] = __a1; \
  s[ f ] = __b1; \
  s[ g ] = __c1; \
  s[ h ] = __d1; \
}

# define AES_ENC_RND_MIX_STEP(a,b,c,d) { \
  aes_gf28_t __a1 = s[ a ]; \
  aes_gf28_t __b1 = s[ b ]; \
  aes_gf28_t __c1 = s[ c ]; \
  aes_gf28_t __d1 = s[ d ]; \
                                  \
  aes_gf28_t __a2 = aes_gf28_mulx ( __a1 ); \
  aes_gf28_t __b2 = aes_gf28_mulx ( __b1 ); \
  aes_gf28_t __c2 = aes_gf28_mulx ( __c1 ); \
  aes_gf28_t __d2 = aes_gf28_mulx ( __d1 ); \
                                      \
  aes_gf28_t __a3 = __a1 ^ __a2; \
  aes_gf28_t __b3 = __b1 ^ __b2; \
  aes_gf28_t __c3 = __c1 ^ __c2; \
  aes_gf28_t __d3 = __d1 ^ __d2; \
                                  \
  s[ a ] = __a2 ^ __b3 ^ __c1 ^ __d1; \
  s[ b ] = __a1 ^ __b2 ^ __c3 ^ __d1; \
  s[ c ] = __a1 ^ __b1 ^ __c2 ^ __d3; \
  s[ d ] = __a3 ^ __b1 ^ __c1 ^ __d2; \
}

# define U8_TO_U8_N(d, s) { \
  memcpy(d, s, 16); \
}

aes_gf28_t aes_gf28_add( aes_gf28_t a, aes_gf28_t b ) {
  return a ^ b;
}

aes_gf28_t aes_gf28_mulx ( aes_gf28_t a ) {
  if( ( a & 0x80 ) == 0x80 ) {
    return 0x1B ^ ( a << 1 );
  } else {
    return ( a << 1 );
  }
}

aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b ) {
  aes_gf28_t t = 0;
  for( int i = 7; i >= 0; i-- ) {
    t = aes_gf28_mulx ( t );
    if( ( b >> i ) & 1 ) {
      t ^= a;
    }
  }
  return t;
}

aes_gf28_t aes_gf28_inv ( aes_gf28_t a ) {
  aes_gf28_t t_0 = aes_gf28_mul (a, a);
  aes_gf28_t t_1 = aes_gf28_mul ( t_0 , a);
  t_0 = aes_gf28_mul ( t_0 , t_0);
  t_1 = aes_gf28_mul ( t_1 ,t_0);
  t_0 = aes_gf28_mul ( t_0 ,t_0);
  t_0 = aes_gf28_mul ( t_1 ,t_0);
  t_0 = aes_gf28_mul ( t_0 ,t_0);
  t_0 = aes_gf28_mul ( t_0 ,t_0);
  t_1 = aes_gf28_mul ( t_1 ,t_0);
  t_0 = aes_gf28_mul ( t_0 ,t_1);
  t_0 = aes_gf28_mul ( t_0 ,t_0);
  return t_0;
}

aes_gf28_t aes_gf28_exp( aes_gf28_t base, uint8_t pow ) {
  aes_gf28_t result = 0x01;

  if ( pow < 0 )
    return aes_gf28_mul( aes_gf28_exp( base, -pow ), aes_gf28_inv( base ) );

  for ( uint8_t i = 0; i < pow; i++ ) {
    result = aes_gf28_mul( result, base );
  }
  return result;
}

aes_gf28_t aes_enc_sbox ( aes_gf28_t a ) {
  a = aes_gf28_inv ( a );

  a = ( 0x63 ) ^
  ( a ) ^
  ( a << 1 ) ^
  ( a << 2 ) ^
  ( a << 3 ) ^
  ( a << 4 ) ^
  ( a >> 7 ) ^
  ( a >> 6 ) ^
  ( a >> 5 ) ^
  ( a >> 4 ) ;
  return a;
}

void aes_enc_keyexp_step ( uint8_t * r, const uint8_t* rk, uint8_t rc) {

  rc = aes_gf28_exp( 0x02, rc - 1 );

  r[ 0 ] = rc ^ aes_enc_sbox ( rk[ 13 ] ) ^ rk [ 0 ];
  r[ 1 ] =      aes_enc_sbox ( rk[ 14 ] ) ^ rk [ 1 ];
  r[ 2 ] =      aes_enc_sbox ( rk[ 15 ] ) ^ rk [ 2 ];
  r[ 3 ] =      aes_enc_sbox ( rk[ 12 ] ) ^ rk [ 3 ];

  r[ 4 ] = r[ 0 ] ^ rk[ 4 ];
  r[ 5 ] = r[ 1 ] ^ rk[ 5 ];
  r[ 6 ] = r[ 2 ] ^ rk[ 6 ];
  r[ 7 ] = r[ 3 ] ^ rk[ 7 ];

  r[ 8 ] = r[ 4 ] ^ rk[ 8 ];
  r[ 9 ] = r[ 5 ] ^ rk[ 9 ];
  r[ 10 ] = r[ 6 ] ^ rk[ 10 ];
  r[ 11 ] = r[ 7 ] ^ rk[ 11 ];

  r[ 12 ] = r[ 8 ] ^ rk[ 12 ];
  r[ 13 ] = r[ 9 ] ^ rk[ 13 ];
  r[ 14 ] = r[ 10 ] ^ rk[ 14 ];
  r[ 15 ] = r[ 11 ] ^ rk[ 15 ];
}

void aes_enc_rnd_key ( aes_gf28_t * s, const aes_gf28_t * rk ) {
  AES_ENC_RND_KEY_STEP ( 0, 1, 2, 3 );
  AES_ENC_RND_KEY_STEP ( 4, 5, 6, 7 );
  AES_ENC_RND_KEY_STEP ( 8, 9, 10, 11 );
  AES_ENC_RND_KEY_STEP ( 12, 13, 14, 15 );
}

void aes_enc_rnd_sub ( aes_gf28_t * s ) {
  AES_ENC_RND_SUB_STEP ( 0, 1, 2, 3 );
  AES_ENC_RND_SUB_STEP ( 4, 5, 6, 7 );
  AES_ENC_RND_SUB_STEP ( 8, 9, 10, 11 );
  AES_ENC_RND_SUB_STEP ( 12, 13, 14, 15 );
}

void aes_enc_rnd_row ( aes_gf28_t * s ) {
AES_ENC_RND_ROW_STEP ( 1, 5, 9, 13,
                       13, 1, 5, 9 );
AES_ENC_RND_ROW_STEP ( 2, 6, 10, 14,
                      10, 14, 2, 6 );
AES_ENC_RND_ROW_STEP ( 3, 7, 11, 15,
                       7, 11, 15, 3 );
}

void aes_enc_rnd_mix ( aes_gf28_t * s ) {
  AES_ENC_RND_MIX_STEP ( 0, 1, 2, 3 );
  AES_ENC_RND_MIX_STEP ( 4, 5, 6, 7 );
  AES_ENC_RND_MIX_STEP ( 8, 9, 10, 11 );
  AES_ENC_RND_MIX_STEP ( 12, 13, 14, 15 );
}

char intToChar( uint8_t num ) {
  if ( num < 10 ) return num + '0';
  if (num < 16) return num + 'A' - 10;
  return 's';
}

void intToStr( uint8_t num, uint8_t* str ) {
  uint8_t nums[2];

  nums[0] = ( num & 0xF0 ) >> 4;
  nums[1] = num & 0x0F;

  str[0] = intToChar( nums[0] );
  str[1] = intToChar( nums[1] );
}

uint8_t charToInt( const char c ) {
  if (c <= 'F' && c >= 'A' ) return (uint8_t)(c - 'A' + 10);
  if (c <= 'f' && c >= 'a' ) return (uint8_t)(c - 'a' + 10);
  if (c <= '9' && c >= '0' ) return (uint8_t)(c - '0');
  return 0;
}

uint8_t strToint( unsigned char* str ) {
  uint8_t num = ( charToInt( str[0] ) << 4 ) | charToInt( str[1] );
  return num;
}

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  octetstr_rd(       uint8_t* r, int n_r ) {

  unsigned char buf[2];
  uint8_t length, num;

  buf[0] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );
  buf[1] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );

  // read colon
  scale_uart_rd( SCALE_UART_MODE_BLOCKING );

  length = strToint( buf );

  if ( length > n_r ) {
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, 'E' );
    scale_delay_ms( 1000 );
    return 0;
  }

  for ( int i = 0; i < length; i++ ) {
    buf[0] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );
    buf[1] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );

    num = strToint( buf );
    r[i] = num;
  }

  // Read new line
  scale_uart_rd( SCALE_UART_MODE_BLOCKING );

  return length;
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

  void octetstr_wr( const uint8_t* x, int n_x ) {

    uint8_t buf[2];
    intToStr( n_x, buf );

    scale_uart_wr( SCALE_UART_MODE_BLOCKING, buf[0] );
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, buf[1] );
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, ':' );

    for ( int i = 0; i < n_x; i++ ) {
      intToStr( x[i], buf );
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, buf[0] );
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, buf[1] );
    }
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, 13 );

  }

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */
void aes (uint8_t* c, const uint8_t * m, const uint8_t * k, uint8_t *r ) {
  uint8_t Nb = 4; // block size
  aes_gf28_t rk[ 4 * Nb ], st[ 4 * Nb ]; // round key and state matrix

  uint8_t Nr = 10;

  aes_gf28_t rcp = 0;
  aes_gf28_t * rkp = rk;

  U8_TO_U8_N( st, m ); // s <- m
  U8_TO_U8_N( rkp, k ); // rkp <- k

  // 1 initial round
  aes_enc_rnd_key ( st, rkp ); // keyAddition
  // Nr - 1 iterated rounds
  for( int i = 1; i < Nr; i++ ) {
    aes_enc_rnd_sub ( st ); // subBytes
    aes_enc_rnd_row ( st ); // shiftRows
    aes_enc_rnd_mix ( st ); // mixColumns
    rcp++;
    aes_enc_keyexp_step ( rkp , rkp , rcp );
    aes_enc_rnd_key ( st, rkp ); // keyAddition
  }
  // 1 final round
  aes_enc_rnd_sub ( st ); // subBytes
  aes_enc_rnd_row ( st ); // shiftRows
  rcp++;
  aes_enc_keyexp_step ( rkp , rkp , rcp );
  aes_enc_rnd_key ( st, rkp ); // keyAddition
  U8_TO_U8_N ( c, st );
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] =  { 0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48, 0x69, 0x77, 0x2A, 0x34, 0x6A, 0X7F, 0x58, 0x13 } /*{ 0xC7, 0x3C, 0x03, 0x30, 0xF7, 0x33, 0xC0, 0x41, 0x5B, 0xFE, 0x47, 0x7A, 0x4F, 0x33, 0xE6, 0xDA }*/, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        scale_uart_wr( SCALE_UART_MODE_BLOCKING, '-' );
        break;
      }
    }
  }

  return 0;
}
