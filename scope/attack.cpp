#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>
#include <string>

#define SAMPLE_LIMIT 15000

using namespace std;

typedef uint8_t aes_gf28_t;

uint32_t t, s;

vector<vector<uint8_t>> load_Uint8_t( ifstream& file ) {
  vector<vector<uint8_t>> data( t, vector<uint8_t>( 16 ) );
  uint8_t chunk;

  for ( int i = 0; i < t; i++ ) {
    for (int j = 0; j < 16; j++ ) {
      file.read( (char*)&chunk, 1 );
      data[i][j] = chunk;
    }
  }

  return data;
}

void load_int16_t( ifstream& file, int16_t *data ) {
  int16_t chunk;

  for ( int i = 0; i < t; i++ ) { // cols = t
    for (int j = 0; j < s; j++ ) { // rows = s
      file.read( (char*)&chunk, 2 );
      data[ j * t + i ] = chunk;
    }
  }
}

// Fills a vector with all possible permutations of a byte
vector<uint8_t> getAllPossibleKeys() {
  vector<uint8_t> k( 256 );

  for (int i = 0; i < 256; i++)
    k[i] = i;

  return k;
}

// extracts the index'th byte from every plaintext
// Assumes: 0 <= index < 16
vector<uint8_t> extractMessagePart( vector<vector<uint8_t>>& messages, uint32_t index ) {

  size_t t = messages.size();
  vector<uint8_t> messagePart( t );

  for ( int i = 0; i < t; i++ ) {
    messagePart[i] = messages[i][index];
  }

  return messagePart;
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

aes_gf28_t inverse_in_GF28 ( aes_gf28_t val ) {
  aes_gf28_t t_0 = aes_gf28_mul ( val, val );
  aes_gf28_t t_1 = aes_gf28_mul ( t_0 , val );
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

aes_gf28_t sbox( aes_gf28_t val ) {
  val = inverse_in_GF28 ( val );

  val = ( 0x63 ) ^
  ( val ) ^
  ( val << 1 ) ^
  ( val << 2 ) ^
  ( val << 3 ) ^
  ( val << 4 ) ^
  ( val >> 7 ) ^
  ( val >> 6 ) ^
  ( val >> 5 ) ^
  ( val >> 4 ) ;
  return val;
}

// Returns a vector V, s.t. V[j][i] = sbox( mesagesPart[j] `xor` keys[i] )
vector<vector<uint8_t>> getHypotheticalIntermediateValues( vector<uint8_t>& keys, vector<uint8_t>& messagesPart ) {
  vector<vector<uint8_t>> V( messagesPart.size(),  vector<uint8_t>( keys.size() ) );

  for ( int i = 0; i < keys.size(); i++ )
    for ( int j = 0; j < messagesPart.size(); j++ )
      V[j][i] = sbox( messagesPart[j] ^ keys[i] );

  return V;

}

inline uint8_t getHamWeight( uint8_t val ) {
  uint8_t result = 0;

  while ( val != 0 ) {
    result += val & 0x01;
    val = val >> 1;
  }

  return result;
}

void getHypotheticalPowerConsumption( vector<vector<uint8_t>>& hypValues, uint8_t *hypPCons, int rows ) {

  for ( int i = 0; i < 256; i++ )
    for ( int j = 0; j < rows; j++ )
      hypPCons[ i * rows + j ] = getHamWeight( hypValues[j][i] );
}

inline float getVerticalMean( int16_t* vec, int rows, int colIndex ) {
  int sum = 0;

  for (size_t i = 0; i < rows; i++)
    sum += vec[ colIndex * rows + i];

  return (float)sum / (float)rows;
}

inline float getVerticalMean( uint8_t* vec, int rows, int colIndex ) {
  int sum = 0;

  for (size_t i = 0; i < rows; i++)
    sum += vec[ colIndex * rows + i];

  return (float)sum / (float)rows;
}

inline float covariance( uint8_t* vec1, int rows1, int col1, float meanVec1, int16_t* vec2, int rows2, int col2, float meanVec2 ) {
  float sum = 0.0;
  for ( int d = 0; d < rows1; d++ ) {
    sum += ( vec1[col1 * rows1 + d] - meanVec1 ) * ( vec2[ col2 * rows2 + d ] - meanVec2 );
  }

  return sum;
}

inline float covariance( int16_t* vec1, int rows1, int col1, float meanVec1, int16_t* vec2, int rows2, int col2, float meanVec2 ) {
  float sum = 0.0;
  for ( int d = 0; d < rows1; d++ ) {
    sum += ( vec1[col1 * rows1 + d] - meanVec1 ) * ( vec2[ col2 * rows2 + d ] - meanVec2 );
  }

  return sum;
}

inline float covariance( uint8_t* vec1, int rows1, int col1, float meanVec1, uint8_t* vec2, int rows2, int col2, float meanVec2 ) {
  float sum = 0.0;
  for ( int d = 0; d < rows1; d++ ) {
    sum += ( vec1[col1 * rows1 + d] - meanVec1 ) * ( vec2[ col2 * rows2 + d ] - meanVec2 );
  }

  return sum;
}

inline float varianceSquared( int16_t* vec, int rows, int col, float meanVec ) {
  return covariance( vec, rows, col, meanVec, vec, rows, col, meanVec );
}

inline float varianceSquared( uint8_t* vec, int rows, int col, float meanVec ) {
  return covariance( vec, rows, col, meanVec, vec, rows, col, meanVec );
}

uint8_t getCorrelationAndMax( uint8_t* vec1, int rows1, int cols1, int16_t* vec2, int rows2, int cols2, float* R ) {
  float meanVec1;
  float meanVec2;
  float max = 0;
  int maxIndex = 0;

  for ( uint8_t i = 0x00; i < 0xff; i++ ) {

    meanVec1 = getVerticalMean( vec1, rows1, i );

    for ( int j = 0; j < cols2; j++ ) {

      meanVec2 = getVerticalMean( vec2, rows2, j );

      R[ i * cols2 + j ] = covariance( vec1, rows1, i, meanVec1, vec2, rows2, j, meanVec2 ) / sqrt( varianceSquared( vec1, rows1, i, meanVec1 ) * varianceSquared( vec2, rows2, j, meanVec2 ) ) ;

      if ( abs( R[ i * cols2 + j ] ) > max ) {
        max = abs( R[ i * cols2 + j ] );
        maxIndex = i;
      }

    }
  }
  return maxIndex;
}

int main() {
  ifstream traces;

  traces.open( "traces.dat" );
  traces.read( (char*)&t, 4 );
  traces.read( (char*)&s, 4 );

  cout << "t = " << t << '\n';
  cout << "s = " << s << '\n';

  // STEP 2:
  vector<vector<uint8_t>> M = load_Uint8_t( traces );
  std::cout << "Messages Loaded Successfully!" << '\n';

  vector<vector<uint8_t>> C = load_Uint8_t( traces );
  std::cout << "Cyphertexts Loaded Successfully!" << '\n';

  int16_t* T = (int16_t*)malloc( s * t * sizeof(int16_t) );
  load_int16_t( traces, T );
  std::cout << "Traces Loaded Successfully!" << '\n';

  traces.close();

  vector<uint8_t> recoveredKey( 16 );

  // STEP 3:
  vector<uint8_t> k = getAllPossibleKeys();

  for ( int byte = 0; byte < 16; byte++ ) {

    std::cout << "Key recovery is " << 100 * (float)byte / 16.0f << "% complete." << '\n';

    vector<uint8_t> messagesPart = extractMessagePart( M, byte );
    // std::cout << "Message Parts extracted Successfully!" << '\n';
    vector<vector<uint8_t>> V = getHypotheticalIntermediateValues( k, messagesPart );
    // std::cout << "Hypothetical intermediate values computed successfully!" << '\n';

    // STEP 4:
    uint8_t* H = (uint8_t*)malloc( V.size() * 256 * 8 );
    getHypotheticalPowerConsumption( V, H, V.size() );
    // std::cout << "Hypothetical power consumption computed successfully!" << '\n';

    // STEP 5:
    float* R = (float*)malloc( 256 * SAMPLE_LIMIT * sizeof(float) );
    recoveredKey[byte] = getCorrelationAndMax( H, V.size(), 256, T, t, SAMPLE_LIMIT, R );

  }
  std::cout << "Key recovery is 100% complete." << '\n';
  std::cout << "Correlation computed successfully!" << '\n';
  std::cout << "Recovered Key is: ";

  for ( size_t i = 0; i < 16; i++ )
    printf( "%x ", recoveredKey[i] );

  printf( "\n" );

  // delete &M;
  // delete &C;
  // delete &T;
  return 0;
}
//key: C7 3C 03 30 F7 33 C0 41 5B FE 47 7A 4F 33 E6 DA
