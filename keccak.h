// //////////////////////////////////////////////////////////
// keccak.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

//#include "hash.h"
#include <cstddef>
#include <cstdint>
#include <string>

namespace stbrumme {
namespace hash {



/// compute Keccak hash (designated SHA3)
/** Usage:
    Keccak keccak;
    std::string myHash  = keccak("Hello World");     // std::string
    std::string myHash2 = keccak("How are you", 11); // arbitrary data, 11 bytes

    // or in a streaming fashion:

    Keccak keccak;
    while (more data available)
      keccak.add(pointer to fresh data, number of new bytes);
    std::string myHash3 = keccak.getHash();
  */
class Keccak //: public Hash
{
public:
  /// algorithm variants
  enum Bits { Keccak224 = 224, Keccak256 = 256, Keccak384 = 384, Keccak512 = 512 };

  /// same as reset()
  explicit Keccak(Bits bits = Keccak256);

  /// compute hash of a memory block
  std::string operator()(const void* data, std::size_t numBytes);
  /// compute hash of a string, excluding final zero
  std::string operator()(const std::string& text);

  /// add arbitrary number of bytes
  void add(const void* data, std::size_t numBytes);

  /// return latest hash as hex characters
  std::string getHash();

  /// restart
  void reset();

private:
  /// process a full block
  void processBlock(const void* data);
  /// process everything left in the internal buffer
  void processBuffer();

  /// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
  enum { StateSize    = 1600 / (8 * 8),
         MaxBlockSize =  200 - 2 * (224 / 8) };

  /// hash
  std::uint64_t m_hash[StateSize];
  /// size of processed data in bytes
  std::uint64_t m_numBytes;
  /// block size (less or equal to MaxBlockSize)
  std::size_t   m_blockSize;
  /// valid bytes in m_buffer
  std::size_t   m_bufferSize;
  /// bytes not processed yet
  std::uint8_t  m_buffer[MaxBlockSize];
  /// variant
  Bits     m_bits;
};

} // namespace hash
} // namespace stbrumme
