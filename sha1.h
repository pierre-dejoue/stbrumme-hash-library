// //////////////////////////////////////////////////////////
// sha1.h
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

/// compute SHA1 hash
/** Usage:
    SHA1 sha1;
    std::string myHash  = sha1("Hello World");     // std::string
    std::string myHash2 = sha1("How are you", 11); // arbitrary data, 11 bytes

    // or in a streaming fashion:

    SHA1 sha1;
    while (more data available)
      sha1.add(pointer to fresh data, number of new bytes);
    std::string myHash3 = sha1.getHash();
  */
class SHA1 //: public Hash
{
public:
  /// split into 64 byte blocks (=> 512 bits), hash is 20 bytes long
  enum { BlockSize = 512 / 8, HashBytes = 20 };

  /// same as reset()
  SHA1();

  /// compute SHA1 of a memory block
  std::string operator()(const void* data, std::size_t numBytes);
  /// compute SHA1 of a string, excluding final zero
  std::string operator()(const std::string& text);

  /// add arbitrary number of bytes
  void add(const void* data, std::size_t numBytes);

  /// return latest hash as 40 hex characters
  std::string getHash();
  /// return latest hash as bytes
  void        getHash(unsigned char buffer[HashBytes]);

  /// restart
  void reset();

private:
  /// process 64 bytes
  void processBlock(const void* data);
  /// process everything left in the internal buffer
  void processBuffer();

  /// size of processed data in bytes
  std::uint64_t m_numBytes;
  /// valid bytes in m_buffer
  std::size_t   m_bufferSize;
  /// bytes not processed yet
  std::uint8_t  m_buffer[BlockSize];

  enum { HashValues = HashBytes / 4 };
  /// hash, stored as integers
  std::uint32_t m_hash[HashValues];
};

} // namespace hash
} // namespace stbrumme
