module GostMagma
  # Base abstract class
  class Magma
    # class constants
    BlockLengthInBytes = 8
    KeyLengthInBytes = 32
    
    # 's' stands for native-endian byte order but 'n' stands for network (big-endian) byte order
    BigEndian = [1].pack('s') == [1].pack('n')

    protected

    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end

    def self.zeroBytes(n)
      ("\x00"*n).force_encoding('BINARY')
    end

    def self.zeroBlock
      ("\x00"*BlockLengthInBytes).force_encoding('BINARY')
    end

    # Unload 32-bit number to 8-byte string
    # (big-endian, adding leading zeroes)
    def self.uint32ToUint8BE(n)
      str = n.to_s(16) # big-endian
      len = str.length
      # add leading zeroes
      str.insert(0, '0'*(8 - len)) if len < 8
      # To byte string
      bytes = [str].pack('H*')
    end 
    
    # Unload 32-bit number to 8-byte string
    # (native-endian, adding leading zeroes)
    def self.uint32ToUint8(n)
      bytes = uint32ToUint8BE(n)    
      bytes.reverse! unless BigEndian   
      bytes
    end
    
    # Unpacks 8-byte string to 32-bit number 
    # (native-endian)
    def self.uint8ToUint32(bytes)
      bytes.unpack('L*')[0]
    end
    
    def self.encryptRound(right, left, key1, key2)
      t = (key1 + right) & 0xffffffff
      left ^= TzTable[0][t & 0xff] ^ TzTable[1][(t >> 8) & 0xff] ^
        TzTable[2][(t >> 16) & 0xff] ^ TzTable[3][t >> 24 & 0xff]
      t = (key2 + left) & 0xffffffff
      right ^= TzTable[0][t & 0xff] ^ TzTable[1][(t >> 8) & 0xff] ^
        TzTable[2][(t >> 16) & 0xff] ^ TzTable[3][(t >> 24) & 0xff]
      [right, left]
    end

    def self.encryptCycle(right, left, keys)
      right, left = encryptRound(right, left, keys[0], keys[1])
      right, left = encryptRound(right, left, keys[2], keys[3])
      right, left = encryptRound(right, left, keys[4], keys[5])
      right, left = encryptRound(right, left, keys[6], keys[7])
      right, left = encryptRound(right, left, keys[0], keys[1])
      right, left = encryptRound(right, left, keys[2], keys[3])
      right, left = encryptRound(right, left, keys[4], keys[5])
      right, left = encryptRound(right, left, keys[6], keys[7])
      right, left = encryptRound(right, left, keys[0], keys[1])
      right, left = encryptRound(right, left, keys[2], keys[3])
      right, left = encryptRound(right, left, keys[4], keys[5])
      right, left = encryptRound(right, left, keys[6], keys[7])
      right, left = encryptRound(right, left, keys[7], keys[6])
      right, left = encryptRound(right, left, keys[5], keys[4])
      right, left = encryptRound(right, left, keys[3], keys[2])
      right, left = encryptRound(right, left, keys[1], keys[0])
      [right, left]
    end

    def self.decryptCycle(right, left, keys)
      right, left = encryptRound(right, left, keys[0], keys[1])
      right, left = encryptRound(right, left, keys[2], keys[3])
      right, left = encryptRound(right, left, keys[4], keys[5])
      right, left = encryptRound(right, left, keys[6], keys[7])
      right, left = encryptRound(right, left, keys[7], keys[6])
      right, left = encryptRound(right, left, keys[5], keys[4])
      right, left = encryptRound(right, left, keys[3], keys[2])
      right, left = encryptRound(right, left, keys[1], keys[0])
      right, left = encryptRound(right, left, keys[7], keys[6])
      right, left = encryptRound(right, left, keys[5], keys[4])
      right, left = encryptRound(right, left, keys[3], keys[2])
      right, left = encryptRound(right, left, keys[1], keys[0])
      right, left = encryptRound(right, left, keys[7], keys[6])
      right, left = encryptRound(right, left, keys[5], keys[4])
      right, left = encryptRound(right, left, keys[3], keys[2])
      right, left = encryptRound(right, left, keys[1], keys[0])
      [right, left]
    end

    def self.encryptBlockUintKey(input, keys)
      right = uint8ToUint32(input[0..3])
      left = uint8ToUint32(input[4..-1])
      right, left = encryptCycle(right, left, keys)
      output = uint32ToUint8(left) + uint32ToUint8(right)
    end

    def self.decryptBlockUintKey(input, keys)
      right = uint8ToUint32(input[0..3])
      left = uint8ToUint32(input[4..-1])
      right, left = decryptCycle(right, left, keys)
      output = uint32ToUint8(left) + uint32ToUint8(right)
    end

    def self.encryptBlock(input, keys)
      tmp_input = input.reverse 
      tmp_output = encryptBlockUintKey(tmp_input, keys)
      output = tmp_output.reverse
    end

    def self.decryptBlock(input, keys)
      tmp_input = input.reverse
      tmp_output = decryptBlockUintKey(tmp_input, keys)
      output = tmp_output.reverse
    end

    # Increment CTR counter
    def self.incrementModulo(counter, size)
      lastIndex = size - 1
      (0...size).each do |i|
        if counter[lastIndex - i].ord > 0xfe then  
          counter[lastIndex - i] = (counter[lastIndex - i].ord - 0xff).chr  
        else 
          counter[lastIndex - i] = (counter[lastIndex - i].ord + 1).chr 
          break 
        end  
      end
      counter
    end
    
    # block - byte string  
    def self.shiftLeftOne(block)
      (0...(BlockLengthInBytes-1)).each do |i|
        ri1 = block[i+1].ord
        ri = block[i].ord << 1
        ri &= 0xfe
        ri |= (ri1 >> 7) & 0x1
        block[i] = ri.chr
      end
      ri = block[BlockLengthInBytes-1].ord << 1
      block[BlockLengthInBytes-1] = (ri & 0xfe).chr
      block
    end
    
    def self.padd(incomplete_block)
      padding_len = BlockLengthInBytes - (incomplete_block.length % BlockLengthInBytes)
      padded_block = incomplete_block.dup
      padded_block += 0x80.chr
      padding_len -= 1
      if padding_len > 0 then
        padded_block += 0.chr * padding_len
      end
      padded_block
    end
  end
end
