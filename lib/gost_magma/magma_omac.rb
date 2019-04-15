module GostMagma
  class MagmaOmac < Magma
    def initialize(key, mac_size)
      @key = key.dup.force_encoding('BINARY')
      @keys = []
      (0...8).each do |i|
        @keys << self.class.uint8ToUint32(@key[i*4...(i+1)*4].reverse)
      end
      
      @mac_size = mac_size
      @ctxR = self.class.zeroBlock
      @ctxB = self.class.zeroBlock
      @ctxB[-1] = 0x1b.chr
      @ctxK1 = self.class.zeroBlock
      @ctxK2 = self.class.zeroBlock
      @ctxC = self.class.zeroBlock
      @lastBlock = ''
      @lastBlockSize = 0
      @isFirstBlock = true
      expandMacKey
      @bytes_count = 0
    end
    
    def update(indata)
      indata_length = indata.length
      indata_index = 0
      @bytes_count += indata_length
      if @lastBlockSize > 0 then
        # prev update data
        if indata_length < BlockLengthInBytes - @lastBlockSize then
          # No full block
          @lastBlock += indata
          @bytes_count += indata_length
          return self
        else
          # Make full block
          @lastBlock += indata[indata_index...indata_index + BlockLengthInBytes - @lastBlockSize]
          if @isFirstBlock then
            @isFirstBlock = false
            indata_index += BlockLengthInBytes - @lastBlockSize
            indata_length -= BlockLengthInBytes - @lastBlockSize
            @lastBlockSize = BlockLengthInBytes
          else
            (0...BlockLengthInBytes).each do |j|
              @lastBlock[j] = (@lastBlock[j].ord ^ @ctxC[j].ord).chr 
            end
            @ctxC = self.class.encryptBlock(@lastBlock, @keys)
            indata_index += BlockLengthInBytes - @lastBlockSize
            indata_length -= BlockLengthInBytes - @lastBlockSize
            if indata_length >= BlockLengthInBytes then
              @LastBlock = indata[indata_index...(indata_index + LCC_KUZNYECHIK_BLOCK_LEN)].dup
              indata_index += BlockLengthInBytes
              @LastBlockSize = BlockLengthInBytes
              indata_length -= BlockLengthInBytes
            else
              @lastBlock = indata[indata_index...(indata_index + indata_length)].dup
              indata_index += indata_length
              @LastBlockSize = indata_length
              indata_length = 0
            end        
          end       
        end
      end
      
      (0...indata_length/BlockLengthInBytes).each do |i|
        indata_index = i * BlockLengthInBytes
        if @isFirstBlock then
          @lastBlock = indata[indata_index...(indata_index + BlockLengthInBytes)].dup
          @lastBlockSize = BlockLengthInBytes
          @isFirstBlock = false
          indata_index += BlockLengthInBytes
          next
        end
        (0...BlockLengthInBytes).each do |j|
          @lastBlock[j] = (@lastBlock[j].ord ^ @ctxC[j].ord).chr
        end
        @ctxC = self.class.encryptBlock(@lastBlock, @keys)
        @lastBlock = indata[indata_index...(indata_index + BlockLengthInBytes)].dup
        indata_index += BlockLengthInBytes
      end
    
      if indata_length % BlockLengthInBytes > 0 then
        if not @isFirstBlock then
          (0...BlockLengthInBytes).each do |j|
            @lastBlock[j] = (@lastBlock[j].ord ^ @ctxC[j].ord).chr
          end
          @ctxC = self.class.encryptBlock(@lastBlock, @keys)
        end
        @lastBlock = indata[indata_index...(indata_index + indata_length % BlockLengthInBytes)].dup
        @lastBlockSize = indata_length % BlockLengthInBytes	  
      end
      return self
    end
    
    def final
      if (@bytes_count == 0) || (@lastBlockSize > 0) then
        tmp_block = @lastBlock.dup
        if @lastBlockSize != BlockLengthInBytes then
          tmp_block = self.class.padd(tmp_block)        
        end
      else  
        tmp_block = self.class.zeroBlock
      end
      (0...BlockLengthInBytes).each do |i|
        tmp_block[i] = (tmp_block[i].ord ^ @ctxC[i].ord).chr
      end
      kK = (@lastBlockSize != BlockLengthInBytes) ? @ctxK2 : @ctxK1
      (0...BlockLengthInBytes).each do |i|
        tmp_block[i] = (tmp_block[i].ord ^ kK[i].ord).chr
      end
      mac = self.class.encryptBlock(tmp_block, @keys)
      result = mac[0...@mac_size]
    end
    
    private
        
    def expandMacKey
      tmp_block = self.class.zeroBytes(KeyLengthInBytes + BlockLengthInBytes)
      @ctxR = self.class.encryptBlock(tmp_block, @keys)
      r = ((@ctxR[0].ord & 0x80) == 0x80)
      self.class.shiftLeftOne(@ctxR)
      if r then
        (0...BlockLengthInBytes).each do |i|
          @ctxK1[i] = (@ctxR[i].ord ^ @ctxB[i].ord).chr
        end
      else
        @ctxK1 = @ctxR.dup
      end
      tmp_block = @ctxK1.dup
      self.class.shiftLeftOne(tmp_block)
      r = ((@ctxK1[0].ord & 0x80) == 0x80)
      if r then
        (0...BlockLengthInBytes).each do |i|
          @ctxK2[i] = (tmp_block[i].ord ^ @ctxB[i].ord).chr
        end
      else
        @ctxK2 = tmp_block
      end    
    end

  end
end
