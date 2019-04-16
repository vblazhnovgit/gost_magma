module GostMagma

  class MagmaOmacAcpkm < MagmaCtrAcpkm

    def initialize(key, section_N, base_key_change_T, mac_size)
      @mac_N = section_N
      @mac_T = base_key_change_T 
      @mac_size = mac_size
      super(key, ACPKM_CTR_IV, BlockLengthInBytes, @mac_T)
      @ecb = MagmaEcb.new(key)
      @mac_R = Magma::zeroBlock
      @mac_B = Magma::zeroBlock
      @mac_B[-1] = 0x1b.chr
      @mac_K1 = Magma::zeroBlock
      @mac_K2 = Magma::zeroBlock
      @mac_C = Magma::zeroBlock
      @mac_encrBlock = Magma::zeroBlock
      @mac_lastBlock = ''
      @mac_lastBlockSize = 0
      @mac_lastBlockIndex = 0
      @mac_isFirstBlock = true    
      @mac_byte_counter = 0
      @mac_block_counter = 0
      @mac_section_counter = 0
      @mac_base_key_counter = 0
      @mac_derived_key_counter = 0
      deriveKeys
      @mac_derived_key_counter += 1   
    end
    
    def update(data)
      data_len = data.length
      (0...data_len).each do |k|
        if @mac_lastBlockSize < BlockLengthInBytes then
          @mac_byte_counter += 1
          @mac_lastBlock[@mac_lastBlockIndex] = data[k]
          @mac_lastBlockIndex += 1
          @mac_lastBlockSize = @mac_lastBlockIndex
          if k == data_len - 1 then
            break
          end
        end  
        if @mac_lastBlockSize == BlockLengthInBytes then
          @mac_block_counter += 1
          (0...BlockLengthInBytes).each do |j|
            @mac_encrBlock[j] = (@mac_lastBlock[j].ord ^ @mac_C[j].ord).chr
          end
          @mac_C = @ecb.encrypt(@mac_encrBlock)
          if @mac_byte_counter % @mac_N == 0 then
            if @mac_section_counter >= OMAC_ACPKM_MAX_N then
              raise RangeError, 'Input message is too long for Magma OMAC-ACPKM'
              return nil
            end  
            @mac_section_counter += 1
            @mac_byte_counter = 0
            if (@mac_derived_key_counter * @mac_N) % @mac_T == 0 then
              @mac_base_key_counter += 1
              acpkmCtrKey
            end
            deriveKeys
            @mac_derived_key_counter += 1
          end
          @mac_lastBlockIndex = 0
          @mac_lastBlockSize = 0
        end
      end
      return self
    end
    
    def final
      @mac_lastBlock = @mac_lastBlock[0...@mac_lastBlockSize]
      if (@mac_byte_counter == 0) || (@mac_lastBlockSize > 0) then
        if @mac_lastBlockSize != BlockLengthInBytes then
          @mac_lastBlock = Magma::padd(@mac_lastBlock)
        end
      end
      (0...BlockLengthInBytes).each do |j|
        @mac_encrBlock[j] = (@mac_lastBlock[j].ord ^ @mac_C[j].ord).chr
      end
      if @mac_lastBlockSize != BlockLengthInBytes then
        deriveK2
        kk = @mac_K2
      else
        kk = @mac_K1
      end
      (0...BlockLengthInBytes).each do |j|
        @mac_encrBlock[j] = (@mac_encrBlock[j].ord ^ kk[j].ord).chr
      end
      mac = @ecb.encrypt(@mac_encrBlock)
      result = mac[0...@mac_size].dup
    end

    private
    
    ACPKM_CTR_IV = [
      0xFF, 0xFF, 0xFF, 0xFF
    ].pack('C*').freeze
    
    OMAC_ACPKM_MAX_N = 0x19999999 # 0x80000000/5
    
    ACPKM_CTR_NULL = Magma::zeroBytes(KeyLengthInBytes+BlockLengthInBytes)

    def deriveKeys
      kk = encrypt(ACPKM_CTR_NULL)      
      # re-initialize ECB context
      @ecb = MagmaEcb.new(kk[0...KeyLengthInBytes].dup)
      @mac_K1 = kk[KeyLengthInBytes..-1].dup
    end

    def deriveK2
      tmp_block = @mac_K1.dup
      Magma::shiftLeftOne(tmp_block)
      if (@mac_K1[0].ord & 0x80) == 0x80 then
        (0...BlockLengthInBytes).each do |i|
          @mac_K2[i] = (tmp_block[i].ord ^ @mac_B[i].ord).chr
        end
      else
        @mac_K2 = tmp_block.dup
      end
    end

  end
end