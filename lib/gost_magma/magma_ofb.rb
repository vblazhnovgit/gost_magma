module GostMagma
  class MagmaOfb < Magma
    def initialize(key, iv, gamma_s)
      @key = key.dup.force_encoding('BINARY')
      @keys = []
      (0...8).each do |i|
        @keys << self.class.uint8ToUint32(@key[i*4...(i+1)*4].reverse)
      end
      
      @gamma_s = gamma_s
      @ctxR = iv.dup.force_encoding('BINARY')
      tmp_block = @ctxR[0...BlockLengthInBytes]
      @gamma_block = self.class.encryptBlock(tmp_block, @keys)
      @ctxR = @ctxR[BlockLengthInBytes..-1] + @gamma_block
      @incomplete_block_len = 0
    end
    
    def encrypt(data)
      data_len = data.length
      outdata = ''
      left_data_len = data_len
      if @incomplete_block_len > 0 then      
        # use old @gamma_block
        if data_len < @gamma_s - @incomplete_block_len then
          # incomplete block yet
          outdata = data.dup
          (0...data_len).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len + j].ord ^ outdata[j].ord).chr
          end
          @incomplete_block_len += data_len
          return outdata
        else
          outdata = data[0...(@gamma_s - @incomplete_block_len)]
          (0...outdata.length).each do |j|
            outdata[j] = (@gamma_block[@incomplete_block_len + j].ord ^ outdata[j].ord).chr
          end
          # complete block - update gamma block
          tmp_block = @ctxR[0...BlockLengthInBytes]
          @gamma_block = self.class.encryptBlock(tmp_block, @keys)
          @ctxR = @ctxR[BlockLengthInBytes..-1] + @gamma_block
          left_data_len -= outdata.length
        end
      end
            
      (0...(left_data_len / @gamma_s)).each do |i|
        if @incomplete_block_len > 0 then
          encr_data = data[((i + 1) * @gamma_s - @incomplete_block_len)...((i + 2) * @gamma_s - @incomplete_block_len)]
        else
          encr_data = data[(i * @gamma_s)...((i + 1) * @gamma_s)]
        end
        (0...@gamma_s).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        # complete block - update gamma block        
        tmp_block = @ctxR[0...BlockLengthInBytes]
        @gamma_block = self.class.encryptBlock(tmp_block, @keys)
        @ctxR = @ctxR[BlockLengthInBytes..-1] + @gamma_block
        left_data_len -= @gamma_s
      end
            
      if left_data_len > 0 then
        # incomplete block start
        encr_data = data[-left_data_len..-1]
        (0...left_data_len).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        @incomplete_block_len = left_data_len
      end
      outdata
    end
    
    def decrypt(data)
      encrypt(data)
    end
    
  end
end  
