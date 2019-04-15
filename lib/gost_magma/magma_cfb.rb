module GostMagma
  class MagmaCfb < Magma
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
      @incomplete_block = ''  
      @incomplete_block_len = 0
    end
    
    def encrypt(data)
      data_len = data.length
      left_data_len = data_len
      outdata = ''
      if @incomplete_block_len > 0 then      
        # use old @gamma_block
        if data_len < @gamma_s - @incomplete_block_len then
          # incomplete block yet
          encr_data = data.dup
          (0...data_len).each do |j|
            encr_data[j] = (@gamma_block[@incomplete_block_len + j].ord ^ encr_data[j].ord).chr
          end
          @incomplete_block_len += data_len
          @incomplete_block += encr_data
          return encr_data
        else
          encr_data = data[0...(@gamma_s - @incomplete_block_len)]
          (0...encr_data.length).each do |j|
            encr_data[j] = (@gamma_block[@incomplete_block_len + j].ord ^ encr_data[j].ord).chr
          end
          outdata += encr_data
          # complete block - gamma update
          @incomplete_block += encr_data
          left_data_len -= encr_data.length
          @ctxR = @ctxR[@gamma_s..-1] + @incomplete_block
          tmp_block = @ctxR[0...BlockLengthInBytes]
          @gamma_block = self.class.encryptBlock(tmp_block, @keys)
          @incomplete_block = ''
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
        # complete block - gamma update        
        @ctxR = @ctxR[@gamma_s..-1] + encr_data
        tmp_block = @ctxR[0...BlockLengthInBytes]
        @gamma_block = self.class.encryptBlock(tmp_block, @keys)      
      end
      
      left_data_len %= @gamma_s 
      if left_data_len > 0 then
        # incomplete block start
        encr_data = data[-left_data_len..-1]
        (0...left_data_len).each do |j|
          encr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += encr_data
        @incomplete_block_len = left_data_len
        @incomplete_block = encr_data
      end
      outdata
    end
    
    # Use input encrypted text to gamma update    
    def decrypt(data)
      data_len = data.length
      left_data_len = data_len
      outdata = ''
      if @incomplete_block_len > 0 then      
        # use old @gamma_block
        if data_len < @gamma_s - @incomplete_block_len then
          # incomplete block yet
          encr_data = data.dup
          decr_data = data.dup
          (0...data_len).each do |j|
            decr_data[j] = (@gamma_block[@incomplete_block_len + j].ord ^ encr_data[j].ord).chr
          end
          @incomplete_block_len += data_len
          @incomplete_block += encr_data
          return decr_data
        else
          encr_data = data[0...(@gamma_s - @incomplete_block_len)]
          decr_data = encr_data.dup
          (0...encr_data.length).each do |j|
            decr_data[j] = (@gamma_block[@incomplete_block_len + j].ord ^ encr_data[j].ord).chr
          end
          outdata += decr_data
          # complete block - gamma update
          @incomplete_block += encr_data
          left_data_len -= encr_data.length
          @ctxR = @ctxR[@gamma_s..-1] + @incomplete_block
          tmp_block = @ctxR[0...BlockLengthInBytes]
          @gamma_block = self.class.encryptBlock(tmp_block, @keys)
          @incomplete_block = ''
        end
      end
      
      (0...(left_data_len / @gamma_s)).each do |i|
        if @incomplete_block_len > 0 then
          encr_data = data[((i + 1) * @gamma_s - @incomplete_block_len)...((i + 2) * @gamma_s - @incomplete_block_len)]
        else
          encr_data = data[(i * @gamma_s)...((i + 1) * @gamma_s)]
        end
        decr_data = encr_data.dup
        (0...@gamma_s).each do |j|
          decr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += decr_data
        # complete block - gamma update        
        @ctxR = @ctxR[@gamma_s..-1] + encr_data
        tmp_block = @ctxR[0...BlockLengthInBytes]
        @gamma_block = self.class.encryptBlock(tmp_block, @keys)      
      end
      
      left_data_len %= @gamma_s 
      if left_data_len > 0 then
        # incomplete block start
        encr_data = data[-left_data_len..-1]
        decr_data = encr_data.dup
        (0...left_data_len).each do |j|
          decr_data[j] = (@gamma_block[j].ord ^ encr_data[j].ord).chr
        end
        outdata += decr_data
        @incomplete_block_len = left_data_len
        @incomplete_block = encr_data
      end
      outdata
    end
    
  end
end  
