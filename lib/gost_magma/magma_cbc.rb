module GostMagma
  class MagmaCbc < Magma
    def initialize(key, iv)
      @key = key.dup.force_encoding('BINARY')
      @keys = []
      (0...8).each do |i|
        @keys << self.class.uint8ToUint32(@key[i*4...(i+1)*4].reverse)
      end
      
      @ctxR = iv.dup.force_encoding('BINARY')
    end
    
    def encrypt(data)
      data_len = data.length
      outdata = ''
      (0...(data_len / BlockLengthInBytes)).each do |i|
        encr_block = data[(i * BlockLengthInBytes)...((i+1) * BlockLengthInBytes)]      
        (0...BlockLengthInBytes).each do |j|
          encr_block[j] = (@ctxR[j].ord ^ data[i * BlockLengthInBytes + j].ord).chr
        end
        encr_block = self.class.encryptBlock(encr_block, @keys)
        outdata += encr_block
        @ctxR = @ctxR[BlockLengthInBytes..-1] + encr_block  
      end
      outdata
    end
    
    def decrypt(data)
      data_len = data.length
      outdata = ''
      (0...(data_len / BlockLengthInBytes)).each do |i|
        encr_block = data[(i * BlockLengthInBytes)...((i+1) * BlockLengthInBytes)]
        decr_block = self.class.decryptBlock(encr_block, @keys)
        (0...BlockLengthInBytes).each do |j|
          decr_block[j] = (@ctxR[j].ord ^ decr_block[j].ord).chr
        end
        outdata += decr_block
        @ctxR = @ctxR[BlockLengthInBytes..-1] + encr_block
      end
      outdata
    end
    
  end
end  
