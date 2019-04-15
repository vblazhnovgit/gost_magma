module GostMagma
  class MagmaEcb < Magma
    # key = 32-byte string
    def initialize(key)
      (0...8).each do |i|
        @keys[i] = Uint8ToUint32(key[i*4...(i+1)*4].reverse);
      end
    end
    
    # returns encrypted text string
    def encrypt(plain_text)
      len = plain_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(plain_text.length == 0) || (plain_text.length % BlockLengthInBytes > 0)"
        return nil
      end
      blocks = plain_text.scan(/.{8}/m)
      encrypted_blocks = []
      blocks.each do |block|
        encryptedBlock = self.class.encryptBlock(block, @keys)
        encrypted_blocks << encryptedBlock
      end
      output = encrypted_blocks.join
      return output
    end
    
    # returns decrypted text string
    def decrypt(encrypted_text)
      len = encrypted_text.length
      if (len == 0) || (len % BlockLengthInBytes > 0) then
        puts "(encrypted_text.length == 0) || (encrypted_text.length % BlockLengthInBytes > 0)"
        return nil
      end
      blocks = encrypted_text.scan(/.{8}/m)
      decrypted_blocks = []
      blocks.each do |block|
        decryptedBlock = self.class.decryptBlock(block, @keys)
        decrypted_blocks << decryptedBlock
      end
      output = decrypted_blocks.join
      return output
    end

  end
end