module GostMagma
  class MagmaKeyExpImp < Kuznyechik
    def self.export(key, key_mac, key_enc, iv)
      mac = MagmaOmac.new(key_mac, BlockLengthInBytes).update(iv+key).final
      ctr = MagmaCtr.new(key_enc, iv, BlockLengthInBytes)
      encr_key = ctr.encrypt(key)
      encr_mac = ctr.encrypt(mac)
      encr_key += encr_mac
    end
    
    def self.import(encr_key, key_mac, key_enc, iv)
      buf = MagmaCtr.new(key_enc, iv, BlockLengthInBytes).decrypt(encr_key)
      decr_key = buf[0...-BlockLengthInBytes]
      decr_mac = buf[decr_key.length..-1]
      mac = MagmaOmac.new(key_mac, BlockLengthInBytes).update(iv+decr_key).final
      if mac != decr_mac then
        decr_key = nil
      end
      decr_key
    end
  end
end  
