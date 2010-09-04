(package (industria (0) (2010 8 25) (1))
  (depends (srfi-1)
           (srfi-13)
           (srfi-14)
           (srfi-19)
           (srfi-26)
           (srfi-27)
           (srfi-39))
  
  (synopsis "Göran Weinholt's library collection")
  (description
   "Industria contains a set of libraries covering:"
   " - Networking protocols: TCP (client only), TLS, DNS, IRC, OTR"
   " - Cryptography: AES, ARC4, MD5, SHA-{1,2}, Blowfish, HMAC, CRC, DES"
   " - Text encodings: base64, punycode"
   " - Compression: ZIP, gzip"
   " - Bytevector pack/unpack syntax"
   " - An amd64 disassembler")
  (homepage "https://code.launchpad.net/~weinholt/scheme-libraries/industria")
  
  (libraries "weinholt"))

;; Local Variables:
;; scheme-indent-styles: ((package 1))
;; End:
