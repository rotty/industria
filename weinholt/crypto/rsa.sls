;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009, 2010 Göran Weinholt <goran@weinholt.se>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
#!r6rs

;; PKCS #1: RSA Encryption.

;; This library is vulnerable to timing attacks and will leak your key.

;; RFC 3447. Public-Key Cryptography Standards (PKCS) #1: RSA
;; Cryptography Specifications Version 2.1

;; But look at RFC 2313, it's easier to read...

(library (weinholt crypto rsa (1 0 20100829))
  (export make-rsa-public-key
          rsa-public-key?
          rsa-public-key-modulus
          rsa-public-key-public-exponent
          rsa-public-key-n
          rsa-public-key-e

          rsa-public-key-from-bytevector
          rsa-public-key-length
          rsa-public-key-byte-length

          ;; make-rsa-private-key

          rsa-decrypt
          rsa-encrypt
          rsa-pkcs1-encrypt
          rsa-pkcs1-decrypt-signature
          rsa-pkcs1-decrypt-digest)
  (import (rnrs)
          (srfi :27 random-bits)
          (weinholt bytevectors)
          (weinholt crypto math)
          (prefix (weinholt struct der (0 0)) der:))

  (define random-nonzero-byte
    (let* ((s (make-random-source))
           (make-int (random-source-make-integers s))
           (urandom (and (file-exists? "/dev/urandom")
                         (open-file-input-port "/dev/urandom"))))
      (unless urandom
        (random-source-randomize! s))
      (lambda ()
        (if urandom
            (let lp ()
              (let ((v (get-u8 urandom)))
                (if (zero? v) (lp) v)))
            (+ 1 (make-int 254))))))

  (define (RSAPublicKey)
    `(sequence (modulus integer)
               (publicExponent integer)))

  (define (DigestInfo)
    `(sequence (digestAlgorithm ,(DigestAlgorithmIdentifier))
               (digest ,(Digest))))

  (define (DigestAlgorithmIdentifier)
    (AlgorithmIdentifier))

  (define (Digest)
    'octet-string)

  (define (AlgorithmIdentifier)
    ;; Same as in x509.sls
    `(sequence (algorithm object-identifier)
               (parameters ANY (default #f))))

  (define-record-type rsa-public-key
    (fields modulus                     ;n
            public-exponent))           ;e

  (define-record-type rsa-private-key
    (fields version
            modulus                     ;n
            public-exponent             ;e
            private-exponent            ;d
            prime1                      ;p
            prime2                      ;q
            exponent1                   ;d mod (p-1)
            exponent2                   ;d mod (q-1)
            coefficient))               ;(inverse of q) mod p

  (define rsa-public-key-n rsa-public-key-modulus)
  (define rsa-public-key-e rsa-public-key-public-exponent)

  (define (rsa-public-key-length key)
    (bitwise-length (rsa-public-key-modulus key)))

  (define (rsa-public-key-byte-length key)
    (let ((bitlen (rsa-public-key-length key)))
      (fxdiv (fxand (fx+ bitlen 7) -8) 8)))

  (define (dsa-private->public key)
    (make-rsa-public-key (rsa-private-key-modulus key)
                         (rsa-private-key-public-exponent key)))

  (define (rsa-public-key-from-bytevector bv)
    (apply make-rsa-public-key (der:translate (der:decode bv)
                                              (RSAPublicKey))))

  ;; TODO: When doing private key operations, use RSA blinding (Boneh,
  ;; D., Brumley, D., "Remote timing attacks are practical", USENIX
  ;; Security Symposium 2003.)
  (define (rsa-encrypt plaintext key)
    (if (rsa-public-key? key)
        (expt-mod plaintext
                  (rsa-public-key-public-exponent key)
                  (rsa-public-key-modulus key))
        (expt-mod plaintext
                  (rsa-private-key-public-exponent key)
                  (rsa-private-key-modulus key))))


  (define (rsa-decrypt ciphertext key)
    (expt-mod ciphertext
              (rsa-private-key-private-exponent key)
              (rsa-private-key-modulus key)))

  (define (rsa-pkcs1-encrypt plaintext-bv key)
    ;; Format the plaintext as per PKCS #1:
    ;; EB = 00 || BT || PS || 00 || D .
    (let* ((keylen (rsa-public-key-byte-length key))
           (eb (make-bytevector keylen #xff))
           (end-of-PS (- keylen
                         (bytevector-length plaintext-bv)
                         1)))
      (bytevector-u8-set! eb 0 #x00)
      (bytevector-u8-set! eb 1 #x02)    ;public key operation

      (unless (> (- end-of-PS 2) 8)
        ;; Recommendation from RFC 3447 7.2: padding should be at
        ;; least eight octets long.
        (error 'rsa-pkcs1-encrypt
               "The plaintext is too long for the key"))

      ;; Pad with random non-zero bytes
      (do ((i 2 (+ i 1)))
          ((= i end-of-PS))
        (bytevector-u8-set! eb i (random-nonzero-byte)))

      (bytevector-u8-set! eb end-of-PS 0)

      (bytevector-copy! plaintext-bv 0
                        eb (+ end-of-PS 1)
                        (bytevector-length plaintext-bv))
      
      (rsa-encrypt (bytevector-uint-ref eb
                                        0
                                        (endianness big)
                                        (bytevector-length eb))
                   key)))

  (define (rsa-pkcs1-decrypt-signature signature key)
    ;; Encrypt the signature with a public key. If it comes out
    ;; alright, the signature was signed with the corresponding
    ;; private key.
    (let ((bvsig (uint->bytevector (rsa-encrypt signature key))))
      (case (bytevector-u8-ref bvsig 0)
        ((#x01)
         (do ((i 1 (fx+ i 1)))
             ((fxzero? (bytevector-u8-ref bvsig i))
              (subbytevector bvsig (fx+ i 1)
                             (bytevector-length bvsig)))
           (unless (fx=? #xff (bytevector-u8-ref bvsig i))
             (error 'rsa-pkcs-decrypt-signature "bad signature"))))
        (else
         (error 'rsa-pkcs1-decrypt-signature "bad signature")))))

  (define (rsa-pkcs1-decrypt-digest signature key)
    ;; Encrypt the signature with a public key. If it comes out
    ;; alright, the signature was signed with the corresponding
    ;; private key. For X.509-certificates this means the signature
    ;; came from the issuer, but anyone can copy a decryptable
    ;; signature, so the message digest also has to be checked.
    (let* ((bvsig (rsa-pkcs1-decrypt-signature signature key))
           (dersig (der:decode bvsig)))
      (unless (= (der:data-length dersig) (bytevector-length bvsig))
        ;; Recommendation from RFC 5246 D.4.
        (error 'rsa-pkcs1-decrypt-digest
               "Bad signature: additional data after hash value"))
      (der:translate dersig (DigestInfo)))))

