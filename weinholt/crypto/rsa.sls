;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009 Göran Weinholt <goran@weinholt.se>
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

(library (weinholt crypto rsa)
  (export rsa-public-key?
          rsa-public-key<-bytevector
          rsa-public-key-length
          rsa-public-key-byte-length
          rsa-decrypt
          rsa-encrypt
          rsa-pkcs1-encrypt
          rsa-pkcs1-decrypt-digest)
  (import (rnrs)
          (srfi :27 random-bits)
          (prefix (weinholt struct der (1)) der:))

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

  (define (rsa-public-key-length key)
    (bitwise-length (rsa-public-key-modulus key)))

  (define (rsa-public-key-byte-length key)
    (let ((bitlen (rsa-public-key-length key)))
      (fxdiv (fxand (fx+ bitlen 7) -8) 8)))

  (define (public<-private key)
    (make-rsa-public-key (rsa-private-key-modulus key)
                         (rsa-private-key-public-exponent key)))

  (define (rsa-public-key<-bytevector bv)
    (apply make-rsa-public-key (der:translate (der:decode bv)
                                              (RSAPublicKey))))
  
  (define (invmod a b)
    ;; Extended Euclidian algorithm. Used to find the inverse of a
    ;; modulo b.
    (do ((a a (mod b a))
         (b b a)
         (x0 0 x1)
         (x1 1 (+ (* (- (div b a)) x1) x0)))
        ((zero? (mod b a))
         x1)))

  (define (expt-mod base exponent modulus)
    ;; Faster version of (mod (expt base exponent) modulus).
    (let lp ((base (if (negative? exponent)
                       (invmod (mod base modulus) modulus)
                       (mod base modulus)))
             (exponent (abs exponent))
             (result 1))
      (if (zero? exponent)
          result
          (lp (mod (* base base) modulus)
              (bitwise-arithmetic-shift-right exponent 1)
              (if (bitwise-bit-set? exponent 0)
                  (mod (* result base) modulus)
                  result)))))

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

  (define (rsa-pkcs1-decrypt-digest signature key)
    ;; Encrypt the signature with a public key. If it comes out
    ;; alright, the signature was signed with the corresponding
    ;; private key. For X.509-certificates this means the signature
    ;; came from the issuer, but anyone can copy a decryptable
    ;; signature, so the message digest also has to be checked.
    (let* ((sig (rsa-encrypt signature key))
           (len (fxdiv (fxand -8 (fx+ 7 (bitwise-length sig)))
                       8))
           (bvsig (make-bytevector len)))
      (bytevector-uint-set! bvsig 0 sig (endianness big) len)
      (case (bytevector-u8-ref bvsig 0)
        ((#x01)
         (do ((i 1 (fx+ i 1)))
             ((fxzero? (bytevector-u8-ref bvsig i))
              (der:translate (der:decode bvsig (fx+ i 1) len)
                             (DigestInfo)))
           (unless (fx=? #xff (bytevector-u8-ref bvsig i))
             (error 'rsa-pkcs-decrypt-signature "bad signature"))))
        (else
         (error 'rsa-pkcs1-decrypt-signature "bad signature"))))))

