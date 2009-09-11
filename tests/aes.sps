#!/usr/bin/env scheme-script
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

(import (weinholt crypto aes)
        (srfi :78 lightweight-testing)
        (rnrs))


;;; Appendix A in FIPS-197

(check (expand-aes-key
        ;; 128-bit key
        #vu8(#x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6 #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c))
       =>
       '#(#x2b7e1516
          #x28aed2a6
          #xabf71588
          #x09cf4f3c
         
          #xa0fafe17
          #x88542cb1
          #x23a33939
          #x2a6c7605
          #xf2c295f2
          #x7a96b943
          #x5935807a
          #x7359f67f
          #x3d80477d
          #x4716fe3e
          #x1e237e44
          #x6d7a883b
          #xef44a541
          #xa8525b7f
          #xb671253b
          #xdb0bad00
          #xd4d1c6f8
          #x7c839d87
          #xcaf2b8bc
          #x11f915bc
          #x6d88a37a
          #x110b3efd
          #xdbf98641
          #xca0093fd
          #x4e54f70e
          #x5f5fc9f3
          #x84a64fb2
          #x4ea6dc4f
          #xead27321
          #xb58dbad2
          #x312bf560
          #x7f8d292f
          #xac7766f3
          #x19fadc21
          #x28d12941
          #x575c006e
          #xd014f9a8
          #xc9ee2589
          #xe13f0cc8
          #xb6630ca6))

(check (expand-aes-key
        ;; 192-bit key
        #vu8(#x8e #x73 #xb0 #xf7 #xda #x0e #x64 #x52 #xc8 #x10 #xf3 #x2b
                  #x80 #x90 #x79 #xe5 #x62 #xf8 #xea #xd2 #x52 #x2c #x6b #x7b))
       =>
       '#(#x8e73b0f7
          #xda0e6452
          #xc810f32b
          #x809079e5
          #x62f8ead2
          #x522c6b7b

          #xfe0c91f7
          #x2402f5a5
          #xec12068e
          #x6c827f6b
          #x0e7a95b9
          #x5c56fec2
          #x4db7b4bd
          #x69b54118
          #x85a74796
          #xe92538fd
          #xe75fad44
          #xbb095386
          #x485af057
          #x21efb14f
          #xa448f6d9
          #x4d6dce24
          #xaa326360
          #x113b30e6
          #xa25e7ed5
          #x83b1cf9a
          #x27f93943
          #x6a94f767
          #xc0a69407
          #xd19da4e1
          #xec1786eb
          #x6fa64971
          #x485f7032
          #x22cb8755
          #xe26d1352
          #x33f0b7b3
          #x40beeb28
          #x2f18a259
          #x6747d26b
          #x458c553e
          #xa7e1466c
          #x9411f1df
          #x821f750a
          #xad07d753
          #xca400538
          #x8fcc5006
          #x282d166a
          #xbc3ce7b5
          #xe98ba06f
          #x448c773c
          #x8ecc7204
          #x01002202))

(check (expand-aes-key 
        ;; 256-bit key
        #vu8(#x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                  #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7 #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4))
       =>
       '#(#x603deb10
          #x15ca71be
          #x2b73aef0
          #x857d7781
          #x1f352c07
          #x3b6108d7
          #x2d9810a3
          #x0914dff4

          #x9ba35411
          #x8e6925af
          #xa51a8b5f
          #x2067fcde
          #xa8b09c1a
          #x93d194cd
          #xbe49846e
          #xb75d5b9a
          #xd59aecb8
          #x5bf3c917
          #xfee94248
          #xde8ebe96
          #xb5a9328a
          #x2678a647
          #x98312229
          #x2f6c79b3
          #x812c81ad
          #xdadf48ba
          #x24360af2
          #xfab8b464
          #x98c5bfc9
          #xbebd198e
          #x268c3ba7
          #x09e04214
          #x68007bac
          #xb2df3316
          #x96e939e4
          #x6c518d80
          #xc814e204
          #x76a9fb8a
          #x5025c02d
          #x59c58239
          #xde136967
          #x6ccc5a71
          #xfa256395
          #x9674ee15
          #x5886ca5d
          #x2e2f31d7
          #x7e0af1fa
          #x27cf73c3
          #x749c47ab
          #x18501dda
          #xe2757e4f
          #x7401905a
          #xcafaaae3
          #xe4d59b34
          #x9adf6ace
          #xbd10190d
          #xfe4890d1
          #xe6188d0b
          #x046df344
          #x706c631e))


;;; Appendix B in FIPS-197 - cipher example

(define (encrypt plaintext key)
  (let ((ret (make-bytevector 16 0))
        (sched (expand-aes-key key)))
    (aes-encrypt! plaintext 0 ret 0 sched)
    (clear-aes-schedule! sched)
    ret))

(define (decrypt plaintext key)
  (let ((ret (make-bytevector 16 0))
        (sched (reverse-aes-schedule (expand-aes-key key))))
    (aes-decrypt! plaintext 0 ret 0 sched)
    (clear-aes-schedule! sched)
    ret))

(check (encrypt #vu8(#x32 #x43 #xf6 #xa8 #x88 #x5a #x30 #x8d #x31 #x31 #x98 #xa2 #xe0 #x37 #x07 #x34)
                #vu8(#x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6 #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c))
       => #vu8(#x39 #x25 #x84 #x1d #x02 #xdc #x09 #xfb #xdc #x11 #x85 #x97 #x19 #x6a #x0b #x32))

(check (decrypt #vu8(#x39 #x25 #x84 #x1d #x02 #xdc #x09 #xfb #xdc #x11 #x85 #x97 #x19 #x6a #x0b #x32)
                #vu8(#x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6 #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c))
       => #vu8(#x32 #x43 #xf6 #xa8 #x88 #x5a #x30 #x8d #x31 #x31 #x98 #xa2 #xe0 #x37 #x07 #x34))

;;; Appendix C in FIPS-197

(define-syntax test
  (lambda (x)
    (define (num->bv n len)
      (let ((bv (make-bytevector (/ len 8))))
        (bytevector-uint-set! bv 0 n (endianness big) (/ len 8))
        bv))
    (syntax-case x ()
      ((_ plaintext keylen key output)
       (with-syntax ((pt (num->bv (syntax->datum #'plaintext) 128))
                     (k (num->bv (syntax->datum #'key) (syntax->datum #'keylen)))
                     (out (num->bv (syntax->datum #'output) 128)))
         #'(begin (check (encrypt pt k) => out)
                  (check (decrypt (encrypt pt k) k) => pt)))))))

(test #x00112233445566778899aabbccddeeff
      128 #x000102030405060708090a0b0c0d0e0f
      #x69c4e0d86a7b0430d8cdb78070b4c55a)

(test #x00112233445566778899aabbccddeeff
      192 #x000102030405060708090a0b0c0d0e0f1011121314151617
      #xdda97ca4864cdfe06eaf70a0ec0d7191)

(test #x00112233445566778899aabbccddeeff
      256 #x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
      #x8ea2b7ca516745bfeafc49904b496089)


;;; http://csrc.nist.gov/groups/ST/toolkit/examples.html

(test #x6BC1BEE22E409F96E93D7E117393172A
      128 #x2B7E151628AED2A6ABF7158809CF4F3C
      #x3AD77BB40D7A3660A89ECAF32466EF97)

(test #xAE2D8A571E03AC9C9EB76FAC45AF8E51
      128 #x2B7E151628AED2A6ABF7158809CF4F3C
      #xF5D3D58503B9699DE785895A96FDBAAF)

(test #x30C81C46A35CE411E5FBC1191A0A52EF
      128 #x2B7E151628AED2A6ABF7158809CF4F3C
      #x43B1CD7F598ECE23881B00E3ED030688)

(test #xF69F2445DF4F9B17AD2B417BE66C3710
      128 #x2B7E151628AED2A6ABF7158809CF4F3C
      #x7B0C785E27E8AD3F8223207104725DD4)

(test #x6BC1BEE22E409F96E93D7E117393172A
      192 #x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B
      #xBD334F1D6E45F25FF712A214571FA5CC)

(test #xAE2D8A571E03AC9C9EB76FAC45AF8E51
      192 #x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B
      #x974104846D0AD3AD7734ECB3ECEE4EEF)

(test #x30C81C46A35CE411E5FBC1191A0A52EF
      192 #x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B
      #xEF7AFD2270E2E60ADCE0BA2FACE6444E)

(test #xF69F2445DF4F9B17AD2B417BE66C3710
      192 #x8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B
      #x9A4B41BA738D6C72FB16691603C18E0E)

(test #x6BC1BEE22E409F96E93D7E117393172A
      256 #x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
      #xF3EED1BDB5D2A03C064B5A7E3DB181F8)

(test #xAE2D8A571E03AC9C9EB76FAC45AF8E51
      256 #x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
      #x591CCB10D410ED26DC5BA74A31362870)

(test #x30C81C46A35CE411E5FBC1191A0A52EF
      256 #x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
      #xB6ED21B99CA6F4F9F153E7B1BEAFED1D)

(test #xF69F2445DF4F9B17AD2B417BE66C3710
      256 #x603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
      #x23304B7A39F9F3FF067D8D8F9E24ECC7)

(check-report)
