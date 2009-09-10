;; -*- mode: scheme; coding: utf-8 -*-
;; Advanced Encryption Standard (AES), FIPS-197.
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

;; This is an implementation of the Rijndael cipher as parameterized
;; by AES (the block length is 16 bytes, keys are 128, 192 or 256 bits
;; long with 10, 12 and 14 rounds respectively).

;; There's nothing original here, just a straightforward
;; implementation of some of the ideas presented in these papers:

;; @MISC{Daemen98aesproposal:,
;;     author = {Joan Daemen and Vincent Rijmen},
;;     title = {AES Proposal: Rijndael},
;;     year = {1998}
;; }

;; @misc{AES-FIPS,
;;    title = "Specification for the Advanced Encryption Standard (AES)",
;;    howpublished = "Federal Information Processing Standards Publication 197",
;;    year = "2001",
;;    url = "http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"
;; }

;; @inproceedings{ BS08,
;;     author      = {Daniel J. Bernstein and Peter Schwabe},
;;     title       = {New {AES} software speed records},
;;     year        = {2008},
;;     booktitle   = {Progress in Cryptology - {INDOCRYPT 2008}},
;;     series      = {Lecture Notes in Computer Science},
;;     volume      = {5365},
;;     pages       = {322--336},
;;     publisher   = {Springer},
;; }
;; http://www.cryptojedi.org/papers/aesspeed-20080926.pdf
;; http://cr.yp.to/aes-speed/aesspeed-20080926.pdf

;; @MISC{Trichina04secureand,
;;     author = {E. Trichina and L. Korkishko},
;;     title = {Secure and Efficient AES Software Implementation for Smart Cards},
;;     year = {2004}
;; }
;; http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.58.2363

(library (weinholt crypto aes (0 0 20090910))
  (export expand-encryption-key encrypt!
          expand-decryption-key decrypt!)
  (import (for (weinholt crypto aes private) expand)
          (for (only (srfi :1 lists) iota) expand)
          (for (rnrs eval) expand)
          (rnrs))

  (define-syntax byte
    (lambda (x)
      (syntax-case x ()
        ((_ b n)
         (with-syntax ((shift (* (syntax->datum #'n) 8)))
           (if (zero? (syntax->datum #'n))
               #'(bitwise-and #xff b)
               #'(bitwise-and #xff (bitwise-arithmetic-shift-right b shift))))))))

  (define-syntax copy-byte
    (lambda (x)
      (syntax-case x ()
        ((_ b n)
         (with-syntax ((mask (bitwise-arithmetic-shift-left #xff (* (syntax->datum #'n) 8))))
           #'(bitwise-and mask b))))))

  ;; do loop with loop unrolling for pre-defined numbers. Has quite a
  ;; lot of limitations and gotchas.
  (define-syntax do/unroll
    (lambda (x)
      (define (unroll iter* init iter-step* len len1 last-code
                      vars/steps commands exprs)
        (with-syntax ((iter iter*)
                      (iter-step iter-step*)
                      (((var step ...) ...) vars/steps)
                      ((command ...) commands)
                      ((expr ...) exprs))
          #`(begin
              command ...
              (let ((iter (+ iter iter-step))
                    (var step ...) ...)
                #,(if (eval `(let ((,len ,len1))
                               (= ,(+ init iter-step*) ,last-code))
                            (environment '(rnrs)))
                      #'(begin expr ...)
                      (unroll iter* (+ init iter-step*) iter-step* len len1 last-code
                              vars/steps commands exprs))))))
      (syntax-case x ()
        ((_ (len1 lens ...)
            ((len len-init)
             (iter iter-init (+ iter** iter-step))
             (var init step ...) ...)
            ((= iter* last) expr ...)
            command ...)
         (and (free-identifier=? #'iter* #'iter)
              (free-identifier=? #'iter** #'iter)
              (integer? (syntax->datum #'iter-init)))
         (with-syntax ((unrolled (unroll #'iter
                                         (syntax->datum #'iter-init)
                                         (syntax->datum #'iter-step)
                                         (syntax->datum #'len)
                                         (syntax->datum #'len1)
                                         (syntax->datum #'last)
                                         #'((var step ...) ...)
                                         #'(command ...)
                                         #'(expr ...))))
           #'(let ((len len-init))
               (if (= len len1)
                   (let ((iter iter-init)
                         (var init) ...)
                     unrolled)
                   (do/unroll (lens ...)
                              ((len len-init)
                               (iter iter-init (+ iter** iter-step))
                               (var init step ...) ...)
                              ((= iter* last) expr ...)
                              command ...)))))
        ;; fallback
        ((_ ()
            ((var init step ...) ...)
            (test expr ...)
            command ...)
         #'(do ((var init step ...) ...)
               (test expr ...)
             command ...)))))

;;; Lookup tables

  ;; The math for these tables is in the private library. The tables
  ;; should probably be bytevectors instead of vectors, if that will
  ;; help any implementations optimize this library.
  (let-syntax ((rcon-table
                (lambda (x)
                  (syntax-case x ()
                    ((_ n)
                     (with-syntax ((tab (list->vector
                                         (map (lambda (i)
                                                (bitwise-arithmetic-shift-left
                                                 (GFexpt 2 i) 24))
                                              (iota (syntax->datum #'n))))))
                       #''tab)))))
               (table
                (lambda (x)
                  (define (sbox-table t e0 e1 e2 e3)
                    (define (table-entry i)
                      (bitwise-ior (bitwise-arithmetic-shift-left
                                    (GF* (syntax->datum e0) (t i)) 24)
                                   (bitwise-arithmetic-shift-left
                                    (GF* (syntax->datum e1) (t i)) 16)
                                   (bitwise-arithmetic-shift-left
                                    (GF* (syntax->datum e2) (t i)) 8)
                                   (GF* (syntax->datum e3) (t i))))
                    (list->vector (map table-entry (iota 256))))
                  (syntax-case x (S invS)
                    ((_ S e0 e1 e2 e3)
                     (with-syntax ((tab (sbox-table S-box #'e0 #'e1 #'e2 #'e3)))
                       #''tab))
                    ((_ invS e0 e1 e2 e3)
                     (with-syntax ((tab (sbox-table inv-S-box #'e0 #'e1 #'e2 #'e3)))
                       #''tab))))))
    ;; Various values for the round constant (expt 2 n) in GF(2⁸).
    (define rcon (rcon-table 20))
    ;; Tables for multiplication and SubBytes from [Daemen98aesproposal]
    (define te0 (table S #b00000010 #b00000001 #b00000001 #b00000011))
    (define te1 (table S #b00000011 #b00000010 #b00000001 #b00000001))
    (define te2 (table S #b00000001 #b00000011 #b00000010 #b00000001))
    (define te3 (table S #b00000001 #b00000001 #b00000011 #b00000010))
    (define te4 (table S 1 1 1 1))
    (define td0 (table invS #b00001110 #b00001001 #b00001101 #b00001011))
    (define td1 (table invS #b00001011 #b00001110 #b00001001 #b00001101))
    (define td2 (table invS #b00001101 #b00001011 #b00001110 #b00001001))
    (define td3 (table invS #b00001001 #b00001101 #b00001011 #b00001110))
    (define td4 (table invS 1 1 1 1)))

;;; Enciphering

  (define (expand-encryption-key key)
    (let* ((rounds (case (bytevector-length key)
                     ((128/8) 10)
                     ((192/8) 12)
                     ((256/8) 14)
                     (else (error 'expand-encryption-key "bad key size"
                                  (* 8 (bytevector-length key))))))
           (ret (make-bytevector (* 16 (+ 1 rounds))))
           (len (bytevector-length key)))
      (do ((i 0 (+ i 4)))
          ((= i len))
        (bytevector-u32-native-set! ret i (bytevector-u32-ref key i (endianness big))))
      (do ((schedlen (bytevector-length ret))
           (i len (+ i 4)))
          ((= i schedlen) ret)
        (let ((Wi-Nk (bytevector-u32-native-ref ret (- i len)))
              (Wi-1 (bytevector-u32-native-ref ret (- i 4))))
          (cond ((zero? (mod i len))
                 (bytevector-u32-native-set!
                  ret i
                  (bitwise-xor
                   Wi-Nk
                   (vector-ref rcon (div (- i len) len))
                   (copy-byte (vector-ref te4 (byte Wi-1 2)) 3)
                   (copy-byte (vector-ref te4 (byte Wi-1 1)) 2)
                   (copy-byte (vector-ref te4 (byte Wi-1 0)) 1)
                   (copy-byte (vector-ref te4 (byte Wi-1 3)) 0))))
                ((and (> len 24) (= (mod i len) 16))
                 (bytevector-u32-native-set!
                  ret i
                  (bitwise-xor
                   Wi-Nk
                   (copy-byte (vector-ref te4 (byte Wi-1 3)) 3)
                   (copy-byte (vector-ref te4 (byte Wi-1 2)) 2)
                   (copy-byte (vector-ref te4 (byte Wi-1 1)) 1)
                   (copy-byte (vector-ref te4 (byte Wi-1 0)) 0))))
                (else
                 (bytevector-u32-native-set! ret i (bitwise-xor Wi-Nk Wi-1))))))))


  (define (encrypt! out in key-schedule)
    ;; First add the first round key. Then do n-1 rounds of
    ;; SubBytes, ShiftRows, MixColumns and AddRoundKey.
    (do/unroll (176 #;208 #;240)        ;unroll for 128-bit keys
        ((len (bytevector-length key-schedule))
         (i 16 (+ i 16))
         (a0 (bitwise-xor (bytevector-u32-native-ref key-schedule 0)
                          (bytevector-u32-ref in 0 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule i)
                          (vector-ref te0 (byte a0 3))
                          (vector-ref te1 (byte a1 2))
                          (vector-ref te2 (byte a2 1))
                          (vector-ref te3 (byte a3 0))))
         (a1 (bitwise-xor (bytevector-u32-native-ref key-schedule 4)
                          (bytevector-u32-ref in 4 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 4))
                          (vector-ref te0 (byte a1 3))
                          (vector-ref te1 (byte a2 2))
                          (vector-ref te2 (byte a3 1))
                          (vector-ref te3 (byte a0 0))))
         (a2 (bitwise-xor (bytevector-u32-native-ref key-schedule 8)
                          (bytevector-u32-ref in 8 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 8))
                          (vector-ref te0 (byte a2 3))
                          (vector-ref te1 (byte a3 2))
                          (vector-ref te2 (byte a0 1))
                          (vector-ref te3 (byte a1 0))))
         (a3 (bitwise-xor (bytevector-u32-native-ref key-schedule 12)
                          (bytevector-u32-ref in 12 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 12))
                          (vector-ref te0 (byte a3 3))
                          (vector-ref te1 (byte a0 2))
                          (vector-ref te2 (byte a1 1))
                          (vector-ref te3 (byte a2 0)))))
        ((= i (- len 16))
         ;; Finally do a round of SubBytes, ShiftRows and AddRoundKey.
         (bytevector-u32-set! out 0
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule i)
                               (copy-byte (vector-ref te4 (byte a0 3)) 3)
                               (copy-byte (vector-ref te4 (byte a1 2)) 2)
                               (copy-byte (vector-ref te4 (byte a2 1)) 1)
                               (copy-byte (vector-ref te4 (byte a3 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 4
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 4))
                               (copy-byte (vector-ref te4 (byte a1 3)) 3)
                               (copy-byte (vector-ref te4 (byte a2 2)) 2)
                               (copy-byte (vector-ref te4 (byte a3 1)) 1)
                               (copy-byte (vector-ref te4 (byte a0 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 8
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 8))
                               (copy-byte (vector-ref te4 (byte a2 3)) 3)
                               (copy-byte (vector-ref te4 (byte a3 2)) 2)
                               (copy-byte (vector-ref te4 (byte a0 1)) 1)
                               (copy-byte (vector-ref te4 (byte a1 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 12
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 12))
                               (copy-byte (vector-ref te4 (byte a3 3)) 3)
                               (copy-byte (vector-ref te4 (byte a0 2)) 2)
                               (copy-byte (vector-ref te4 (byte a1 1)) 1)
                               (copy-byte (vector-ref te4 (byte a2 0)) 0))
                              (endianness big)))))

;;; Deciphering

  (define (expand-decryption-key key)
    ;; Reverse the key schedule, then do InvMixColumns
    (do ((ret (uint-list->bytevector
               (reverse (bytevector->uint-list (expand-encryption-key key)
                                               (native-endianness) 16))
               (native-endianness) 16))
         (i 16 (+ i 4)))
        ((= i (- (bytevector-length ret) 16))
         ret)
      (let ((temp (bytevector-u32-native-ref ret i)))
        (bytevector-u32-native-set!
         ret i
         (bitwise-xor
          (vector-ref td0 (copy-byte (vector-ref te4 (byte temp 3)) 0))
          (vector-ref td1 (copy-byte (vector-ref te4 (byte temp 2)) 0))
          (vector-ref td2 (copy-byte (vector-ref te4 (byte temp 1)) 0))
          (vector-ref td3 (copy-byte (vector-ref te4 (byte temp 0)) 0)))))))


  (define (decrypt! out in key-schedule)
    ;; First add the first round key. Then do n-1 rounds of
    ;; InvSubBytes, InvShiftRows, InvMixColumns and AddRoundKey.
    (do/unroll (176 #;208 #;240)        ;unroll for 128-bit keys
        ((len (bytevector-length key-schedule))
         (i 16 (+ i 16))
         (a0 (bitwise-xor (bytevector-u32-native-ref key-schedule 0)
                          (bytevector-u32-ref in 0 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule i)
                          (vector-ref td0 (byte a0 3))
                          (vector-ref td1 (byte a3 2))
                          (vector-ref td2 (byte a2 1))
                          (vector-ref td3 (byte a1 0))))
         (a1 (bitwise-xor (bytevector-u32-native-ref key-schedule 4)
                          (bytevector-u32-ref in 4 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 4))
                          (vector-ref td0 (byte a1 3))
                          (vector-ref td1 (byte a0 2))
                          (vector-ref td2 (byte a3 1))
                          (vector-ref td3 (byte a2 0))))
         (a2 (bitwise-xor (bytevector-u32-native-ref key-schedule 8)
                          (bytevector-u32-ref in 8 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 8))
                          (vector-ref td0 (byte a2 3))
                          (vector-ref td1 (byte a1 2))
                          (vector-ref td2 (byte a0 1))
                          (vector-ref td3 (byte a3 0))))
         (a3 (bitwise-xor (bytevector-u32-native-ref key-schedule 12)
                          (bytevector-u32-ref in 12 (endianness big)))
             (bitwise-xor (bytevector-u32-native-ref key-schedule (+ i 12))
                          (vector-ref td0 (byte a3 3))
                          (vector-ref td1 (byte a2 2))
                          (vector-ref td2 (byte a1 1))
                          (vector-ref td3 (byte a0 0)))))
        ((= i (- len 16))
         ;; Finally do a round of InvSubBytes, InvShiftRows and AddRoundKey.
         (bytevector-u32-set! out 0
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule i)
                               (copy-byte (vector-ref td4 (byte a0 3)) 3)
                               (copy-byte (vector-ref td4 (byte a3 2)) 2)
                               (copy-byte (vector-ref td4 (byte a2 1)) 1)
                               (copy-byte (vector-ref td4 (byte a1 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 4
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 4))
                               (copy-byte (vector-ref td4 (byte a1 3)) 3)
                               (copy-byte (vector-ref td4 (byte a0 2)) 2)
                               (copy-byte (vector-ref td4 (byte a3 1)) 1)
                               (copy-byte (vector-ref td4 (byte a2 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 8
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 8))
                               (copy-byte (vector-ref td4 (byte a2 3)) 3)
                               (copy-byte (vector-ref td4 (byte a1 2)) 2)
                               (copy-byte (vector-ref td4 (byte a0 1)) 1)
                               (copy-byte (vector-ref td4 (byte a3 0)) 0))
                              (endianness big))
         (bytevector-u32-set! out 12
                              (bitwise-xor
                               (bytevector-u32-native-ref key-schedule (+ i 12))
                               (copy-byte (vector-ref td4 (byte a3 3)) 3)
                               (copy-byte (vector-ref td4 (byte a2 2)) 2)
                               (copy-byte (vector-ref td4 (byte a1 1)) 1)
                               (copy-byte (vector-ref td4 (byte a0 0)) 0))
                              (endianness big))))))
