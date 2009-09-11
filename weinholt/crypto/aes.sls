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

;;; Usage

;; (expand-aes-key bytevector)
;;     Returns an AES key schedule value suitable for aes-encrypt!.
;;     The bytevector must be 16, 24, or 32 bytes long. The type of
;;     the return value is unspecified.

;; (aes-encrypt! source source-start target target-start key-schedule)
;;     Takes the eight bytes at source + source-start, encrypts them in
;;     ECB mode, and puts the result at target + target-start.

;; (reverse-aes-schedule key-schedule)
;;     Returns a reversed key schedule which is suitable for aes-decrypt!.

;; (aes-decrypt! source source-start target target-start key-schedule)
;;     The inverse of aes-encrypt!.

;; (clear-aes-schedule! key-schedule)
;;     Clears the AES key schedule value so that it no longer contains
;;     cryptographic material.

;;; Examples

;; (let ((out (make-bytevector 16))
;;       (sched (expand-aes-key (string->utf8 "ABCDEFGHIJKLMNOP"))))
;;   (aes-encrypt! (string->utf8 "R6RS über alles")
;;                 0 out 0 sched)
;;   out)
;; =>
;; #vu8(43 144 162 123 165 123 210 173 245 78 156 23 149 203 8 139)

;; (let ((out (make-bytevector 16))
;;       (sched (reverse-aes-schedule
;;               (expand-aes-key (string->utf8 "ABCDEFGHIJKLMNOP")))))
;;   (aes-decrypt! #vu8(43 144 162 123 165 123 210 173 245 78 156 23 149 203 8 139)
;;                 0 out 0 sched)
;;   (utf8->string out))
;; =>
;; "R6RS über alles"

;;; Version history

;; (1 0 20090911) - Initial version.

;;; Implementation details

;; The main operations in the encryption and decryption procedures are
;; bitwise-xor, bitwise-and and bitwise-arithmetic-shift-right. The
;; operands are 32-bit integers, mostly from vector-ref. If your
;; implementation does flow analysis then it might be beneficial to
;; switch to bytevectors and bytevector-u32-native-ref.

;; The encryption and decryption procedures are unrolled for the
;; 128-bit key case. I would have unrolled the 192-bit and 256-bit
;; cases too, but Ikarus takes forever to expand the code then.

;; The performance will depend on your Scheme implementation. I'm
;; getting around 1.87 MB/s with a 128-bit key, Ikarus 64-bit revision
;; 1856 on an AMD Athlon(tm) 64 X2 Dual Core Processor 5600+. For
;; comparison: OpenSSL gets around 120 MB/s.

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

(library (weinholt crypto aes (1 0 20090911))
  (export expand-aes-key aes-encrypt!
          reverse-aes-schedule aes-decrypt!
          clear-aes-schedule!)
  (import (for (weinholt crypto aes private) expand)
          (for (only (srfi :1 lists) iota) expand)
          (only (srfi :1 lists) split-at concatenate)
          (for (rnrs eval) expand)
          (rename (rnrs)
                  (bitwise-xor r6rs:bitwise-xor)))

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

  (define-syntax bitwise-xor
    ;; This is for Ikarus, which allocates memory for bitwise-xor with
    ;; more than four arguments [2009-09-11].
    (lambda (x)
      (with-syntax ((foo 'bar))
        (syntax-case x ()
          ((_ a b c d e f) #'(r6rs:bitwise-xor a b c (r6rs:bitwise-xor d e f)))
          ((_ a b c d e) #'(r6rs:bitwise-xor a b c (r6rs:bitwise-xor d e)))
          ((_ x ...) #'(r6rs:bitwise-xor x ...))))))

  (define (uncat l n)
    (if (null? l)
        l
        (let-values (((this next) (split-at l n)))
          (cons this (uncat next n)))))

;;; Lookup tables

  ;; The math for these tables is in the private library.
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

  (define (expand-aes-key key)
    (let* ((rounds (case (bytevector-length key)
                     ((128/8) 10)
                     ((192/8) 12)
                     ((256/8) 14)
                     (else (error 'expand-encryption-key "bad key size"
                                  (* 8 (bytevector-length key))))))
           (ret (make-vector (* 4 (+ 1 rounds))))
           (len (div (bytevector-length key) 4)))
      (do ((i 0 (+ i 1)))
          ((= i len))
        (vector-set! ret i (bytevector-u32-ref key (* i 4) (endianness big))))
      (do ((schedlen (vector-length ret))
           (i len (+ i 1)))
          ((= i schedlen) ret)
        (let ((Wi-Nk (vector-ref ret (- i len)))
              (Wi-1 (vector-ref ret (- i 1))))
          (cond ((zero? (mod i len))
                 (vector-set!
                  ret i
                  (bitwise-xor
                   Wi-Nk
                   (vector-ref rcon (div (- i len) len))
                   (copy-byte (vector-ref te4 (byte Wi-1 2)) 3)
                   (copy-byte (vector-ref te4 (byte Wi-1 1)) 2)
                   (copy-byte (vector-ref te4 (byte Wi-1 0)) 1)
                   (copy-byte (vector-ref te4 (byte Wi-1 3)) 0))))
                ((and (> len 6) (= (mod i len) 4))
                 (vector-set!
                  ret i
                  (bitwise-xor
                   Wi-Nk
                   (copy-byte (vector-ref te4 (byte Wi-1 3)) 3)
                   (copy-byte (vector-ref te4 (byte Wi-1 2)) 2)
                   (copy-byte (vector-ref te4 (byte Wi-1 1)) 1)
                   (copy-byte (vector-ref te4 (byte Wi-1 0)) 0))))
                (else
                 (vector-set! ret i (bitwise-xor Wi-Nk Wi-1))))))))


  (define (aes-encrypt! in in-start out out-start key-schedule)
    ;; First add the first round key. Then do n-1 rounds of
    ;; SubBytes, ShiftRows, MixColumns and AddRoundKey.
    (do/unroll (176/4 #;208/4 #;240/4)
               ((len (vector-length key-schedule))
                (i 4 (+ i 4))
                (a0 (bitwise-xor (vector-ref key-schedule 0)
                                 (bytevector-u32-ref in in-start (endianness big)))
                    (bitwise-xor (vector-ref key-schedule i)
                                 (vector-ref te0 (byte a0 3))
                                 (vector-ref te1 (byte a1 2))
                                 (vector-ref te2 (byte a2 1))
                                 (vector-ref te3 (byte a3 0))))
                (a1 (bitwise-xor (vector-ref key-schedule 1)
                                 (bytevector-u32-ref in (+ in-start 4) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 1))
                                 (vector-ref te0 (byte a1 3))
                                 (vector-ref te1 (byte a2 2))
                                 (vector-ref te2 (byte a3 1))
                                 (vector-ref te3 (byte a0 0))))
                (a2 (bitwise-xor (vector-ref key-schedule 2)
                                 (bytevector-u32-ref in (+ in-start 8) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 2))
                                 (vector-ref te0 (byte a2 3))
                                 (vector-ref te1 (byte a3 2))
                                 (vector-ref te2 (byte a0 1))
                                 (vector-ref te3 (byte a1 0))))
                (a3 (bitwise-xor (vector-ref key-schedule 3)
                                 (bytevector-u32-ref in (+ in-start 12) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 3))
                                 (vector-ref te0 (byte a3 3))
                                 (vector-ref te1 (byte a0 2))
                                 (vector-ref te2 (byte a1 1))
                                 (vector-ref te3 (byte a2 0)))))
               ((= i (- len 4))
                ;; Finally do a round of SubBytes, ShiftRows and AddRoundKey.
                (bytevector-u32-set! out out-start
                                     (bitwise-xor
                                      (vector-ref key-schedule i)
                                      (copy-byte (vector-ref te4 (byte a0 3)) 3)
                                      (copy-byte (vector-ref te4 (byte a1 2)) 2)
                                      (copy-byte (vector-ref te4 (byte a2 1)) 1)
                                      (copy-byte (vector-ref te4 (byte a3 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 4)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 1))
                                      (copy-byte (vector-ref te4 (byte a1 3)) 3)
                                      (copy-byte (vector-ref te4 (byte a2 2)) 2)
                                      (copy-byte (vector-ref te4 (byte a3 1)) 1)
                                      (copy-byte (vector-ref te4 (byte a0 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 8)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 2))
                                      (copy-byte (vector-ref te4 (byte a2 3)) 3)
                                      (copy-byte (vector-ref te4 (byte a3 2)) 2)
                                      (copy-byte (vector-ref te4 (byte a0 1)) 1)
                                      (copy-byte (vector-ref te4 (byte a1 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 12)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 3))
                                      (copy-byte (vector-ref te4 (byte a3 3)) 3)
                                      (copy-byte (vector-ref te4 (byte a0 2)) 2)
                                      (copy-byte (vector-ref te4 (byte a1 1)) 1)
                                      (copy-byte (vector-ref te4 (byte a2 0)) 0))
                                     (endianness big)))))


;;; Deciphering

  (define (reverse-aes-schedule key)
    ;; Reverse the key schedule, then do InvMixColumns
    (do ((ret (list->vector
               (concatenate (reverse (uncat (vector->list key) 4)))))
         (i 4 (+ i 1)))
        ((= i (- (vector-length ret) 4))
         ret)
      (let ((temp (vector-ref ret i)))
        (vector-set! ret i
                     (bitwise-xor
                      (vector-ref td0 (copy-byte (vector-ref te4 (byte temp 3)) 0))
                      (vector-ref td1 (copy-byte (vector-ref te4 (byte temp 2)) 0))
                      (vector-ref td2 (copy-byte (vector-ref te4 (byte temp 1)) 0))
                      (vector-ref td3 (copy-byte (vector-ref te4 (byte temp 0)) 0)))))))

  (define (aes-decrypt! in in-start out out-start key-schedule)
    ;; First add the first round key. Then do n-1 rounds of
    ;; InvSubBytes, InvShiftRows, InvMixColumns and AddRoundKey.
    (do/unroll (176/4 #;208/4 #;240/4)
               ((len (vector-length key-schedule))
                (i 4 (+ i 4))
                (a0 (bitwise-xor (vector-ref key-schedule 0)
                                 (bytevector-u32-ref in in-start (endianness big)))
                    (bitwise-xor (vector-ref key-schedule i)
                                 (vector-ref td0 (byte a0 3))
                                 (vector-ref td1 (byte a3 2))
                                 (vector-ref td2 (byte a2 1))
                                 (vector-ref td3 (byte a1 0))))
                (a1 (bitwise-xor (vector-ref key-schedule 1)
                                 (bytevector-u32-ref in (+ in-start 4) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 1))
                                 (vector-ref td0 (byte a1 3))
                                 (vector-ref td1 (byte a0 2))
                                 (vector-ref td2 (byte a3 1))
                                 (vector-ref td3 (byte a2 0))))
                (a2 (bitwise-xor (vector-ref key-schedule 2)
                                 (bytevector-u32-ref in (+ in-start 8) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 2))
                                 (vector-ref td0 (byte a2 3))
                                 (vector-ref td1 (byte a1 2))
                                 (vector-ref td2 (byte a0 1))
                                 (vector-ref td3 (byte a3 0))))
                (a3 (bitwise-xor (vector-ref key-schedule 3)
                                 (bytevector-u32-ref in (+ in-start 12) (endianness big)))
                    (bitwise-xor (vector-ref key-schedule (+ i 3))
                                 (vector-ref td0 (byte a3 3))
                                 (vector-ref td1 (byte a2 2))
                                 (vector-ref td2 (byte a1 1))
                                 (vector-ref td3 (byte a0 0)))))
               ((= i (- len 4))
                ;; Finally do a round of InvSubBytes, InvShiftRows and AddRoundKey.
                (bytevector-u32-set! out out-start
                                     (bitwise-xor
                                      (vector-ref key-schedule i)
                                      (copy-byte (vector-ref td4 (byte a0 3)) 3)
                                      (copy-byte (vector-ref td4 (byte a3 2)) 2)
                                      (copy-byte (vector-ref td4 (byte a2 1)) 1)
                                      (copy-byte (vector-ref td4 (byte a1 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 4)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 1))
                                      (copy-byte (vector-ref td4 (byte a1 3)) 3)
                                      (copy-byte (vector-ref td4 (byte a0 2)) 2)
                                      (copy-byte (vector-ref td4 (byte a3 1)) 1)
                                      (copy-byte (vector-ref td4 (byte a2 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 8)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 2))
                                      (copy-byte (vector-ref td4 (byte a2 3)) 3)
                                      (copy-byte (vector-ref td4 (byte a1 2)) 2)
                                      (copy-byte (vector-ref td4 (byte a0 1)) 1)
                                      (copy-byte (vector-ref td4 (byte a3 0)) 0))
                                     (endianness big))
                (bytevector-u32-set! out (+ out-start 12)
                                     (bitwise-xor
                                      (vector-ref key-schedule (+ i 3))
                                      (copy-byte (vector-ref td4 (byte a3 3)) 3)
                                      (copy-byte (vector-ref td4 (byte a2 2)) 2)
                                      (copy-byte (vector-ref td4 (byte a1 1)) 1)
                                      (copy-byte (vector-ref td4 (byte a0 0)) 0))
                                     (endianness big)))))

;;;

  (define (clear-aes-schedule! sched)
    (vector-fill! sched 0))

  )
