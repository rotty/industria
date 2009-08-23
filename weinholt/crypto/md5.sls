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

;; The MD5 Message-Digest Algorithm. RFC 1321

(library (weinholt crypto md5 (1 0 20090821))
  (export make-md5 md5-update! md5-finish! md5-clear!
          md5 md5-copy md5-finish
          md5-copy-hash! md5->bytevector md5->string
          hmac-md5)
  (import (except (rnrs) bitwise-rotate-bit-field)
          (only (srfi :43 vectors) vector-copy))

  (define (print . x) (for-each display x) (newline))

  (define (bitwise-rotate-bit-field ei1 ei2 ei3 ei4)
    (let* ((n     ei1)
           (start ei2)
           (end   ei3)
           (count ei4)
           (width (- end start)))
      (if (positive? width)
          (let* ((count (mod count width))
                 (field0 (bitwise-bit-field n start end))
                 (field1 (bitwise-arithmetic-shift-left field0 count))
                 (field2 (bitwise-arithmetic-shift-right field0 (- width count)))
                 (field (bitwise-ior field1 field2)))
            (bitwise-copy-bit-field n start end field))
          n)))

  (define-record-type md5state
    (fields (immutable H)               ;Hash
            (immutable W)               ;temporary data
            (immutable m)               ;unprocessed data
            (mutable pending)           ;length of unprocessed data
            (mutable processed)))       ;length of processed data

  (define (make-md5)
    (let ((H (list->vector initial-hash))
          (W (make-bytevector (* 4 16)))
          (m (make-bytevector (* 4 16))))
      (make-md5state H W m 0 0)))

  (define (md5-copy state)
    (let ((H (vector-copy (md5state-H state)))
          (W (make-bytevector (* 4 16)))
          (m (bytevector-copy (md5state-m state))))
      (make-md5state H W m
                     (md5state-pending state)
                     (md5state-processed state))))

  (define (md5-clear! state)
    (for-each (lambda (i v)
                (vector-set! (md5state-H state) i v))
              '(0 1 2 3)
              initial-hash)
    (bytevector-fill! (md5state-W state) 0)
    (bytevector-fill! (md5state-m state) 0)
    (md5state-pending-set! state 0)
    (md5state-processed-set! state 0))

  (define initial-hash '(#x67452301 #xEFCDAB89 #x98BADCFE #x10325476))

  (define (f t x y z)
    (cond ((<= 0 t 15)
           (bitwise-ior (bitwise-and x y)
                        (bitwise-and (bitwise-not x) z)))
          ((<= 16 t 31)
           (bitwise-ior (bitwise-and x z)
                        (bitwise-and (bitwise-not z) y)))
          ((<= 32 t 47)
           (bitwise-xor x y z))
          (else
           (bitwise-xor y (bitwise-ior (bitwise-not z) x)))))

  (define (g t)
    (cond ((<= 0 t 15)  t)
          ((<= 16 t 31) (mod (+ (* 5 t) 1) 16))
          ((<= 32 t 47) (mod (+ (* 3 t) 5) 16))
          (else         (mod (* 7 t) 16))))

  (define r
    '#(7 12 17 22  7 12 17 22  7 12 17 22  7 12 17 22
       5  9 14 20  5  9 14 20  5  9 14 20  5  9 14 20
       4 11 16 23  4 11 16 23  4 11 16 23  4 11 16 23
       6 10 15 21  6 10 15 21  6 10 15 21  6 10 15 21))

  (define k
    '#(#xd76aa478 #xe8c7b756 #x242070db #xc1bdceee
       #xf57c0faf #x4787c62a #xa8304613 #xfd469501
       #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be
       #x6b901122 #xfd987193 #xa679438e #x49b40821
       #xf61e2562 #xc040b340 #x265e5a51 #xe9b6c7aa
       #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
       #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed
       #xa9e3e905 #xfcefa3f8 #x676f02d9 #x8d2a4c8a
       #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c
       #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70
       #x289b7ec6 #xeaa127fa #xd4ef3085 #x04881d05
       #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665
       #xf4292244 #x432aff97 #xab9423a7 #xfc93a039
       #x655b59c3 #x8f0ccc92 #xffeff47d #x85845dd1
       #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1
       #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391))

  ;; This function transforms a whole 512 bit block.
  (define (md5-transform! H W m offset)
    ;; Copy the message block
    (do ((t 0 (+ t 4)))
        ((= t (* 4 16)))
      (bytevector-u32-native-set! W t (bytevector-u32-ref m (+ t offset) (endianness little))))
    ;; Do the hokey pokey
    (let lp ((A (vector-ref H 0))
             (B (vector-ref H 1))
             (C (vector-ref H 2))
             (D (vector-ref H 3))
             (t 0))
      (cond ((= t 64)
             (vector-set! H 0 (bitwise-and #xffffffff (+ A (vector-ref H 0))))
             (vector-set! H 1 (bitwise-and #xffffffff (+ B (vector-ref H 1))))
             (vector-set! H 2 (bitwise-and #xffffffff (+ C (vector-ref H 2))))
             (vector-set! H 3 (bitwise-and #xffffffff (+ D (vector-ref H 3)))))
            (else
             (lp D
                 (bitwise-and #xffffffff
                              (+ B
                                 (bitwise-rotate-bit-field
                                  (+ A
                                     (f t B C D)
                                     (bytevector-u32-native-ref W (* 4 (g t)))
                                     (vector-ref k t))
                                  0 32
                                  (vector-ref r t))))
                 B
                 C
                 (+ t 1))))))

  ;; Add a bytevector to the state. Align your data to whole blocks if
  ;; you want this to go a little faster.
  (define md5-update!
    (case-lambda
      ((state data start end)
       (let ((m (md5state-m state))    ;unprocessed data
             (H (md5state-H state))
             (W (md5state-W state)))
         (let lp ((offset start))
           (cond ((= (md5state-pending state) 64)
                  ;; A whole block is pending
                  (md5-transform! H W m 0)
                  (md5state-pending-set! state 0)
                  (md5state-processed-set! state (+ 64 (md5state-processed state)))
                  (lp offset))
                 ((= offset end)
                  (values))
                 ((or (> (md5state-pending state) 0)
                      (> (+ offset 64) end))
                  ;; Pending data exists or less than a block remains.
                  ;; Add more pending data.
                  (let ((added (min (- 64 (md5state-pending state))
                                    (- end offset))))
                    (bytevector-copy! data offset
                                      m (md5state-pending state)
                                      added)
                    (md5state-pending-set! state (+ added (md5state-pending state)))
                    (lp (+ offset added))))
                 (else
                  ;; Consume a whole block
                  (md5-transform! H W data offset)
                  (md5state-processed-set! state (+ 64 (md5state-processed state)))
                  (lp (+ offset 64)))))))
      ((state data)
       (md5-update! state data 0 (bytevector-length data)))))

  (define zero-block (make-bytevector 64 0))

  ;; Finish the state by adding a 1, zeros and the counter.
  (define (md5-finish! state)
    ;; TODO: the rfc has a prettier way to do this.
    (let ((m (md5state-m state))
          (pending (+ (md5state-pending state) 1)))
      (bytevector-u8-set! m (md5state-pending state) #x80)
      (cond ((> pending 56)
             (bytevector-copy! zero-block 0
                               m pending
                               (- 64 pending))
             (md5-transform! (md5state-H state)
                             (md5state-W state)
                             m
                             0)
             (bytevector-fill! m 0))
            (else
             (bytevector-copy! zero-block 0
                               m pending
                               (- 64 pending))))
      ;; Number of bits in the data
      (bytevector-u64-set! m 56
                           (* (+ (md5state-processed state)
                                 (- pending 1))
                              8)
                           (endianness little))
      (md5-transform! (md5state-H state)
                      (md5state-W state)
                      m
                      0)))

  (define (md5-finish state)
    (let ((copy (md5-copy state)))
      (md5-finish! copy)
      copy))

  ;; Find the MD5 of the concatenation of the given bytevectors.
  (define (md5 . data)
    (let ((state (make-md5)))
      (for-each (lambda (d) (md5-update! state d))
                data)
      (md5-finish! state)
      state))

  (define (md5-copy-hash! state bv off)
    (do ((i 0 (+ i 1)))
        ((= i 4))
      (bytevector-u32-set! bv (+ off (* 4 i)) (vector-ref (md5state-H state) i) (endianness little))))

  (define (md5->bytevector state)
    (let ((ret (make-bytevector (* 4 4))))
      (md5-copy-hash! state ret 0)
      ret))

  (define (md5->string state)
    (apply string-append
           (map (lambda (x)
                  (if (< x #x10)
                      (string-append "0" (number->string x 16))
                      (number->string x 16)))
                (bytevector->u8-list (md5->bytevector state)))))

  (define (hmac-md5 secret . data)
    ;; RFC 2104.
    (if (> (bytevector-length secret) 64)
        (apply hmac-md5 (md5->bytevector (md5 secret)) data)
        (let ((k-ipad (make-bytevector 64 0))
              (k-opad (make-bytevector 64 0)))
          (bytevector-copy! secret 0 k-ipad 0 (bytevector-length secret))
          (bytevector-copy! secret 0 k-opad 0 (bytevector-length secret))
          (do ((i 0 (fx+ i 1)))
              ((fx=? i 64))
            (bytevector-u8-set! k-ipad i (fxxor #x36 (bytevector-u8-ref k-ipad i)))
            (bytevector-u8-set! k-opad i (fxxor #x5c (bytevector-u8-ref k-opad i))))
          (let ((state (make-md5)))
            (md5-update! state k-ipad)
            (for-each (lambda (d) (md5-update! state d)) data)
            (md5-finish! state)
            (let ((digest (md5->bytevector state)))
              (md5-clear! state)
              (md5-update! state k-opad)
              (md5-update! state digest)
              (md5-finish! state)
              state))))))
