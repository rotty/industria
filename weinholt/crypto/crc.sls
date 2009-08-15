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

;; Syntax for defining procedures that calculate Cyclic Redundancy Codes.

;; Ross N. Williams, "A painless guide to CRC error detection
;; algorithms". http://www.ross.net/crc/crcpaper.html

;; Quick and possibly confusing guide to using define-crc, for those
;; who are too busy to read the above paper:

;; Syntax: (define-src name width polynomial init ref-in ref-out
;;                     xor-out check)

;; The width is the bitwise length of the polynomial. You might be
;; lead to believe that it should sometimes be 33, but if so you've
;; been counting the highest bit, which doesn't count.

;; The polynomial for CRC-16 is given sometimes given as x^16 + x^15 +
;; x^2 + 1. This translates to #b1000000000000101 (#x8005). Notice
;; that x^16 is absent. CRCs use polynomial division with modulo two
;; arithmetic (better known as XOR). Don't use the reversed polynomial
;; if you have one of those, instead set ref-in and ref-out properly.

;; After a CRC has been calculated it is sometimes XOR'd with a final
;; value, this is xor-out.

;; check is either the CRC of the ASCII string "123456789", or #f.

;; The functions defined are like these:

;; (crc-32 bytevector)
;;     returns the final CRC of the entire bytevector
;; (crc-32-init)
;;     returns an initial CRC state
;; (crc-32-update state bv)
;; (crc-32-update state bv start)
;; (crc-32-update state bv start end)
;;     returns a new state which includes the CRC on the given bytes
;; (crc-32-finish state)
;;     returns the final CRC
;; (crc-32-self-test)
;;     returns 'sucess, 'failure, or 'no-self-test

;; CRC-32 is supposedly used for .ZIP, AUTODIN II, Ethernet, FDDI,
;; PNG, MPEG-2 and various other things. No doubt it is very popular
;; indeed.

(library (weinholt crypto crc (0 0))
  (export define-crc
          crc-32 crc-32-init crc-32-update crc-32-finish crc-32-self-test
          crc-16 crc-16-init crc-16-update crc-16-finish crc-16-self-test)
  (import (rnrs)
          (for (only (srfi :1 lists) iota) expand))

  (define-syntax define-crc
    (lambda (x)
      (define (bitwise-reverse-bit-field v start end)
        ;; This is only for the benefit of Ikarus, which does not
        ;; implement this procedure as of 2009-08-16.
        (do ((i start (+ i 1))
             (ret 0 (if (bitwise-bit-set? v i)
                        (bitwise-ior ret (bitwise-arithmetic-shift-left 1 (- end i 1)))
                        ret)))
            ((= i end)
             (bitwise-ior (bitwise-arithmetic-shift-left ret start)
                          (bitwise-copy-bit-field v start end 0)))))
      (define (calc-table index width ref-in poly)
        (if ref-in
            (bitwise-reverse-bit-field (calc-table (bitwise-reverse-bit-field index 0 8)
                                                   width #f poly)
                                       0 width)
            (do ((bit 0 (+ bit 1))
                 (r (bitwise-arithmetic-shift-left index (- width 8))
                    (if (bitwise-bit-set? r (- width 1))
                        (bitwise-xor (bitwise-arithmetic-shift-left r 1) poly)
                        (bitwise-arithmetic-shift-left r 1))))
                ((= bit 8)
                 (bitwise-bit-field r 0 width)))))
      (define (symcat name suffix)
        (datum->syntax name (string->symbol (string-append
                                             (symbol->string (syntax->datum name))
                                             suffix))))
      (syntax-case x ()
        ((_ name width polynomial init ref-in ref-out xor-out check)
         ;; TODO: do a sanity check on the width. Not every width is
         ;; supported... only 32 and 16 have been tested properly.
         ;; Sub-byte widths need something completely different.
         (let* ((width* (syntax->datum #'width))
                (polynomial* (syntax->datum #'polynomial))
                (init* (syntax->datum #'init))
                (ref-in* (syntax->datum #'ref-in))
                (ref-out* (syntax->datum #'ref-out)))
           (with-syntax ((mask (- (bitwise-arithmetic-shift-left 1 width*) 1))
                         (init (if ref-in* (bitwise-reverse-bit-field init* 0 width*) init*))
                         (table (list->vector
                                 (map (lambda (i) (calc-table i width* ref-in* polynomial*))
                                      (iota 256))))
                         (crc-init (symcat #'name "-init"))
                         (crc-finish (symcat #'name "-finish"))
                         (crc-update (symcat #'name "-update"))
                         (crc-self-test (symcat #'name "-self-test")))
             #`(begin
                 (define (name bv)
                   (crc-finish (crc-update (crc-init) bv)))
                 (define (crc-init) init)
                 (define (crc-finish r) (bitwise-xor r xor-out))
                 (define (crc-self-test)
                   (if check
                       (if (= (name (string->utf8 "123456789")) check)
                           'success 'failure)
                       'no-self-test))
                 (define t 'table)
                 (define crc-update
                   (case-lambda
                     ((r* bv)
                      (crc-update r* bv 0 (bytevector-length bv)))
                     ((r* bv start)
                      (crc-update r* bv start (bytevector-length bv)))
                     ((r* bv start end)
                      (do ((i 0 (+ i 1))
                           (r r*
                              ;; TODO: implement the other ref-in ref-out combinations?
                              #,(cond ((and ref-in* ref-out*)
                                       ;; TODO: fixnums
                                       #'(bitwise-xor (bitwise-arithmetic-shift-right r 8)
                                                      (vector-ref
                                                       t (bitwise-and (bitwise-xor r (bytevector-u8-ref bv i))
                                                                      #xff))))
                                      ((and (not ref-in*) (not ref-out*))
                                       #'(bitwise-xor (bitwise-and mask (bitwise-arithmetic-shift-left r 8))
                                                      (vector-ref
                                                       t (bitwise-xor
                                                          (bytevector-u8-ref bv i)
                                                          (bitwise-and
                                                           (bitwise-arithmetic-shift-right r (- width 8))
                                                           #xff)))))
                                      (else (syntax-violation #f "unimplemented reflection" x)))))
                          ((= i (bytevector-length bv)) r))))))))))))

;;; Parameterized CRCs, using the parameters from Williams's paper

  (define-crc crc-32 32 #x04C11DB7 #xFFFFFFFF #t #t #xFFFFFFFF #xCBF43926)

  (define-crc crc-16 16 #x8005 #x0000 #t #t #x0000 #xBB3D)

  ;; Some examples...

  ;; (define-crc crc-16/ccitt 16 #x1021 #xffff #f #f 0 #x29B1)

  ;; CRC-32C specified in e.g. RFC4960 or RFC3385. Used by SCTP and iSCSI.
  ;; (define-crc crc-32c 32 #x1EDC6F41 #xFFFFFFFF #t #t #xFFFFFFFF #xE3069283)

  )
