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

;; Describes how the calculations in GF(2⁸) work, more or less:

;; INPROCEEDINGS{Win96afast,
;;     author = {Erik De Win and Antoon Bosselaers and Servaas Vanderberghe and Peter De Gersem and Joos Vandewalle},
;;     title = {A Fast Software Implementation for Arithmetic Operations in GF(2^n)},
;;     booktitle = {},
;;     year = {1996},
;;     pages = {65--76},
;;     publisher = {Springer-Verlag}
;; }

(library (weinholt crypto aes private (0 0 20090910))
  (export S-box inv-S-box GFexpt GF*)
  (import (rnrs))

  ;; Calculations in GF(2⁸)... all children need to learn their
  ;; GF(2⁸) logarithm tables by heart.
  (define alog
    (do ((alog (make-bytevector 256))
         (p 1 (let ((p (fxxor p (fxarithmetic-shift-left p 1))))
                (if (fxbit-set? p 8)
                    (fxxor p #b100011011) ;subtract X⁸+X⁴+X³+X+1
                    p)))
         (i 0 (+ i 1)))
        ((= i 256)
         (lambda (i) (bytevector-u8-ref alog i)))
      (bytevector-u8-set! alog i p)))

  (define ilog                          ;called `log' in [Win96afast]
    (do ((ilog (make-bytevector 256))
         (i 0 (+ i 1)))
        ((= i 256)
         (lambda (i) (bytevector-u8-ref ilog i)))
      (bytevector-u8-set! ilog (alog i) i)))

  (define (GF* a b)
    (if (or (zero? a) (zero? b))
        0
        (alog (mod (+ (ilog a) (ilog b)) 255))))

  (define (GFexpt a n)
    (if (zero? n) 1
        (GF* a (GFexpt a (- n 1)))))

  (define (GFinv a)
    (if (zero? a)
        0
        (alog (mod (- (ilog a)) 255))))

  ;; What follows is from Rijndael

  (define (affine-transform b)
    (define (bit x i)
      (fxbit-field x i (+ i 1)))
    (do ((c #b01100011)
         (i 0 (+ i 1))
         (tmp 0 (fxior (fxarithmetic-shift-left
                        (fxxor (bit b i)
                               (bit b (mod (+ i 4) 8))
                               (bit b (mod (+ i 5) 8))
                               (bit b (mod (+ i 6) 8))
                               (bit b (mod (+ i 7) 8))
                               (bit c i))
                        i)
                       tmp)))
        ((= i 8) tmp)))

  (define S-box                         ;for SubBytes
    (do ((S (make-bytevector 256))
         (i 0 (+ i 1)))
        ((= i 256)
         (lambda (i) (bytevector-u8-ref S i)))
      (bytevector-u8-set! S i (affine-transform (GFinv i)))))

  (define inv-S-box                     ;for InvSubBytes
    (do ((invS (make-bytevector 256))
         (i 0 (+ i 1)))
        ((= i 256)
         (lambda (i) (bytevector-u8-ref invS i)))
      (bytevector-u8-set! invS (affine-transform (GFinv i)) i))))
