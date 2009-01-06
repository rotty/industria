;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2008 Göran Weinholt <goran@weinholt.se>
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

(library (se weinholt assembler x86-misc (1 0 0))
    (export make-modr/m make-sib bitwidth<=
            number->bytevector)
    (import (rnrs))

  (define (number->bytevector imm size)
    "Takes a number that fits in the signed OR unsigned range of
`size' bits."
    (case size
      ((8) (let ((bv (make-bytevector 1)))
             ((if (<= 0 imm (- (expt 2 8) 1))
                  bytevector-u8-set!
                  bytevector-s8-set!)
              bv 0 imm)
             bv))
      ((16) (let ((bv (make-bytevector 2)))
              ((if (<= 0 imm (- (expt 2 16) 1))
                   bytevector-u16-set!
                   bytevector-s16-set!)
               bv 0 imm (endianness little))
              bv))
      ((32) (let ((bv (make-bytevector 4)))
              ;; FIXME: does this work for the unsigned range??
              (bytevector-s32-set! bv 0 imm (endianness little))
              bv))
      ((64) (let ((bv (make-bytevector 8)))
              (bytevector-s64-set! bv 0 imm (endianness little))
              bv))
      ((128) (let ((bv (make-bytevector 16)))
              (bytevector-sint-set! bv 0 imm (endianness little) 16)
              bv))
      (else
       (error 'number->bytevector
              "Unknown size" size))))

  (define (make-modr/m mod reg r/m)
      (fxior (fxarithmetic-shift-left (fxand mod #b11) 6)
             (fxarithmetic-shift-left (fxand reg #b111) 3)
             (fxand r/m #b111)))

  (define (make-sib scale index base)
    (fxior (fxarithmetic-shift-left (case scale
                                      ((1) #b00)
                                      ((2) #b01)
                                      ((4) #b10)
                                      ((8) #b11)
                                      (else (error 'make-sib "invalid scale" scale)))
                                    6)
           (fxarithmetic-shift-left (fxand index #b111) 3)
           (fxand base #b111)))

  (define (bitwidth<= x l u)
    (<= (- (expt 2 l)) x (- (expt 2 u) 1))))
