#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Actual - the scheming operating system
;; Copyright © 2008, 2009 Göran Weinholt <goran@weinholt.se>
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

;; Test suite for the (weinholt struct pack) library.

;; This program also tests the host implementation's bytevector
;; procedures quite thoroughly, as it turns out.

(import (rnrs)
        (rnrs eval)
        (weinholt struct pack)
        (only (weinholt struct pack-aux) roundb)
        (srfi :78 lightweight-testing)
        (only (srfi :1 lists) make-list)
        (rename (only (srfi :27 random-bits) random-integer
                      default-random-source random-source-randomize!)
                (random-integer random)))

(random-source-randomize! default-random-source)

(define (check-pack expect fmt . values)
  (display "\nFormat: ") (write fmt)
  (display "\nValues: ") (write values) (newline)
  (check (apply pack fmt values) => expect)
  (check (eval `(pack ,fmt ,@values)
               (environment '(rnrs) '(weinholt struct pack)))
         => expect)
  (check (call-with-values (lambda () (unpack fmt expect)) list)
         => values)
  (check (eval `(call-with-values (lambda () (unpack ,fmt ',expect)) list)
               (environment '(rnrs) '(weinholt struct pack)))
         => values))

(define (print . x) (for-each display x) (newline))

(define (random-integer n set ref)
  (let ((bv (make-bytevector n)))
    (do ((i 0 (+ i 1)))
        ((= i n) (ref bv 0 (native-endianness)))
      (bytevector-u8-set! bv i (random 256)))))

(define (random-float n set ref)
  (let ((v (inexact (/ (random 10000)
                       (+ 1 (random 100)))))
        (bv (make-bytevector n)))
    (set bv 0 v (native-endianness))
    (ref bv 0 (native-endianness))))

(define types
  (vector (vector #\c
                  (lambda (b i e) (bytevector-s8-ref b i))
                  (lambda (b i v e) (bytevector-s8-set! b i v))
                  1 #f)
          (vector #\C
                  (lambda (b i e) (bytevector-u8-ref b i))
                  (lambda (b i v e) (bytevector-u8-set! b i v))
                  1 #f)
          (vector #\s bytevector-s16-ref bytevector-s16-set! 2 #f)
          (vector #\S bytevector-u16-ref bytevector-u16-set! 2 #f)
          (vector #\l bytevector-s32-ref bytevector-s32-set! 4 #f)
          (vector #\L bytevector-u32-ref bytevector-u32-set! 4 #f)
          (vector #\q bytevector-s64-ref bytevector-s64-set! 8 #f)
          (vector #\Q bytevector-u64-ref bytevector-u64-set! 8 #f)
          (vector #\f bytevector-ieee-single-ref bytevector-ieee-single-set! 4 'float)
          (vector #\d bytevector-ieee-double-ref bytevector-ieee-double-set! 8 'float)))

(define (random-test endianness)
  "Construct random format strings and values, alongside a bytevector
that is expected to contain the values encoded correctly according to
the format string. Then see if pack/unpack gives the expected result."
  (let-values (((p extract) (open-bytevector-output-port))
               ((count) (random 15)))
    (let lp ((i 0)
             (align #t)
             (codes (case endianness
                      ((little) '(#\<))
                      ((big) (if (zero? (random 2))
                                 '(#\!) '(#\>)))
                      ((native) '(#\=))))
             (values '())
             (o 0))
      (let ((t (vector-ref types (random (vector-length types)))))
        (if (= i count)
            (let ((fmt (list->string (reverse codes)))
                  (values (reverse values))
                  (bv (extract)))
              (apply check-pack bv fmt values))
            (let* ((v ((if (eq? (vector-ref t 4) 'float)
                           random-float
                           random-integer)
                       (vector-ref t 3) (vector-ref t 2) (vector-ref t 1)))
                   (padsize (random 5))
                   (pad (make-list padsize #\x))
                   (rep (random 5))
                   (repcode (string->list (number->string rep)))
                   (bv (make-bytevector (vector-ref t 3)))
                   (new-align (if (zero? (random 3)) (not align) align))
                   (no (if align (roundb o (vector-ref t 3)) o)))
              ;; align
              (put-bytevector p (make-bytevector (- no o) 0))
              ((vector-ref t 2) bv 0 v (if (eq? endianness 'native)
                                           (native-endianness)
                                           endianness))
              (do ((i 0 (+ i 1))
                   (m (if (zero? rep) 1 rep)))
                  ((= i m))
                ;; values
                (put-bytevector p bv))
              ;; "x"
              (put-bytevector p (make-bytevector padsize 0))
              (cond ((zero? rep)
                     (lp (+ i 1) new-align
                         (append pad
                                 (if (boolean=? align new-align) '()
                                     (if new-align '(#\a) '(#\u)))
                                 (cons (vector-ref t 0) codes))
                         (cons v values)
                         (+ no padsize (vector-ref t 3))))
                    (else
                     (lp (+ i 1) new-align
                         (append pad
                                 (if (boolean=? align new-align) '()
                                     (if new-align '(#\a) '(#\u)))
                                 (cons (vector-ref t 0)
                                       (append repcode codes)))
                         (append (make-list rep v) values)
                         (+ no padsize (* rep (vector-ref t 3))))))))))))

(do ((i 0 (+ i 1)))
    ((= i 50))
  (random-test 'native))

(do ((i 0 (+ i 1)))
    ((= i 50))
  (random-test (endianness big)))

(do ((i 0 (+ i 1)))
    ((= i 50))
  (random-test (endianness little)))

(check-pack '#vu8() "")
(check-pack '#vu8(0) "x")
(check-pack '#vu8(0 0 0) "3x")
(check-pack '#vu8() "0x")
(check-pack '#vu8() "!0x")
(check-pack '#vu8(#xff) "c" -1)
(check-pack '#vu8(0 #xff) "xC" 255)

(check-pack '#vu8(0 1 0 0 0 0 0 2 0 0 0 0 0 0 0 3) "!SLQ" 1 2 3)
(check-pack '#vu8(0 0 0 0 0 0 0 1 0 0 0 2 0 3) "!QLS" 1 2 3)
(check-pack '#vu8(0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 2 0 0 0 3) "!SQL" 1 2 3)
(check-pack '#vu8(0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 2 0 0 0 3) ">SQL" 1 2 3)
(check-pack '#vu8(1 0 0 0 0 0 0 0 2 0 0 0 3 0) "<QLS" 1 2 3)

(check (unpack "!C" '#vu8(1 2 3 4 6 0) 5) => 0)
(check (unpack "!S" '#vu8(1 2 3 4 0 0) 4) => 0)

(check (let ((bv (make-bytevector 4 0))) (pack! "!S" bv 2 #xffee) bv)
       => '#vu8(0 0 #xff #xee))


(check-pack '#vu8(4 1 0) "u!C S" 4 #x100)
(check-pack '#vu8(4 0 1 0) "u!CaS" 4 #x100)

(check-pack '#vu8(4 0 0 1 0) "u!C L" 4 #x100)

(check-pack '#vu8(4 0 0 0 0 0 0 1 0) "u!C Q" 4 #x100)

(check (let-values ((x (get-unpack (open-bytevector-input-port #vu8(4 3 2 1 2 1 1 #xff #xff))
                                "<LSC")))
         x)
       => '(#x01020304 #x0102 #x01))

(check (apply get-unpack (open-bytevector-input-port #vu8(#xff))
              "c" '())
       => -1)

(check (unpack "C" #vu8(0 1) 1) => 1)

(check (let ((offset 1)) (unpack "C" #vu8(0 1) offset)) => 1)

(check (let ((offset 1))
         (unpack "!uxxS" #vu8(5 5 5 0 1) offset))
       => 1)

(check (pack "!SS" 1 2) => #vu8(0 1 0 2))

(check (let ((bv (make-bytevector 6 #xff))
             (offset 1))
         (pack! "!SS" bv offset 1 2)
         bv)
       => #vu8(#xff 0 0 1 0 2))

(check (let ((bv (make-bytevector 9 #xff)))
         (pack! "<ucQ" bv (+ 0) 1 2)
         bv)
       => #vu8(1 2 0 0 0 0 0 0 0))

(check (map unpack
            '("C" "!S" "!xxC")
            '(#vu8(1) #vu8(0 1) #vu8(42 42 1)))
       => '(1 1 1))

(check (map pack
            '("C" "!S" "!xxC")
            '(1 1 1))
       => '(#vu8(1) #vu8(0 1) #vu8(0 0 1)))

(check-report)
