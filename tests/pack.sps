#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Actual - the scheming operating system
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

(import (rnrs)
        (rnrs eval)
        (se weinholt struct pack)
        (se weinholt struct pack-aux)
        (only (ikarus) random))

;; Needs (random n) which gives a random integer x, 0 <= x < n.

(define (make-list n v)
  (if (> n 0) (cons v (make-list (- n 1) v)) '()))

(define (check-pack expect fmt . values)
  (let ((result (apply pack fmt values)))
    (unless (bytevector=? result expect)
      (error 'check-pack "Bad result from pack"
             result expect
             fmt values))
    (let ((result2
           (eval `(call-with-values (lambda () (unpack ,fmt ',result)) list)
                 (environment '(rnrs) '(se weinholt struct pack)))))
      (unless (equal? values result2)
        (error 'check-pack "Bad result from unpack"
               result2 values fmt)))))

(define-syntax check
  (lambda (x)
    (syntax-case x ()
      ((_ test)
       #'(unless test
           (error 'check "Test returned #f" 'test))))))

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
  (vector (vector #\s bytevector-s16-ref bytevector-s16-set! 2 #f)
          (vector #\S bytevector-u16-ref bytevector-u16-set! 2 #f)
          (vector #\l bytevector-s32-ref bytevector-s32-set! 4 #f)
          (vector #\L bytevector-u32-ref bytevector-u32-set! 4 #f)
          (vector #\q bytevector-s64-ref bytevector-s64-set! 8 #f)
          (vector #\Q bytevector-u64-ref bytevector-u64-set! 8 #f)
          (vector #\f bytevector-ieee-single-ref bytevector-ieee-single-set! 4 'float)
          (vector #\d bytevector-ieee-double-ref bytevector-ieee-double-set! 8 'float)))

(define (random-test endianness)
  "Construct random format strings and values, alongside a bytevector
that is expected to contain the values encoded correctly accordingto
the format string. Then see if pack/unpack give the expected result."
  (call-with-values open-bytevector-output-port
    (lambda (p extract)
      (let ((count (random 10)))
        (let lp ((i 0)
                 (codes (case endianness
                          ((little) '(#\<))
                          ((big) '(#\>))))
                 (values '())
                 (o 0))
          (let ((t (vector-ref types (random (vector-length types)))))
            (cond ((= i count)
                   (let ((fmt (list->string (reverse codes)))
                         (values (reverse values))
                         (bv (extract)))
                     (apply check-pack bv fmt values)))
                  (else
                   (let* ((v ((if (vector-ref t 4)
                                  random-float
                                  random-integer)
                              (vector-ref t 3) (vector-ref t 2) (vector-ref t 1)))
                          (padsize (random 5))
                          (pad (make-list padsize #\x))
                          (rep (random 5))
                          (repcode (string->list (number->string rep)))
                          (bv (make-bytevector (vector-ref t 3))))
                     (let ((no (roundb o (vector-ref t 3))))
                       ;; align
                       (put-bytevector p (make-bytevector (- no o) 0))
                       ((vector-ref t 2) bv 0 v endianness)
                       (do ((i 0 (+ i 1))
                            (m (if (zero? rep) 1 rep)))
                           ((= i m))
                         ;; values
                         (put-bytevector p bv))
                       ;; "x"
                       (put-bytevector p (make-bytevector padsize 0))
                       (cond ((zero? rep)
                              (lp (+ i 1)
                                  (append pad (cons (vector-ref t 0) codes))
                                  (cons v values)
                                  (+ no padsize (vector-ref t 3))))
                             (else
                              (lp (+ i 1)
                                  (append pad (cons (vector-ref t 0)
                                                    (append repcode codes)))
                                  (append (make-list rep v) values)
                                  (+ no padsize (* rep (vector-ref t 3))))))))))))))))

(do ((i 0 (+ i 1)))
    ((= i 50))
  (random-test (native-endianness)))

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

(check (zero? (unpack "!C" '#vu8(1 2 3 4 6 0) 5)))
(check (zero? (unpack "!S" '#vu8(1 2 3 4 0 0) 4)))

(check (let ((bv (make-bytevector 4 0)))
         (pack! "!S" bv 2 #xffee)
         (bytevector=? bv '#vu8(0 0 #xff #xee))))

