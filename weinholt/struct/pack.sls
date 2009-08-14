;; -*- mode: scheme; coding: utf-8 -*-
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

;; Syntax for packing and unpacking C structs using bytevectors

;; This syntax is similar to Python's struct module or Perl's
;; pack/unpack functions.

;; The syntax of the format string is as follows:

;; x: padding; c: s8; C: u8; s: s16; S: u16; l: s32; L: u32; q: s64;
;; Q: u64; f: ieee-single; d: ieee-double; ! or >: big-endian (network
;; byte order); <: little-endian; =: native-endian. u: disable natural
;; alignment. a: enable natural alignment. Whitespace is ignored.
;; Format characters can be prefixed with a decimal number, which
;; repeats the format character. Padding is done with zeros.

;; Fields are by default aligned to their natural alignment!

;; (pack "!xd" 3.14)
;; => #vu8(0 0 0 0 0 0 0 0 64 9 30 184 81 235 133 31)

;; (unpack "!xd" (pack "!xd" 3.14))
;; => 3.14

;; TODO: pack syntax

;;; Version history

;; (1 0 0) - Initial version.

;; (1 1 0) - `unpack' can now be used as a function.

;; (1 2 0) - added the format characters a and u

;; (1 3 0) - added get-unpack. Removed the unnecessary size check.

;;; Versioning scheme

;; The version is made of (major minor patch) sub-versions.

;; `patch' is incremented when backwards-compatible changes are made. TODO: this sub-version is probably not needed

;; `minor' is incremented when new functionality is introduced.

;; `major' is incremented when backwards compatibility is broken.

(library (weinholt struct pack (1 3 0))
  (export format-size pack pack! unpack get-unpack)
  (import (rnrs)
          (weinholt struct pack-aux (1 0 0)))

  (define-syntax unpack*
    (lambda (x)
      (syntax-case x ()
        ((_ fmt bytevector)
         #'(unpack* fmt bytevector 0))
        ((_ fmt bytevector offset)
         (letrec ((type (lambda (c)
                          (case c
                            ((#\c) (values 's8 #'bytevector-s8-ref 1)) ;special cases
                            ((#\C) (values 'u8 #'bytevector-u8-ref 1))
                            ((#\s) (values #'bytevector-s16-ref
                                           #'bytevector-s16-native-ref 2))
                            ((#\S) (values #'bytevector-u16-ref
                                           #'bytevector-u16-native-ref 2))
                            ((#\l) (values #'bytevector-s32-ref
                                           #'bytevector-s32-native-ref 4))
                            ((#\L) (values #'bytevector-u32-ref
                                           #'bytevector-u32-native-ref 4))
                            ((#\q) (values #'bytevector-s64-ref
                                           #'bytevector-s64-native-ref 8))
                            ((#\Q) (values #'bytevector-u64-ref
                                           #'bytevector-u64-native-ref 8))
                            ((#\f) (values #'bytevector-ieee-single-ref
                                           #'bytevector-ieee-single-native-ref 4))
                            ((#\d) (values #'bytevector-ieee-double-ref
                                           #'bytevector-ieee-double-native-ref 8))
                            (else (syntax-violation
                                   'unpack "Bad character in format string" x c))))))
           (with-syntax (((refs ...)
                          (let ((fmt (syntax->datum #'fmt)))
                            (let lp ((i 0)
                                     (o (syntax->datum #'offset))
                                     (rep #f)
                                     (endian #f)
                                     (align #t)
                                     (refs '()))
                              (cond ((= i (string-length fmt))
                                     (reverse refs))
                                    ((char-whitespace? (string-ref fmt i))
                                     (lp (+ i 1) o rep endian align refs))
                                    (else
                                     (case (string-ref fmt i)
                                       ((#\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9)
                                        (lp (+ i 1) o
                                            (+ (- (char->integer (string-ref fmt i))
                                                  (char->integer #\0))
                                               (* (if rep rep 0) 10))
                                            endian align refs))
                                       ((#\=)
                                        (lp (+ i 1) o #f #f align refs))
                                       ((#\<)
                                        (lp (+ i 1) o #f #'(endianness little) align refs))
                                       ((#\> #\!)
                                        (lp (+ i 1) o #f #'(endianness big) align refs))
                                       ((#\x)
                                        (lp (+ i 1) (+ o (or rep 1)) #f endian align refs))
                                       ((#\a)
                                        (lp (+ i 1) o #f endian #t refs))
                                       ((#\u)
                                        (lp (+ i 1) o #f endian #f refs))
                                       (else
                                        (let-values (((ref nref n) (type (string-ref fmt i))))
                                          (let ((o (if align (roundb o n) o))
                                                (rep (or rep 1)))
                                            (lp (+ i 1) (+ o (* n rep)) #f
                                                endian align
                                                (let lp* ((o o) (rep rep) (refs refs))
                                                  (if (zero? rep) refs
                                                      (lp* (+ o n) (- rep 1)
                                                           (cons (cond ((eq? ref 's8)
                                                                        #`(bytevector-s8-ref bv #,o))
                                                                       ((eq? ref 'u8)
                                                                        #`(bytevector-u8-ref bv #,o))
                                                                       (endian
                                                                        #`(#,ref bv #,o #,endian))
                                                                       ((not align)
                                                                        #`(#,ref bv #,o (native-endianness)))
                                                                       (else
                                                                        #`(#,nref bv #,o)))
                                                                 refs)))))))))))))))
             #`(let ((bv bytevector))
                 (values refs ...))))))))

  (define unpack**
    (case-lambda
      ((fmt bv offset)
       (letrec ((type (lambda (c)
                        (case c
                          ((#\c) (values 's8 bytevector-s8-ref 1)) ;special cases
                          ((#\C) (values 'u8 bytevector-u8-ref 1))
                          ((#\s) (values bytevector-s16-ref
                                         bytevector-s16-native-ref 2))
                          ((#\S) (values bytevector-u16-ref
                                         bytevector-u16-native-ref 2))
                          ((#\l) (values bytevector-s32-ref
                                         bytevector-s32-native-ref 4))
                          ((#\L) (values bytevector-u32-ref
                                         bytevector-u32-native-ref 4))
                          ((#\q) (values bytevector-s64-ref
                                         bytevector-s64-native-ref 8))
                          ((#\Q) (values bytevector-u64-ref
                                         bytevector-u64-native-ref 8))
                          ((#\f) (values bytevector-ieee-single-ref
                                         bytevector-ieee-single-native-ref 4))
                          ((#\d) (values bytevector-ieee-double-ref
                                         bytevector-ieee-double-native-ref 8))
                          (else (error 'unpack "Bad character in format string" fmt c))))))
         (let lp ((i 0)
                  (o offset)
                  (rep #f)
                  (endian #f)
                  (align #t)
                  (refs '()))
           (cond ((= i (string-length fmt))
                  (apply values (reverse refs)))
                 ((char-whitespace? (string-ref fmt i))
                  (lp (+ i 1) o rep endian align refs))
                 (else
                  (case (string-ref fmt i)
                    ((#\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9)
                     (lp (+ i 1) o
                         (+ (- (char->integer (string-ref fmt i))
                               (char->integer #\0))
                            (* (if rep rep 0) 10))
                         endian align refs))
                    ((#\=)
                     (lp (+ i 1) o #f #f align refs))
                    ((#\<)
                     (lp (+ i 1) o #f (endianness little) align refs))
                    ((#\> #\!)
                     (lp (+ i 1) o #f (endianness big) align refs))
                    ((#\x)
                     (lp (+ i 1) (+ o (or rep 1)) #f endian align refs))
                    ((#\a)
                     (lp (+ i 1) o #f endian #t refs))
                    ((#\u)
                     (lp (+ i 1) o #f endian #f refs))
                    (else
                     (let-values (((ref nref n) (type (string-ref fmt i))))
                       (let ((o (if align (roundb o n) o))
                             (rep (or rep 1)))
                         (lp (+ i 1) (+ o (* n rep)) #f
                             endian align
                             (let lp* ((o o) (rep rep) (refs refs))
                               (if (zero? rep) refs
                                   (lp* (+ o n) (- rep 1)
                                        (cons (cond ((eq? ref 's8)
                                                     (bytevector-s8-ref bv o))
                                                    ((eq? ref 'u8)
                                                     (bytevector-u8-ref bv o))
                                                    (endian
                                                     (ref bv o endian))
                                                    ((not align)
                                                     (ref bv o (native-endianness)))
                                                    (else
                                                     (nref bv o)))
                                              refs))))))))))))))
      ((fmt bv)
       (unpack** fmt bv 0))))

  ;; Use the unpack* expander if possible, otherwise use the unpack**
  ;; function.
  (define-syntax unpack
    (make-variable-transformer
     (lambda (x)
       (syntax-case x ()
         ((_ fmt bytevector) #'(unpack fmt bytevector 0))
         ((_ fmt bytevector offset)
          ;; FIXME: handle non-constant offsets!
          (and (string? (syntax->datum #'fmt)) (integer? (syntax->datum #'o)))
          #'(unpack* fmt bytevector offset))
         ((_ . rest) #'(unpack** . rest))
         (_ #'unpack**)))))

  (define (get-unpack port fmt)
    (unpack fmt (get-bytevector-n port (format-size fmt))))

  (define (pack fmt . values)
    (let ((bv (make-bytevector (format-size fmt))))
      (apply pack! fmt bv 0 values)
      bv))

  (define (pack! fmt bv offset . vals)
    (define (type c)
      (case c
        ((#\c) (values 's8 1)) ;special cases
        ((#\C) (values 'u8 1))
        ((#\s) (values bytevector-s16-set! 2))
        ((#\S) (values bytevector-u16-set! 2))
        ((#\l) (values bytevector-s32-set! 4))
        ((#\L) (values bytevector-u32-set! 4))
        ((#\q) (values bytevector-s64-set! 8))
        ((#\Q) (values bytevector-u64-set! 8))
        ((#\f) (values bytevector-ieee-single-set! 4))
        ((#\d) (values bytevector-ieee-double-set! 8))
        (else (error 'pack! "Bad character in format string" fmt c))))
    (define (zero! i n)
      (do ((i i (+ i 1))
           (m (+ i n)))
          ((= i m))
        (bytevector-u8-set! bv i 0)))
    (let lp ((i 0)
             (o offset)
             (rep #f)
             (endian (native-endianness))
             (align #t)
             (vals vals))
      (cond ((= i (string-length fmt))
             (unless (null? vals)
               (error 'pack! "Too many values for the format" fmt))
             (unless (= o (bytevector-length bv))
               (error 'pack! "The bytevector is smaller than the format"
                      fmt (bytevector-length bv))))
            ((char-whitespace? (string-ref fmt i))
             (lp (+ i 1) o rep endian align vals))
            (else
             (case (string-ref fmt i)
               ((#\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9)
                (lp (+ i 1) o
                    (+ (- (char->integer (string-ref fmt i))
                          (char->integer #\0))
                       (* (if rep rep 0) 10))
                    endian align vals))
               ((#\=) (lp (+ i 1) o #f (native-endianness) align vals))
               ((#\<) (lp (+ i 1) o #f (endianness little) align vals))
               ((#\> #\!) (lp (+ i 1) o #f (endianness big) align vals))
               ((#\x)
                (zero! o (or rep 1))
                (lp (+ i 1) (+ o (or rep 1)) #f endian align vals))
               ((#\a)
                (lp (+ i 1) o #f endian #t vals))
               ((#\u)
                (lp (+ i 1) o #f endian #f vals))
               (else
                (let*-values (((set n) (type (string-ref fmt i)))
                              ((o*) (if align (roundb o n) o)))
                  (zero! o (- o* o))
                  (do ((rep (or rep 1) (- rep 1))
                       (o o* (+ o n))
                       (vals vals (cdr vals)))
                      ((zero? rep)
                       (lp (+ i 1) (+ o (* n rep)) #f endian align vals))
                    (when (null? vals)
                      (error 'pack! "Too few values for the format" fmt))
                    (cond ((eq? set 's8)
                           (bytevector-s8-set! bv o (car vals)))
                          ((eq? set 'u8)
                           (bytevector-u8-set! bv o (car vals)))
                          (else
                           (set bv o (car vals) endian))))))))))))
