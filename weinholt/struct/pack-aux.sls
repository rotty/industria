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

;; Auxiliary library for (weinholt struct). Please don't use this
;; library directly.

(library (weinholt struct pack-aux (1 0 20091003))
  (export format-size roundb add)
  (import (for (rnrs) (meta -1)))

  (define (add augend addend)
    (if (integer? augend)
        (+ augend addend)
        (with-syntax ((x augend) (y addend))
          #'(+ x y))))

  (define (roundb offset alignment)
    (cond ((integer? offset)
           (bitwise-and (+ offset (- alignment 1))
                        (- alignment)))
          ((and (integer? alignment) (= alignment 1))
           offset)
          (else
           (with-syntax ((x offset))
             #`(bitwise-and (+ x #,(- alignment 1))
                            #,(- alignment))))))
  
  ;; Find the number of bytes the format requires.
  ;; (format-size "2SQ") => 16
  (define (format-size fmt)
    (define (size c)
      (case c
        ((#\x #\c #\C) 1)
        ((#\s #\S) 2)
        ((#\l #\L #\f) 4)
        ((#\q #\Q #\d) 8)
        (else
         (error 'format-size "Bad character in format string" fmt c))))
    (let lp ((i 0) (s 0) (rep #f) (align #t))
      (cond ((= i (string-length fmt))
             s)
            ((char<=? #\0 (string-ref fmt i) #\9)
             (lp (+ i 1) s
                 (+ (- (char->integer (string-ref fmt i))
                       (char->integer #\0))
                    (* (if rep rep 0) 10))
                 align))
            ((char-whitespace? (string-ref fmt i))
             (lp (+ i 1) s rep align))
            ((char=? (string-ref fmt i) #\a)
             (lp (+ i 1) s rep #t))
            ((char=? (string-ref fmt i) #\u)
             (lp (+ i 1) s rep #f))
            ((memv (string-ref fmt i) '(#\@ #\= #\< #\> #\!))
             (lp (+ i 1) s #f align))
            (else
             (let ((n (size (string-ref fmt i))))
               (lp (+ i 1) (+ (if align (roundb s n) s)
                              (if rep (* n rep) n))
                   #f align)))))))
