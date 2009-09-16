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

(library (weinholt crypto math (0 0 20090914))
  (export invmod expt-mod)
  (import (rnrs))

  (define (invmod a b)
    ;; Extended Euclidian algorithm. Used to find the inverse of a
    ;; modulo b.
    (do ((a a (mod b a))
         (b b a)
         (x0 0 x1)
         (x1 1 (+ (* (- (div b a)) x1) x0)))
        ((zero? (mod b a))
         x1)))

  (define (expt-mod base exponent modulus)
    ;; Faster version of (mod (expt base exponent) modulus).
    (let lp ((base (if (negative? exponent)
                       (invmod (mod base modulus) modulus)
                       (mod base modulus)))
             (exponent (abs exponent))
             (result 1))
      (if (zero? exponent)
          result
          (lp (mod (* base base) modulus)
              (bitwise-arithmetic-shift-right exponent 1)
              (if (bitwise-bit-set? exponent 0)
                  (mod (* result base) modulus)
                  result)))))

  )
