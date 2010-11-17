#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2010 Göran Weinholt <goran@weinholt.se>
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

(import (weinholt crypto dh)
        (srfi :78 lightweight-testing)
        (rnrs))

(define-syntax check-dh
  (lambda (x)
    (syntax-case x ()
      ((_ g p)
       #'(let-values (((y Y) (make-dh-secret g p (bitwise-length p)))
                      ((x X) (make-dh-secret g p (bitwise-length p))))
           (check (expt-mod X y p) => (expt-mod Y x p)))))))

(check-dh modp-group1-g modp-group1-p)
(check-dh modp-group2-g modp-group2-p)
(check-dh modp-group5-g modp-group5-p)
(check-dh modp-group14-g modp-group14-p)
;; These take too long to test on slower systems, and will probably
;; pass anyway:
;; (check-dh modp-group15-g modp-group15-p)
;; (check-dh modp-group16-g modp-group16-p)
;; (check-dh modp-group17-g modp-group17-p)
;; (check-dh modp-group18-g modp-group18-p)

(check-report)
