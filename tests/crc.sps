#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009, 2010 Göran Weinholt <goran@weinholt.se>
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

(import (weinholt crypto crc)
        (weinholt compression adler-32)
        (srfi :78 lightweight-testing)
        (rnrs))

;; Simple tests on the pre-defined CRCs:

(define-crc crc-32)
(check (crc-32-self-test) => 'success)

(define-crc crc-16)
(check (crc-16-self-test) => 'success)

(define-crc crc-16/ccitt)
(check (crc-16/ccitt-self-test) => 'success)

(define-crc crc-32c)
(check (crc-32c-self-test) => 'success)

(define-crc crc-24)
(check (crc-24-self-test) => 'success)

(define-crc crc-64)
(check (crc-64-self-test) => 'success)

;; Tests the other procedures

(check (crc-32c-finish
        (crc-32c-update (crc-32c-update (crc-32c-init)
                                        (string->utf8 "12345"))
                        (string->utf8 "6789")))
       => #xE3069283)

(check (crc-32c-finish
        (crc-32c-update (crc-32c-update (crc-32c-init)
                                        (string->utf8 "XX12345") 2)
                        (string->utf8 "XX6789XX")  2 6))
       => #xE3069283)

(check (crc-32c (string->utf8 "123456789"))
       => #xE3069283)

;; Test the syntax for defining new CRCs

(define-crc crc-test (24 23 18 17 14 11 10 7 6 5 4 3 1 0)
            #xB704CE #f #f 0 #x21CF02)  ;CRC-24

(check (crc-test-self-test) => 'success)

;; And last a test for Adler-32
(check (adler-32-self-test) => 'success)

(check-report)
