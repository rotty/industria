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

(import (srfi :78 lightweight-testing)
        (rnrs)
        (prefix (weinholt struct der) der:))

(define (SubjectAltName)
  `(sequence-of 1 +inf.0 ,(GeneralName)))

(define (GeneralName)
  `(choice #;(otherName (implicit context 0 ,(OtherName)))
           (rfc822Name (implicit context 1 ia5-string))
           (dNSName (implicit context 2 ia5-string))
           #;etc...))

(check
 (der:translate (der:decode #vu8(48 30 130 15 119 119 119 46 119 101 105 110 104 111 108 116
                                    46 115 101 130 11 119 101 105 110 104 111 108 116 46 115 101))
                (SubjectAltName))
 => '("www.weinholt.se" "weinholt.se"))

;; TODO: needs more tests, to say the least.

(check-report)
