#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
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

(import (rnrs)
        (srfi :78 lightweight-testing)
        (weinholt disassembler m68hc12))

(define (d bv)
  (let ((p (open-bytevector-input-port bv)))
    (let ((instr (get-instruction p (lambda x #f))))
      (unless (port-eof? p)
        (error 'd "Bytes remain to be disassembled" (get-bytevector-all p)))
      instr)))

;; Memory-memory move
(check (d #vu8(#x18 #x00 #x90 #x11 #x22)) =>      '(movw #x1122   (-16 sp)))
(check (d #vu8(#x18 #x01 #x90 #x11 #x22)) =>      '(movw (#x1122) (-16 sp)))
(check (d #vu8(#x18 #x02 #x90 #x9f)) =>           '(movw (-16 sp) (-1 sp)))
(check (d #vu8(#x18 #x03 #x11 #x22 #x33 #x44)) => '(movw #x1122   (#x3344)))
(check (d #vu8(#x18 #x04 #x11 #x22 #x33 #x44)) => '(movw (#x1122) (#x3344)))
(check (d #vu8(#x18 #x05 #x90 #x11 #x22)) =>      '(movw (-16 sp) (#x1122)))

(check (d #vu8(#x18 #x08 #x90 #x42)) =>           '(movb #x42     (-16 sp)))
(check (d #vu8(#x18 #x09 #x90 #x11 #x22)) =>      '(movb (#x1122) (-16 sp)))
(check (d #vu8(#x18 #x0a #x90 #x9f)) =>           '(movb (-16 sp) (-1 sp)))
(check (d #vu8(#x18 #x0b #x42 #x11 #x22)) =>      '(movb #x42     (#x1122)))
(check (d #vu8(#x18 #x0c #x11 #x22 #x33 #x44)) => '(movb (#x1122) (#x3344)))
(check (d #vu8(#x18 #x0d #x90 #x11 #x22)) =>      '(movb (-16 sp) (#x1122)))

;; Various
(check (d #vu8(#x81 #x07)) => '(cmpa 7))

(check (d #vu8(#x22 #xfe)) => '(bhi (-2 pc)))
(check (d #vu8(#x15 #x00)) => '(jsr (x)))

(check (d #vu8(#x4A #x10 #x24 #x24)) => '(call #x1024 #x24))

;; A few adressing modes
(check (d #vu8(#xA6 #x8f)) => '(ldaa (15 sp)))
(check (d #vu8(#xA6 #x77)) => '(ldaa (post+ 8 y)))
(check (d #vu8(#xA6 #x78)) => '(ldaa (post- 8 y)))

;; Indirect addressing. For example: a 16-bit pointer is read from the
;; location #x2FFF+x.
(check (d #vu8(#xA6 #xE3 #x2F #xFF)) => '(ldaa ((#x2FFF x))))
(check (d #vu8(#xA6 #xEB #x2F #xFF)) => '(ldaa ((#x2FFF y))))
(check (d #vu8(#xA6 #xF3 #x2F #xFF)) => '(ldaa ((#x2FFF sp))))
(check (d #vu8(#xA6 #xFB #x2F #xFF)) => '(ldaa ((#x2FFF pc))))
(check (d #vu8(#xA6 #xE7)) => '(ldaa ((d x))))
(check (d #vu8(#xA6 #xEF)) => '(ldaa ((d y))))
(check (d #vu8(#xA6 #xF7)) => '(ldaa ((d sp))))
(check (d #vu8(#xA6 #xFF)) => '(ldaa ((d pc))))
(check (d #vu8(#xA6 #xE4)) => '(ldaa (a x)))
(check (d #vu8(#xA6 #xEC)) => '(ldaa (a y)))
(check (d #vu8(#xA6 #xF4)) => '(ldaa (a sp)))
(check (d #vu8(#xA6 #xFD)) => '(ldaa (b pc)))
(check (d #vu8(#xA6 #xFE)) => '(ldaa (d pc)))

;; Transfer/exchange
(check (d #vu8(#xB7 #x00)) => '(tfr a a))
(check (d #vu8(#xB7 #x01)) => '(tfr a b))
(check (d #vu8(#xB7 #x02)) => '(tfr a ccr))
(check (d #vu8(#xB7 #x03)) => '(sex a tmp2))
(check (d #vu8(#xB7 #x05)) => '(sex a x))
(check (d #vu8(#xB7 #x30)) => '(tfr tmp3 a))
(check (d #vu8(#xB7 #x27)) => '(sex ccr sp))
(check (d #vu8(#xB7 #xF7)) => '(exg sp sp))
(check (d #vu8(#xB7 #x77)) => '(tfr sp sp))
(check (d #vu8(#xB7 #xC1)) => '(exg d b))
(check (d #vu8(#xB7 #xA2)) => '(exg ccr ccr))
(check (d #vu8(#xB7 #xB3)) => '(exg tmp3 tmp2))

(check-report)
