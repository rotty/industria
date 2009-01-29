#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Industria Actual - an operating system
;; Copyright © 2009 Göran Weinholt <goran@weinholt.se>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.
;;
;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
#!r6rs

(import (rnrs) (se weinholt disassembler m68hc12))


(define (test bv . expect)
  (let ((p (open-bytevector-input-port bv)))
    (let lp ((instrs '()))
      (let ((instr (get-instruction p (lambda x
                                        ;; (display (list 'collect x))
                                        x))))
        (cond ((eof-object? instr)
               (unless (equal? (reverse instrs) expect)
                 (error 'test "Bad disassembly" bv expect (reverse instrs)))
               ;; (newline) (for-each display instrs) (newline)
               ;; (display "OK\n")
               )
              (else
               (lp (cons instr instrs))))))))


;; Memory-memory move
(test '#vu8(#x18 #x00 #x90 #x11 #x22)      '(movw #x1122        (mem+ sp -16)))
(test '#vu8(#x18 #x01 #x90 #x11 #x22)      '(movw (mem+ #x1122) (mem+ sp -16)))
(test '#vu8(#x18 #x02 #x90 #x9f)           '(movw (mem+ sp -16) (mem+ sp -1)))
(test '#vu8(#x18 #x03 #x11 #x22 #x33 #x44) '(movw #x1122        (mem+ #x3344)))
(test '#vu8(#x18 #x04 #x11 #x22 #x33 #x44) '(movw (mem+ #x1122) (mem+ #x3344)))
(test '#vu8(#x18 #x05 #x90 #x11 #x22)      '(movw (mem+ sp -16) (mem+ #x1122)))

(test '#vu8(#x18 #x08 #x90 #x42)           '(movb #x42          (mem+ sp -16)))
(test '#vu8(#x18 #x09 #x90 #x11 #x22)      '(movb (mem+ #x1122) (mem+ sp -16)))
(test '#vu8(#x18 #x0a #x90 #x9f)           '(movb (mem+ sp -16) (mem+ sp -1)))
(test '#vu8(#x18 #x0b #x42 #x11 #x22)      '(movb #x42          (mem+ #x1122)))
(test '#vu8(#x18 #x0c #x11 #x22 #x33 #x44) '(movb (mem+ #x1122) (mem+ #x3344)))
(test '#vu8(#x18 #x0d #x90 #x11 #x22)      '(movb (mem+ sp -16) (mem+ #x1122)))

;; Various
(test '#vu8(#x81 #x07) '(cmpa 7))


(test '#vu8(#x22 #xfe) '(bhi (+ pc -2)))
(test '#vu8(#x15 #x00) '(jsr (mem+ x 0)))

(test '#vu8(#x4A #x10 #x24 #x24) '(call #x1024 #x24))


;; A few adressing modes
(test '#vu8(#xA6 #x8f) '(ldaa (mem+ sp 15)))
(test '#vu8(#xA6 #x77) '(ldaa (mem+ (post+ y 8))))
(test '#vu8(#xA6 #x78) '(ldaa (mem+ (post- y 8))))

;; Indirect... some of these should probably be something different.
(test '#vu8(#xA6 #xE3 #x2F #xFF) '(ldaa (mem+ #x2FFF x)))
(test '#vu8(#xA6 #xEB #x2F #xFF) '(ldaa (mem+ #x2FFF y)))
(test '#vu8(#xA6 #xF3 #x2F #xFF) '(ldaa (mem+ #x2FFF sp)))
(test '#vu8(#xA6 #xFB #x2F #xFF) '(ldaa (mem+ #x2FFF pc)))
(test '#vu8(#xA6 #xE7) '(ldaa (mem+ d x)))
(test '#vu8(#xA6 #xEF) '(ldaa (mem+ d y)))
(test '#vu8(#xA6 #xF7) '(ldaa (mem+ d sp)))
(test '#vu8(#xA6 #xFF) '(ldaa (mem+ d pc)))
(test '#vu8(#xA6 #xE4) '(ldaa (mem+ a x)))
(test '#vu8(#xA6 #xEC) '(ldaa (mem+ a y)))
(test '#vu8(#xA6 #xF4) '(ldaa (mem+ a sp)))
(test '#vu8(#xA6 #xFD) '(ldaa (mem+ b pc)))
(test '#vu8(#xA6 #xFE) '(ldaa (mem+ d pc)))
