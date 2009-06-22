#!/usr/bin/env scheme-script
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

(import (weinholt crypto md5)
        (rnrs))

(define (test/s expect . data)
  (let ((result (md5->string (apply md5 (map string->utf8 data)))))
    (unless (string-ci=? result expect)
      (error 'test "Bad result" result))))

(test/s "5793f7e3037448b250ae716b43ece2c2" (make-string 100000 #\A))
(test/s "48fcdb8b87ce8ef779774199a856091d" (make-string 1000000 #\A))

;; From RFC 1321
(test/s "d41d8cd98f00b204e9800998ecf8427e" "")
(test/s "0cc175b9c0f1b6a831c399e269772661" "a")
(test/s "900150983cd24fb0d6963f7d28e17f72" "abc")
(test/s "f96b697d7cb7938d525a2f31aaf161d0" "message digest")
(test/s "c3fcd3d76192e4007dfb496cca67e13b" "abcdefghijklmnopqrstuvwxyz")
(test/s "d174ab98d277d9f5a5611c2c9f419d9f" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
(test/s "57edf4a22be3c955ac49da2e2107b67a" "12345678901234567890123456789012345678901234567890123456789012345678901234567890")
