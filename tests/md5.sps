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
        (weinholt crypto md5)
        (srfi :78 lightweight-testing))

(define (m str) (string-downcase (md5->string (md5 (string->utf8 str)))))

(check (m (make-string 100000 #\A)) => "5793f7e3037448b250ae716b43ece2c2")
(check (m (make-string 1000000 #\A)) => "48fcdb8b87ce8ef779774199a856091d")

;;; From RFC 1321
(check (m "")
       => "d41d8cd98f00b204e9800998ecf8427e")
(check (m "a")
       => "0cc175b9c0f1b6a831c399e269772661")
(check (m "abc")
       => "900150983cd24fb0d6963f7d28e17f72")
(check (m "message digest")
       => "f96b697d7cb7938d525a2f31aaf161d0")
(check (m "abcdefghijklmnopqrstuvwxyz")
       => "c3fcd3d76192e4007dfb496cca67e13b")
(check (m "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
       => "d174ab98d277d9f5a5611c2c9f419d9f")
(check (m "12345678901234567890123456789012345678901234567890123456789012345678901234567890")
       => "57edf4a22be3c955ac49da2e2107b67a")

;;; From RFC 2104/2202
(define (h key data) (string-downcase (md5->string (hmac-md5 key data))))

(check (h (make-bytevector 16 #x0b)
          (string->utf8 "Hi There"))
       => "9294727a3638bb1c13f48ef8158bfc9d")

(check (h (string->utf8 "Jefe")
          (string->utf8 "what do ya want for nothing?"))
       => "750c783e6ab0b503eaa86e310a5db738")

(check (h (make-bytevector 16 #xAA)
          (make-bytevector 50 #xDD))
       => "56be34521d144c88dbb8c733f0e8b3f6")

(check (h #vu8(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08 #x09 #x0a #x0b #x0c
                    #x0d #x0e #x0f #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18 #x19)
          (make-bytevector 50 #xcd))
       => "697eaf0aca3a3aea3a75164746ffaa79")

(check (h (make-bytevector 16 #x0c)
          (string->utf8 "Test With Truncation"))
       => "56461ef2342edc00f9bab995690efd4c") ; not testing truncation...
;; digest-96 = 0x56461ef2342edc00f9bab995

(check (h (make-bytevector 80 #xaa)
          (string->utf8 "Test Using Larger Than Block-Size Key - Hash Key First"))
       => "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")

(check (h (make-bytevector 80 #xaa)
          (string->utf8 "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"))
       => "6f630fad67cda0ee1fb1f562db3aa53e")

(check-report)
