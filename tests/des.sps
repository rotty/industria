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

(import (weinholt crypto des)
        (rnrs))

;; TESTING IMPLEMENTATIONS OF DES, Ronald L. Rivest
;; http://people.csail.mit.edu/rivest/Destest.txt
(do ((x (bytevector-copy '#vu8(#x94 #x74 #xB8 #xE8 #xC7 #x3B #xCA #x7D)))
     (i 0 (+ i 1)))
    ((= i 16)
     (unless (equal? x '#vu8(#x1B #x1A #x2D #xDB #x4C #x64 #x24 #x38))
       (error 'test-des "Ron Rivest's test failed")))
  (des! x (if (even? i)
              (permute-key x)           ;encipher
              (reverse (permute-key x))))) ;decipher

(define (test-crypt password salt expect)
  (let ((result (crypt password salt)))
    (unless (string=? result expect)
      (error 'test-crypt "Bad result" result))))

(test-crypt "foodbard" ".."
            "..o6avrdNBOA6")

(test-crypt "test" ".."
            "..9sjyf8zL76k")

(test-crypt "X" ".."
            "..XhpOnw6KMZg")

(test-crypt "foobar" "Ax"
            "AxTdjVtckZ0Rs")

(test-crypt "ZZZZ" "zz"
            "zz/CBDeUpwD26")

(test-crypt "" ".."
            "..X8NBuQ4l6uQ")

(test-crypt "" "ZZ"
            "ZZvIHp4MBMwSE")

(define (test-tdea plaintext k1 k2 k3 expect)
  (let ((bv (bytevector-copy plaintext)))
    (tdea-encipher! bv k1 k2 k3)
    (unless (equal? bv expect)
      (error 'test-tdea "Bad ciphertext" bv expect))
    (tdea-decipher! bv k1 k2 k3)
    (unless (equal? bv plaintext)
      (error 'test-tdea "Bad deciphered plaintext" bv plaintext))))

(test-tdea (string->utf8 "The Msg.")
           (permute-key (string->utf8 "01234567"))
           (permute-key (string->utf8 "abcdefgh"))
           (permute-key (string->utf8 "qwertyui"))
           #vu8(243 85 37 68 185 248 44 83))

;; From NIST Special Publication 800-67 version 1.1,
;; revised 19 may 2008.
(let ((k1 (permute-key #vu8(#x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)))
      (k2 (permute-key #vu8(#x23 #x45 #x67 #x89 #xAB #xCD #xEF #x01)))
      (k3 (permute-key #vu8(#x45 #x67 #x89 #xAB #xCD #xEF #x01 #x23))))

  (test-tdea (string->utf8 "The qufc")  ;sic
             k1 k2 k3
             #vu8(#xA8 #x26 #xFD #x8C #xE5 #x3B #x85 #x5F))
  (test-tdea (string->utf8 "k brown ")
             k1 k2 k3
             #vu8(#xCC #xE2 #x1C #x81 #x12 #x25 #x6F #xE6))
  (test-tdea (string->utf8 "fox jump")
             k1 k2 k3
             #vu8(#x68 #xD5 #xC0 #x5D #xD9 #xB6 #xB9 #x00)))
