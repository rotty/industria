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
        (srfi :78 lightweight-testing)
        (rnrs))

(define (print . x) (for-each display x) (newline))

(define (rivest)
  ;; TESTING IMPLEMENTATIONS OF DES, Ronald L. Rivest
  ;; http://people.csail.mit.edu/rivest/Destest.txt
  (do ((x (bytevector-copy '#vu8(#x94 #x74 #xB8 #xE8 #xC7 #x3B #xCA #x7D)))
       (i 0 (+ i 1)))
      ((= i 16) x)
    (print i ": " x)
    (des! x (if (even? i)
                (permute-key x)            ;encipher
                (reverse (permute-key x)))))) ;decipher

(check (rivest) => '#vu8(#x1B #x1A #x2D #xDB #x4C #x64 #x24 #x38))


(define (test-tdea plaintext k1 k2 k3)
  ;; Returns the ciphertext and the deciphered ciphertext, which
  ;; should match the plaintext.
  (let ((bv (bytevector-copy plaintext))
        (key (tdea-permute-key k1 k2 k3)))
    (tdea-encipher! bv 0 key)
    (let ((enciphered (bytevector-copy bv)))
      (tdea-decipher! bv 0 key)
      (list enciphered bv))))

(check (test-tdea (string->utf8 "The Msg.")
                  (string->utf8 "01234567")
                  (string->utf8 "abcdefgh")
                  (string->utf8 "qwertyui"))
       => (list #vu8(243 85 37 68 185 248 44 83)
                (string->utf8 "The Msg.")))

;; From NIST Special Publication 800-67 version 1.1,
;; revised 19 may 2008.
(let ((k1 #vu8(#x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF))
      (k2 #vu8(#x23 #x45 #x67 #x89 #xAB #xCD #xEF #x01))
      (k3 #vu8(#x45 #x67 #x89 #xAB #xCD #xEF #x01 #x23)))

  (check (test-tdea (string->utf8 "The qufc") ;sic
                    k1 k2 k3)
         => (list #vu8(#xA8 #x26 #xFD #x8C #xE5 #x3B #x85 #x5F)
                  (string->utf8 "The qufc")))

  (check (test-tdea (string->utf8 "k brown ")
                    k1 k2 k3)
         => (list #vu8(#xCC #xE2 #x1C #x81 #x12 #x25 #x6F #xE6)
                  (string->utf8 "k brown ")))
  
  (check (test-tdea (string->utf8 "fox jump")
                    k1 k2 k3)
         => (list #vu8(#x68 #xD5 #xC0 #x5D #xD9 #xB6 #xB9 #x00)
                  (string->utf8 "fox jump"))))

(check-report)
