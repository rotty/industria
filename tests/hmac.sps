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
        (only (srfi :13 strings) string-filter)
        (only (srfi :14 char-sets) char-set:hex-digit)
        (srfi :78 lightweight-testing)
        (weinholt crypto sha-2))

(define (filter-digest str)
  (string-filter char-set:hex-digit str))

(define (digest->bv str)
  (let* ((str (filter-digest str))
         (int (string->number str 16))
         (ret (make-bytevector (/ (string-length str) 2) 0)))
    (bytevector-uint-set! ret 0 int (endianness big) (bytevector-length ret))
    ret))

(define (corrupt-bv bv)
  ;; Corrupt the last byte of bv. This way it can be tested that the
  ;; hash=? predicates check all of the bytevector.
  (let ((len (bytevector-length bv))
        (ret (bytevector-copy bv)))
    (bytevector-u8-set! ret (- len 1)
                        (fxxor 1 (bytevector-u8-ref ret (- len 1))))
    ret))

(define-syntax test/128
  (lambda (x)
    (syntax-case x ()
      ((_ key data hmac hash=? digest)
       #'(begin
           (check (hash=? (hmac key data) (digest->bv digest)) => #t)
           (check (hash=? (hmac key data)
                          (corrupt-bv (digest->bv digest))) => #f))))))

(define-syntax hmac-test/128
  (lambda (x)
    (syntax-case x ()
      ((_ key data digest ...)
       (with-syntax (((hmac ...) #'(hmac-sha-224
                                    hmac-sha-256
                                    hmac-sha-384
                                    hmac-sha-512))
                     ((hash=? ...) #'(sha-224-128-hash=?
                                      sha-256-128-hash=?
                                      sha-384-128-hash=?
                                      sha-512-128-hash=?)))
         #'(begin (test/128 key data hmac hash=? digest)
                  ...))))))

(define-syntax test
  (lambda (x)
    (syntax-case x ()
      ((_ key data hmac hash=? ->string digest)
       #'(begin
           (check (->string (hmac key data)) (=> string-ci=?)
                  (filter-digest digest))
           (check (hash=? (hmac key data) (digest->bv digest)) => #t)
           (check (hash=? (hmac key data)
                          (corrupt-bv (digest->bv digest))) => #f))))))

(define-syntax hmac-test
  (lambda (x)
    (syntax-case x ()
      ((_ key data digest ...)
       (with-syntax (((hmac ...) #'(hmac-sha-224
                                    hmac-sha-256
                                    hmac-sha-384
                                    hmac-sha-512))
                     ((hash=? ...) #'(sha-224-hash=?
                                      sha-256-hash=?
                                      sha-384-hash=?
                                      sha-512-hash=?))
                     ((->string ...) #'(sha-224->string
                                        sha-256->string
                                        sha-384->string
                                        sha-512->string)))
         #'(begin (test key data hmac hash=? ->string digest)
                  ...))))))

;;; HMAC tests from RFC 4231

(hmac-test
 (make-bytevector 20 #x0b)
 (string->utf8 "Hi There")
 "896fb1128abbdf196832107cd49df33f
  47b4b1169912ba4f53684b22"
 "b0344c61d8db38535ca8afceaf0bf12b
  881dc200c9833da726e9376c2e32cff7"
 "afd03944d84895626b0825f4ab46907f
  15f9dadbe4101ec682aa034c7cebc59c
  faea9ea9076ede7f4af152e8b2fa9cb6"
 "87aa7cdea5ef619d4ff0b4241a1d6cb0
  2379f4e2ce4ec2787ad0b30545e17cde
  daa833b7d6b8a702038b274eaea3f4e4
  be9d914eeb61f1702e696c203a126854")

(hmac-test
 (string->utf8 "Jefe")
 (string->utf8 "what do ya want for nothing?")
 "a30e01098bc6dbbf45690f3a7e9e6d0f
  8bbea2a39e6148008fd05e44"
 "5bdcc146bf60754e6a042426089575c7
  5a003f089d2739839dec58b964ec3843"
 "af45d2e376484031617f78d2b58a6b1b
  9c7ef464f5a01b47e42ec3736322445e
  8e2240ca5e69e2c78b3239ecfab21649"
 "164b7a7bfcf819e2e395fbe73b56e0a3
  87bd64222e831fd610270cd7ea250554
  9758bf75c05a994a6d034f65f8f0e6fd
  caeab1a34d4a6b4b636e070a38bce737")

(hmac-test
 (make-bytevector 20 #xaa)
 (make-bytevector 50 #xdd)
 "7fb3cb3588c6c1f6ffa9694d7d6ad264
  9365b0c1f65d69d1ec8333ea"
 "773ea91e36800e46854db8ebd09181a7
  2959098b3ef8c122d9635514ced565fe"
 "88062608d3e6ad8a0aa2ace014c8a86f
  0aa635d947ac9febe83ef4e55966144b
  2a5ab39dc13814b94e3ab6e101a34f27"
 "fa73b0089d56a284efb0f0756c890be9
  b1b5dbdd8ee81a3655f83e33b2279d39
  bf3e848279a722c806b485a47e67c807
  b946a337bee8942674278859e13292fb")

(hmac-test
 (digest->bv "0102030405060708090a0b0c0d0e0f10111213141516171819")
 (make-bytevector 50 #xcd)
 "6c11506874013cac6a2abc1bb382627c
  ec6a90d86efc012de7afec5a"
 "82558a389a443c0ea4cc819899f2083a
  85f0faa3e578f8077a2e3ff46729665b"
 "3e8a69b7783c25851933ab6290af6ca7
  7a9981480850009cc5577c6e1f573b4e
  6801dd23c4a7d679ccf8a386c674cffb"
 "b0ba465637458c6990e5a8c5f61d4af7
  e576d97ff94b872de76f8050361ee3db
  a91ca5c11aa25eb4d679275cc5788063
  a5f19741120c4f2de2adebeb10a298dd")

(hmac-test/128
 (make-bytevector 20 #x0c)
 (string->utf8 "Test With Truncation")
 "0e2aea68a90c8d37c988bcdb9fca6fa8"
 "a3b6167473100ee06e0c796c2955552b"
 "3abf34c3503b2a23a46efc619baef897"
 "415fad6271580a531d4179bc891d87a6")

(hmac-test
 (make-bytevector 131 #xaa)
 (string->utf8 "Test Using Larger Than Block-Size Key - Hash Key First")
 "95e9a0db962095adaebe9b2d6f0dbce2
  d499f112f2d2b7273fa6870e"
 "60e431591ee0b67f0d8a26aacbf5b77f
  8e0bc6213728c5140546040f0ee37f54"
 "4ece084485813e9088d2c63a041bc5b4
  4f9ef1012a2b588f3cd11f05033ac4c6
  0c2ef6ab4030fe8296248df163f44952"
 "80b24263c7c1a3ebb71493c1dd7be8b4
  9b46d1f41b4aeec1121b013783f8f352
  6b56d037e05f2598bd0fd2215d6a1e52
  95e64f73f63f0aec8b915a985d786598")

(hmac-test
 (make-bytevector 131 #xaa)
 (string->utf8 "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")
 "3a854166ac5d9f023f54d517d0b39dbd
  946770db9c2b95c9f6f565d1"
 "9b09ffa71b942fcb27635fbcd5b0e944
  bfdc63644f0713938a7f51535c3a35e2"
 "6617178e941f020d351e2f254e8fd32c
  602420feb0b8fb9adccebb82461e99c5
  a678cc31e799176d3860e6110c46523e"
 "e37b6a775dc87dbaa4dfa9f96e5e3ffd
  debd71f8867289865df5a32d20cdc944
  b6022cac3c4982b10d5eeb55c3e4de15
  134676fb6de0446065c97440fa8c6a58")

(check-report)
