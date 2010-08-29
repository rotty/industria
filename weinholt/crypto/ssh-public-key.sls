;; -*- mode: scheme; coding: utf-8 -*-
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

;; Procedures that read and write SSH 2 public keys

;; 4253 The Secure Shell (SSH) Transport Layer Protocol. T. Ylonen, C.
;;      Lonvick, Ed.. January 2006. (Format: TXT=68263 bytes) (Status:
;;      PROPOSED STANDARD)

;; 4716 The Secure Shell (SSH) Public Key File Format. J. Galbraith, R.
;;      Thayer. November 2006. (Format: TXT=18395 bytes) (Status:
;;      INFORMATIONAL)

(library (weinholt crypto ssh-public-key (1 0 20100829))
  (export get-ssh-public-key
          ssh-public-key->bytevector
          ssh-public-key-fingerprint
          ssh-public-key-random-art)
  (import (only (srfi :13 strings) string-pad
                string-join)
          (except (rnrs) put-string)
          (weinholt bytevectors)
          (weinholt crypto dsa)
          (weinholt crypto md5)
          (weinholt crypto rsa)
          (weinholt struct pack)
          (weinholt text base64)
          (weinholt text random-art))

  (define (mpnegative? bv)
    (and (> (bytevector-length bv) 1)
         (fxbit-set? (bytevector-u8-ref bv 0) 7)))

  (define (get-mpint p)
    (let ((bv (get-bytevector-n p (get-unpack p "!L"))))
      (when (mpnegative? bv)
        (error 'get-ssh-public-key "Refusing to read a negative mpint"))
      (bytevector->uint bv)))

  (define (put-mpint p i)
    (let ((bv (uint->bytevector i)))
      (cond ((mpnegative? bv)
             ;; Prevent this from being considered a negative number
             (put-bytevector p (pack "!L" (+ 1 (bytevector-length bv))))
             (put-u8 p 0)
             (put-bytevector p bv))
            (else
             (put-bytevector p (pack "!L" (bytevector-length bv)))
             (put-bytevector p bv)))))

  (define (get-string p)
    (utf8->string (get-bytevector-n p (get-unpack p "!L"))))

  (define (put-string p s)
    (let ((bv (string->utf8 s)))
      (put-bytevector p (pack "!L" (bytevector-length bv)))
      (put-bytevector p bv)))

  ;; ssh-dss           REQUIRED     sign   Raw DSS Key
  ;; ssh-rsa           RECOMMENDED  sign   Raw RSA Key
  ;; pgp-sign-rsa      OPTIONAL     sign   OpenPGP certificates (RSA key)
  ;; pgp-sign-dss      OPTIONAL     sign   OpenPGP certificates (DSS key)

  ;; Reads a binary SSH public key. They are normally Base64 encoded
  ;; when stored in files.
  (define (get-ssh-public-key p)
    (let ((type (get-string p)))
      (cond ((string=? type "ssh-rsa")
             (let* ((e (get-mpint p))
                    (n (get-mpint p)))
               (make-rsa-public-key n e)))
            ((string=? type "ssh-dss")
             (let* ((p* (get-mpint p))
                    (q (get-mpint p))
                    (g (get-mpint p))
                    (y (get-mpint p)))
               (make-dsa-public-key p* q g y)))
            (else
             (error 'get-ssh-public-key
                    "Unknown public key algorithm"
                    type p)))))

  (define (ssh-public-key->bytevector key)
    (call-with-bytevector-output-port
      (lambda (p)
        (cond ((rsa-public-key? key)
               (put-string p "ssh-rsa")
               (put-mpint p (rsa-public-key-e key))
               (put-mpint p (rsa-public-key-n key)))
              ((dsa-public-key? key)
               (put-string p "ssh-dss")
               (put-mpint p (dsa-public-key-p key))
               (put-mpint p (dsa-public-key-q key))
               (put-mpint p (dsa-public-key-g key))
               (put-mpint p (dsa-public-key-y key)))
              (else
               (error 'ssh-public-key->bytevector
                      "Unknown public key algorithm"
                      key))))))

  (define (ssh-public-key-fingerprint key)
    (string-join
     (map (lambda (b)
            (string-pad (string-downcase (number->string b 16)) 2 #\0))
          (bytevector->u8-list
           (md5->bytevector (md5 (ssh-public-key->bytevector key)))))
     ":" 'infix))

  ;; TODO: bubblebabble

  (define (ssh-public-key-random-art key)
    (random-art (md5->bytevector (md5 (ssh-public-key->bytevector key)))
                (cond ((rsa-public-key? key)
                       (string-append
                        "RSA "
                        (number->string (rsa-public-key-length key))))
                      ((dsa-public-key? key)
                       (string-append
                        "DSA "
                        (number->string (dsa-public-key-length key))))))))
