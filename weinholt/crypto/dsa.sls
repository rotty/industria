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

;; The Digital Signature Algorithm from FIPS Pub 186.

(library (weinholt crypto dsa (0 0 20100615))
  (export make-dsa-public-key dsa-public-key?
          dsa-public-key-p
          dsa-public-key-q
          dsa-public-key-g
          dsa-public-key-y

          make-dsa-private-key dsa-private-key?
          dsa-private-key-p
          dsa-private-key-q
          dsa-private-key-g
          dsa-private-key-y
          dsa-private-key-x

          dsa-private->public
          dsa-private-key-from-bytevector
          dsa-private-key-from-pem-file

          dsa-signature-from-int
          dsa-verify-signature
          dsa-create-signature)
  (import (prefix (weinholt struct der (0 0)) der:)
          (weinholt bytevectors)
          (weinholt crypto entropy)
          (weinholt crypto math)
          (weinholt text base64)
          (rnrs))

  ;; y is (expt-mod g x p). x is secret.

  (define-record-type dsa-public-key
    (fields p q g y))

  (define-record-type dsa-private-key
    (fields p q g y x))

  (define (Dss-Parms)
    '(sequence (p integer)
               (q integer)
               (g integer)))

  (define (Dss-Sig-Value)
    '(sequence (r integer)
               (s integer)))

  (define (DSAPrivateKey)
    ;; Not sure where this is specified. Copied from gnutls.asn.
    '(sequence (version integer)        ;should be zero
               (p integer)
               (q integer)
               (g integer)
               (y integer)
               (x integer)))

  (define (dsa-private->public priv)
    (make-dsa-public-key (dsa-private-key-p priv)
                         (dsa-private-key-q priv)
                         (dsa-private-key-g priv)
                         (dsa-private-key-y priv)))

  (define (dsa-private-key-from-bytevector bv)
    (let ((data (der:translate (der:decode bv) (DSAPrivateKey))))
      (unless (zero? (car data))
        (error 'dsa-private-key-from-bytevector
               "Bad version on private DSA key" (car data)))
      (apply make-dsa-private-key (cdr data))))

  (define (dsa-private-key-from-pem-file filename)
    (let-values (((type data) (get-delimited-base64 (open-input-file filename))))
      (unless (string=? type "DSA PRIVATE KEY")
        (assertion-violation 'dsa-private-key-from-pem-file
                             "The file is not a 'DSA PRIVATE KEY' PEM file" filename))
      (dsa-private-key-from-bytevector data)))

  ;; The int is normally from an X.509 certificate and this procedure
  ;; returns r and s in a list.
  (define (dsa-signature-from-int int)
    (der:translate (der:decode (uint->bytevector int)) (Dss-Sig-Value)))

  (define (dsa-verify-signature Hm pubkey r s)
    (and (< 0 r (dsa-public-key-q pubkey))
         (< 0 s (dsa-public-key-q pubkey))
         (let* ((w (expt-mod s -1 (dsa-public-key-q pubkey)))
                ;; FIXME: leftmost min(n,outlen) bits:
                (z (bytevector->uint Hm))
                (u1 (mod (* z w) (dsa-public-key-q pubkey)))
                (u2 (mod (* r w) (dsa-public-key-q pubkey)))
                (v1 (expt-mod (dsa-public-key-g pubkey) u1
                              (dsa-public-key-p pubkey)))
                (v2 (expt-mod (dsa-public-key-y pubkey) u2
                              (dsa-public-key-p pubkey)))
                (v (mod (mod (* v1 v2)
                             (dsa-public-key-p pubkey))
                        (dsa-public-key-q pubkey))))
           (= v r))))

  (define (make-random q)
    ;; Generate a random number less than q
    (mod (bytevector->uint
          (make-random-bytevector
           (div (+ (bitwise-length q) 7) 8)))
         q))

  (define (dsa-create-signature Hm privkey)
    (let ((p (dsa-private-key-p privkey))
          (q (dsa-private-key-q privkey)))
      (let* ((k (make-random q))
             (r (mod (expt-mod (dsa-private-key-g privkey) k p) q))
             (s (mod (* (expt-mod k -1 q)
                        (+ (bytevector->uint Hm)
                           (* (dsa-private-key-x privkey) r)))
                     q)))
        (values r s))))

  )
