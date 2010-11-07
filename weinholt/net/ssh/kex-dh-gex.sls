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

;; RFC4419 Diffie-Hellman Group Exchange for the Secure Shell (SSH)
;; Transport Layer Protocol.

;; This handles diffie-hellman-group-exchange-sha256 and
;; diffie-hellman-group-exchange-sha1.

;; TODO: this library doesn't do anything yet

(library (weinholt net ssh kex-dh-gex (1 0 20101107))
  (export register-kex-dh-gex
          make-kex-dh-gex-key-exchanger)
  (import (rnrs)
          (weinholt crypto sha-1)
          (weinholt crypto sha-2)
          (weinholt net ssh private (1)))

  (define SSH-MSG-KEX-DH-GEX-REQUEST-OLD 30)
  (define SSH-MSG-KEX-DH-GEX-REQUEST 34)
  (define SSH-MSG-KEX-DH-GEX-GROUP 31)
  (define SSH-MSG-KEX-DH-GEX-INIT 32)
  (define SSH-MSG-KEX-DH-GEX-REPLY 33)

  (define (register-kex-dh-gex reg)
    (reg SSH-MSG-KEX-DH-GEX-REQUEST-OLD #f #f)
    (reg SSH-MSG-KEX-DH-GEX-REQUEST #f #f)
    (reg SSH-MSG-KEX-DH-GEX-GROUP #f #f)
    (reg SSH-MSG-KEX-DH-GEX-INIT #f #f)
    (reg SSH-MSG-KEX-DH-GEX-REPLY #f #f))

  (define-record-type kex-dh-gex-request-old
    (parent ssh-packet)
    (fields n)
    (protocol
     (lambda (p)
       (lambda (min n max)
         ((p SSH-MSG-KEX-DH-GEX-REQUEST-OLD) n)))))

  (define-record-type kex-dh-gex-request
    (parent ssh-packet)
    (fields min n max)
    (protocol
     (lambda (p)
       (lambda (min n max)
         ((p SSH-MSG-KEX-DH-GEX-REQUEST) min n max)))))

  (define-record-type kex-dh-gex-group
    (parent ssh-packet)
    (fields p g)
    (protocol
     (lambda (p)
       (lambda (p* g)
         ((p SSH-MSG-KEX-DH-GEX-GROUP) p* g)))))

  (define-record-type kex-dh-gex-init
    (parent ssh-packet)
    (fields e)
    (protocol
     (lambda (p)
       (lambda (e)
         ((p SSH-MSG-KEX-DH-GEX-GROUP) e)))))

  (define-record-type kex-dh-gex-reply
    (parent ssh-packet)
    (fields host-key f signature)
    (protocol
     (lambda (p)
       (lambda (host-key f signature)
         ((p SSH-MSG-KEX-DH-GEX-GROUP) host-key f signature)))))

;;; Key exchange logic

  (define (make-kex-dh-gex-key-exchanger kex keyalg client? V_C V_S I_C I_S send)
    #f)


  #;
  (hash-kex-data sha-256 sha-256->bytevector
                          'V_C V_C 'V_S V_S 'I_C I_C 'I_S I_S
                          'K_S (ssh-public-key->bytevector hostkey)
                          'min min 'n n 'max max
                          'p p 'g g 'e e 'f 'f 'K K)

  )
