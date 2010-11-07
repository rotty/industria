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

;; Diffie-Hellman Key Exchange from RFC4253

;; This handles diffie-hellman-group14-sha1 and
;; diffie-hellman-group1-sha1.

(library (weinholt net ssh kexdh (1 0 20101107))
  (export register-kexdh
          make-kexdh-init kexdh-init? kexdh-init-e
          make-kexdh-reply kexdh-reply? kexdh-reply-f
          kexdh-reply-host-key kexdh-reply-signature
          make-kex-dh-key-exchanger)
  (import (rnrs)
          (weinholt crypto dh)
          (weinholt crypto sha-1 (1 (>= 1)))
          (weinholt crypto ssh-public-key)
          (weinholt net ssh private (1)))

;;; Messages

  (define SSH-MSG-KEXDH-INIT 30)
  (define SSH-MSG-KEXDH-REPLY 31)

  (define (register-kexdh reg)
    (reg SSH-MSG-KEXDH-INIT parse-kexdh-init put-kexdh-init)
    (reg SSH-MSG-KEXDH-REPLY parse-kexdh-reply put-kexdh-reply))

  (define-record-type kexdh-init
    (parent ssh-packet)
    (fields e)
    (protocol
     (lambda (p)
       (lambda (e)
         ((p SSH-MSG-KEXDH-INIT) e)))))

  (define (parse-kexdh-init b)
    (make-kexdh-init (read-mpint b)))

  (define (put-kexdh-init p m)
    (put-u8 p SSH-MSG-KEXDH-INIT)
    (put-mpint p (kexdh-init-e m)))

  (define-record-type kexdh-reply
    (parent ssh-packet)
    (fields host-key f signature)
    (protocol
     (lambda (p)
       (lambda (host-key f signature)
         ((p SSH-MSG-KEXDH-REPLY) host-key f signature)))))

  (define (parse-kexdh-reply b)
    (let* ((key-bv (read-bytevector b))
           (f (read-mpint b))
           (sig (read-bytevector b)))
      (make-kexdh-reply key-bv f sig)))

  (define (put-kexdh-reply p m)
    (put-u8 p SSH-MSG-KEXDH-REPLY)
    (put-bvstring p (kexdh-reply-host-key m))
    (put-mpint p (kexdh-reply-f m))
    (put-bvstring p (kexdh-reply-signature m)))

;;; Kex exchange logic

  (define (make-kex-dh-key-exchanger kex client? send)
    (let ((kexer (if client? make-client-kexer make-server-kexer)))
      (cond ((string=? kex "diffie-hellman-group1-sha1")
             ;; SHA-1 and Oakley Group 2.
             (kexer modp-group2-p modp-group2-g send))
            ((string=? kex "diffie-hellman-group14-sha1")
             ;; SHA-1 and Oakley Group 14.
             (kexer modp-group14-p modp-group14-g send))
            (else
             (error 'make-kex-dh-key-exchanger
                    "Unknown D-H group" kex)))))

  (define (invalid-state method state)
    (error 'kexdh "Invalid state" method state))

  ;; Client part

  (define (make-client-kexer group-p group-g send)
    (let ((state 'send-kexdh-init)
          (init-data #f))
      (let-values (((x e) (make-dh-secret group-g group-p
                                          (bitwise-length group-p))))
        (lambda (method arg)
          (case method
            ((start)
             (case state
               ((send-kexdh-init recv-kexdh-reply)
                (set! state 'wait-version/init)
                (send (make-kexdh-init e)) ; e = g^x mod p
                #f)
               (else (invalid-state method state))))
            ((init)
             (case state
               ((wait-version/init)
                (set! state 'recv-kexdh-reply)
                (set! init-data arg)    ; host-key-algorithm V_C V_S I_C I_S
                #f)
               (else (invalid-state method state))))
            ((packet)
             (case state
               ((recv-kexdh-reply)
                (set! state 'done)
                (let ((key-bv (kexdh-reply-host-key arg))
                      (f (kexdh-reply-f arg)) ; f = g^y mod p
                      (sig (kexdh-reply-signature arg)))
                  (unless (< 1 f (- group-p 1)) (error 'kexdh "Bad kexdh-reply"))
                  (let* ((keyalg (cadr (memq 'host-key-algorithm init-data)))
                         (hostkey (get-ssh-public-key (open-bytevector-input-port key-bv)))
                         (K (expt-mod f x group-p))
                         (H (apply hash-kex-data sha-1 sha-1->bytevector
                                   'K_S (ssh-public-key->bytevector hostkey)
                                   'e e 'f f 'K K init-data)))
                    (unless (eq? 'ok (verify-signature H keyalg hostkey sig))
                      (error 'kexdh "Bad kexdh-reply"))
                    (list hostkey (integer->mpint K) H prf-sha-1))))
               (else (invalid-state method state))))
            (else (invalid-state method state)))))))

  ;; Server part

  (define (make-server-kexer group-p group-g send)
    (let ((state 'recv-kexdh-init)
          (init-data #f)
          (private-key #f))
      (let-values (((y f) (make-dh-secret group-g group-p
                                          (bitwise-length group-p))))
        (lambda (method arg)
          (case method
            ((start)
             (case state
               ((recv-kexdh-init)
                (set! state 'wait-version/init)
                #f)
               (else (invalid-state method state))))
            ((init)
             (case state
               ((wait-version/init)
                (set! state 'recv-kexdh-reply)
                (set! init-data arg)    ; V_C V_S I_C I_S
                #f)
               (else (invalid-state method state))))
            ((private-key) (set! private-key arg)) ;TODO: checks
            ((packet)
             (case state
               ((recv-kexdh-reply)
                (set! state 'done)
                (let ((e (kexdh-init-e arg)))       ; e = g^x mod p
                  (unless (< 1 e (- group-p 1)) (error 'kexdh "Bad kexdh-init"))
                  (let* ((hostkey (private->public private-key))
                         (K (expt-mod e y group-p))
                         (H (apply hash-kex-data sha-1 sha-1->bytevector
                                   'K_S (ssh-public-key->bytevector hostkey)
                                   'e e 'f f 'K K init-data))
                         (sig (make-signature H private-key)))
                    (send (make-kexdh-reply (ssh-public-key->bytevector hostkey)
                                            f sig)) ; f = g^y mod p
                    (list hostkey (integer->mpint K) H prf-sha-1))))
               (else (invalid-state method state))))
            (else (invalid-state method state))))))))
