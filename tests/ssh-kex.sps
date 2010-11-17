#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
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

(import (rnrs)
        (srfi :78 lightweight-testing)
        (weinholt crypto dsa)
        (weinholt crypto entropy)
        (weinholt net ssh algorithms)
        (weinholt net ssh kexdh)      ;to recognize kexdh-init
        (weinholt net ssh kex-dh-gex) ;to recognize kex-dh-gex-request
        (weinholt net ssh transport)
        (weinholt text base64))

(define (print . x) (for-each display x) (newline))

(define (parse-key s)
  (let-values (((type bv) (get-delimited-base64
                           (open-string-input-port s))))
    (dsa-private-key-from-bytevector bv)))

(define server-dsa-key
  (parse-key
   "-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCsWqA7PlEkryVmODG5kEUyFQX7NydZZ6+NZu33gnRyMRYiEEvc
XQHuwpPS89snjwnkkPhv4RFN+4sLiu+5T0MbZ4qZ/fq7Heec2A4/DK9n8qzSdVBg
6hkNZsB0AQIC/xI+MlYsQ1ZS7mLAPT6m+zjFYo0sbZUJNbGCRX6m/iibrwIVAMk7
LJkmuIKCTyP/a9m21hXYyqJXAoGAPU+js+GrtDB5FRAUWt3Cbrzdcv/Orj6F37on
THG1iYf8FAl6Fj/uxvKasgIYeMgFQhhMKu+p9pRNfAWIYSVuUqtVVsPKc68aEucP
+OcCynJ0V16eb2fGdC3c4yzwHIXeEHM7bkNS/tiLQaace+ogtjrSENd5GquuA3OQ
LbSrAt8CgYBdZc7hocR3mTReopmBZ6V41RDDdK0JYQ4BW0r9nGH20ciH0QbsMf3D
J907A8afiPaxVWzwd326Yeit5VdRiEut32PMRILcbqveGTdhvBD8RJSrDuwW+06P
K2NBpZ7bW3ncxXT0QMNVjvLdHh4+3C4z3PNhOlUIE8fIIBfZxCWv8AIUJlYxaPDf
WAhaSeMnKo/oDbb2ICI=
-----END DSA PRIVATE KEY-----"))

;; The kexinit data is just part of the signed data here
(define (dummy-kexinit client?)
  (call-with-bytevector-output-port
    (lambda (p)
      (put-kexinit p (make-kexinit (make-random-bytevector 16)
                                   '("diffie-hellman-group14-sha1")
                                   '("ssh-dss")
                                   '("aes128-ctr") '("aes128-ctr")
                                   '("hmac-sha1") '("hmac-sha1")
                                   '("none") '("none")
                                   '() '() client? 0)))))
(define dummy-kexinit-client (dummy-kexinit #t))
(define dummy-kexinit-server (dummy-kexinit #f))
(define dummy-init-data (list 'host-key-algorithm "ssh-dss"
                              'V_S (string->utf8 "SSH-2.0-Server")
                              'V_C (string->utf8 "SSH-2.0-Client")
                              'I_C dummy-kexinit-client
                              'I_S dummy-kexinit-server))

(define (no-attacker)
  (let ((seen-kexdh-init? #f))
    (lambda (name x)
      (cond ((and (not seen-kexdh-init?)
                  (or (kexdh-init? x)
                      (kex-dh-gex-request? x)))
             ;; Filter out the first KEX packet
             (print ";; Server ignores " x)
             (set! seen-kexdh-init? #t) 
             #f)
            (else x)))))

(define (queue name attacker)
  (let ((q '()))
    (case-lambda
      ((x)
       ;; The "attacker" can be used to simulate an active attacker
       (let ((x* (attacker name x)))
         (when x*
           (print ";; Packet to " name ": " x*)
           (set! q (append q (list (attacker name x)))))))
      (()
       (and (not (null? q))
            (let ((x (car q))) (set! q (cdr q)) x))))))

(define (compare k1 k2)
  (unless (and (list? k1) (list? k2))
    (error 'text-kex "The key exchange did not run to completion"
           k1 k2))
  (let ((key1 (car k1)) (key2 (car k2)))
    (and (= (dsa-public-key-p key1) (dsa-public-key-p key2))
         (= (dsa-public-key-q key1) (dsa-public-key-q key2))
         (= (dsa-public-key-g key1) (dsa-public-key-g key2))
         (= (dsa-public-key-y key1) (dsa-public-key-y key2))
         (equal? (cadr k1) (cadr k2))
         (equal? (caddr k1) (caddr k2)))))

(define (test-kex kexalg server-key attacker)
  ;; TODO: try starting the client twice. this is needed so that
  ;; misguessed KEXes don't require a new dh secret.
  (let* ((cq (queue 'client attacker))
         (sq (queue 'server attacker))
         (client (make-key-exchanger kexalg #t sq))
         (server (make-key-exchanger kexalg #f cq)))
    ;; Initialize the client
    (client 'start #f)
    (client 'start #f)                  ;simulate misguessed KEX
    (client 'init dummy-init-data)
    ;; Initialize the server
    (server 'start #f)
    (server 'init dummy-init-data)
    (server 'private-key server-key)
    ;; Run the server and the client against each other
    (let lp ((cstatus 'c-kex-failed) (sstatus 's-kex-failed))
      (cond ((cq) => (lambda (p)
                       (lp (client 'packet p) sstatus)))
            ((sq) => (lambda (p)
                       (lp cstatus (server 'packet p))))
            (else (compare cstatus sstatus))))))

(check (test-kex "diffie-hellman-group1-sha1" server-dsa-key (no-attacker))
       => #t)
(check (test-kex "diffie-hellman-group14-sha1" server-dsa-key (no-attacker))
       => #t)

(check (test-kex "diffie-hellman-group-exchange-sha256" server-dsa-key (no-attacker))
       => #t)
(check (test-kex "diffie-hellman-group-exchange-sha1" server-dsa-key (no-attacker))
       => #t)

(check-report)
