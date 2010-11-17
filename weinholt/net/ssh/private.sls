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

;; Private parsing, formatting, stuff

(library (weinholt net ssh private (1 0 20101107))
  (export ssh-packet? ssh-packet-type ssh-packet
          parse-signature make-signature
          verify-signature hash-kex-data
          private->public prf-sha-1 prf-sha-256
          get-record read-byte read-uint32
          read-bytevector read-string read-name-list read-mpint
          put-record put-bvstring put-name-list put-mpint
          integer->mpint)
  (import (rnrs)
          (only (srfi :13 strings) string-join)
          (srfi :26 cut)
          (weinholt bytevectors)
          (weinholt crypto dsa)
          (weinholt crypto rsa)
          (weinholt crypto sha-1)
          (weinholt crypto sha-2)
          (weinholt net buffer)
          (weinholt struct pack)
          (weinholt text strings))

  (define (private->public key)
    (cond #;((rsa-private-key? key)
             (rsa-private->public key))
          ((dsa-private-key? key)
           (dsa-private->public key))
          (else
           (error 'private->public
                  "Unimplemented public key algorithm"
                  key))))

  (define (parse-signature sig)
    (define (get p)
      (get-bytevector-n p (get-unpack p "!L")))
    (let ((p (open-bytevector-input-port sig)))
      (let ((type (utf8->string (get p))))
        (cond ((string=? type "ssh-rsa")
               (list 'rsa (bytevector->uint (get p))))
              ((string=? type "ssh-dss")
               (let* ((bv (get p))
                      (r (subbytevector bv 0 160/8))
                      (s (subbytevector bv 160/8 (* 160/8 2))))
                 (list 'dsa (bytevector->uint r)
                       (bytevector->uint s))))
              (else
               (error 'parse-signature "Unimplemented signature algorithm"
                      type))))))

  (define (make-signature msg key)
    (call-with-bytevector-output-port
      (lambda (p)
        ;; TODO: RSA
        (cond #;((rsa-private-key? key)
                 )
              ((dsa-private-key? key)
               (let-values (((r s) (dsa-create-signature
                                    (sha-1->bytevector (sha-1 msg)) key)))
                 (let ((sig (make-bytevector (* 160/8 2) 0)))
                   (bytevector-uint-set! sig 0 r (endianness big) 160/8)
                   (bytevector-uint-set! sig 160/8 s (endianness big) 160/8)
                   (put-bvstring p "ssh-dss")
                   (put-bytevector p (pack "!L" (bytevector-length sig)))
                   (put-bytevector p sig))))
              (else
               (error 'make-signature
                      "Unimplemented public key algorithm"
                      key))))))

  (define (verify-signature H keyalg key sig-bv)
    (let ((H-digest (sha-1 H))
          (signature (parse-signature sig-bv)))
      (cond ((and (string=? keyalg "ssh-rsa")
                  (rsa-public-key? key)
                  (eq? (car signature) 'rsa))
             (let ((sig (cadr (rsa-pkcs1-decrypt-digest
                               (cadr signature) key))))
               (if (sha-1-hash=? H-digest sig)
                   'ok 'bad)))
            ((and (string=? keyalg "ssh-dss")
                  (dsa-public-key? key)
                  (eq? (car signature) 'dsa))
             (if (dsa-verify-signature (sha-1->bytevector H-digest)
                                       key (cadr signature)
                                       (caddr signature))
                 'ok 'bad))
            (else
             (error 'verify-signature
                    "Unimplemented public key algorithm or bad signature"
                    keyalg key signature)))))

  ;; Used by kexdh and kex-dh-gex. The server signs this digest to
  ;; prove it owns the key it sent.
  (define (hash-kex-data hash ->bytevector . data)
    ;; For kexdh:
    ;; H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
    ;; For kex-dh-gex:
    ;; H = hash(V_C || V_S || I_C || I_S || K_S || min || n ||
    ;;          max || p || g || e || f || K)
    (->bytevector
     (hash
      (call-with-bytevector-output-port
        (lambda (p)
          (for-each (lambda (k) (put-bvstring p (cadr (memq k data))))
                    '(V_C V_S I_C I_S K_S))
          (for-each (lambda (k)
                      (cond ((memq k data) =>
                             (lambda (v)
                               (put-bytevector p (pack "!L" (cadr v)))))))
                    '(min n max))
          (for-each (lambda (k)
                      (cond ((memq k data) =>
                             (lambda (v)
                               (put-mpint p (cadr v))))))
                    '(p g e f K)))))))

  (define (make-prf make length update! copy finish! finish ->bytevector)
    (lambda (X len session-id K H)
      ;; Generate LEN bytes of key material. Section 7.2 in RFC 4253.
      (call-with-bytevector-output-port
        (lambda (p)
          (let ((s (make)))
            (update! s K)
            (update! s H)
            (let ((s* (copy s)))
              (update! s* (pack "C" (char->integer X)))
              (update! s* session-id)
              (finish! s*)
              (do ((Kn (->bytevector s*) (->bytevector (finish s)))
                   (len len (- len (length))))
                  ((<= len 0))
                (update! s Kn)
                (put-bytevector p Kn 0 (min len (bytevector-length Kn))))))))))

  (define prf-sha-1 (make-prf make-sha-1 sha-1-length sha-1-update! sha-1-copy
                              sha-1-finish! sha-1-finish sha-1->bytevector))

  (define prf-sha-256 (make-prf make-sha-256 sha-256-length sha-256-update! sha-256-copy
                                sha-256-finish! sha-256-finish sha-256->bytevector))

  ;; The parent of all record abstractions of ssh packets
  (define-record-type ssh-packet
    (fields type))

  (define (get-record b make field-types)
    (define (read b type)
      (case type
        ((string) (read-string b))
        ((bytevector) (read-bytevector b))
        ((uint32) (read-uint32 b))
        ((mpint) (read-mpint b))
        ((name-list) (read-name-list b))
        ((boolean) (positive? (read-byte b)))
        ((byte) (read-byte b))
        ((cookie)
         (when (< (buffer-length b) 16)
           (error 'get-record "short record" (buffer-length b)))
         (let ((bv (subbytevector (buffer-data b)
                                  (buffer-top b)
                                  (+ (buffer-top b) 16))))
           (buffer-seek! b 16)
           bv))
        (else
         (error 'get-record "bug: unknown type" type))))
    (do ((field 0 (+ field 1))
         (types field-types (cdr types))
         (ret '() (cons (read b (car types)) ret)))
        ((null? types) (apply make (reverse ret)))))

  (define (read-byte b)
    (let ((x (read-u8 b 0)))
      (buffer-seek! b 1)
      x))

  (define (read-uint32 b)
    (let ((x (read-u32 b 0)))
      (buffer-seek! b 4)
      x))

  (define (read-bytevector b)
    (let ((len (read-u32 b 0)))
      (when (> len (buffer-length b))
        (error 'read-bytevector "overlong string" len))
      (buffer-seek! b 4)
      (let ((bv (subbytevector (buffer-data b)
                               (buffer-top b)
                               (+ (buffer-top b) len))))
        (buffer-seek! b len)
        bv)))

  (define (read-string b)
    (utf8->string (read-bytevector b)))

  (define (read-name-list b)
    (let ((str (read-string b)))
      (if (string=? str "")
          '()
          (string-split str #\,))))

  (define (read-mpint b)
    (let ((bv (read-bytevector b)))
      (bytevector-sint-ref bv 0 (endianness big) (bytevector-length bv))))

;;; Formatting

  (define (put-record p msg rtd field-types)
    (do ((rtd (or rtd (record-rtd msg)))
         (field 0 (+ field 1))
         (types field-types (cdr types)))
        ((null? types))
      (let ((v ((record-accessor rtd field) msg)))
        (case (car types)
          ((string) (put-bvstring p v))
          ((uint32) (put-bytevector p (pack "!L" v)))
          ((mpint) (put-mpint p v))
          ((name-list) (put-name-list p v))
          ((boolean) (put-u8 p (if v 1 0)))
          ((byte) (put-u8 p v))
          ((cookie) (put-bytevector p v 0 16))
          (else
           (error 'put-record "bug: unknown type"
                  (car types)))))))

  (define (put-bvstring p s)
    (let ((bv (if (string? s) (string->utf8 s) s)))
      (put-bytevector p (pack "!L" (bytevector-length bv)))
      (put-bytevector p bv)))

  (define (put-name-list p l)
    (put-bvstring p (string-join l ",")))

  (define (mpnegative? bv)
    (and (> (bytevector-length bv) 1)
         (fxbit-set? (bytevector-u8-ref bv 0) 7)))

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

  (define (integer->mpint int)
    (call-with-bytevector-output-port
      (cut put-mpint <> int))))
