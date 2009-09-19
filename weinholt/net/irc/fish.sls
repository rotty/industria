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

;; Blowcrypt/FiSH encryption for IRC. Messages are encrypted with
;; Blowfish in ECB mode and then encoded with a peculiar base64
;; encoding. Keys can be exchanged with Diffie-Hellman (vulnerable to
;; middleman attacks) or they can be pre-shared. FiSH is useful if you
;; want to draw attention to your communications.

;; Implemented from this description:
;; http://blog.bjrn.se/2009/01/proposal-for-better-irc-encryption.html

;; TODO: initiating key exchange

(library (weinholt net irc fish (0 0 20090918))
  (export fish-message? fish-decrypt-message fish-encrypt-message
          fish-key-init? fish-generate-key make-fish-key)
  (import (rnrs)
          (only (srfi :1 lists) iota)
          (only (srfi :13 strings) string-index string-prefix?)
          (srfi :27 random-bits)
          (weinholt bytevectors)
          (weinholt crypto blowfish)
          (weinholt crypto sha-2)
          (weinholt crypto math)
          (weinholt struct pack)
          (weinholt text base64))

  (define alphabet "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

  (define (fish-message? str)
    (cond ((string-prefix? "+OK " str)  ;FiSH
           (substring str 4 (string-length str)))
          ((string-prefix? "mcps " str) ;Mircryption
           (substring str 5 (string-length str)))
          (else #f)))

  (define (fish-encode-base64 bv p)
    (define (enc x)
      (list->string
       (map (lambda (sh) (string-ref alphabet (bitwise-bit-field x sh (+ sh 6))))
            (iota 6 0 6))))
    (do ((i 0 (+ i 8)))
        ((>= i (- (bytevector-length bv) 7)))
      (let-values (((x y) (unpack ">LL" bv i)))
        (display (enc y) p)
        (display (enc x) p))))

  (define (fish-decode-base64 str)
    (call-with-bytevector-output-port
      (lambda (p)
        (define (dec s)
          (apply bitwise-ior
                 (map (lambda (i sh)
                        (bitwise-arithmetic-shift-left (string-index alphabet i) sh))
                      (string->list s) (iota 6 0 6))))
        (do ((i 0 (+ i 12)))
            ((>= i (- (string-length str) 11)))
          (put-bytevector p (pack ">LL"
                                  (dec (substring str (+ i 6) (+ i 12)))
                                  (dec (substring str i (+ i 6)))))))))

  (define (fish-encrypt-message msg key)
    (call-with-string-output-port
      (lambda (p)
        (display "+OK " p)
        (let ((buf (make-bytevector 8)))
          (do ((i 0 (+ i 8)))
              ((>= i (bytevector-length msg)))
            (bytevector-fill! buf 0)
            (bytevector-copy! msg i buf 0 (min 8 (- (bytevector-length msg) i)))
            (blowfish-encrypt! buf 0 buf 0 (car key))
            (fish-encode-base64 buf p))))))

  (define (sanitize bv)
    ;; Remove trailing NUL bytes
    (let lp ((i (bytevector-length bv)))
      (cond ((zero? i) bv)
            ((not (zero? (bytevector-u8-ref bv (- i 1))))
             (if (= i (bytevector-length bv))
                 bv
                 (let ((ret (make-bytevector i)))
                   (bytevector-copy! bv 0 ret 0 i)
                   ret)))
            (else
             (lp (- i 1))))))

  (define (fish-decrypt-message msg key)
    (sanitize
     (call-with-bytevector-output-port
       (lambda (p)
         (let ((buf (make-bytevector 8)))
           (let ((in (fish-decode-base64 (fish-message? msg))))
             (do ((i 0 (+ i 8)))
                 ((>= i (- (bytevector-length in) 7)))
               (blowfish-decrypt! in i buf 0 (cdr key))
               (put-bytevector p buf))))))))

  (define (make-fish-key x)
    (if (string? x)
        (make-fish-key (string->utf8 x))
        (let ((sched (expand-blowfish-key x)))
          (cons sched (reverse-blowfish-schedule sched)))))
  
;;; Diffie-Hellman key exchange

  (define (dh1080-base64-decode str)
    (let ((padding (- (bitwise-and -4 (+ (string-length str) 3))
                      (string-length str))))
      (if (and (= padding 3))
          (base64-decode (substring str 0 (- (string-length str) 1)))
          (base64-decode (string-append str (make-string padding #\=))))))

  (define (dh1080-base64-encode bv)
    (let ((str
           (call-with-string-output-port
             (lambda (p)
               (base64-encode bv p 0 (bytevector-length bv) #f #t base64-alphabet)))))
      (if (zero? (mod (string-length str) 4))
          (string-append str "A")
          str)))

  ;; Serious business
  (define n (bytevector->uint (dh1080-base64-decode "++ECLiPSE+is+proud+to+\
present+latest+FiSH+release+featuring+even+more+security+for+you+++shouts+go+\
out+to+TMG+for+helping+to+generate+this+cool+sophie+germain+prime+number++++\
/C32L")))
  (define g 2)

  (define (fish-key-init? msg)
    (cond ((string-prefix? "DH1080_INIT " msg)
           (substring msg 12 (string-length msg)))
          (else #f)))

  (define make-random-bytevector        ;also present in net/tls
    (let* ((s (make-random-source))
           (make-int (random-source-make-integers s))
           (urandom (and (file-exists? "/dev/urandom")
                         (open-file-input-port "/dev/urandom"))))
      (lambda (len)
        (unless urandom
          (random-source-randomize! s))
        (do ((bv (make-bytevector len))
             (i 0 (fx+ i 1)))
            ((fx=? i len) bv)
          (if urandom
              (bytevector-u8-set! bv i (get-u8 urandom))
              (bytevector-u8-set! bv i (make-int 255)))))))

  (define (make-secret tries)
    (unless (< tries 1000)
      (error 'make-secret "unable to make a secret"))
    (let* ((y (bytevector->uint (make-random-bytevector 1080/8)))
           (Y (expt-mod g y n)))
      (if (and (<= (expt 2 512) Y (- n 2))
               (= 1 (expt-mod Y (/ (- n 1) 2) n)))
          (values y Y)
          (make-secret (+ tries 1)))))

  ;; Returns a DH1080_FINISH message and a key.
  (define (fish-generate-key init)
    (let ((X (bytevector->uint (dh1080-base64-decode (fish-key-init? init)))))
      (unless (<= 1 X (- n 2))
        (error 'fish-key-generate "bad public number sent" X))
      (let-values (((y Y) (make-secret 0)))
        (let ((k (expt-mod X y n)))
          (values (make-fish-key (dh1080-base64-encode
                                  (sha-256->bytevector (sha-256 (uint->bytevector k)))))
                  (string-append "DH1080_FINISH "
                                 (dh1080-base64-encode (uint->bytevector Y)))))))))
