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

;; Encryption, MAC and KEX algorithms. This library is considered
;; private.

;; RFC4253 The Secure Shell (SSH) Transport Layer Protocol.

;; RFC4345 Improved Arcfour Modes for the Secure Shell (SSH) Transport
;; Layer Protocol.

;; Describes a new kex that I haven't seen used yet:
;; RFC4432 RSA Key Exchange for the Secure Shell (SSH) Transport Layer
;; Protocol.

;; GNU lsh has the host key algorithm spki-sign-rsa. SPKI is from RFC
;; 2693 and uses Rivest's S-expression format.

;; Some encryption algorithms and considerations:
;; RFC4344 The Secure Shell (SSH) Transport Layer Encryption Modes.

;; This describes the MAC algorithm umac-64@openssh.com:
;; RFC4418 UMAC: Message Authentication Code using Universal Hashing

(library (weinholt net ssh algorithms (1 0 20101107))
  (export make-reader make-writer
          make-read-mac make-write-mac
          make-key-exchanger register-key-exchange
          preferred-kex-algorithms
          preferred-server-host-key-algorithms
          preferred-encryption-algorithms-client->server
          preferred-encryption-algorithms-server->client
          preferred-mac-algorithms-client->server
          preferred-mac-algorithms-server->client
          preferred-compression-algorithms-client->server
          preferred-compression-algorithms-server->client)
  (import (rnrs)
          (srfi :26 cut)
          (srfi :39 parameters)
          (weinholt bytevectors)
          (weinholt crypto aes)
          (weinholt crypto arcfour)
          (weinholt crypto blowfish (0 (>= 1)))
          (weinholt crypto des)
          (weinholt crypto sha-1 (1 (>= 1)))
          (weinholt crypto md5 (1 (>= 1)))
          (weinholt net buffer)
          (weinholt net ssh kexdh (1))
          (weinholt net ssh kex-dh-gex (1))
          (weinholt struct pack))

  (define (algfilter valid)
    (cut filter (cut member <> valid) <>))

  ;; kex is short for key exchange.
  (define kexes
    '(#;"diffie-hellman-group-exchange-sha256" #;"diffie-hellman-group-exchange-sha1"
      "diffie-hellman-group14-sha1" "diffie-hellman-group1-sha1"))

  (define preferred-kex-algorithms
    (make-parameter kexes (algfilter kexes)))

  (define keyalgs
    '("ssh-rsa" "ssh-dss"))

  (define preferred-server-host-key-algorithms
    (make-parameter keyalgs (algfilter keyalgs)))

  (define ciphers
    '("aes128-ctr" "aes192-ctr" "aes256-ctr"
      "aes128-cbc" "aes192-cbc" "aes256-cbc"
      "blowfish-cbc"
      "arcfour256" "arcfour128"
      ;; "arcfour"   ;; this is considered broken
      "3des-cbc"))

  (define preferred-encryption-algorithms-client->server
    (make-parameter ciphers (algfilter ciphers)))

  (define preferred-encryption-algorithms-server->client
    (make-parameter ciphers (algfilter ciphers)))

  (define macs
    '("hmac-md5" "hmac-sha1"
      "hmac-sha1-96" "hmac-md5-96"))

  (define preferred-mac-algorithms-client->server
    (make-parameter macs (algfilter macs)))

  (define preferred-mac-algorithms-server->client
    (make-parameter macs (algfilter macs)))

  (define comps '("none"))

  (define preferred-compression-algorithms-client->server
    (make-parameter comps (algfilter comps)))

  (define preferred-compression-algorithms-server->client
    (make-parameter comps (algfilter comps)))

  (define (fxalign len blocksize)
    (fx+ len (fxand (fx- len) (fx- blocksize 1))))

  ;; Returns a procedure that reads N bytes from a net buffer B and
  ;; decrypts them.
  (define (make-reader algorithm iv-gen keygen)
    (define (cbc-reader ivlen keylen reverse expand decrypt!)
      (let ((iv (iv-gen ivlen))
            (key (reverse (expand (keygen keylen)))))
        (lambda (b n)
          (let ((n (fxalign n ivlen))
                (start (fxalign (buffer-top b) ivlen)))
            (buffer-read! b (- n start))
            (decrypt! (buffer-data b) start
                      (buffer-data b) start
                      (- (buffer-bottom b) start)
                      key iv)))))
    (define (aes-cbc-reader keylen)
      (cbc-reader 16 keylen reverse-aes-schedule expand-aes-key
                  aes-cbc-decrypt!))
    (define (aes-ctr-reader keylen)
      (let ((ctr (bytevector->uint (iv-gen 16)))
            (key (expand-aes-key (keygen keylen))))
        (lambda (b n)
          (let ((n (fxalign n 16))
                (start (fxalign (buffer-top b) 16)))
            (buffer-read! b (- n start))
            (set! ctr (aes-ctr! (buffer-data b) start
                                (buffer-data b) start
                                (- (buffer-bottom b) start)
                                key ctr))))))
    (define (arcfour-reader keylen discard)
      (let ((key (expand-arcfour-key (keygen keylen))))
        (arcfour-discard! key discard)
        (lambda (b n)
          ;; ARCFOUR is a stream cipher, so it doesn't use blocks, but
          ;; the transport layer gives us eight-byte blocks anyway.
          (let ((n (fxalign n 8))
                (start (fxalign (buffer-top b) 8)))
            (buffer-read! b (- n start))
            (arcfour! (buffer-data b) start
                      (buffer-data b) start
                      (- (buffer-bottom b) start)
                      key)))))
    (cond ((string=? algorithm "none")
           (lambda (b n) (buffer-read! b n)))
          ((string=? algorithm "aes128-cbc") (aes-cbc-reader 128/8))
          ((string=? algorithm "aes192-cbc") (aes-cbc-reader 192/8))
          ((string=? algorithm "aes256-cbc") (aes-cbc-reader 256/8))
          ((string=? algorithm "aes128-ctr") (aes-ctr-reader 128/8))
          ((string=? algorithm "aes192-ctr") (aes-ctr-reader 192/8))
          ((string=? algorithm "aes256-ctr") (aes-ctr-reader 256/8))
          ((string=? algorithm "3des-cbc")
           (let ((iv (iv-gen 8))
                 (key (tdea-permute-key (keygen 24))))
             (lambda (b n)
               (let ((n (fxalign n 8))
                     (start (fxalign (buffer-top b) 8)))
                 (buffer-read! b (- n start))
                 (tdea-cbc-decipher! (buffer-data b) key iv
                                     start
                                     (- (buffer-bottom b) start))))))
          ((string=? algorithm "blowfish-cbc")
           (cbc-reader 8 128/8 reverse-blowfish-schedule
                       expand-blowfish-key blowfish-cbc-decrypt!))
          ((string=? algorithm "arcfour128") (arcfour-reader 128/8 1536))
          ((string=? algorithm "arcfour256") (arcfour-reader 256/8 1536))
          ((string=? algorithm "arcfour") (arcfour-reader 128/8 0))
          (else
           (error 'make-reader "Unimplemented decryption algorithm"
                  algorithm))))

  ;; Returns a procedure that encrypts LEN bytes from the bytevector
  ;; BUF and writes them to OUT.
  (define (make-writer algorithm iv-gen keygen)
    (define (cbc-writer ivlen keylen expand encrypt!)
      (let ((iv (iv-gen ivlen))
            (key (expand (keygen keylen))))
        (lambda (out buf len)
          (encrypt! buf 0 buf 0 len key iv)
          (put-bytevector out buf 0 len))))
    (define (aes-cbc-writer keylen)
      (cbc-writer 16 keylen expand-aes-key aes-cbc-encrypt!))
    (define (aes-ctr-writer keylen)
      (let ((ctr (bytevector->uint (iv-gen 16)))
            (key (expand-aes-key (keygen keylen))))
        (lambda (out buf len)
          ;; TODO: ctr should wrap after 2^128-1. But it just seems
          ;; unlikely it will happen?
          (set! ctr (aes-ctr! buf 0 buf 0 len key ctr))
          (put-bytevector out buf 0 len))))
    (define (arcfour-writer keylen discard)
      (let ((key (expand-arcfour-key (keygen keylen))))
        (arcfour-discard! key discard)
        (lambda (out buf len)
          (arcfour! buf 0 buf 0 len key)
          (put-bytevector out buf 0 len))))
    (cond ((string=? algorithm "none")
           (lambda (out buf len)
             (do ((i (- len (unpack "C" buf (format-size "!L")))
                     (+ i 1)))
                 ((= i len))
               ;; Because this is unencrypted, zero out the random
               ;; padding.
               (bytevector-u8-set! buf i 0))
             (put-bytevector out buf 0 len)))
          ((string=? algorithm "aes128-cbc") (aes-cbc-writer 128/8))
          ((string=? algorithm "aes192-cbc") (aes-cbc-writer 192/8))
          ((string=? algorithm "aes256-cbc") (aes-cbc-writer 256/8))
          ((string=? algorithm "aes128-ctr") (aes-ctr-writer 128/8))
          ((string=? algorithm "aes192-ctr") (aes-ctr-writer 192/8))
          ((string=? algorithm "aes256-ctr") (aes-ctr-writer 256/8))
          ((string=? algorithm "3des-cbc")
           (let ((iv (iv-gen 8))
                 (key (tdea-permute-key (keygen 24))))
             (lambda (out buf len)
               (tdea-cbc-encipher! buf key iv 0 len)
               (put-bytevector out buf 0 len))))
          ((string=? algorithm "blowfish-cbc")
           (cbc-writer 8 128/8 expand-blowfish-key blowfish-cbc-encrypt!))
          ((string=? algorithm "arcfour128") (arcfour-writer 128/8 1536))
          ((string=? algorithm "arcfour256") (arcfour-writer 256/8 1536))
          ((string=? algorithm "arcfour") (arcfour-writer 128/8 0))
          (else
           (error 'make-writer "Unimplemented encryption algorithm"
                  algorithm))))

  ;; Returns a procedure that reads a MAC from the net buffer B's port
  ;; and verifies that it matches the contents of the buffer and the
  ;; sequence number.
  (define (make-read-mac algorithm keygen)
    (define (reader keylen len hmac hash=?)
      (let ((secret (keygen keylen))
            (seqbuf (make-bytevector (format-size "!L")))
            (macbuf (make-bytevector len)))
        (lambda (seqno b)
          (pack! "!L" seqbuf 0 seqno)
          (get-bytevector-n! (buffer-port b) macbuf 0
                             (bytevector-length macbuf))
          ;; TODO: take the hmac without consing
          (let ((data (subbytevector (buffer-data b)
                                     0
                                     (buffer-bottom b))))
            (if (hash=? (hmac secret seqbuf data) macbuf)
                'ok
                'bad)))))
    (cond ((string=? algorithm "none")
           (lambda (seqno b) 'ok))
          ((string=? algorithm "hmac-sha1")
           (reader (sha-1-length) (sha-1-length) hmac-sha-1 sha-1-hash=?))
          ((string=? algorithm "hmac-sha1-96")
           (reader (sha-1-length) 96/8 hmac-sha-1 sha-1-96-hash=?))
          ((string=? algorithm "hmac-md5")
           (reader (md5-length) (md5-length) hmac-md5 md5-hash=?))
          ((string=? algorithm "hmac-md5-96")
           (reader (md5-length) 96/8 hmac-md5 md5-96-hash=?))
          (else
           (error 'make-read-mac "Unimplemented MAC algorithm"
                  algorithm))))

  ;; Returns a procedure that returns a MAC from the sequence number
  ;; and the first N bytes of the bytevector BUF.
  (define (make-write-mac algorithm keygen)
    (define (writer keylen len hmac copy-hash!)
      (let ((secret (keygen keylen))
            (seqbuf (make-bytevector (format-size "!L")))
            (macbuf (make-bytevector len)))
        (lambda (seqno buf n)
          (pack! "!L" seqbuf 0 seqno)
          ;; TODO: take the hmac without consing
          (copy-hash! (hmac secret seqbuf (subbytevector buf 0 n))
                      macbuf 0)
          macbuf)))
    (cond ((string=? algorithm "none")
           (lambda (seqno buf n) #vu8()))
          ((string=? algorithm "hmac-sha1")
           (writer (sha-1-length) (sha-1-length) hmac-sha-1 sha-1-copy-hash!))
          ((string=? algorithm "hmac-md5")
           (writer (md5-length) (md5-length) hmac-md5 md5-copy-hash!))
          ((string=? algorithm "hmac-sha1-96")
           (writer (sha-1-length) 96/8 hmac-sha-1 sha-1-96-copy-hash!))
          ((string=? algorithm "hmac-md5-96")
           (writer (md5-length) 96/8 hmac-md5 md5-96-copy-hash!))
          (else
           (error 'make-write-mac "Unimplemented MAC algorithm"
                  algorithm))))

  (define (make-key-exchanger kex client? send)
    (cond ((or (string=? kex "diffie-hellman-group-exchange-sha256")
               (string=? kex "diffie-hellman-group-exchange-sha1"))
           (make-kex-dh-gex-key-exchanger kex client? send))
          ((or (string=? kex "diffie-hellman-group14-sha1")
               (string=? kex "diffie-hellman-group1-sha1"))
           (make-kex-dh-key-exchanger kex client? send))
          (else
           (error 'make-key-exchanger "Unimplemented key exchange algorithm"
                  kex))))

  (define (register-key-exchange kex reg)
    (cond ((or (string=? kex "diffie-hellman-group-exchange-sha256")
               (string=? kex "diffie-hellman-group-exchange-sha1"))
           (register-kex-dh-gex reg))
          ((or (string=? kex "diffie-hellman-group14-sha1")
               (string=? kex "diffie-hellman-group1-sha1"))
           (register-kexdh reg))
          (else
           (error 'register-key-exchange "Unimplemented key exchange algorithm"
                  kex)))))
