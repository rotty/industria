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

;; Procedures for dealing with OpenPGP messages.

;; XXX: Currently only does enough to verify detached signatures of
;; binary data.

;; 4880 OpenPGP Message Format. J. Callas, L. Donnerhacke, H. Finney, D.
;;      Shaw, R. Thayer. November 2007. (Format: TXT=203706 bytes) (Obsoletes
;;      RFC1991, RFC2440) (Updated by RFC5581) (Status: PROPOSED STANDARD)

;; TODO: radix64 reader, not just base64

(library (weinholt crypto openpgp (1 0 20100705))
  (export get-openpgp-keyring
          get-openpgp-detached-signature/ascii
          verify-openpgp-signature

          openpgp-signature?
          openpgp-signature-issuer
          (rename (openpgp-signature-pkalg
                   openpgp-signature-public-key-algorithm)
                  (openpgp-signature-halg
                   openpgp-signature-hash-algorithm))
          openpgp-signature-creation-time

          openpgp-user-id?
          openpgp-user-attribute?

          openpgp-public-key?
          openpgp-public-key-fingerprint
          openpgp-public-key-id
          )
  (import (rnrs)
          (srfi :19 time)
          (weinholt bytevectors)
          (weinholt crypto dsa)
          (weinholt crypto md5)
          (weinholt crypto rsa)
          (weinholt crypto sha-1)
          (weinholt crypto sha-2)
          (weinholt text base64)
          (weinholt struct pack))

  (define-syntax print
    (syntax-rules ()
      #;
      ((_ . args)
       (begin
         (for-each display (list . args))
         (newline)))
      ((_ . args) (values))))

  (define (unixtime n)
    (time-monotonic->date (make-time 'time-monotonic 0 n)))

  (define (bytevector->bitnames bv names)
    (define (bit-set? bv i)
      (let ((idx (fxarithmetic-shift-right i 3))
            (bit (fxand i #b111)))
        (and (< idx (bytevector-length bv))
             (fxbit-set? (bytevector-u8-ref bv idx) bit))))
    (do ((names names (cdr names))
         (i 0 (fx+ i 1))
         (bits '()
               (if (bit-set? bv i)
                   (cons (car names) bits)
                   bits)))
        ((null? names) (reverse bits))))

;;; Constants

  (define PACKET-SESSION-KEY 1)
  (define PACKET-SIGNATURE 2)
  ;; 3        -- Symmetric-Key Encrypted Session Key Packet
  ;; 4        -- One-Pass Signature Packet
  ;; 5        -- Secret-Key Packet
  (define PACKET-PUBLIC-KEY 6)
  ;; 7        -- Secret-Subkey Packet
  ;; 8        -- Compressed Data Packet
  ;; 9        -- Symmetrically Encrypted Data Packet
  ;; 10       -- Marker Packet
  ;; 11       -- Literal Data Packet
  (define PACKET-TRUST 12)
  (define PACKET-USER-ID 13)
  (define PACKET-PUBLIC-SUBKEY 14)
  (define PACKET-USER-ATTRIBUTE 17)
  ;; 18       -- Sym. Encrypted and Integrity Protected Data Packet
  ;; 19       -- Modification Detection Code Packet

  (define PUBLIC-KEY-RSA 1)
  (define PUBLIC-KEY-RSA-ENCRYPT-ONLY 2)
  (define PUBLIC-KEY-RSA-SIGN-ONLY 3)
  (define PUBLIC-KEY-ELGAMAL-ENCRYPT-ONLY 16)
  (define PUBLIC-KEY-DSA 17)

  (define (public-key-algorithm id)
    (cond ((= id PUBLIC-KEY-RSA) 'rsa)
          ((= id PUBLIC-KEY-DSA) 'dsa)
          ((= id PUBLIC-KEY-ELGAMAL-ENCRYPT-ONLY) 'elgamal)
          (else id)))

  (define SYMMETRIC-KEY-PLAINTEXT 0)
  (define SYMMETRIC-KEY-IDEA 1)
  (define SYMMETRIC-KEY-TRIPLE-DES 2)
  (define SYMMETRIC-KEY-CAST5-128 3)
  (define SYMMETRIC-KEY-BLOWFISH-128 4)
  (define SYMMETRIC-KEY-AES-128 7)
  (define SYMMETRIC-KEY-AES-192 8)
  (define SYMMETRIC-KEY-AES-256 9)
  (define SYMMETRIC-KEY-TWOFISH-256 10)

  (define (symmetric-key-algorithm id)
    (cond ((= id SYMMETRIC-KEY-PLAINTEXT) 'plaintext)
          ((= id SYMMETRIC-KEY-IDEA) 'idea)
          ((= id SYMMETRIC-KEY-TRIPLE-DES) 'tdea)
          ((= id SYMMETRIC-KEY-CAST5-128) 'cast5-128)
          ((= id SYMMETRIC-KEY-BLOWFISH-128) 'blowfish-128)
          ((= id SYMMETRIC-KEY-AES-128) 'aes-128)
          ((= id SYMMETRIC-KEY-AES-192) 'aes-192)
          ((= id SYMMETRIC-KEY-AES-256) 'aes-256)
          ((= id SYMMETRIC-KEY-TWOFISH-256) 'twofish-256)
          (else id)))

  (define HASH-MD5 1)
  (define HASH-SHA-1 2)
  (define HASH-RIPE-MD160 3)
  (define HASH-SHA-256 8)
  (define HASH-SHA-384 9)
  (define HASH-SHA-512 10)
  (define HASH-SHA-224 11)

  (define (hash-algorithm id)
    (cond ((= id HASH-MD5) 'md5)
          ((= id HASH-SHA-1) 'sha-1)
          ((= id HASH-RIPE-MD160) 'ripe-md160)
          ((= id HASH-SHA-256) 'sha-256)
          ((= id HASH-SHA-384) 'sha-384)
          ((= id HASH-SHA-512) 'sha-512)
          ((= id HASH-SHA-224) 'sha-224)
          (else id)))

  (define COMPRESSION-UNCOMPRESSED 0)
  (define COMPRESSION-ZIP 1)            ;deflate
  (define COMPRESSION-ZLIB 2)
  (define COMPRESSION-BZIP2 3)

  (define (compression-algorithm id)
    (cond ((= id COMPRESSION-UNCOMPRESSED) 'uncompressed)
          ((= id COMPRESSION-ZIP) 'deflate)
          ((= id COMPRESSION-ZLIB) 'zlib)
          ((= id COMPRESSION-BZIP2) 'bzip2)
          (else id)))

  (define SUBPACKET-SIGNATURE-CTIME 2)
  (define SUBPACKET-SIGNATURE-ETIME 3)
  ;;  4 = Exportable Certification
  (define SUBPACKET-TRUST-SIGNATURE 5)
  ;;  6 = Regular Expression
  (define SUBPACKET-REVOCABLE 7)
  (define SUBPACKET-KEY-ETIME 9)
  (define SUBPACKET-PREFERRED-SYMMETRIC-ALGORITHMS 11)
  ;; 12 = Revocation Key
  (define SUBPACKET-ISSUER 16)
  (define SUBPACKET-NOTATION-DATA 20)
  (define SUBPACKET-PREFERRED-HASH-ALGORITHMS 21)
  (define SUBPACKET-PREFERRED-COMPRESSION-ALGORITHMS 22)
  (define SUBPACKET-KEY-SERVER-PREFERENCES 23)
  (define SUBPACKET-PREFERRED-KEY-SERVER 24)
  (define SUBPACKET-PRIMARY-USER-ID 25)
  (define SUBPACKET-POLICY-URI 26)
  (define SUBPACKET-KEY-FLAGS 27)
  (define SUBPACKET-SIGNER-USER-ID 28)
  (define SUBPACKET-REASON-FOR-REVOCATION 29)
  (define SUBPACKET-FEATURES 30)
  ;; 31 = Signature Target
  (define SUBPACKET-EMBEDDED-SIGNATURE 32)

  (define SIGNATURE-BINARY #x00)
  (define SIGNATURE-TEXT #x01)
  (define SIGNATURE-STANDALONE #x02)
  (define SIGNATURE-GENERIC-CERT #x10)
  (define SIGNATURE-PERSONA-CERT #x11)
  (define SIGNATURE-CASUAL-CERT #x12)
  (define SIGNATURE-POSITIVE-CERT #x13)
  (define SIGNATURE-SUBKEY-BINDING #x18)
  (define SIGNATURE-PRIMARY-KEY-BINDING #x19)
  (define SIGNATURE-DIRECT #x1f)
  (define SIGNATURE-KEY-REVOCATION #x20)
  (define SIGNATURE-SUBKEY-REVOCATION #x28)
  (define SIGNATURE-CERT-REVOCATION #x30)
  (define SIGNATURE-TIMESTAMP #x40)
  (define SIGNATURE-THIRD-PARTY #x50)
  
;;; Parsing

  (define (get-mpi p)
    (let* ((bitlen (get-unpack p "!S"))
           (bytelen (fxdiv (fx+ bitlen 7) 8)))
      (print " MPI of length " bitlen " " (list bytelen))
      (bytevector->uint (get-bytevector-n p bytelen))))

  (define (get-v4-length p)
    ;; TODO: indeterminate length (only for data packets)
    (let ((o1 (get-u8 p)))
      (cond ((< o1 192) o1)
            ((< o1 255)
             (+ (fxarithmetic-shift-left (fx- o1 192) 8)
                (get-u8 p)
                192))
            ((= o1 255)
             (get-unpack p "!L")))))

  (define (get-packet p)
    (let ((tag (get-u8 p)))
      #;(unless (fxbit-set? tag 7)
          (error 'get-packet "Invalid tag" tag))
      (cond ((fxbit-set? tag 6)         ;New packet format
             (let ((tag (fxbit-field tag 0 6))
                   (len (get-v4-length p)))
               (get-data p tag len)))
            (else                       ;Old packet format
             (let ((tag (fxbit-field tag 2 6))
                   (len (case (fxbit-field tag 0 2)
                          ((0) (get-unpack p "!C"))
                          ((1) (get-unpack p "!S"))
                          ((2) (get-unpack p "!L"))
                          ((3) #f))))
               (get-data p tag len))))))

  (define (get-data p tag len)
    (let ((pp (if len
                  (open-bytevector-input-port (get-bytevector-n p len))
                  p)))                  ;indeterminate length
      (cond
        ((= tag PACKET-SIGNATURE)
         (get-signature pp))
        ((= tag PACKET-PUBLIC-KEY)
         (get-public-key pp #f))
        ((= tag PACKET-TRUST)
         'openpgp-trust)                ;non-standard format?
        ((= tag PACKET-USER-ID)
         (get-user-id pp len))
        ((= tag PACKET-PUBLIC-SUBKEY)
         (get-public-key pp #t))
        ((= tag PACKET-USER-ATTRIBUTE)
         (get-user-attribute pp len))
        (else
         (error 'get-data "Unsupported packet type" tag)))))

;;; Signatures

  (define-record-type openpgp-signature
    (fields version
            type
            pkalg halg
            hashl16
            append-data                 ;append to data when hashing
            hashed-subpackets
            unhashed-subpackets
            value))

  (define (openpgp-signature-issuer sig)
    (cond ((assq 'issuer (openpgp-signature-unhashed-subpackets sig)) => cdr)
          ;; XXX: is the issuer always in the unhashed subpackets?
          (else #f)))

  (define (openpgp-signature-creation-time sig)
    (cond ((assq 'signature-ctime (openpgp-signature-hashed-subpackets sig))
           => (lambda (x) (unixtime (cdr x))))
          ;; XXX: should be an error?
          (else #f)))

  ;; Read one ASCII armored detached OpenPGP signature
  (define (get-openpgp-detached-signature/ascii p)
    (define who 'get-openpgp-detached-signatures/ascii)
    (let-values (((type data) (get-delimited-base64 p)))
      (cond ((eof-object? data) data)
            ((string=? type "PGP SIGNATURE")
             (let ((pkt (get-packet (open-bytevector-input-port data))))
               (unless (openpgp-signature? pkt)
                 (error who "Expected an OpenPGP signature" pkt))
               pkt))
            (else
             (error who "Expected PGP SIGNATURE" type)))))

  ;; FIXME: some easy way to see which key made the signature, so the
  ;; user id can be displayed. will probably change the return value.
  ;; returns (good-signature (#<openpgp-public-key etc etc> ...)
  ;; returns (missing-key key-id)
  ;; FIXME: let user check for revoked keys
  (define (verify-openpgp-signature sig keyring dataport)
    (define who 'verify-openpgp-signature)
    (define (check-digest pgpkey digest)
      (print "Computed message digest: " digest)
      (let ((value (openpgp-signature-value sig))
            (key (openpgp-public-key-value pgpkey)))
        (cond ((dsa-public-key? key)
               (let ((digest
                      (subbytevector digest
                                     0
                                     (div (bitwise-length
                                           (dsa-public-key-q key))
                                          8))))
                 (if (apply dsa-verify-signature digest key value)
                     (values 'good-signature pgpkey)
                     (values 'bad-signature pgpkey))))
              ((rsa-public-key? key)
               (let ((digest* (rsa-pkcs1-decrypt-digest value key)))
                 ;; TODO: check the signature algorithm, i.e. that the
                 ;; object ID in (car digest*) matches
                 ;; (openpgp-signature-halg sig).
                 (print "Decrypted RSA signature: " digest*)
                 (if (bytevector=? (cadr digest*) digest)
                     (values 'good-signature pgpkey)
                     (values 'bad-signature pgpkey))))
              (else
               (error who "Unimplemented public key algorithm"
                      key)))))
    (define (verify pgpkey make-md md-update! md-finish! md->bytevector)
      (let ((md (make-md)))
        (let ((buf (make-bytevector (* 1024 16)))
              (type (openpgp-signature-type sig)))
          (cond
            ((= type SIGNATURE-BINARY)
             (let lp ()
               (unless (port-eof? dataport)
                 (let ((n (get-bytevector-n! dataport buf 0 (bytevector-length buf))))
                   (md-update! md buf 0 n)
                   (lp)))))
            ((= type SIGNATURE-TEXT)
             ;; TODO: newline conversion for textual signatures
             (error who "TODO: canonical text document signature"))
            (else
             (print "Signature made using invalid signature type")
             (values 'bad-signature pgpkey))))
        (for-each (lambda (bv) (md-update! md bv))
                  (openpgp-signature-append-data sig))
        (md-finish! md)
        (guard (cnd
                (else
                 (print "Error while verifying signature: " cnd)
                 ;; Note: identical to the return values from
                 ;; check-digest.
                 (values 'bad-signature pgpkey)))
          (check-digest pgpkey (md->bytevector md)))))
    (let ((issuer (openpgp-signature-issuer sig)))
      (cond ((hashtable-ref keyring issuer #f) =>
             (lambda (keydata)
               ;; Find the primary key or subkey that made the
               ;; signature.
               (let ((key (find (lambda (k)
                                  (and (openpgp-public-key? k)
                                       (= (openpgp-public-key-id k) issuer)))
                                keydata)))
                 (print "Signature made with key: " key)
                 (case (openpgp-signature-halg sig)
                   ((md5)
                    (verify key make-md5 md5-update!
                            md5-finish! md5->bytevector))
                   ((sha-1)
                    (verify key make-sha-1 sha-1-update!
                            sha-1-finish! sha-1->bytevector))
                   ((sha-256)
                    (verify key make-sha-256 sha-256-update!
                            sha-256-finish! sha-256->bytevector))
                   ((sha-384)
                    (verify key make-sha-384 sha-384-update!
                            sha-384-finish! sha-384->bytevector))
                   ((sha-512)
                    (verify key make-sha-512 sha-512-update!
                            sha-512-finish! sha-512->bytevector))
                   ((sha-224)
                    (verify key make-sha-224 sha-224-update!
                            sha-224-finish! sha-224->bytevector))
                   (else
                    ;; Only missing ripe-md160
                    (error who "Unimplemented signature algorithm"
                           (openpgp-signature-halg sig)))))))
            (else
             (values 'missing-key issuer)))))

  (define (get-signature p)
    (define who 'get-signature)
    (define (get-sig p pkalg)
      (cond ((= pkalg PUBLIC-KEY-RSA)
             (print "RSA signature")
             (get-mpi p))
            ((= pkalg PUBLIC-KEY-DSA)
             (print "DSA signature")
             (let* ((r (get-mpi p)) (s (get-mpi p)))
               (list r s)))
            (else
             (list 'unsupported-algorithm
                   (public-key-algorithm pkalg)
                   (get-bytevector-all p)))))
    (let ((version (get-u8 p)))
      (case version
        ((3)
         (let-values (((hmlen type ctime keyid pkalg halg hashl16)
                       (get-unpack p "!uCCLQCCS")))
           (unless (= hmlen 5)
             (error who "Invalid signature packet"))
           (print "Signature type: " type " creation time: " (unixtime ctime))
           (print "Hash algorithm: " (hash-algorithm halg))
           (let ((value (get-sig p pkalg)))
             (unless (port-eof? p)
               (print "Trailing data in signature: " (get-bytevector-all p)))
             (make-openpgp-signature version type
                                     (public-key-algorithm pkalg)
                                     (hash-algorithm halg) hashl16
                                     (list (pack "!uCL" type ctime))
                                     ;; Emulate hashed subpackets
                                     (list (cons 'signature-ctime ctime))
                                     ;; Unhashed subpackets
                                     (list (cons 'issuer keyid))
                                     value))))
        ((4)
         (let*-values (((type pkalg halg) (get-unpack p "!3C"))
                       ((hashed-subpackets)
                        (get-bytevector-n p (get-unpack p "!S")))
                       ((unhashed-subpackets)
                        (get-bytevector-n p (get-unpack p "!S")))
                       ((hashl16) (get-unpack p "!S")))
           (print "Signature type: " type)
           (print "Hash algorithm: " (hash-algorithm halg))
           (let ((value (get-sig p pkalg)))
             (unless (port-eof? p)
               (print "Trailing data in signature: " (get-bytevector-all p)))
             (let ((append-data
                    (list
                     (pack "!4CS" version type pkalg halg
                           (bytevector-length hashed-subpackets))
                     hashed-subpackets
                     ;; http://www.rfc-editor.org/errata_search.php?rfc=4880
                     ;; Errata ID: 2214.
                     (pack "!uCCL" #x04 #xff
                           (+ (format-size "!4CS")
                              (bytevector-length hashed-subpackets))))))
               (make-openpgp-signature version type
                                       (public-key-algorithm pkalg)
                                       (hash-algorithm halg) hashl16
                                       append-data
                                       (parse-subpackets hashed-subpackets)
                                       (parse-subpackets unhashed-subpackets)
                                       value)))))
        (else
         (error who "Unsupported signature version" version)))))

  (define (parse-subpackets bv)
    (define (parse tag data)
      (let ((type (fxbit-field tag 0 7))
            (critical? (fxbit-set? tag 7)))
        (cond
          ((= type SUBPACKET-SIGNATURE-CTIME)
           (cons 'signature-ctime (unpack "!L" data)))
          ((= type SUBPACKET-SIGNATURE-ETIME)
           (cons 'signature-etime (unpack "!L" data)))
          ((= type SUBPACKET-TRUST-SIGNATURE)
           (cons 'trust-signature (let-values ((x (unpack "CC" data)))
                                    x)))
          ((= type SUBPACKET-REVOCABLE)
           (cons 'revocable (= (unpack "C" data) 1)))
          ((= type SUBPACKET-KEY-ETIME)
           (cons 'key-etime (unpack "!L" data)))
          ((= type SUBPACKET-PREFERRED-SYMMETRIC-ALGORITHMS)
           (cons 'preferred-symmetric-algorithms
                 (map symmetric-key-algorithm (bytevector->u8-list data))))
          ((= type SUBPACKET-ISSUER)
           (cons 'issuer (unpack "!Q" data)))
          ((= type SUBPACKET-NOTATION-DATA)
           (let ((p (open-bytevector-input-port data)))
             (let-values (((f1 nlen vlen) (get-unpack p "!CxxxSS")))
               (let* ((name (get-bytevector-n p nlen))
                      (value (get-bytevector-n p vlen)))
                 (cons 'notation-data
                       (list (utf8->string name)
                             (if (fxbit-set? f1 7)
                                 (utf8->string value)
                                 value)))))))
          ((= type SUBPACKET-PREFERRED-HASH-ALGORITHMS)
           (cons 'preferred-hash-algorithms
                 (map hash-algorithm (bytevector->u8-list data))))
          ((= type SUBPACKET-PREFERRED-COMPRESSION-ALGORITHMS)
           (cons 'preferred-compression-algorithms
                 (map compression-algorithm (bytevector->u8-list data))))
          ((= type SUBPACKET-KEY-SERVER-PREFERENCES)
           (cons 'key-server-preferences
                 (if (and (>= (bytevector-length data) 1)
                          (fxbit-set? (unpack "C" data) 7))
                     (list 'no-modify)
                     (list))))
          ((= type SUBPACKET-PREFERRED-KEY-SERVER)
           (cons 'preferred-key-server (utf8->string data)))
          ((= type SUBPACKET-PRIMARY-USER-ID)
           (cons 'primary-user-id (not (zero? (unpack "C" data)))))
          ((= type SUBPACKET-POLICY-URI)
           (cons 'policy-uri (utf8->string data)))
          ((= type SUBPACKET-KEY-FLAGS)
           (cons 'key-flags (bytevector->bitnames
                             data
                             '(certification sign-data
                                             communications-encryption
                                             storage-encryption
                                             split-key authentication
                                             group-key))))
          ((= type SUBPACKET-SIGNER-USER-ID)
           (cons 'signer-user-id (utf8->string data)))
          ((= type SUBPACKET-REASON-FOR-REVOCATION)
           (let* ((p (open-bytevector-input-port data))
                  (revocation-code (get-u8 p)))
             (cons 'reason-for-revocation
                   (list revocation-code
                         (if (port-eof? p)
                             ""
                             (utf8->string (get-bytevector-all p)))))))
          ((= type SUBPACKET-FEATURES)
           (cons 'features (bytevector->bitnames
                            data '(modification-detection))))
          ((= type SUBPACKET-EMBEDDED-SIGNATURE)
           (cons 'embedded-signature
                 (get-signature (open-bytevector-input-port data))))
          (else
           ;; Unknown subpacket type. If it is critical, then the
           ;; signature should be considered invalid.
           (print "Unknown subpacket type: " type)
           (list 'unsupported-subpacket type critical? data)))))
    (let ((p (open-bytevector-input-port bv)))
      (let lp ((subpackets '()))
        ;; In case of multiple subpackets of the same type, the last
        ;; one should be used. Therefore the list is not reversed
        ;; here.
        (if (port-eof? p)
            subpackets
            (let* ((len (- (get-v4-length p) 1))
                   (tag (get-u8 p))
                   (sp (parse tag (get-bytevector-n p len))))
              (print "#;Subpacket " sp)
              (lp (cons sp subpackets)))))))

;;; Public keys

  (define-record-type openpgp-public-key
    (fields version subkey? time value
            fingerprint id))

  (define (get-public-key p subkey?)
    (define who 'get-public-key)
    (define (fingerprint p)
      (let ((len (port-position p)))
        (set-port-position! p 0)
        (sha-1 (pack "!uCS" #x99 len) (get-bytevector-all p))))
    (define (get-key p alg)
      (cond ((= alg PUBLIC-KEY-RSA)
             (print "Public RSA key")
             (let* ((n (get-mpi p)) (e (get-mpi p)))
               (make-rsa-public-key n e)))
            ((= alg PUBLIC-KEY-DSA)
             (print "Public DSA key")
             (let* ((p* (get-mpi p)) (q (get-mpi p))
                    (g (get-mpi p)) (y (get-mpi p)))
               (make-dsa-public-key p* q g y)))
            #;
            ((= alg PUBLIC-KEY-ELGAMAL-ENCRYPT-ONLY)
             (print "Public El-Gamal Key")
             (let* ((p* (get-mpi p)) (g (get-mpi p)) (y (get-mpi p)))
               (make-public-elgamal-key p* g y)))
            (else
             (list 'unsupported-algorithm
                   (public-key-algorithm alg)
                   (get-bytevector-all p)))))
    (let ((version (get-u8 p)))
      (case version
        ((4)
         (let-values (((ctime alg) (get-unpack p "!LC")))
           (print "Key creation time: " (unixtime ctime))
           (let ((key (get-key p alg)))
             (unless (port-eof? p)
               ;; Probably an error? Gonna cause trouble anyway.
               (print "Trailing data in public key: " (get-bytevector-all p)))
             (let ((digest (fingerprint p)))
               (make-openpgp-public-key version subkey? ctime key
                                        (sha-1->string digest)
                                        (let ((bv (sha-1->bytevector digest)))
                                          (unpack "!uQ" bv
                                                  (- (bytevector-length bv)
                                                     (format-size "!uQ")))))))))
        (else (error who "Unsupported public key version" version)))))

  (define (openpgp-public-key-primary? key)
    (and (openpgp-public-key? key)
         (not (openpgp-public-key-subkey? key))))

;;; User IDs and User attributes

  (define-record-type openpgp-user-id (fields unparsed))

  (define (openpgp-user-id-value x)
    (utf8->string (openpgp-user-id-unparsed x)))

  (define (get-user-id p len)
    ;; utf8 conversion is delayed
    (make-openpgp-user-id (get-bytevector-n p len)))

  (define-record-type openpgp-user-attribute (fields unparsed))

  (define (get-user-attribute p len)
    (let ((bv (get-bytevector-n p len)))
      ;; TODO: bv contains subpackets. Type 1 is JFIF.
      (make-openpgp-user-attribute bv)))

;;; Keyring management

  ;; Reads a keyring from the binary input port p. It must not be
  ;; ASCII armored.
  (define (get-openpgp-keyring p)
    (define (get-pkt p)
      (guard (cnd (else cnd))
        (if (port-eof? p)
            (eof-object)
            (get-packet p))))
    (let ((kr (make-eqv-hashtable)))
      (let lp ((pkt (get-pkt p)))
        (print "#;key " pkt)
        (cond ((eof-object? pkt) kr)
              ((openpgp-public-key-primary? pkt)
               ;; Read signatures, user id's, subkeys
               (let lp* ((pkt (get-pkt p))
                         (pkts (list pkt))
                         (key-ids (list (openpgp-public-key-id pkt))))
                 (print "#;keydata " pkt)
                 (cond ((or (eof-object? pkt)
                            (openpgp-public-key-primary? pkt))
                        (let ((pkts (reverse pkts)))
                          ;; Hashtable is indexed by key-id. Key ids
                          ;; for both the primary key and subkeys all
                          ;; point to the list of packets.
                          (for-each (lambda (key-id)
                                      (print "#;key-id " key-id)
                                      (hashtable-set! kr key-id pkts))
                                    key-ids)
                          (lp pkt)))
                       ((openpgp-public-key? pkt) ;subkey
                        (lp* (get-pkt p) (cons pkt pkts)
                             (cons (openpgp-public-key-id pkt) key-ids)))
                       ((condition? pkt)
                        ;; Ignore errors reading the keyring.
                        (lp* (get-pkt p) pkts key-ids))
                       (else
                        (lp* (get-pkt p) (cons pkt pkts) key-ids)))))
              (else
               ;; Skip until there's a primary key. Ignore errors...
               (lp (get-pkt p)))))))

  ;; XXX: should probably detect ascii armoring
  (define (openpgp-keyring-from-file filename)
    (call-with-port (open-file-input-port filename)
      (lambda (p) (get-openpgp-keyring p))))

  )
