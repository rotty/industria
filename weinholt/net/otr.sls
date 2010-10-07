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

;; Off-the-Record Messaging Protocol version 2

;; http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html

;; TODO: fix the state transitions (most are probably missing)
;; TODO: Ypsilon is very slow on D-H key generation.
;; TODO: should it be possible to establish a session with someone
;; using our own DSA key?
;; TODO: finishing sessions.
;; TODO: let the library user decide what errors to send

(library (weinholt net otr (0 0 20101007))
  (export otr-message?
          otr-update!
          otr-send-encrypted!
          otr-authenticate!
          otr-empty-queue!
          make-otr-state
          otr-state-their-dsa-key
          otr-state-our-dsa-key
          otr-state-secure-session-id
          otr-hash-public-key
          otr-format-session-id
          otr-state-mss otr-state-mss-set!)
  (import (rnrs)
          (only (srfi :1 lists) iota map-in-order
                alist-delete take)
          (only (srfi :13 strings) string-contains string-join
                string-index string-index-right string-pad
                string-trim-right)
          (srfi :26 cut)
          (srfi :27 random-bits)
          (srfi :39 parameters)
          (weinholt bytevectors)
          (weinholt crypto aes)
          (weinholt crypto dsa)
          (weinholt crypto entropy)
          (weinholt crypto math)
          (weinholt crypto sha-1)
          (weinholt crypto sha-2)
          (weinholt struct pack)
          (weinholt text base64)
          (weinholt text strings))

;;; Helpers

  (define-syntax print
    (syntax-rules ()
      #;
      ((_ . args)
       (begin
         (for-each display (list . args))
         (newline)))
      ((_ . args) (values))))

  (define (hex x)
    (string-append "#x" (number->string x 16)))

  (define (make-secret g n bits tries) ;also in net/irc/fish, should be in crypto/dh maybe?
    (unless (< tries 1000)
      (error 'make-secret "unable to make a secret"))
    (let* ((y (bytevector->uint (make-random-bytevector (div (+ bits 7) 8))))
           (Y (expt-mod g y n)))
      ;; See RFC 2631. Probably not clever enough.
      (if (and (<= 2 Y (- n 1))
               (= 1 (expt-mod Y (/ (- n 1) 2) n)))
          (values y Y)
          (make-secret g n bits (+ tries 1)))))

  (define (get-bytevector p n)
    (when (> n 65536)
      (error 'get-bytevector "unlikely read size" n))
    (let ((ret (get-bytevector-n p n)))
      (unless (eqv? (bytevector-length ret) n)
        (error 'get-bytevector "short read" n (bytevector-length ret)))
      ret))

  ;; OTR's multiple precision integer format.
  (define (mpi->uint bv)
    (bytevector-uint-ref bv 4 (endianness big)
                         (bytevector-u32-ref bv 0 (endianness big))))

  (define (uint->mpi int)
    (let* ((len (div (bitwise-and -8 (+ 7 (bitwise-length int))) 8))
           (ret (make-bytevector (+ 4 len))))
      (bytevector-u32-set! ret 0 len (endianness big))
      (unless (zero? len)
        (bytevector-uint-set! ret 4 int (endianness big) len))
      ret))

  (define (dsa-public-key->bytevector key)
    (bytevector-append
     (pack "!S" key-type-dsa)
     (uint->mpi (dsa-public-key-p key))
     (uint->mpi (dsa-public-key-q key))
     (uint->mpi (dsa-public-key-g key))
     (uint->mpi (dsa-public-key-y key))))

  (define (get-public-dsa-key port)
    ;; Read a public DSA key from the X in reveal-signature or
    ;; signature messages.
    (let* ((p (bytevector->uint (get-bytevector port (get-unpack port "!L"))))
           (q (bytevector->uint (get-bytevector port (get-unpack port "!L"))))
           (g (bytevector->uint (get-bytevector port (get-unpack port "!L"))))
           (y (bytevector->uint (get-bytevector port (get-unpack port "!L")))))
      (make-dsa-public-key p q g y)))

  (define (get-public-key p)
    ;; Read the DSA public key from pub[A] in: X[A] = pub[A],
    ;; keyid[A], sig[A](M[A]).
    (let ((keytype (get-unpack p "!S")))
      (if (= keytype key-type-dsa)
          (get-public-dsa-key p)
          (error 'auth-state-awaiting-reveal-sig "Bad keytype" keytype))))

  (define (sign-public-key key secret keyid Y X)
    ;; Signs the public part of the private key and returns pub[B],
    ;; keyid[B], sig[B](M[B]).
    (let*-values (((pub) (dsa-public-key->bytevector
                          (dsa-private->public key)))
                  ((r s) (dsa-create-signature
                          (sha-256->bytevector
                           (hmac-sha-256 secret
                                         (uint->mpi Y) (uint->mpi X)
                                         pub
                                         (pack "!L" keyid)))
                          key)))
      (bytevector-append pub
                         (pack "!L" keyid)
                         (bytevector-pad (uint->bytevector r) q-len 0)
                         (bytevector-pad (uint->bytevector s) q-len 0))))

  (define (verify-public-key key secret keyid X Y r s)
    (dsa-verify-signature (sha-256->bytevector
                           (hmac-sha-256 secret
                                         (uint->mpi X) (uint->mpi Y)
                                         (dsa-public-key->bytevector key)
                                         (pack "!L" keyid)))
                          key r s))

  (define (bytevector-pad bv outlen padding)
    (let ((inlen (bytevector-length bv))
          (ret (make-bytevector outlen padding)))
      (bytevector-copy! bv (if (< outlen inlen) (- inlen outlen) 0)
                        ret (max 0 (- outlen inlen))
                        (min outlen inlen))
      ret))

  (define (MAC secret . data)
    (subbytevector (sha-256->bytevector
                    (apply hmac-sha-256 secret data))
                   0 160/8))


  (define (h1 b secbytes)
    (let ((s (make-sha-1)))
      (sha-1-update! s (make-bytevector 1 b))
      (sha-1-update! s secbytes)
      (sha-1-finish! s)
      (let ((ret (sha-1->bytevector s)))
        (sha-1-clear! s)
        ret)))

  (define (h2 b secbytes)
    (let ((s (make-sha-256)))
      (sha-256-update! s (make-bytevector 1 b))
      (sha-256-update! s secbytes)
      (sha-256-finish! s)
      (let ((ret (sha-256->bytevector s)))
        (sha-256-clear! s)
        ret)))

  (define (make-keys X y)
    (let* ((secbytes (uint->mpi (expt-mod X y n)))
           (ssid (bytevector-u64-ref (h2 0 secbytes) 0
                                     (endianness big)))
           (key-material (h2 1 secbytes))
           (aeskey (subbytevector key-material 0 16))
           (aeskey* (subbytevector key-material 16 32))
           (m1 (h2 2 secbytes))
           (m2 (h2 3 secbytes))
           (m1* (h2 4 secbytes))
           (m2* (h2 5 secbytes)))
      ;; XXX: can't actually erase the result of expt-mod and so on...
      (bytevector-fill! secbytes 0)
      (bytevector-fill! key-material 0)
      (let ((c (expand-aes-key aeskey))
            (c* (expand-aes-key aeskey*)))
        (bytevector-fill! aeskey 0)
        (bytevector-fill! aeskey* 0)
        (values ssid c c* m1 m2 m1* m2*))))

;;;

  (define otr-version #x0002)

  (define whitespace-prefix
    (string-append "\x20;\x09;\x20;\x20;\x09;\x09;\x09;\x09;"
                   "\x20;\x09;\x20;\x09;\x20;\x09;\x20;\x20;"))

  (define v2-tag "\x20;\x20;\x09;\x09;\x20;\x20;\x09;\x20;")

  ;; Diffie-Hellman modulus and generator. Diffie-Hellman Group 5 from
  ;; RFC 3526.
  (define n
    (string->number
     "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
      29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
      EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
      E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
      EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
      C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
      83655D23DCA3AD961C62F356208552BB9ED529077096966D\
      670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
     16))
  (define g 2)

  (define dh-length 640)              ;length for the private D-H keys

  ;; XXX: unfortunately libotr assumes 160-bit signatures. It is
  ;; assumed here as well for simplicity, but should probably be
  ;; generalized.
  (define q-len 160/8)                  ;1024-bit DSA keys, 160-bit q

  ;; Message types
  (define msg-diffie-hellman-commit #x02)
  (define msg-diffie-hellman-key #x0a)
  (define msg-reveal-signature #x11)
  (define msg-signature #x12)
  (define msg-data #x03)

  ;; Data message flags
  (define flag-ignore-unreadable #b00000001)

  ;; Key types
  (define key-type-dsa #x0000)

  ;; TLV types (tag-length-value)
  (define tlv-null #x0000)
  (define tlv-disconnect #x0001)
  (define tlv-smp-1 #x0002)
  (define tlv-smp-2 #x0003)
  (define tlv-smp-3 #x0004)
  (define tlv-smp-4 #x0005)
  (define tlv-smp-abort #x0006)
  ;; This one is not in the specification, but it's in libotr 3.2.0's
  ;; UPGRADING. Supposedly contains a question, but is otherwise like
  ;; #x0002.
  (define tlv-smp-1q #x0007)

  (define (smp-tlv? i)
    (memv (car i) (list tlv-smp-1 tlv-smp-2 tlv-smp-3 tlv-smp-4
                        tlv-smp-abort tlv-smp-1q)))

  (define-record-type otr-state
    (opaque #t)
    (nongenerative otr-state-92d95444-59ad-4658-9d3f-8d605ad87180)
    (fields (immutable our-dsa-key)
            (mutable their-dsa-key)
            (mutable secure-session-id)
            ;; Maximum segment size
            (mutable mss)
            ;; De-fragmentation buffer
            (mutable frag-n)
            (mutable frag-k)
            (mutable frags)
            ;; Result queue
            (mutable queue)
            ;; Handler for the next message
            (mutable k)
            ;; Diffie-Hellman keys
            (mutable our-keys)
            (mutable their-pubkeys)
            (mutable our-latest-acked)
            (mutable our-pubkeys)
            ;; MAC keys
            (mutable mackeys)
            ;; Last used top half of the AES counter
            (mutable their-ctr)
            (mutable our-ctr)
            ;; SMP state
            (mutable smp))
    (protocol
     (lambda (p)
       (lambda (dsa-key mss)
         (assert (dsa-private-key? dsa-key))
         ;; The DSA keys have to have a 160-bit q-parameter, or the
         ;; reference implementation will reject the signatures. A
         ;; 1024-bit DSA key will probably be OK.
         (assert (= 160 (bitwise-length (dsa-private-key-q dsa-key))))
         (p dsa-key #f 0 mss
            0 0 '()
            '()
            plaintext-state
            '() '() 0 '()
            '()
            '() 0
            #f)))))

  (define-record-type smp-state
    (opaque #t)
    (nongenerative smp-state-edef0336-67da-4d9e-8851-f4d41bf1d9e8)
    (fields (mutable next)
            (mutable values))
    (protocol
     (lambda (p)
       (lambda ()
         (p 'expect1 '())))))

  ;; (define-enumeration policy
  ;;   (allow-v1 allow-v2 require-encryption send-whitespace-tag
  ;;             whitespace-start-ake error-start-ake)
  ;;   otr-policy)

  (define (set-established! state ssid our-keyid y Y their-keyid X their-dsa-key)
    (otr-state-our-keys-set! state (list (cons our-keyid y)))
    (otr-state-our-pubkeys-set! state (list (cons our-keyid Y)))
    (otr-state-their-pubkeys-set! state (list (cons their-keyid X)))
    (otr-state-their-dsa-key-set! state their-dsa-key)
    (otr-state-secure-session-id-set! state ssid)
    (otr-state-their-ctr-set! state '())
    (otr-state-our-ctr-set! state 0)
    (otr-state-our-latest-acked-set! state our-keyid)
    (otr-state-smp-set! state (make-smp-state)))

  (define (forget-session! state)
    (otr-state-our-keys-set! state '())
    (otr-state-our-pubkeys-set! state '())
    (otr-state-their-pubkeys-set! state '())
    (otr-state-their-dsa-key-set! state #f)
    (otr-state-secure-session-id-set! state 0)
    (otr-state-their-ctr-set! state '())
    (otr-state-our-ctr-set! state 0)
    (otr-state-our-latest-acked-set! state 0)
    (otr-state-smp-set! state #f))

  ;; Verify that an incoming counter value is larger than the previous
  ;; value used for these key ids.
  (define (verify-ctr state ctr skeyid rkeyid)
    (print (list 'their-ctr (otr-state-their-ctr state)))
    (cond ((assoc (cons skeyid rkeyid) (otr-state-their-ctr state))
           => (lambda (c) (> ctr (cdr c))))
          (else #t)))

  ;; Associate a new counter value with these key ids.
  (define (store-ctr! state ctr skeyid rkeyid)
    (otr-state-their-ctr-set! state
                              (cons (cons (cons skeyid rkeyid) ctr)
                                    (alist-delete (cons skeyid rkeyid)
                                                  (otr-state-their-ctr state)))))

  ;; Remove counter values that are no longer needed.
  (define (remove-old-ctrs! state)
    (otr-state-their-ctr-set!
     state
     (filter (lambda (c)
               (or (assv (caar c) (otr-state-their-pubkeys (*state*)))
                   (assv (cdar c) (otr-state-our-pubkeys (*state*)))))
             (otr-state-their-ctr state))))

  ;; Remember the MAC key associated with these key ids.
  (define (store-mackey! state mackey their-keyid our-keyid)
    (let ((k (cons their-keyid our-keyid)))
      (unless (assoc k (otr-state-mackeys state))
        (print "Remembering MAC key: " (list their-keyid our-keyid mackey))
        (otr-state-mackeys-set! state
                                (cons (cons k mackey)
                                      (otr-state-mackeys state))))))

  ;; Remove and return MAC keys that can not possibly be used any
  ;; more.
  (define (remove-old-mackeys! state)
    (let-values (((remembered forgotten)
                  (partition
                   (lambda (k)
                     (or (assv (caar k) (otr-state-their-pubkeys (*state*)))
                         (assv (cdar k) (otr-state-our-pubkeys (*state*)))))
                   (otr-state-mackeys state))))
      (otr-state-mackeys-set! state remembered)
      (map cdr forgotten)))


  (define (fragment outmsg mss)
    ;; Splits an outgoing message into pieces that fit in the maximum
    ;; message size. TODO: maximize space usage.
    (if (< (string-length outmsg) mss)
        (list outmsg)
        (let ((mss (- mss (string-length "?OTR,12345,12345,,"))))
          (let lp ((pieces '())
                   (outmsg outmsg))
            (if (<= (string-length outmsg) mss)
                (let* ((pieces (cons outmsg pieces))
                       (total (length pieces)))
                  (map (lambda (p i)
                         (string-append "?OTR," (number->string i)
                                        "," (number->string total)
                                        "," p ","))
                       (reverse pieces) (iota total 1)))
                (lp (cons (substring outmsg 0 mss) pieces)
                    (substring outmsg mss (string-length outmsg))))))))

  (define (hash-public-key pubkey)
    (let ((pub (dsa-public-key->bytevector pubkey))
          (m (make-sha-1)))
      (sha-1-update! m pub
                     (if (zero? (unpack "!S" pub))
                         2
                         0)
                     (bytevector-length pub))
      (sha-1-finish! m)
      (sha-1->bytevector m)))

  (define (otr-hash-public-key pubkey)
    ;; Returns the SHA-1 hash of a key, formatted for the user.
    (string-upcase
     (string-join (map (lambda (i) (string-pad (number->string i 16) 8 #\0))
                       (bytevector->uint-list (hash-public-key pubkey)
                                              (endianness big) 4))
                  " ")))

  (define (otr-format-session-id id)
    ;; Formats a secure session ID for the user.
    (string-upcase
     (string-append (string-pad (number->string (bitwise-bit-field id 32 64) 16) 8 #\0)
                    " "
                    (string-pad (number->string (bitwise-bit-field id 0 32) 16) 8 #\0))))

;;; Protocol state machine building blocks

  (define *state* (make-parameter 'no-state))

  (define (send msg)
    (assert (bytevector? msg))
    (for-each (cut queue-data 'outgoing <>)
              (fragment (string-append "?OTR:" (base64-encode msg) ".")
                        (otr-state-mss (*state*)))))

  ;; Send an error message to the correspondent. It will probably be
  ;; shown verbatim, or perhaps it will be translated if it matches
  ;; one of the messages libotr uses.
  (define (send-error msg)
    (assert (string? msg))
    (queue-data 'outgoing (string-append "?OTR Error: " msg)))

  (define (queue-data type data)
    (otr-state-queue-set!
     (*state*)
     (append (otr-state-queue (*state*))
             (list (cons type data)))))

  (define (otr-empty-queue! state)
    (let ((queue (otr-state-queue state)))
      (otr-state-queue-set! state '())
      queue))

  (define (return state p)
    (parameterize ((*state* state))
      (guard (con
              ;; TODO: Should probably only handle the explicit error
              ;; calls and reset the session.
              (else
               (when (message-condition? con)
                 (print "Error: " (condition-message con)))
               (queue-data 'local-error con)))
        ((otr-state-k (*state*)) p))))

  (define (next-state proc . args)
    ;; Set the procedure that handles the next incoming message.
    (otr-state-k-set! (*state*) (lambda (p) (apply proc p args))))
  
;;; Socialist Milllionaire's Protocol

  ;; The state transitions are much simpler here so continuations are
  ;; not used. All messages have been decrypted and MACed etc, so only
  ;; the correspondent can pass us SMP messages.

  (define smp-version 1)

  ;; Subtraction and multiplication for the zero-knowledge proofs is
  ;; done modulo this number, which is called q in Alexander and
  ;; Goldberg's paper.
  (define order (/ (- n 1) 2))

  (define (smp-secret user-input we-start)
    (let ((m (make-sha-256))
          (their (hash-public-key (otr-state-their-dsa-key (*state*))))
          (our (hash-public-key (dsa-private->public
                                 (otr-state-our-dsa-key (*state*))))))
      (sha-256-update! m (make-bytevector 1 smp-version))
      (sha-256-update! m (if we-start our their))
      (sha-256-update! m (if we-start their our))
      (sha-256-update! m (pack "!Q" (otr-state-secure-session-id (*state*))))
      (sha-256-update! m user-input)
      (sha-256-finish! m)
      (bytevector->uint (sha-256->bytevector m))))

  (define (smp-hash version . ints)
    (bytevector->uint
     (sha-256->bytevector (apply sha-256 (make-bytevector 1 version)
                                 (map uint->mpi ints)))))

  (define (send-smp type . ints)
    (print "Sending SMP values: " ints)
    ;; TODO: how about only putting the TLV in a queue and sending it
    ;; along with the next user message? Might complicate the API, but
    ;; might also save some bandwidth because of the next-key
    ;; overhead.
    (otr-send-encrypted! (*state*) "" (tlv-encode type (apply bytevector-append
                                                              (pack "!L" (length ints))
                                                              (map uint->mpi ints)))))

  (define (smp-goto next)
    (smp-state-next-set! (otr-state-smp (*state*)) next))

  (define (save-smp-values . x)
    (print "New SMP values: " x)
    (smp-state-values-set! (otr-state-smp (*state*))
                           (append x (smp-state-values
                                      (otr-state-smp (*state*))))))

  (define (get-smp-value id)
    (cond ((memq id (smp-state-values
                     (otr-state-smp (*state*))))
           => cadr)
          (else (error 'get-smp-value "undefined value" id))))

  (define (random-exponent)
    ;; "Pick random exponents" in the spec.
    (bytevector->uint (make-random-bytevector 1536/8)))

  (define (random-value)
    ;; "Pick random values" in the spec.
    (bytevector->uint (make-random-bytevector 128/8)))

  ;; This takes one TLV from the correspondent and carefully crafts a
  ;; witty reply.
  (define (handle-smp tlv)
    (define (abort)
      (print "Aborting SMP.")
      (otr-state-smp-set! (*state*) (make-smp-state))
      (cond ((= (car tlv) tlv-smp-abort)
             (queue-data 'authentication 'aborted-by-them))
            (else
             (queue-data 'authentication 'aborted-by-us)
             (otr-send-encrypted! (*state*) "" (tlv-encode tlv-smp-abort #vu8())))))
    (define (get-ints)
      (let ((p (open-bytevector-input-port (cdr tlv))))
        (apply values (map-in-order
                       (lambda (i)
                         (bytevector->uint (get-bytevector p (get-unpack p "!L"))))
                       (iota (get-unpack p "!L"))))))
    (guard (exn
            (else
             (print "SMP error: " exn)
             (abort)))
      (let ((smp (otr-state-smp (*state*)))
            (type (car tlv)))
        (print "SMP " type " ")
        (case (smp-state-next smp)
          ((expect1)
           (assert (or (= type tlv-smp-1) (= type tlv-smp-1q)))
           (let-values (((g2a c2 D2 g3a c3 D3) (get-ints)))
             ;; TODO: sanity checks on the incoming values
             ;; Verify zero-knowledge proofs:
             (unless (= c2 (smp-hash 1 (mod (* (expt-mod g D2 n) (expt-mod g2a c2 n)) n)))
               (error 'smp-expect1 "c2 is bad"))
             (unless (= c3 (smp-hash 2 (mod (* (expt-mod g D3 n) (expt-mod g3a c3 n)) n)))
               (error 'smp-expect1 "c3 is bad"))
             (save-smp-values 'g2a g2a 'g3a g3a)
             ;; Wait for the local secret. TODO: get the user
             ;; message from 1q messages.
             (queue-data 'authentication 'expecting-secret)
             (smp-goto 'expecting-secret)))
          ((expect2)
           (assert (= type tlv-smp-2))
           (let-values (((g2b c2 D2 g3b c3 D3 Pb Qb cP D5 D6) (get-ints)))
             ;; TODO: sanity checks
             (unless (= c2 (smp-hash 3 (mod (* (expt-mod g D2 n) (expt-mod g2b c2 n)) n)))
               (error 'smp-expect2 "c2 is bad"))
             (unless (= c3 (smp-hash 4 (mod (* (expt-mod g D3 n) (expt-mod g3b c3 n)) n)))
               (error 'smp-expect2 "c3 is bad"))
             (let ((g2 (expt-mod g2b (get-smp-value 'a2) n))
                   (g3 (expt-mod g3b (get-smp-value 'a3) n)))
               (unless (= cP (smp-hash 5 (mod (* (expt-mod g3 D5 n)
                                                 (expt-mod Pb cP n))
                                              n)
                                       (mod (* (expt-mod g D5 n)
                                               (expt-mod g2 D6 n)
                                               (expt-mod Qb cP n))
                                            n)))
                 (error 'smp-expect2 "cP is bad"))
               (let ((r4 (random-exponent))
                     (r5 (random-exponent))
                     (r6 (random-exponent))
                     (r7 (random-exponent)))
                 (let ((Pa (expt-mod g3 r4 n))
                       (Qa (mod (* (expt-mod g r4 n)
                                   (expt-mod g2 (get-smp-value 'x) n))
                                n)))
                   ;; zero-knowledge proofs:
                   (let* ((cP (smp-hash 6 (expt-mod g3 r5 n)
                                        (mod (* (expt-mod g r5 n)
                                                (expt-mod g2 r6 n))
                                             n)))
                          (D5 (mod (- r5 (* r4 cP)) order))
                          (D6 (mod (- r6 (* (get-smp-value 'x) cP)) order)))
                     (let ((Pa/Pb (mod (* Pa (expt-mod Pb -1 n)) n))
                           (Qa/Qb (mod (* Qa (expt-mod Qb -1 n)) n)))
                       (let ((Ra (expt-mod Qa/Qb (get-smp-value 'a3) n)))
                         ;; More zero-knowledge proofs:
                         (let* ((cR (smp-hash 7 (expt-mod g r7 n)
                                              (expt-mod Qa/Qb r7 n)))
                                (D7 (mod (- r7 (* (get-smp-value 'a3) cR)) order)))
                           (save-smp-values 'g3b g3b 'Pa/Pb Pa/Pb
                                            'Qa/Qb Qa/Qb 'Ra Ra)
                           (send-smp tlv-smp-3 Pa Qa cP D5 D6 Ra cR D7)
                           (smp-goto 'expect4))))))))))
          ((expect3)
           (assert (= type tlv-smp-3))
           (let-values (((Pa Qa cP D5 D6 Ra cR D7) (get-ints)))
             ;; TODO: sanity checks on the incoming values
             (unless (= cP (smp-hash 6 (mod (* (expt-mod (get-smp-value 'g3) D5 n)
                                               (expt-mod Pa cP n))
                                            n)
                                     (mod (* (expt-mod g D5 n)
                                             (expt-mod (get-smp-value 'g2) D6 n)
                                             (expt-mod Qa cP n))
                                          n)))
               (error 'smp-expect3 "cP is bad"))
             (let ((Pa/Pb (mod (* Pa (expt-mod (get-smp-value 'Pb) -1 n)) n))
                   (Qa/Qb (mod (* Qa (expt-mod (get-smp-value 'Qb) -1 n)) n))
                   (b3 (get-smp-value 'b3)))
               (unless (= cR (smp-hash 7 (mod (* (expt-mod g D7 n)
                                                 (expt-mod (get-smp-value 'g3a) cR n))
                                              n)
                                       (mod (* (expt-mod Qa/Qb D7 n)
                                               (expt-mod Ra cR n))
                                            n)))
                 (error 'smp-expect3 "cR is bad"))
               (let ((Rab (expt-mod Ra b3 n)))
                 ;; Ever more zero-knowledge proofs
                 (let* ((r7 (random-exponent))
                        (Rb (expt-mod Qa/Qb b3 n))
                        (cR (smp-hash 8 (expt-mod g r7 n)
                                      (expt-mod Qa/Qb r7 n)))
                        (D7 (mod (- r7 (* b3 cR)) order)))
                   (send-smp tlv-smp-4 Rb cR D7)
                   ;; Tell the caller if authentication worked or not:
                   (queue-data 'authentication (= Pa/Pb Rab))
                   (otr-state-smp-set! (*state*) (make-smp-state)))))))
          ((expect4)
           (assert (= type tlv-smp-4))
           (let-values (((Rb cR D7) (get-ints)))
             (unless (= cR (smp-hash 8 (mod (* (expt-mod g D7 n)
                                               (expt-mod (get-smp-value 'g3b) cR n))
                                            n)
                                     (mod (* (expt-mod (get-smp-value 'Qa/Qb) D7 n)
                                             (expt-mod Rb cR n))
                                          n)))
               (error 'smp-expect4 "cR is bad"))
             (let ((Rab (expt-mod Rb (get-smp-value 'a3) n)))
               ;; Tell the caller if authentication worked or not:
               (queue-data 'authentication (= (get-smp-value 'Pa/Pb) Rab))
               (otr-state-smp-set! (*state*) (make-smp-state)))))
          (else (abort))))))

  ;; This procedure is used to continue or initiate an SMP
  ;; authentication with the correspondent.
  (define otr-authenticate!
    (case-lambda
      ((state secret)
       (otr-authenticate! state secret #f))
      ((state secret question)
       ;; The secret is called 'y' or 'x' in the protocol spec
       (parameterize ((*state* state))
         (let ((smp (otr-state-smp state)))
           (case (smp-state-next smp)
             ((expecting-secret)
              (print "constructing an smp-2 message")
              (let ((y (smp-secret secret #f))
                    (b2 (random-exponent))
                    (b3 (random-exponent))
                    (r2 (random-exponent))
                    (r3 (random-exponent))
                    (r4 (random-exponent))
                    (r5 (random-exponent))
                    (r6 (random-exponent)))
                (let* ((g2b (expt-mod g b2 n))
                       (g3b (expt-mod g b3 n))
                       ;; Zero-knowledge proofs:
                       (c2 (smp-hash 3 (expt-mod g r2 n)))
                       (D2 (mod (- r2 (* b2 c2)) order))
                       (c3 (smp-hash 4 (expt-mod g r3 n)))
                       (D3 (mod (- r3 (* b3 c3)) order)))
                  (let ((g2 (expt-mod (get-smp-value 'g2a) b2 n))
                        (g3 (expt-mod (get-smp-value 'g3a) b3 n)))
                    (let ((Pb (expt-mod g3 r4 n))
                          (Qb (mod (* (expt-mod g r4 n)
                                      (expt-mod g2 y n))
                                   n)))
                      ;; More zero-knowledge proofs:
                      (let* ((cP (smp-hash 5 (expt-mod g3 r5 n)
                                           (mod (* (expt-mod g r5 n)
                                                   (expt-mod g2 r6 n))
                                                n)))
                             (D5 (mod (- r5 (* r4 cP)) order))
                             (D6 (mod (- r6 (* y cP)) order)))
                        (save-smp-values 'g2 g2 'g3 g3 'b3 b3 'Pb Pb 'Qb Qb)
                        (send-smp tlv-smp-2 g2b c2 D2 g3b c3 D3 Pb Qb cP D5 D6)
                        (smp-goto 'expect3)))))))
             ((expect1)
              (print "constructing an smp-1 message")
              (let ((x (smp-secret secret #t))
                    (a2 (random-value))
                    (a3 (random-value))
                    (r2 (random-value))
                    (r3 (random-value)))
                (let ((g2a (expt-mod g a2 n))
                      (g3a (expt-mod g a3 n))
                      ;; Zero-knowledge proofs
                      (c2 (smp-hash 1 (expt-mod g r2 n)))
                      (c3 (smp-hash 2 (expt-mod g r3 n))))
                  (let ((D2 (mod (- r2 (* a2 c2)) order))
                        (D3 (mod (- r3 (* a3 c3)) order)))
                    (save-smp-values 'x x 'a2 a2 'a3 a3)
                    ;; TODO: send the question (1q).
                    (send-smp tlv-smp-1 g2a c2 D2 g3a c3 D3)
                    (smp-goto 'expect2)))))
             ;; The authentication process is already under way.
             (else #f)))))))

;;; Everything below here deals with decoding and encoding messages

  (define (tlv-decode bv)
    ;; Decodes all tlvs in the bytevector
    (let ((p (open-bytevector-input-port bv)))
      (let lp ((ret '()))
        (if (port-eof? p)
            (reverse ret)
            (let-values (((type len) (get-unpack p "!SS")))
              (lp (cons (cons type (get-bytevector p len))
                        ret)))))))

  (define (tlv-encode type bv)
    ;; Encode one tlv
    (bytevector-append (pack "!SS" type (bytevector-length bv)) bv))

  ;; "Bob" starts the Authenticated Key Exchange.
  (define (start-ake _)
    (let-values (((x X) (make-secret g n dh-length 100))
                 ((r) (make-random-bytevector 128/8)))
      (let* ((Xbv (uint->mpi X))
             (X-hash (sha-256->bytevector (sha-256 Xbv))))
        ;; Encrypt our public D-H key
        (aes-ctr! Xbv 0 Xbv 0 (bytevector-length Xbv) (expand-aes-key r) 0)
        ;; Send the public D-H key X encrypted with the key r and the
        ;; hash of the unencrypted X.
        (send (bytevector-append (pack "!SC" otr-version msg-diffie-hellman-commit)
                                 (pack "!L" (bytevector-length Xbv)) Xbv
                                 (pack "!L" (bytevector-length X-hash)) X-hash))
        (next-state auth-state-awaiting-dhkey Xbv X-hash x X r))))

  ;; "Bob" gets Alice's public D-H key.
  (define (auth-state-awaiting-dhkey p Xbv X-hash x X r)
    (let ((type (get-u8 p)))
      (cond ((= type msg-diffie-hellman-key)
             (let ((Y (bytevector->uint (get-bytevector p (get-unpack p "!L")))))
               (unless (and (<= 2 Y (- n 2)) (not (= X Y)))
                 (error 'auth-state-awaiting-dhkey "Received bad Y" Y))
               (let-values (((ssid c c* m1 m2 m1* m2*) (make-keys Y x)))
                 (let* ((keyid-bob 1)
                        (X-bob (sign-public-key (otr-state-our-dsa-key (*state*))
                                                m1 keyid-bob X Y)))
                   ;; Encrypt our public DSA key
                   (aes-ctr! X-bob 0 X-bob 0 (bytevector-length X-bob) c 0)
                   (clear-aes-schedule! c)
                   (send (bytevector-append
                          (pack "!SC" otr-version msg-reveal-signature)
                          (pack "!L" (bytevector-length r)) r
                          (pack "!L" (bytevector-length X-bob)) X-bob
                          (MAC m2
                               (pack "!L" (bytevector-length X-bob))
                               X-bob)))
                   (next-state auth-state-awaiting-signature
                               x X Y keyid-bob
                               ssid c* m1* m2*)))))
            ((= type msg-diffie-hellman-commit)
             ;; Both sides started the AKE.
             ;; TODO: test this.
             (get-bytevector p (get-unpack p "!L"))
             (let ((their-mac (bytevector->uint (get-bytevector p (get-unpack p "!L"))))
                   (our-mac (bytevector->uint X-hash)))
               (cond ((> our-mac their-mac)
                      ;; Resend our D-H Commit message and ignore theirs.
                      (send (bytevector-append
                             (pack "!SC" otr-version msg-diffie-hellman-commit)
                             (pack "!L" (bytevector-length Xbv)) Xbv
                             (pack "!L" (bytevector-length X-hash)) X-hash))
                      (next-state auth-state-awaiting-dhkey Xbv X-hash x X r))
                     (else
                      ;; Ignore the D-H Commit message we sent.
                      (set-port-position! p 2)
                      (auth-state-none p)))))
            (else
             (next-state auth-state-awaiting-dhkey Xbv X-hash x X r)))))

  ;; "Bob" gets Alice's public DSA key
  (define (auth-state-awaiting-signature p x X Y keyid-bob ssid c* m1* m2*)
    (let ((type (get-u8 p)))
      (cond ((= type msg-signature)
             (let ((X-alice (get-bytevector p (get-unpack p "!L")))
                   (mac (get-bytevector p 160/8)))
               (unless (bytevector=? mac (MAC m2* (pack "!L" (bytevector-length X-alice))
                                              X-alice))
                 (error 'auth-state-awaiting-signature "Bad message MAC"))
               (aes-ctr! X-alice 0 X-alice 0 (bytevector-length X-alice) c* 0)
               (let* ((X-alice (open-bytevector-input-port X-alice))
                      (key-alice (get-public-key X-alice))
                      (keyid-alice (get-unpack X-alice "!L"))
                      (r (bytevector->uint (get-bytevector X-alice q-len)))
                      (s (bytevector->uint (get-bytevector X-alice q-len))))
                 (unless (verify-public-key key-alice m1* keyid-alice Y X r s)
                   (error 'auth-state-awaiting-signature "Bad message signature"))
                 (clear-aes-schedule! c*)
                 (set-established! (*state*) ssid keyid-bob x X keyid-alice Y key-alice)
                 (queue-data 'session-established 'from-here)
                 (next-state msg-state-encrypted))))
            (else
             (next-state auth-state-awaiting-signature
                         x X Y keyid-bob ssid c* m1* m2*)))))

  (define (plaintext-state p)
    (let ((type (get-u8 p)))
      (cond ((= type msg-diffie-hellman-commit)
             (set-port-position! p 2)   ;before the type
             (auth-state-none p))
            (else
             (send-error "I can't read your pernicious secret writing right now")
             (queue-data 'undecipherable-message #f)
             (next-state plaintext-state)))))

  (define (auth-state-none p)
    (let ((type (get-u8 p)))
      (cond ((= type msg-diffie-hellman-commit)
             ;; X-encrypted is "Bob"'s g^x encrypted with a key he
             ;; reveals in the next message.
             (let* ((X-encrypted (get-bytevector p (get-unpack p "!L")))
                    (X-hash (get-bytevector p (get-unpack p "!L"))))
               (let-values (((y Y) (make-secret g n dh-length 100)))
                 (print (list 'our-dh-privkey (hex y)))
                 (print (list 'our-dh-pubkey (hex Y)))
                 (send (bytevector-append (pack "!SC" otr-version
                                                msg-diffie-hellman-key)
                                          (uint->mpi Y)))
                 (next-state auth-state-awaiting-reveal-sig
                             X-encrypted X-hash y Y))))
            (else
             (next-state auth-state-none)))))

  (define (auth-state-awaiting-reveal-sig p X-encrypted X-hash y Y)
    (unless (eqv? msg-reveal-signature (get-u8 p))
      (error 'auth-state-awaiting-reveal-sig "wrong message type"))
    (let* ((rkey (get-bytevector p (get-unpack p "!L")))
           (X-bob (get-bytevector p (get-unpack p "!L")))
           (mac (get-bytevector p 160/8))
           (X (make-bytevector (bytevector-length X-encrypted))))
      ;; Decrypt "Bob"'s g^x
      (aes-ctr! X-encrypted 0 X 0 (bytevector-length X) (expand-aes-key rkey) 0)
      (unless (bytevector=? X-hash (sha-256->bytevector (sha-256 X)))
        (error 'auth-state-awaiting-reveal-sig "Bad message M(X)"))
      (let ((X (mpi->uint X)))
        (unless (and (<= 2 X (- n 2)) (not (= X Y)))
          (error 'auth-state-awaiting-reveal-sig "Bad message g^x"))
        (print (list 'their-dh-pubkey (number->string X 16)))
        (let-values (((ssid c c* m1 m2 m1* m2*) (make-keys X y)))
          (unless (bytevector=? mac (MAC m2 (pack "!L" (bytevector-length X-bob))
                                         X-bob))
            (error 'auth-state-awaiting-reveal-sig "Bad message MAC"))
          ;; Decrypt "Bob"'s public key
          (aes-ctr! X-bob 0 X-bob 0 (bytevector-length X-bob) c 0)
          (clear-aes-schedule! c)
          (let* ((X-bob (open-bytevector-input-port X-bob))
                 (key-bob (get-public-key X-bob))
                 (keyid-bob (get-unpack X-bob "!L"))
                 (keyid-alice 1)        ;ID for the D-H key
                 (X-alice (sign-public-key (otr-state-our-dsa-key (*state*))
                                           m1* keyid-alice Y X))
                 (r (bytevector->uint (get-bytevector X-bob q-len)))
                 (s (bytevector->uint (get-bytevector X-bob q-len))))
            (unless (verify-public-key key-bob m1 keyid-bob X Y r s)
              (error 'auth-state-awaiting-reveal-sig "Bad message signature"))
            ;; Encrypt our public key
            (aes-ctr! X-alice 0 X-alice 0 (bytevector-length X-alice) c* 0)
            (clear-aes-schedule! c*)
            (send (bytevector-append
                   (pack "!SC" otr-version msg-signature)
                   (pack "!L" (bytevector-length X-alice))
                   X-alice
                   (MAC m2* (pack "!L" (bytevector-length X-alice)) X-alice)))
            (set-established! (*state*) ssid keyid-alice y Y keyid-bob X key-bob)
            (queue-data 'session-established 'from-there)
            (next-state msg-state-encrypted))))))

  ;; "Bob"'s part of the data exchange phase
  (define (msg-state-encrypted p)
    (let ((type (get-unpack p "C")))
      (cond ((= type msg-data)
             (let*-values (((flags skeyid rkeyid) (get-unpack p "!uCLL"))
                           ((next-key) (get-bytevector p (get-unpack p "!L")))
                           ((ctr) (get-unpack p "!Q"))
                           ((msg) (get-bytevector p (get-unpack p "!L")))
                           ((pos) (port-position p))
                           ((mac) (get-bytevector p 160/8))
                           ((old-keys)
                            (let ((len (get-unpack p "!L")))
                              (map-in-order (lambda (_) (get-bytevector-n p 20))
                                            (iota (div len 20))))))
               ;; TODO: handle flag-ignore-unreadable
               (assert (port-eof? p))
               (assert (and (not (zero? ctr))))
               (unless (verify-ctr (*state*) ctr skeyid rkeyid)
                 (send-error "You transmitted an unreadable encrypted message.")
                 (error 'msg-state-encrypted "Bad CTR"))
               (print (list 'flags flags 'skeyid skeyid 'rkeyid rkeyid
                            'ctr (hex ctr) 'old-keys old-keys))
               (let* ((X (cdr (assv skeyid (otr-state-their-pubkeys (*state*)))))
                      (Y (cdr (assv rkeyid (otr-state-our-pubkeys (*state*)))))
                      (y (cdr (assv rkeyid (otr-state-our-keys (*state*)))))
                      (secbytes (uint->mpi (expt-mod X y n)))
                      ;;(sendbyte (if (> Y X) 1 2))
                      (recvbyte (if (> Y X) 2 1))
                      (enckey (subbytevector (h1 recvbyte secbytes) 0 16))
                      (mackey (sha-1->bytevector (sha-1 enckey))))

                 (set-port-position! p 0)
                 (unless (bytevector=? mac (sha-1->bytevector
                                            (hmac-sha-1 mackey (get-bytevector p pos))))
                   (send-error "You transmitted an unreadable encrypted message.")
                   (error 'msg-state-encrypted "Bad MAC"))

                 (store-mackey! (*state*) mackey skeyid rkeyid)
                 (store-ctr! (*state*) ctr skeyid rkeyid)
                 (unless (= (otr-state-our-latest-acked (*state*)) rkeyid)
                   ;; The correspondent used a new key that we just
                   ;; sent him, so it's ok to reset our counter. It's
                   ;; also ok to forget our previous D-H key.
                   (otr-state-our-ctr-set! (*state*) 0)
                   (otr-state-our-latest-acked-set! (*state*) rkeyid)
                   (otr-state-our-keys-set! (*state*) (take (otr-state-our-keys (*state*)) 1))
                   (otr-state-our-pubkeys-set! (*state*) (take (otr-state-our-pubkeys (*state*)) 1)))
                 (for-each (lambda (k)
                             (queue-data 'they-revealed k))
                           old-keys)

                 (unless (assv (+ skeyid 1) (otr-state-their-pubkeys (*state*)))
                   ;; Add their next key
                   (print "Added key: " (+ skeyid 1) " "
                          (hex (bytevector->uint next-key)))
                   (otr-state-their-pubkeys-set!
                    (*state*) (take (cons (cons (+ skeyid 1) (bytevector->uint next-key))
                                          (otr-state-their-pubkeys (*state*)))
                                    2))
                   (print "Their keys: " (otr-state-their-pubkeys (*state*))))
                 (remove-old-ctrs! (*state*))
                 ;; Decrypt the message
                 (aes-ctr! msg 0 msg 0 (bytevector-length msg)
                           (expand-aes-key enckey)
                           (bitwise-arithmetic-shift-left ctr 64))
                 (cond ((bytevector-u8-index msg 0) =>
                        (lambda (nulpos)
                          (let ((msgpart (subbytevector msg 0 nulpos))
                                (tlvpart (subbytevector msg (+ nulpos 1)
                                                        (bytevector-length msg))))
                            (unless (bytevector=? msgpart #vu8())
                              (queue-data 'encrypted (utf8->string msgpart)))
                            ;; XXX: The library user should probably
                            ;; send heartbeats... it's not possible to
                            ;; know here if a reply to this encrypted
                            ;; message will be generated anyway.
                            (let ((tlvs (tlv-decode tlvpart)))
                              (cond ((assv tlv-disconnect tlvs) =>
                                     (lambda (_)
                                       (forget-session! (*state*))
                                       (queue-data 'session-finished 'by-them)
                                       (next-state plaintext-state)))
                                    (else
                                     (print "TLVs: " tlvs)
                                     (for-each handle-smp (filter smp-tlv? tlvs))
                                     (next-state msg-state-encrypted)))))))
                       (else
                        (unless (bytevector=? msg #vu8())
                          (queue-data 'encrypted (utf8->string msg)))
                        (next-state msg-state-encrypted))))))
            (else
             (send-error "That was unexpected of you.") ;XXX:
             (next-state msg-state-encrypted)))))

  ;; Alice's part of the data exchange phase. Used to send an
  ;; encrypted message to the correspondent.
  (define (otr-send-encrypted! state msg . tlvs)
    (define (make-next-key! state)
      (let ((latest-id (caar (otr-state-our-keys state))))
        (when (= (otr-state-our-latest-acked state) latest-id)
          (print "Making a new DH key")
          (let-values (((y Y) (make-secret g n dh-length 100)))
            ;; (print "Next public key: " (+ latest-id 1) " -- " (hex Y))
            ;; (print "Next private key: " (+ latest-id 1) " -- " (hex y))
            (otr-state-our-keys-set! state (take (cons (cons (+ latest-id 1) y)
                                                       (otr-state-our-keys state))
                                                 2))
            (otr-state-our-pubkeys-set! state (take (cons (cons (+ latest-id 1) Y)
                                                          (otr-state-our-pubkeys state))
                                                    2))))))
    ;; This will go in the encrypted message part
    (define (encode-message msg tlvs)
      (let ((msg (string->utf8 msg)))
        (apply bytevector-append
               (cond ((bytevector-u8-index-right msg 0) =>
                      (lambda (i) (subbytevector msg 0 i)))
                     (else msg))
               #vu8(0)
               ;; Slightly random padding
               (tlv-encode tlv-null (make-bytevector
                                     (random-integer 7)
                                     0))
               tlvs)))
    (parameterize ((*state* state))
      (make-next-key! state)
      (otr-state-our-ctr-set! state (+ 1 (otr-state-our-ctr state)))
      (let ((X (car (otr-state-their-pubkeys state)))
            (next-Y (car (otr-state-our-pubkeys state)))
            (Y (assv (otr-state-our-latest-acked state) (otr-state-our-pubkeys state)))
            (y (assv (otr-state-our-latest-acked state) (otr-state-our-keys state)))
            (ctr (otr-state-our-ctr state))
            (msg (encode-message msg tlvs)))
        (let* ((secbytes (uint->mpi (expt-mod (cdr X) (cdr y) n)))
               (sendbyte (if (> (cdr Y) (cdr X)) 1 2))
               ;;(recvbyte (if (> (cdr Y) (cdr X)) 2 1))
               (enckey (subbytevector (h1 sendbyte secbytes) 0 16))
               (mackey (sha-1->bytevector (sha-1 enckey)))
               (old-keys (remove-old-mackeys! (*state*))))
          ;; Encrypt the message
          (aes-ctr! msg 0 msg 0 (bytevector-length msg) (expand-aes-key enckey)
                    (bitwise-arithmetic-shift-left ctr 64))
          (print "Revealing MAC keys: " old-keys)
          ;; XXX: should read those security papers before doing this:
          ;; (store-mackey! (*state*) mackey (car X) (car Y))
          (print "Sending with MAC key: " mackey)
          (let ((data (bytevector-append
                       (pack "!SC" otr-version msg-data)
                       (pack "!uCLL" 0 (car Y) (car X))
                       (uint->mpi (cdr next-Y))
                       (pack "!Q" ctr)
                       (pack "!L" (bytevector-length msg)) msg)))
            (send (apply bytevector-append
                         data
                         (sha-1->bytevector (hmac-sha-1 mackey data))
                         (pack "!L" (apply + (map bytevector-length old-keys)))
                         old-keys)))))))

  ;; Is this a message intended for OTR? Such messages should be given
  ;; to otr-update!.
  (define (otr-message? msg)
    (cond ((string-contains msg "?OTR"))
          ((string-contains msg whitespace-prefix) =>
           ;; Tagged plaintext
           (lambda (i)
             ;; They offer OTRv2?
             (string-contains msg v2-tag (+ i (string-length whitespace-prefix)))))
          (else #f)))

  ;; Updates the OTR state with the given message. The caller
  ;; retrieves the result with otr-empty-queue!.
  (define (otr-update! state msg)
    (cond ((string-contains msg "?OTR,") =>
           ;; Fragmented message
           (lambda (i)
             (let ((parts (string-split msg #\, 3 i (string-index-right msg #\,))))
               (let ((k (string->number (cadr parts) 10))
                     (n (string->number (caddr parts) 10))
                     (piece (cadddr parts)))
                 ;; TODO: sanity checks.
                 (otr-state-frags-set! state (cons piece (otr-state-frags state)))
                 (if (= k n)
                     (let ((msg (apply string-append (reverse (otr-state-frags state)))))
                       (otr-state-frags-set! state '())
                       (otr-update! state msg)))))))
          ((string-contains msg "?OTR:") =>
           (lambda (i)
             (let ((p (open-bytevector-input-port
                       (base64-decode (substring msg (+ i (string-length "?OTR:"))
                                                 (string-index-right msg #\.))))))
               ;; TODO: what about bad versions? Send an error?
               (cond ((= (get-unpack p "!S") otr-version)
                      (return state p))))))
          ((string-contains msg "?OTR Error:") =>
           (lambda (i)
             ;; TODO: initiate AKE depending on policy
             (otr-state-k-set! state auth-state-none)
             (parameterize ((*state* state))
               (queue-data 'remote-error
                           (substring msg (+ i (string-length "?OTR Error:"))
                                      (string-length msg))))))
          ((string-contains msg whitespace-prefix) =>
           ;; Tagged plaintext
           (lambda (i)
             (parameterize ((*state* state))
               (queue-data 'unencrypted (string-trim-right msg)))
             (cond ((string-contains msg v2-tag (+ i (string-length whitespace-prefix)))
                    ;; They offer OTRv2
                    (otr-state-k-set! state start-ake)
                    (return state #f))
                   (else #f))))         ;offer not taken
          ((or (string-contains msg "?OTR?")
               (string-contains msg "?OTRv"))
           ;; TODO: handle the other combinations of versions
           (otr-state-k-set! state start-ake)
           (return state #f))
          (else
           ;; We might end up here if the corresponent used OTR
           ;; fragmentation, but did not send a whitespace tag.
           (parameterize ((*state* state))
             (queue-data 'unencrypted msg))))))
