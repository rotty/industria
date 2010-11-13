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

;; Secure Shell (SSH) Transport Layer

;; RFC4250 The Secure Shell (SSH) Protocol Assigned Numbers.
;; RFC4251 The Secure Shell (SSH) Protocol Architecture.
;; RFC4253 The Secure Shell (SSH) Transport Layer Protocol.

;; http://www.iana.org/assignments/ssh-parameters

;; Note: inevitably the system memory will contain key material and it
;; might be written to disk if the system has swap.

;; TODO: fast path for channel-data

(library (weinholt net ssh (1 0 20101113))
  (export
    make-ssh-client make-ssh-server
    ssh-conn-peer-identification
    ssh-conn-host-key
    ssh-conn-session-id
    ssh-finish-key-exchange
    ssh-conn-registrar
    ssh-error
    put-ssh get-ssh close-ssh
    ;; Client and server identification
    (rename (proto-version identification-protocol-version)
            (software-version identification-software-version)
            (comments identification-comments))
    ;; Preferred algorithms. You can remove and reorder the
    ;; algorithms, but you can't introduce new ones without adding
    ;; them to (weinholt net ssh algorithms) first.
    preferred-kex-algorithms
    preferred-server-host-key-algorithms
    preferred-encryption-algorithms-client->server
    preferred-encryption-algorithms-server->client
    preferred-mac-algorithms-client->server
    preferred-mac-algorithms-server->client
    preferred-compression-algorithms-client->server
    preferred-compression-algorithms-server->client
    preferred-languages-client->server
    preferred-languages-server->client
    ;; Debugging parameter
    (rename (debug ssh-debugging)))
  (import (rnrs)
          (only (srfi :1 lists) iota)
          (only (srfi :13 strings) string-every string-join
                string-trim-right string-prefix?)
          (srfi :14 char-sets)
          (srfi :26 cut)
          (srfi :39 parameters)
          (weinholt bytevectors)
          (weinholt crypto dsa)
          (weinholt crypto entropy)
          (weinholt crypto rsa)
          (weinholt crypto ssh-public-key)
          (weinholt net buffer)
          (weinholt net ssh algorithms (1))
          (weinholt net ssh connection (1))
          (weinholt net ssh kexdh (1))
          (weinholt net ssh private (1))
          (weinholt net ssh transport (1))
          (weinholt net ssh userauth (1))
          (weinholt struct pack)
          (weinholt text hexdump)
          (weinholt text strings))

  ;; bit 0 gives a few crappy messages, bit 1 gives packet tracing,
  ;; bit 2 gives packet hex dumps.
  (define debug (make-parameter #b000 (lambda (x) (fxand x #b111))))

  (define-syntax trace
    (syntax-rules ()
      ((_ . args)
       (when (fxbit-set? (debug) 0)
         (for-each display (list . args))
         (newline)))
      ((_ . args) (values))))

  (define-syntax packet-trace
    (syntax-rules ()
      ((_ prefix packet)
       (when (fxbit-set? (debug) 1)
         (display prefix)
         (write packet)
         (newline)))
      ((_ . args) (values))))

  (define (check-version disallow)
    (lambda (spec)
      (cond ((not (string-every (char-set-difference
                                 char-set:printing
                                 disallow
                                 char-set:whitespace)
                                spec))
             (error 'proto-version "Invalid SSH version specification"
                    spec))
            (else spec))))

  (define proto-version
    (make-parameter "2.0" (check-version (char-set #\-))))

  (define software-version
    (make-parameter "Industria_1" (check-version (char-set #\-))))

  (define comments
    (make-parameter
     #f
     (lambda (ver) (if (not ver) ver ((check-version (char-set)) ver)))))

  (define preferred-languages-client->server
    (make-parameter '()))

  (define preferred-languages-server->client
    (make-parameter '()))

;;; State

  (define-record-type ssh-conn
    (fields (immutable client?)
            (immutable inbuf)
            (immutable out)
            (immutable outbuf)
            (mutable peer-identification)
            (mutable local-identification)
            (mutable host-key)
            (mutable private-key)
            (mutable algorithms)
            ;; Used for generating key material:
            (mutable kexer)
            (mutable session-id)
            ;; sequence numbers
            (mutable peer-seq)
            (mutable local-seq)
            ;; encryption
            (mutable reader)
            (mutable writer)
            (mutable next-reader)
            (mutable next-writer)
            ;; integrity
            (mutable read-mac)
            (mutable write-mac)
            (mutable next-read-mac)
            (mutable next-write-mac)
            ;; packet parsing and formatting
            (immutable type-map)
            (immutable registrar))
    (protocol
     (lambda (p)
       (lambda (client? inport outport)
         (let ((typemap (make-vector 256 #f)))
           (p (and client? #t)
              (make-buffer inport)
              outport
              (make-bytevector 35000 0)
              #vu8() #vu8()
              'no-public-key-yet
              'no-private-key
              (list (cons 'kex (guessed-kex-algorithm)))
              #f
              'no-session-id-yet
              0 0
              (make-reader "none" #f #f)
              (make-writer "none" #f #f)
              'bug:no-reader 'bug:no-writer
              (make-read-mac "none" #f)
              (make-write-mac "none" #f)
              'bug:no-read-mac 'bug:no-write-mac
              typemap (make-registrar typemap)))))))

  (define (ssh-conn-algorithm conn alg)
    ;; Keeps track of which algorithms were negotiated.
    (cdr (assq alg (ssh-conn-algorithms conn))))

  (define (ssh-conn-server? x) (not (ssh-conn-client? x)))

  (define (flush-ssh-output conn)
    (flush-output-port (ssh-conn-out conn)))

  (define (close-ssh conn)
    (define (fill! x)
      (if (bytevector? x) (bytevector-fill! x 0)))
    (fill! (ssh-conn-session-id conn))
    (flush-ssh-output conn)
    (close-port (buffer-port (ssh-conn-inbuf conn)))
    (fill! (buffer-data (ssh-conn-inbuf conn)))
    (fill! (ssh-conn-outbuf conn))
    (close-port (ssh-conn-out conn)))

  (define (ssh-error conn who msg code . irritants)
    (put-ssh conn (make-disconnect code msg ""))
    (close-ssh conn)
    (apply error who (string-append "Local SSH error: " msg)
           irritants))

;;; Version exchange.

  (define (get-line* p)
    ;; Read a line. Used for the protocol version exchange. The line
    ;; ends with CR LF, but may also end with only LF.
    (call-with-bytevector-output-port
      (lambda (out)
        (do ((i 0 (fx+ i 1))
             (b (get-u8 p) (get-u8 p)))
            ((or (eof-object? b)
                 (and (fx=? b (char->integer #\return))
                      (eqv? (lookahead-u8 p)
                            (char->integer #\linefeed))
                      (get-u8 p))
                 (fx=? b (char->integer #\linefeed))
                 (fx=? i 256)))
          (put-u8 out b)))))

  ;; Split an identification string into its parts: proto-version,
  ;; software-version, comments. For compatibility reasons 1.99 is the
  ;; same as 2.0.
  (define (parse-identification id-str)
    (let ((str (if (string? id-str) id-str (utf8->string id-str))))
      (let*-values (((_ version s+c)
                     (apply values (string-split str #\- 2)))
                    ((software . comment)
                     (apply values (string-split s+c #\space 1))))
        (values (if (string=? version "1.99") "2.0" version)
                software
                (if (null? comment) #f (car comment))))))

  (define (get-version-exchange conn)
    ;; FIXME: maybe limit the number of junk lines that can be
    ;; received
    (flush-ssh-output conn)
    (let ((p (buffer-port (ssh-conn-inbuf conn))))
      (if (port-eof? p)
          (eof-object)
          (let ((line (get-line* p)))
            (packet-trace "<- " (utf8->string line))
            (cond ((string-prefix? "SSH-" (utf8->string line))
                   line)
                  ;; rfc4253 suggests this could be shown to the user.
                  (else (get-version-exchange p)))))))

  (define (put-version-exchange conn)
    (let ((line (string->utf8
                 (string-append "SSH-" (proto-version)
                                "-" (software-version)
                                (if (comments)
                                    (string-append " " (comments))
                                    "")))))
      (ssh-conn-local-identification-set! conn line)
      (packet-trace "-> " (utf8->string line))
      (put-bytevector (ssh-conn-out conn) line)
      (put-bytevector (ssh-conn-out conn)
                      (string->utf8 "\r\n"))))

;;; Binary packet protocol

  (define (get-packet conn)
    (flush-ssh-output conn)
    (let ((b (ssh-conn-inbuf conn))
          (seq (ssh-conn-peer-seq conn)))
      (ssh-conn-peer-seq-set! conn (bitwise-and (+ seq 1) #xffffffff))
      (buffer-reset! b)
      ((ssh-conn-reader conn) b (format-size "!L"))
      (let ((len (read-u32 b 0)))
        (when (> len 65535)             ;arbitrary limit
          (ssh-error conn 'get-packet "Packet length over the arbitrary limit"
                     SSH-DISCONNECT-PROTOCOL-ERROR len))
        (buffer-seek! b (format-size "!L"))
        ((ssh-conn-reader conn) b len))
      (let ((padding (read-byte b)))
        (unless (eq? 'ok ((ssh-conn-read-mac conn) seq b))
          (ssh-error conn 'get-packet "Bad MAC"
                     SSH-DISCONNECT-MAC-ERROR))
        (buffer-shorten! b padding)
        (when (fxbit-set? (debug) 2)
          (hexdump #f (buffer-data b) (buffer-top b) (buffer-bottom b) "<" "; "))
        seq)))

  (define (put-packet conn payload)
    ;; TODO: payload should be more flexible, so that a header can be
    ;; prepended to channel-data (and that data should be possible to
    ;; select by giving the bytevector, start and end).
    (define (pad-length len blocksize)
      ;; Number of bytes to add when padding packets. Must be at least
      ;; four and can be at most 255.
      (let ((blocksize (fxmax blocksize 8)))
        ;; XXX: adds unrequested padding. doesn't matter really. should
        ;; maybe add randomly large padding anyway.
        (fx+ blocksize (fxand (fx- len) (fx- blocksize 1)))))
    (let* ((head+payload (+ (format-size "!LC") (bytevector-length payload)))
           ;; TODO: cipher block length can be 8, not that it matters
           ;; that much
           (padding (pad-length head+payload 16))
           (seq (ssh-conn-local-seq conn))
           (buf (ssh-conn-outbuf conn)))
      (ssh-conn-local-seq-set! conn (bitwise-and (+ seq 1) #xffffffff))
      (pack! "!LC" buf 0 (+ (format-size "C") (bytevector-length payload)
                            padding)
             padding)
      (bytevector-copy! payload 0 buf (format-size "!LC")
                        (bytevector-length payload))
      ;; TODO: pad with zeros for "none" and counter mode ciphers.
      (bytevector-randomize! buf head+payload padding)
      (let ((mac ((ssh-conn-write-mac conn) seq buf (+ head+payload padding))))
        (when (fxbit-set? (debug) 2)
          (hexdump #f buf (format-size "!LC") head+payload ">" "; "))
        ((ssh-conn-writer conn) (ssh-conn-out conn) buf (+ head+payload padding))
        (put-bytevector (ssh-conn-out conn) mac))))

;;; Sending and receiving records

  (define (type-category type)
    (cond ((<= 1 type 19) '(transport-layer generic))
          ((<= 20 type 29) '(transport-layer algorithm-negotiation))
          ((<= 30 type 49) '(transport-layer key-exchange))
          ((<= 50 type 59) '(userauth generic))
          ((<= 60 type 79) '(userauth method-specific))
          ((<= 80 type 89) '(connection generic))
          ((<= 90 type 127) '(connection channel))
          ((<= 128 type 191) '(reserved client-protocol))
          ((<= 192 type 255) '(local extensions))
          (else (list 'invalid type))))

  (define (put-ssh conn msg)
    (let ((type (ssh-packet-type msg)))
      (cond ((vector-ref (ssh-conn-type-map conn) type)
             => (lambda (handlers)
                  (packet-trace "=> " msg)
                  (put-packet conn
                              (call-with-bytevector-output-port
                                (cut (cdr handlers) <> msg)))))
            (else
             (error 'put-ssh "Tried to send a record with an unregistered type"
                    (ssh-packet-type msg) (type-category (ssh-packet-type msg)))))))

  (define (get-ssh conn)
    (define (buffer->bytevector b)
      (subbytevector (buffer-data b) (buffer-top b) (buffer-bottom b)))
    (define (get)
      (let ((seq-no (get-packet conn))
            (b (ssh-conn-inbuf conn)))
        (let ((type (read-byte b)))
          (cond ((vector-ref (ssh-conn-type-map conn) type)
                 => (lambda (handlers)
                      (trace "#;parser: " (car handlers))
                      (let ((msg ((car handlers) b)))
                        (unless (zero? (buffer-length b))
                          (trace "The parser " (car handlers)
                                 " left " (buffer-length b) " bytes unparsed: "
                                 (buffer->bytevector b))
                          #;
                          (ssh-error conn 'get-ssh "Unparsed data in record"
                                     SSH-DISCONNECT-PROTOCOL-ERROR
                                     type (buffer-length b)))
                        msg)))
                (else
                 ;; These messages MUST be sent, so do that here.
                 ;; Perhaps they should be sent by the library user
                 ;; sometimes as well?
                 (put-ssh conn (make-unimplemented seq-no))
                 (trace "Received a record with an unregistered type: "
                        (list type (type-category type)))
                 (list 'unimplemented (buffer->bytevector b)))))))
    (flush-ssh-output conn)
    (let ((msg (if (port-eof? (buffer-port (ssh-conn-inbuf conn)))
                   (eof-object)
                   (get))))
      (packet-trace "<= " msg)
      msg))

  (define (make-registrar typemap)
    (lambda (type parse put)
      (vector-set! typemap type
                   (and parse put (cons parse put)))))

;;; Key exchange

  (define (guessed-kex-algorithm)
    ;; This algorithm will be used to send a key exchange packet
    ;; immediately after put-kexinit without waiting for gex-kexinit.
    ;; If after get-kexinit it turns out a different algorithm was
    ;; chosen, a new key exchange packet must be sent and the first
    ;; one must be ignored by the receiver. This only applies if the
    ;; bool in put-kexinit is true.
    (car (preferred-kex-algorithms)))

  (define (build-kexinit-packet first-kex-packet-follows?)
    (make-kexinit (make-random-bytevector 16)
                  (preferred-kex-algorithms)
                  (preferred-server-host-key-algorithms)
                  (preferred-encryption-algorithms-client->server)
                  (preferred-encryption-algorithms-server->client)
                  (preferred-mac-algorithms-client->server)
                  (preferred-mac-algorithms-server->client)
                  (preferred-compression-algorithms-client->server)
                  (preferred-compression-algorithms-server->client)
                  (preferred-languages-client->server)
                  (preferred-languages-server->client)
                  ;; true if a guessed kex init packet is sent
                  first-kex-packet-follows? 0))

  (define (kexinit->bytevector m)
    (call-with-bytevector-output-port (cut put-kexinit <> m)))

  ;; Takes the kexinit packets and returns the negotiated algorithms.
  (define (find-algorithms client-kex server-kex)
    (define (first-kex our their)
      ;; TODO: this has to be compatible with the available
      ;; server-host-key-algorithms (for signature and encryption
      ;; operations)
      (first-match our their))
    (define (first-match client server)
      (let lp ((client client))
        (cond ((null? client) #f)
              ((member (car client) server) (car client))
              (else (lp (cdr client))))))
    (let ((fields '(keyalg enc-cs enc-sc mac-cs mac-sc
                           cmp-cs cmp-sc lang-cs lang-sc)))
      `((kex . ,(first-kex (kexinit-kex-algorithms client-kex)
                           (kexinit-kex-algorithms server-kex)))
        ,@(map (lambda (field index)
                 (let ((ref (record-accessor (record-rtd client-kex) index)))
                   (cons field (first-match (ref client-kex) (ref server-kex)))))
               fields (iota (length fields) 2)))))

  ;; Set the "next" cryptographical closures. These will be used after
  ;; newkeys packets have been sent. prf is the pseudorandom function
  ;; determined by the key exchange, it is used to generate keys from
  ;; K, H and session-id.
  (define (generate-key-material! conn hostkey K H prf)
    (define (keygen S C)
      (lambda (len)
        (trace ";; Generating " (if (ssh-conn-client? conn) C S)
               " key of length " len)
        (prf (if (ssh-conn-client? conn) C S) len
             (ssh-conn-session-id conn) K H)))
    (define (alg C S)
      (ssh-conn-algorithm conn (if (ssh-conn-client? conn) C S)))
    (ssh-conn-host-key-set! conn hostkey)
    (trace "Host key fingerprint: "
           (ssh-public-key-fingerprint (ssh-conn-host-key conn)))
    (unless (bytevector? (ssh-conn-session-id conn))
      (ssh-conn-session-id-set! conn (bytevector-copy H)))
    (ssh-conn-next-reader-set! conn (make-reader (alg 'enc-sc 'enc-cs)
                                                 (keygen #\A #\B)
                                                 (keygen #\C #\D)))
    (ssh-conn-next-writer-set! conn (make-writer (alg 'enc-cs 'enc-sc)
                                                 (keygen #\B #\A)
                                                 (keygen #\D #\C)))
    (ssh-conn-next-read-mac-set! conn (make-read-mac (alg 'mac-sc 'mac-cs)
                                                     (keygen #\E #\F)))
    (ssh-conn-next-write-mac-set! conn (make-write-mac (alg 'mac-cs 'mac-sc)
                                                       (keygen #\F #\E)))
    (bytevector-fill! K 0))

  (define (switch-write-keys! conn)
    (ssh-conn-writer-set! conn (ssh-conn-next-writer conn))
    (ssh-conn-write-mac-set! conn (ssh-conn-next-write-mac conn))
    (ssh-conn-next-writer-set! conn #f)
    (ssh-conn-next-write-mac-set! conn #f))

  (define (switch-read-keys! conn)
    (ssh-conn-reader-set! conn (ssh-conn-next-reader conn))
    (ssh-conn-read-mac-set! conn (ssh-conn-next-read-mac conn))
    (ssh-conn-next-reader-set! conn #f)
    (ssh-conn-next-read-mac-set! conn #f))

;;; Starting connections
  
  (define (bad-guess? local-kex peer-kex)
    (not (and (equal? (car (kexinit-kex-algorithms local-kex))
                      (car (kexinit-kex-algorithms peer-kex)))
              (equal? (car (kexinit-server-host-key-algorithms local-kex))
                      (car (kexinit-server-host-key-algorithms peer-kex))))))

  (define (start-ssh conn)
    (define (start-kex kex)
      (register-key-exchange kex (ssh-conn-registrar conn))
      (unless (ssh-conn-kexer conn)
        (ssh-conn-kexer-set! conn
                             (make-key-exchanger kex
                                                 (ssh-conn-client? conn)
                                                 (cut put-ssh conn <>))))
      ((ssh-conn-kexer conn) 'start #f))
    (register-transport (ssh-conn-registrar conn))
    (put-version-exchange conn)
    ;; Tell the peer what algorithms are supported
    (let* ((client? (ssh-conn-client? conn))
           (local-kex (build-kexinit-packet client?)))
      (put-ssh conn local-kex)
      ;; Clients speculatively start the key exchange
      (when client? (start-kex (guessed-kex-algorithm)))
      (let ((id (get-version-exchange conn)))
        (when (eof-object? id)
          (ssh-error conn 'start-ssh "No identification string received"
                     SSH-DISCONNECT-PROTOCOL-ERROR))
        (ssh-conn-peer-identification-set! conn id))
      (let-values (((version server-version comment)
                    (parse-identification (ssh-conn-peer-identification conn))))
        (unless (string-prefix? "2." version)
          (ssh-error conn 'make-ssh-client "Unsupported protocol version"
                     SSH-DISCONNECT-PROTOCOL-VERSION-NOT-SUPPORTED
                     version server-version comment)))
      ;; Get the peer's list of algorithms (and cookie)
      (let* ((peer-kex (get-ssh conn))
             (algorithms (if (ssh-conn-client? conn)
                             (find-algorithms local-kex peer-kex)
                             (find-algorithms peer-kex local-kex))))
        (trace "#;algorithms: " algorithms)
        (for-each (lambda (alg)
                    (unless (or (memq (car alg) '(lang-cs lang-sc))
                                (cdr alg))
                      (ssh-error conn 'find-algorithms
                                 "No common algorithms"
                                 SSH-DISCONNECT-KEY-EXCHANGE-FAILED
                                 algorithms)))
                  algorithms)
        (ssh-conn-algorithms-set! conn algorithms)
        (when (and (kexinit-first-kex-packet-follows? peer-kex)
                   (bad-guess? local-kex peer-kex))
          ;; Ignore the next packet, because the peer guessed the
          ;; wrong kex algorithm.
          (trace "Ignoring next packet because of wrong algorithm guess.")
          (get-packet conn))
        (when (or (not client?) (bad-guess? local-kex peer-kex))
          ;; Server start KEX here. Clients start KEX again if the
          ;; server guessed wrong.
          (start-kex (ssh-conn-algorithm conn 'kex)))
        ((ssh-conn-kexer conn) 'init (list 'host-key-algorithm
                                           (ssh-conn-algorithm conn 'keyalg)
                                           (if client? 'V_C 'V_S)
                                           (ssh-conn-local-identification conn)
                                           (if client? 'V_S 'V_C)
                                           (ssh-conn-peer-identification conn)
                                           (if client? 'I_C 'I_S)
                                           (kexinit->bytevector local-kex)
                                           (if client? 'I_S 'I_C)
                                           (kexinit->bytevector peer-kex))))))

  ;; Run the initial key exchange
  (define (run-kex conn)
    ;; FIXME: let the KEX signal errors properly so that ssh-error can
    ;; be called from here
    (trace "Key exchange running...")
    (cond (((ssh-conn-kexer conn) 'packet (get-ssh conn))
           ;; FIXME: should deregister all KEX packets types now
           => (lambda (success)
                (trace "Key exchange finished.")
                (apply generate-key-material! conn success)))
          (else (run-kex conn))))

  ;; Start up an SSH client on the given ports. The host key will be
  ;; known (and its signature verified) when this procedure returns.
  (define (make-ssh-client inport outport)
    (let ((conn (make-ssh-conn 'client inport outport)))
      (start-ssh conn)
      (run-kex conn)
      conn))

  (define (make-ssh-server inport outport keys)
    (define (supported? algo)
      (cond #;((string=? algo "ssh-rsa")
             (exists rsa-private-key? keys))
            ((string=? algo "ssh-dss")
             (exists dsa-private-key? keys))
            (else #f)))
    (parameterize ((preferred-server-host-key-algorithms
                    (filter supported?
                            (preferred-server-host-key-algorithms))))
      (unless (list? (preferred-server-host-key-algorithms))
        (error 'make-ssh-server "No usable host keys" inport outport))
      (let ((conn (make-ssh-conn #f inport outport)))
        (start-ssh conn)
        ;; FIXME: select a key based on the negotiated algorithms.
        (ssh-conn-private-key-set! conn (car keys))
        ((ssh-conn-kexer conn) 'private-key (ssh-conn-private-key conn))
        (run-kex conn)
        conn)))

  (define (ssh-finish-key-exchange conn)
    ;; Tell the peer that the next packet will use the new keys.
    (put-ssh conn (make-newkeys))
    (switch-write-keys! conn)
    (let ((msg (get-ssh conn)))
      (unless (newkeys? msg)
        (ssh-error conn 'ssh-finish-key-exchange
                   "Unexpected message"
                   SSH-DISCONNECT-PROTOCOL-ERROR msg)))
    ;; The next packet from the peer will use the new keys.
    (switch-read-keys! conn)))
