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

;; Custom input and output ports that start a TLS connection

;; (tls-connect hostname portname)
;;  Initiates a TCP connection to the given host and port and
;;  negotiates a TLS connection. Can hang forever. Returns a binary
;;  input port, a binary output port, and a TLS connection object.

;; (start-tls hostname portname binary-input-port binary-output-port)
;;  Negotiates TLS on two already opened ports. Same return values
;;  as tls-connect.


;; TODO: avoid all this extra copying

(library (weinholt net tls simple (0 0 20100115))
  (export tls-connect start-tls)
  (import (rnrs)
          (weinholt bytevectors)
          (weinholt net tcp)
          (weinholt net tls))

  (define-syntax print
    (syntax-rules ()
      #;
      ((_ . args)
       (begin
         (for-each display (list . args))
         (newline)))
      ((_ . args) (values))))

  (define-syntax trace
    (syntax-rules ()
      #;
      ((_ x)
       (begin
         (let ((v x))
           (display "TLS: ")
           (display v)
           (newline)
           v)))
      ((_ x) x)))

  ;; TODO: let tls.sls handle fragmentation
  (define maxlen (expt 2 14))



  (define (tls-connect host service)
    (let-values (((in out) (tcp-connect host service)))
      (start-tls host service in out)))

  (define (start-tls host service in out)
    (let ((s (make-tls-wrapper in out host))
          (send-cert? #f)
          (other-closed? #f)
          (unread #f)
          (offset 0))
      (define (fail msg . irritants)
        (close-output-port out)
        (close-input-port in)
        (raise
          (condition
           (make-error)
           (make-i/o-error)
           (make-i/o-port-error in)
           (make-message-condition msg)
           (make-irritants-condition irritants))))

      (define (read! bytevector start count)
        ;; Read up to `count' bytes from the source, write them to
        ;; `bytevector' at index `start'. Return the number of bytes
        ;; read (zero means end of file).
        (define (return data offset*)
          (let* ((valid (- (bytevector-length data) offset*))
                 (returned (min count valid)))
            (cond ((= returned valid)
                   (set! unread #f)
                   (set! offset 0))
                  (else
                   (set! unread data)
                   (set! offset (+ offset returned))))
            (bytevector-copy! data offset* bytevector start returned)
            returned))
        (if unread
            (return unread offset)
            (let lp ()
              (let ((r (get-tls-record s)))
                (cond ((and (pair? r) (eq? (car r) 'application-data))
                       (if (zero? (bytevector-length (cadr r)))
                           (lp)
                           (return (cadr r) 0)))
                      ((condition? r)
                       ;; XXX: other alerts can also cause it to
                       ;; close... but in error.
                       (if (equal? (condition-irritants r) '((0 . close-notify)))
                           0
                           (lp)))
                      ((eof-object? r)
                       0)
                      ;; FIXME: do something about this record...
                      (else (lp)))))))

      (define (write! bytevector start count)
        ;; Send up to `count' bytes from `bytevector' at index
        ;; `start'. Returns the number of bytes written. A zero count
        ;; should send a close-notify.
        (cond ((zero? count)
               (put-tls-alert-record s 1 0)
               (flush-tls-output s)
               0)
              (else
               (do ((rem count (- rem maxlen))
                    (idx start (+ idx maxlen)))
                   ((<= rem 0)
                    (flush-tls-output s)
                    count)
                 (put-tls-application-data s (subbytevector bytevector idx
                                                            (+ idx (min maxlen rem))))))))

      (define (close)
        (cond (other-closed?
               (put-tls-alert-record s 1 0)
               (flush-tls-output s)
               (close-output-port out)
               (close-input-port in))
              (else
               ;; This is so that each port can be closed independently.
               (set! other-closed? #t))))

      ;; Start negotiation
      (put-tls-handshake-client-hello s)
      (flush-tls-output s)

      (unless (eq? (trace (get-tls-record s)) 'handshake-server-hello)
        (fail "Expected SERVER-HELLO"))

      (let lp ((allowed '(handshake-certificate
                          handshake-server-key-exchange
                          handshake-certificate-request
                          handshake-server-hello-done)))
        (let ((data (trace (get-tls-record s))))
          (when (eof-object? data)
            (fail "The server disconnected during the handshake"))
          (unless (memq data allowed)
            (fail "The server did the handshake in the wrong order"))
          (case data
            ((handshake-certificate-request)
             (set! send-cert? #t)
             (lp '(handshake-server-hello-done)))
            ((handshake-server-hello-done) #t)
            (else
             (lp (cdr (memq data allowed)))))))

      (print "server handshake done. client sends its own handshake now")
      (when send-cert?
        (print "sending client certificate")
        (put-tls-handshake-certificate s #f))
      (put-tls-handshake-client-key-exchange s)
      (put-tls-change-cipher-spec s)
      (put-tls-handshake-finished s)
      (flush-tls-output s)

      (unless (eq? 'change-cipher-spec (trace (get-tls-record s)))
        (fail "Expected CHANGE-CIPHER-SPEC"))

      (unless (eq? 'handshake-finished (trace (get-tls-record s)))
        (fail "Expected HANDSHAKE-FINISHED"))

      (let ((id (string-append "tls " host ":" service)))
        (values (make-custom-binary-input-port id read! #f #f close)
                (make-custom-binary-output-port id write! #f #f close)
                s)))))
