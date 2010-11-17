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

;; RFC4253 The Secure Shell (SSH) Transport Layer Protocol.

;; This contains only the parsing and formatting of the transport
;; layer messages. All the meat is in (weinholt net ssh).

(library (weinholt net ssh transport (1 0 20101107))
  (export register-transport

          disconnect? make-disconnect disconnect-code
          disconnect-message disconnect-language
          
          ignore? make-ignore 

          unimplemented? make-unimplemented
          unimplemented-sequence-number

          debug? make-debug debug-always-display?
          debug-message debug-language

          service-request? make-service-request
          service-request-name

          service-accept? make-service-accept
          service-accept-name

          kexinit? put-kexinit
          make-kexinit kexinit-cookie kexinit-kex-algorithms
          kexinit-server-host-key-algorithms
          kexinit-encryption-algorithms-client-to-server
          kexinit-encryption-algorithms-server-to-client
          kexinit-mac-algorithms-client-to-server
          kexinit-mac-algorithms-server-to-client
          kexinit-compression-algorithms-client-to-server
          kexinit-compression-algorithms-server-to-client
          kexinit-languages-client-to-server
          kexinit-languages-server-to-client
          kexinit-first-kex-packet-follows?
          kexinit-reserved
          
          newkeys? make-newkeys 

          SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT
          SSH-DISCONNECT-PROTOCOL-ERROR
          SSH-DISCONNECT-KEY-EXCHANGE-FAILED
          SSH-DISCONNECT-RESERVED
          SSH-DISCONNECT-MAC-ERROR
          SSH-DISCONNECT-COMPRESSION-ERROR
          SSH-DISCONNECT-SERVICE-NOT-AVAILABLE
          SSH-DISCONNECT-PROTOCOL-VERSION-NOT-SUPPORTED
          SSH-DISCONNECT-HOST-KEY-NOT-VERIFIABLE
          SSH-DISCONNECT-CONNECTION-LOST
          SSH-DISCONNECT-BY-APPLICATION
          SSH-DISCONNECT-TOO-MANY-CONNECTIONS
          SSH-DISCONNECT-AUTH-CANCELLED-BY-USER
          SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE
          SSH-DISCONNECT-ILLEGAL-USER-NAME)
  (import (rnrs)
          (weinholt net buffer)
          (weinholt net ssh private (1))
          (weinholt struct pack))

  (define SSH-MSG-DISCONNECT 1)
  (define SSH-MSG-IGNORE 2)
  (define SSH-MSG-UNIMPLEMENTED 3)
  (define SSH-MSG-DEBUG 4)
  (define SSH-MSG-SERVICE-REQUEST 5)
  (define SSH-MSG-SERVICE-ACCEPT 6)
  (define SSH-MSG-KEXINIT 20)
  (define SSH-MSG-NEWKEYS 21)

  (define (register-transport reg)
    (reg SSH-MSG-DISCONNECT parse-disconnect put-disconnect)
    (reg SSH-MSG-IGNORE parse-ignore put-ignore)
    (reg SSH-MSG-UNIMPLEMENTED parse-unimplemented put-unimplemented)
    (reg SSH-MSG-DEBUG parse-debug put-debug)
    (reg SSH-MSG-SERVICE-REQUEST parse-service-request put-service-request)
    (reg SSH-MSG-SERVICE-ACCEPT parse-service-accept put-service-accept)
    (reg SSH-MSG-KEXINIT parse-kexinit put-kexinit)
    (reg SSH-MSG-NEWKEYS parse-newkeys put-newkeys))

;;; Disconnection messages

  ;; Disconnect codes
  (define SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT 1)
  (define SSH-DISCONNECT-PROTOCOL-ERROR 2)
  (define SSH-DISCONNECT-KEY-EXCHANGE-FAILED 3)
  (define SSH-DISCONNECT-RESERVED 4)
  (define SSH-DISCONNECT-MAC-ERROR 5)
  (define SSH-DISCONNECT-COMPRESSION-ERROR 6)
  (define SSH-DISCONNECT-SERVICE-NOT-AVAILABLE 7)
  (define SSH-DISCONNECT-PROTOCOL-VERSION-NOT-SUPPORTED 8)
  (define SSH-DISCONNECT-HOST-KEY-NOT-VERIFIABLE 9)
  (define SSH-DISCONNECT-CONNECTION-LOST 10)
  (define SSH-DISCONNECT-BY-APPLICATION 11)
  (define SSH-DISCONNECT-TOO-MANY-CONNECTIONS 12)
  (define SSH-DISCONNECT-AUTH-CANCELLED-BY-USER 13)
  (define SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE 14)
  (define SSH-DISCONNECT-ILLEGAL-USER-NAME 15)

  (define-record-type disconnect
    (parent ssh-packet)
    (fields code message language)
    (protocol
     (lambda (p)
       (lambda (code message language)
         ((p SSH-MSG-DISCONNECT) code message language)))))

  (define (parse-disconnect b)
    (let* ((code (read-uint32 b))
           (msg (read-string b))
           ;; Some implementations don't send the language field
           (lang (if (zero? (buffer-length b)) "" (read-string b))))
      (make-disconnect code msg lang)))

  (define (put-disconnect p m)
    (put-u8 p (ssh-packet-type m))
    (put-record p m #f '(uint32 string string)))

;;; Ignore

  ;; If these are going to be used a lot then it might be better to
  ;; just record the length and discard the data in them.

  (define-record-type ignore
    (parent ssh-packet)
    (fields data)
    (protocol
     (lambda (p)
       (lambda (data)
         ((p SSH-MSG-IGNORE) data)))))

  (define (parse-ignore b)
    (make-ignore (read-bytevector b)))

  (define (put-ignore p m)
    (put-u8 p (ssh-packet-type m))
    (put-bvstring p (ignore-data m)))

;;; Unimplemented

  (define-record-type unimplemented
    (parent ssh-packet)
    (fields sequence-number)
    (protocol
     (lambda (p)
       (lambda (seq-no)
         ((p SSH-MSG-UNIMPLEMENTED) seq-no)))))

  (define (parse-unimplemented b)
    (make-unimplemented (read-uint32 b)))

  (define (put-unimplemented p m)
    (put-u8 p (ssh-packet-type m))
    (put-record p m #f '(uint32)))

;;; Debug messages

  (define-record-type debug
    (parent ssh-packet)
    (fields always-display? message language)
    (protocol
     (lambda (p)
       (lambda x
         (apply (p SSH-MSG-DEBUG) x)))))

  (define (parse-debug b)
    (let* ((always-display? (positive? (read-byte b)))
           (message (read-string b))
           (language (read-string b)))
      (make-debug always-display? message language)))

  (define (put-debug p m)
    (put-u8 p (ssh-packet-type m))
    (put-record p m #f '(boolean string string)))

;;; Service requests

  ;; After the key exchange the client uses this message to request a
  ;; service, e.g. ssh-userauth.

  (define-record-type service-request
    (parent ssh-packet)
    (fields name)
    (protocol
     (lambda (p)
       (lambda (name)
         ((p SSH-MSG-SERVICE-REQUEST) name)))))

  (define (parse-service-request b)
    (make-service-request (read-string b)))

  (define (put-service-request p msg)
    (put-u8 p SSH-MSG-SERVICE-REQUEST)
    (put-bvstring p (service-request-name msg)))

  (define-record-type service-accept
    (parent ssh-packet)
    (fields name)
    (protocol
     (lambda (p)
       (lambda (name)
         ((p SSH-MSG-SERVICE-ACCEPT) name)))))

  (define (parse-service-accept b)
    (make-service-accept (read-string b)))

  (define (put-service-accept p msg)
    (put-u8 p SSH-MSG-SERVICE-ACCEPT)
    (put-bvstring p (service-accept-name msg)))

;;; Kex exchange initialization

  (define-record-type kexinit
    (parent ssh-packet)
    (fields cookie kex-algorithms
            server-host-key-algorithms
            encryption-algorithms-client-to-server
            encryption-algorithms-server-to-client
            mac-algorithms-client-to-server
            mac-algorithms-server-to-client
            compression-algorithms-client-to-server
            compression-algorithms-server-to-client
            languages-client-to-server
            languages-server-to-client
            first-kex-packet-follows?
            reserved)
    (protocol
     (lambda (p)
       (lambda x
         (apply (p SSH-MSG-KEXINIT) x)))))

  (define kexinit-fields
    '(cookie
      name-list name-list name-list
      name-list name-list name-list
      name-list name-list name-list
      name-list boolean uint32))

  (define (parse-kexinit b)
    (get-record b make-kexinit kexinit-fields))

  (define (put-kexinit p m)
    (put-u8 p (ssh-packet-type m))
    (put-record p m #f kexinit-fields))

;;; Tells the peer to use the new keys

  (define-record-type newkeys
    (parent ssh-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda ()
         ((p SSH-MSG-NEWKEYS))))))

  (define (parse-newkeys b)
    (make-newkeys))

  (define (put-newkeys p m) (put-u8 p (ssh-packet-type m))))
