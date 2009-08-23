#!/usr/bin/env scheme-script
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

(import (rnrs)
        (only (ikarus) tcp-connect udp-connect)
        (weinholt net dns))

(define (print . x) (for-each display x) (newline))

;; TODO: accept command line arguments

;; TODO: timeouts and all that

(define (query-and-print host service protocol qname qtype qclass)
  (let-values (((i o)
                (case protocol
                  ((tcp) (tcp-connect host service))
                  ((udp) (udp-connect host service)))))
    (let ((q (make-normal-query qname qtype qclass #t)))
      (print ";;; Sending query: ") (print-dns-message q)
      (case protocol
        ((tcp) (put-dns-message/delimited o q))
        ((udp) (put-dns-message o q)))
      (flush-output-port o)
      (let lp ()
        (let ((r (case protocol
                   ((tcp) (parse-dns-message/delimited i))
                   ((udp) (parse-dns-message (get-bytevector-some i))))))
          (cond ((or (not (= (dns-message-id r) (dns-message-id q)))
                     (not (= (dns-message-opcode r) opcode-QUERY))
                     (not (= (length (dns-message-question r)) 1))
                     (not (question=? (car (dns-message-question q))
                                      (car (dns-message-question r))))
                     (zero? (fxand (dns-message-flagbits r) flag-response)))
                 (print ";;; FALSIFIED MESSAGE:")
                 (print-dns-message r)
                 (print ";;; FALSIFIED MESSAGE DISCARDED!")
                 (lp))
                ((= (dns-message-rcode r) rcode-NOERROR)
                 ;; TODO: restore the case from qname
                 (print ";;; Reply:") (print-dns-message r)
                 (dnssec-experiment r))
                (else
                 (print ";; Reply with an ERROR:")
                 (print-dns-message r)
                 (print "\n\n;;; THERE IS AN ERROR!!!!"))))))
    (close-port i)
    (close-port o)))


(query-and-print "95.80.36.26" "53" 'udp "weinholt.se" rr-SOA class-IN)

;; (query-and-print "localhost" "53" 'tcp "weinholt.se" rr-DS class-IN)
