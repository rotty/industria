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

(import (weinholt net tls)
        (weinholt net tcp)
        (rnrs))

(define (print . x) (for-each display x) (newline))

(let*-values (((in out) (tcp-connect (cadr (command-line))
                                     (caddr (command-line))))
              ((s) (make-tls-wrapper in out (cadr (command-line)))))

  (put-tls-handshake-client-hello s)
  (flush-tls-output s)

  (let lp ()
    (unless (eq? 'handshake-server-hello-done (get-tls-record s))
      (print "still waiting for HELLO-DONE...")
      (lp)))

  (print "\n\n\n\nClient sends its own handshake now, see...\n\n\n\n")

  ;; (put-tls-handshake-certificate s)
  (put-tls-handshake-client-key-exchange s)
  (put-tls-change-cipher-spec s)
  (put-tls-handshake-finished s)
  (flush-tls-output s)

  (print "expecting CHANGE-CIPHER-SPEC")
  (unless (eq? 'change-cipher-spec (get-tls-record s))
    (error 'tls "unexpected message"))

  (print "expecting HANDSHAKE-FINISHED")
  (unless (eq? 'handshake-finished (get-tls-record s))
    (error 'tls "unexpected message"))

  (print "\n\n\n\nClient will now write application data and wait for a reply...\n\n\n\n")

  (put-tls-application-data s (string->utf8
                               (string-append "GET / HTTP/1.1\r\n"
                                              "Host: " (cadr (command-line)) ":" (caddr (command-line)) "\r\n"
                                              "\r\n\r\n")))
  (flush-tls-output s)

  (let lp ()
    (print "read a record: " (get-tls-record s))
    (lp)))


(print "client exited normally...")
