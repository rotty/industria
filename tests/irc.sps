#!/usr/bin/env scheme-script
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

(import (weinholt bytevectors)
        (weinholt net irc)
        (srfi :78 lightweight-testing)
        (rnrs))

(define (fmt-whitewash prefix cmd . parameters)
  (utf8->string (apply fmt-whitewash/bv prefix cmd parameters)))

(define (fmt-whitewash/bv prefix cmd . parameters)
  (call-with-bytevector-output-port
    (lambda (p)
      (apply format-message-with-whitewash p (utf-8-codec)
             prefix cmd parameters))))

(define (parse str)
  (let-values ((x (parse-message (substring str 0 (- (string-length str) 2)))))
    x))

(define (parse/bv str)
  (let-values ((x (parse-message-bytevector
                   (subbytevector str 0 (- (bytevector-length str) 2)))))
    x))

;; See what happens when the last parameter is empty, and when there's
;; more than one space between parameters.
(check (fmt-whitewash #f 'TOPIC "#test" "")
       =>
       "TOPIC #test :\r\n")

(check (parse (fmt-whitewash #f 'TOPIC "#test" ""))
       =>
       '(#f TOPIC ("#test" "")))

(check (parse "TOPIC #test \r\n")
       =>
       '(#f TOPIC ("#test")))

(check (parse "TOPIC    #test   \r\n")
       =>
       '(#f TOPIC ("#test")))

(check (parse "TOPIC    #test   :\r\n")
       =>
       '(#f TOPIC ("#test" "")))

(check (parse "TOPIC    #test   : \r\n")
       =>
       '(#f TOPIC ("#test" " ")))

;; utf-8 equivalent
(check (parse/bv (string->utf8 "TOPIC #test \r\n"))
       =>
       '(#f TOPIC (#vu8(35 116 101 115 116))))

(check (parse/bv (string->utf8 "TOPIC  #test    \r\n"))
       =>
       '(#f TOPIC (#vu8(35 116 101 115 116))))

(check (parse/bv (string->utf8 "TOPIC  #test    :\r\n"))
       =>
       '(#f TOPIC (#vu8(35 116 101 115 116) #vu8())))

(check (parse/bv (string->utf8 "TOPIC  #test    : \r\n"))
       =>
       '(#f TOPIC (#vu8(35 116 101 115 116) #vu8(32))))


;; Examples..
(check (utf8->string
        (call-with-bytevector-output-port
          (lambda (port)
            (format-message-with-whitewash port (utf-8-codec)
                                           #f 'NOTICE "#abusers"
                                           "DrAbuse: your answer is: 123\r\nJOIN 0"))))
       => "NOTICE #abusers :DrAbuse: your answer is: 123  JOIN 0\r\n")

(check (utf8->string
        (call-with-bytevector-output-port
          (lambda (port)
            (format-message-and-verify port (utf-8-codec)
                                       "irc.example.net" 'NOTICE "ErrantUser"
                                       "The server has taken a liking to you"))))
       => ":irc.example.net NOTICE ErrantUser :The server has taken a liking to you\r\n")

(check
 (call-with-values open-bytevector-output-port
   (lambda (port extract)
     (format-message-raw port (utf-8-codec)
                         "irc.example.net" 001 "luser"
                         "Welcome to the Example Internet Relay Chat Network luser")
     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))
 => ":irc.example.net 001 luser :Welcome to the Example Internet Relay Chat Network luser\r\n")

(check
 (call-with-values open-bytevector-output-port
   (lambda (port extract)
     (format-message-raw port (utf-8-codec)
                         #f 'PRIVMSG "#example"
                         "This is a message to a channel")
     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))
 => "PRIVMSG #example :This is a message to a channel\r\n")


(check-report)
