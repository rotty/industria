#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- #!
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

;; Tests for Off-The-Record messaging

(import (rnrs)
        (srfi :78 lightweight-testing)
        (weinholt crypto dsa)
        (weinholt net otr)
        (weinholt text base64))

(define (parse-key s)
  (let-values (((type bv)
                (get-delimited-base64 (open-string-input-port s))))
    (dsa-private-key-from-bytevector bv)))

(define key1
  (parse-key
   "-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCsWqA7PlEkryVmODG5kEUyFQX7NydZZ6+NZu33gnRyMRYiEEvc
XQHuwpPS89snjwnkkPhv4RFN+4sLiu+5T0MbZ4qZ/fq7Heec2A4/DK9n8qzSdVBg
6hkNZsB0AQIC/xI+MlYsQ1ZS7mLAPT6m+zjFYo0sbZUJNbGCRX6m/iibrwIVAMk7
LJkmuIKCTyP/a9m21hXYyqJXAoGAPU+js+GrtDB5FRAUWt3Cbrzdcv/Orj6F37on
THG1iYf8FAl6Fj/uxvKasgIYeMgFQhhMKu+p9pRNfAWIYSVuUqtVVsPKc68aEucP
+OcCynJ0V16eb2fGdC3c4yzwHIXeEHM7bkNS/tiLQaace+ogtjrSENd5GquuA3OQ
LbSrAt8CgYBdZc7hocR3mTReopmBZ6V41RDDdK0JYQ4BW0r9nGH20ciH0QbsMf3D
J907A8afiPaxVWzwd326Yeit5VdRiEut32PMRILcbqveGTdhvBD8RJSrDuwW+06P
K2NBpZ7bW3ncxXT0QMNVjvLdHh4+3C4z3PNhOlUIE8fIIBfZxCWv8AIUJlYxaPDf
WAhaSeMnKo/oDbb2ICI=
-----END DSA PRIVATE KEY-----"))

(define key2
  (parse-key
   "-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDptUYYtm/e0ZXxmreL/darbVcJ/PGj2FkOJhzuXMbmmKfJMu40
4N7cWcFI34CyNYe4X9VtLaMA7vWCFqwhRUYaijVv56TID/iqR5dvHNgCWaYIb4d8
ch9MNbW7OsZ/dN/f+plC1lv81bSWWEvTQJySFLwy17EEyndq3+c5pWK2lwIVANJj
c9KXUuruyWv5h3Rtf8ZR7+P7AoGBAL5pTEujp2zMFqsqTIcPJMFtX+TjlIVcQJch
rVVryFTVZbWs+kN5tWHci/TSRcCZ5u36ZPOTiQi8hxyA5SJ1qcDLqFPme3WlL8Gv
ZHq7GnmgrIeCoS/W6mn8miGxvgkYWPCEU3Z4/2eeztC3X9VKRqnonpV7TkwYms9U
6N7mqpi+AoGAQ8JXK5u7zXRuWQOe6fdX2aB44KpG4cvuWBWr3flimznmH66eUPnu
bRZd5H/sX4KFzSwG4A1EI2p9Q9B9Lj8kYM8MCmy2JpHA2djezYYde1qFKnv/GJoO
i5iWp03PqfEH832BUgxUlkcH5v9J/JGTHqn/ElLJ3nqTFjLn1RchCIICFBj90oQ9
daOZBopKox5oXEbXK0gw
-----END DSA PRIVATE KEY-----"))

(define Alice (make-otr-state key1 160)) ;test fragmentation
(define Bob (make-otr-state key2 200))

(define (shuffle X Y Xname Yname)
  ;; Shuffle messages between X and Y until both queues are empty.
  (let ((ret '()))
    (let lp ((X X) (Y Y)
             (Xname Xname) (Yname Yname)
             (Xq (otr-empty-queue! X)))
      (let lp* ((Xq Xq))
        (if (null? Xq)
            (let ((Yq (otr-empty-queue! Y)))
              (if (null? Yq)
                  (reverse ret)
                  (lp Y X Yname Xname Yq)))
            (let ((e (car Xq)))
              (case (car e)
                ((outgoing)
                 ;; Show the messages, for fun!
                 (display ";; ")
                 (write (list Xname '=> Yname (cdr e)))
                 (newline)
                 (otr-update! Y (cdr e)))
                ((they-revealed) 'ignore)
                (else
                 (set! ret (cons (cons Xname e) ret))))
              (lp* (cdr Xq))))))))

;; Alice wants to chat with Bob
(check (begin (otr-update! Alice "?OTRv2?")
              (shuffle Alice Bob 'Alice 'Bob))
       =>
       '((Bob session-established . from-there)
         (Alice session-established . from-here)))

;; Alice greets Bob
(check (begin (otr-send-encrypted! Alice "Hello, Bob!")
              (shuffle Alice Bob 'Alice 'Bob))
       =>
       '((Bob encrypted . "Hello, Bob!")))

;; Bob greets back
(check (begin (otr-send-encrypted! Bob "Hello, I am Bob!")
              (shuffle Bob Alice 'Bob 'Alice))
       =>
       '((Alice encrypted . "Hello, I am Bob!")))

;; Alice starts S-M-P
(check (begin (otr-authenticate! Alice (string->utf8 "Waterloo"))
              (shuffle Alice Bob 'Alice 'Bob))
       =>
       '((Bob authentication . expecting-secret)))

;; Bob finishes S-M-P
(check (begin (otr-authenticate! Bob (string->utf8 "Waterloo"))
              (shuffle Bob Alice 'Bob 'Alice))
       =>
       '((Bob authentication . #t)
         (Alice authentication . #t)))

;; Bob starts S-M-P. Test with mismatching secrets.
(check (begin (otr-authenticate! Bob (string->utf8 "Waterloo"))
              (shuffle Bob Alice 'Bob 'Alice))
       =>
       '((Alice authentication . expecting-secret)))

;; Alice finishes S-M-P with a different secret.
(check (begin (otr-authenticate! Alice (string->utf8 "Boston"))
              (shuffle Alice Bob 'Alice 'Bob))
       =>
       '((Alice authentication . #f)
         (Bob authentication . #f)))

(check-report)
