;; -*- mode: scheme; coding: utf-8 -*-
;; An IRC parser library useful for both IRC clients and servers.
;; Copyright © 2008, 2009, 2010 Göran Weinholt <goran@weinholt.se>
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

;;; Version history

;; (1 0) - Unreleased. Initial version.

;; (2 0) - Unreleased. Replaced swe-ascii-string-ci=? with
;; string-irc=?, which uses the CASEMAPPING ISUPPORT parameter. Added
;; string-upcase-irc, string-downcase-irc, parse-isupport,
;; isupport-defaults and ctcp-message?.

;; (2 1) - Unreleased. Added irc-match?.

;;; Usage etc

;; Note that this library isn't really ready to use. The parser will
;; probably fail on malformed input (i.e. it will give exceptions
;; other than &irc-parse). But if you're writing a client, it will be
;; OK since if the server wants you to fail it can just disconnect
;; you.

;; See programs/meircbot for an example usage.

;; Note that the maximum message length that IRC supports is 512
;; bytes, including the newline at the end of the message. But if you
;; are writing a client you should be careful: when the server relays
;; your message it will prepend your prefix (":nick!user@host ") to
;; the message. So if you never want your message to be truncated and
;; want to transmit maximum size messages, you must take the prefix
;; into consideration.

;; Should follow RFC 2810-2813.

;; Good IRC bot netiquette: never do anything in response to a NOTICE,
;; and send all your replies as NOTICEs. IRC bots can get into wars
;; with each other if they send PRIVMSGs.

(library (weinholt net irc (2 1 20100421))
  (export irc-format-condition? irc-parse-condition?
          parse-message parse-message-bytevector
          format-message-raw format-message-and-verify
          format-message-with-whitewash
          extended-prefix? prefix-split prefix-nick
          parse-isupport isupport-defaults ctcp-message?
          string-irc=? string-upcase-irc string-downcase-irc
          irc-match?)
  (import (rnrs)
          (only (srfi :1 lists) make-list drop-right append-map)
          (only (srfi :13 strings) string-index string-map)
          (weinholt bytevectors)
          (weinholt text strings))

  (define-condition-type &irc-format &condition
    make-irc-format-condition irc-format-condition?)

  (define-condition-type &irc-parse &condition
    make-irc-parse-condition irc-parse-condition?)

  (define (parse-error who msg . irritants)
    (raise (condition
            (make-who-condition who)
            (make-message-condition msg)
            (make-irritants-condition irritants)
            (make-irc-parse-condition))))

  (define (format-error who msg . irritants)
    (raise (condition
            (make-who-condition who)
            (make-message-condition msg)
            (make-irritants-condition irritants)
            (make-irc-format-condition))))

;;; Helpers

  (define (ascii->string bv)
    (list->string (map (lambda (b) (integer->char (fxand #x7f b)))
                       (bytevector->u8-list bv))))

  (define (parameter->bytevector x transcoder)
    (cond ((bytevector? x)
           x)
          ((string? x)
           (string->bytevector x transcoder))
          ((number? x)
           (string->bytevector (number->string x) transcoder))
          ((symbol? x)
           (string->bytevector (symbol->string x) transcoder))
          (else
           (format-error 'parameter->bytevector
                         "Parameters can be bytevectors, strings, numbers or symbols."
                         x))))

;;; Parsing code

  ;; (parse-message ":irc.example.net PONG irc.example.net :irc.example.net")
  ;; => "irc.example.net"
  ;; => PONG
  ;; => ("irc.example.net" "irc.example.net")

  ;; (parse-message ":user!ident@example.com PRIVMSG #test :this is a test")
  ;; => "user!ident@example.com"
  ;; => PRIVMSG
  ;; => ("#test" "this is a test")

  ;; (parse-message "PING irc.example.net" "irc.example.net")
  ;; => "irc.example.net"
  ;; => PING
  ;; => ("irc.example.net")

  ;; (parse-message "PING irc.example.net")
  ;; => #f
  ;; => PING
  ;; => ("irc.example.net")

  ;; The second return value is the command, and it is either a number
  ;; or a symbol.
  (define parse-message
    (case-lambda
      ((msg remote-server)
       (let-values (((prefix start)
                     (if (string-index msg #\: 0 1)
                         (let ((idx (string-index msg #\space 1)))
                           (values (substring msg 1 idx)
                                   (+ idx 1)))
                         (values remote-server 0))))
         (define (args-done args)
           (let* ((args (reverse args))
                  (cmd (car args)))
             ;; Ignore this error, because e.g. Dancer ircd sends more parameters in ISUPPORT.
             ;; (when (> (length (cdr args)) 15)
             ;;   (parse-error 'parse-message
             ;;                "Too many parameters"
             ;;                prefix cmd args))
             (values prefix
                     (cond ((char-numeric? (string-ref cmd 0))
                            (unless (and (= (string-length cmd) 3)
                                         (for-all char-numeric? (string->list cmd)))
                              (parse-error 'parse-message
                                           "Malformed numerical command"
                                           prefix args))
                            (string->number cmd))
                           (else
                            (string->symbol cmd)))
                     (cdr args))))
         (let lp ((i start) (tokens '()))
           (let ((start i))
             (let lpc ((end i))
               (cond ((= end (string-length msg))
                      (args-done (cons (substring msg start end) tokens)))
                     ((and (char=? #\space (string-ref msg end))
                           (< (+ 1 end) (string-length msg))
                           (char=? #\: (string-ref msg (+ 1 end))))
                      ;; If there's a " :" then what's behind that is the last param
                      (args-done (cons (substring msg (+ 2 end) (string-length msg))
                                       (cons (substring msg start end)
                                             tokens))))
                     ((char=? #\space (string-ref msg end))
                      (lp (+ end 1) (cons (substring msg start end) tokens)))
                     (else
                      (lpc (+ end 1)))))))))
      ((msg)
       (parse-message msg #f))))

  ;; The parse-mssage-bytevector function reads an IRC message from
  ;; the given bytevector and only within the given range. Use this
  ;; function if you don't want to transcode messages from latin-1 or
  ;; utf-8. The return values are the same as for parse-message, but
  ;; the parameters are returned as bytevectors.

  ;; This function is useful for a server that shouldn't transcode the
  ;; message parameter of PRIVMSGs etc. Different channels often use
  ;; different encodings.
  (define parse-message-bytevector
    (case-lambda
      ((msg bvstart bvend remote-server)
       (let-values (((prefix start)
                     (if (bytevector-u8-index msg (char->integer #\:)
                                              bvstart (min (+ bvstart 1) bvend))
                         (let ((idx (bytevector-u8-index msg (char->integer #\space)
                                                         (+ bvstart 1) bvend)))
                           (values (subbytevector msg (+ bvstart 1) idx)
                                   (+ idx 1)))
                         (values remote-server bvstart))))
         (define (args-done args)
           (let* ((args (reverse args))
                  (cmd (ascii->string (car args))))
             ;; (when (> (length (cdr args)) 15)
             ;;   (parse-error 'parse-message-binary
             ;;                "Too many parameters"
             ;;                prefix cmd args))
             (values (if (bytevector? prefix) (ascii->string prefix) prefix)
                     (cond ((char-numeric? (string-ref cmd 0))
                            (unless (and (= (string-length cmd) 3)
                                         (for-all char-numeric? (string->list cmd)))
                              (parse-error 'parse-message-binary
                                           "Malformed numerical command"
                                           prefix args))
                            (string->number cmd))
                           (else
                            (string->symbol cmd)))
                     (cdr args))))
         (let lp ((i start) (tokens '()))
           (let ((start i))
             (let lpc ((end i))
               (cond ((= end bvend)
                      (args-done (cons (subbytevector msg start end) tokens)))
                     ((and (= (char->integer #\space) (bytevector-u8-ref msg end))
                           (< (+ 1 end) bvend)
                           (= (char->integer #\:) (bytevector-u8-ref msg (+ 1 end))))
                      ;; If there's a " :" then what's behind that is the last param
                      (args-done (cons (subbytevector msg (+ 2 end) bvend)
                                       (cons (subbytevector msg start end)
                                             tokens))))
                     ((= (char->integer #\space) (bytevector-u8-ref msg end))
                      (lp (+ end 1) (cons (subbytevector msg start end) tokens)))
                     (else
                      (lpc (+ end 1)))))))))
      ((msg bvstart bvend)
       (parse-message-bytevector msg bvstart bvend #f))
      ((msg bvstart)
       (parse-message-bytevector msg bvstart (bytevector-length msg) #f))
      ((msg)
       (parse-message-bytevector msg 0 (bytevector-length msg) #f))))


;;; Formatting

  ;; Output a message to the given port. `prefix' specifies the prefix
  ;; part of the message, i.e. name of the server that originated the
  ;; message. IRC clients should use #f as prefix. The `cmd' is a
  ;; symbol or string representing an IRC command, but it can also be
  ;; an integer (should be between 000 and 999) that will be
  ;; zero-padded. Only servers send numerical commands. The rest of
  ;; the arguments are the parameters for the given command, which can
  ;; be either numbers, strings or bytevectors. Only the last of the
  ;; parameters can contain whitespace.

  ;; (call-with-values open-bytevector-output-port
  ;;   (lambda (port extract)
  ;;     (format-message-raw port (utf-8-codec)
  ;;                         "irc.example.net" 001 "luser"
  ;;                         "Welcome to the Example Internet Relay Chat Network luser")
  ;;     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))

  ;; => ":irc.example.net 001 luser :Welcome to the Example Internet Relay Chat Network luser\r\n"

  ;; (call-with-values open-bytevector-output-port
  ;;   (lambda (port extract)
  ;;     (format-message-raw port (utf-8-codec)
  ;;                         #f 'PRIVMSG "#example"
  ;;                         "This is a message to a channel")
  ;;     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))

  ;; => "PRIVMSG #example :This is a message to a channel\r\n"

  (define (format-message-raw port codec prefix cmd . parameters)
    (let ((t (make-transcoder codec)))
      (when prefix
        (put-u8 port (char->integer #\:))
        (put-bytevector port (parameter->bytevector prefix t))
        (put-u8 port (char->integer #\space)))
      (cond ((number? cmd)
             (when (< cmd 10)
               (put-u8 port (char->integer #\0)))
             (when (< cmd 100)
               (put-u8 port (char->integer #\0)))
             (put-bytevector port (string->bytevector
                                   (number->string cmd) t)))
            ((symbol? cmd)
             (put-bytevector port (string->bytevector
                                   (symbol->string cmd) t)))
            (else
             (put-bytevector port (string->bytevector cmd t))))
      (let lp ((p parameters))
        (cond ((null? p)
               (if #f #f))
              ((null? (cdr p))
               ;; Last parameter, if it contains a space character
               ;; then prefix the whole parameter with a colon.
               (put-u8 port (char->integer #\space))
               (let ((b (parameter->bytevector (car p) t)))
                 (when (bytevector-u8-index b (char->integer #\space))
                   (put-u8 port (char->integer #\:)))
                 (put-bytevector port b)))
              (else
               (put-u8 port (char->integer #\space))
               (put-bytevector port (parameter->bytevector (car p) t))
               (lp (cdr p)))))
      (put-bytevector port '#vu8(13 10))))

  ;; The format-message-and-verify function outputs an IRC message to
  ;; the given port, but first it reads back the formatted message and
  ;; compares it with the input to make sure it is the same.

  ;; Example of something that works fine:

  ;; (call-with-values open-bytevector-output-port
  ;;   (lambda (port extract)
  ;;     (format-message-and-verify port (utf-8-codec)
  ;;                                "irc.example.net" 'NOTICE "ErrantUser"
  ;;                                "The server has taken a liking to you")
  ;;     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))

  ;; => ":irc.example.net NOTICE ErrantUser :The server has taken a liking to you\r\n"

  ;; Here DrAbuse tried to make our bot respond with an embedded newline:

  ;; (call-with-values open-bytevector-output-port
  ;;   (lambda (port extract)
  ;;     (format-message-and-verify port (utf-8-codec)
  ;;                                #f 'NOTICE "#abusers"
  ;;                                "DrAbuse: your answer is: 123\r\nJOIN 0")
  ;;     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))

  ;; The above raises an &irc-format exception, because of the
  ;; newline.

  (define (format-message-and-verify port codec prefix cmd . parameters)
    (let ((bv (call-with-bytevector-output-port
                (lambda (p)
                  (apply format-message-raw p codec prefix cmd parameters))))
          (t (make-transcoder codec)))
      (call-with-values
        (lambda ()
          (guard (con
                  ((irc-parse-condition? con)
                   (format-error 'format-message-and-verify
                                 (condition-message con)
                                 prefix cmd parameters)))
            (parse-message-bytevector bv 0 (min (bytevector-u8-index bv (char->integer #\return))
                                                (bytevector-u8-index bv (char->integer #\linefeed))))))
        (lambda (prefix* cmd* parameters*)
          (let ((parameters (map (lambda (x) (parameter->bytevector x t)) parameters)))
            (if (equal? (list prefix* cmd* parameters*)
                        (list prefix cmd parameters))
                (put-bytevector port bv)
                (format-error 'format-message-and-verify
                              "Malformed message"
                              prefix cmd parameters)))))))


  ;; format-message-with-whitewash replaces carriage return and
  ;; newlines in the parameters. Hopefully you will make sure yourself
  ;; that the prefix, the command all but last the parameter is sane.

  ;; (call-with-values open-bytevector-output-port
  ;;   (lambda (port extract)
  ;;     (format-message-with-whitewash port (utf-8-codec)
  ;;                                    #f 'NOTICE "#abusers"
  ;;                                    "DrAbuse: your answer is: 123\r\nJOIN 0")
  ;;     (bytevector->string (extract) (make-transcoder (utf-8-codec)))))

  ;; => "NOTICE #abusers :DrAbuse: your answer is: 123  JOIN 0\r\n"
  (define (format-message-with-whitewash port codec prefix cmd . parameters)
    (let ((t (make-transcoder codec)))
      (apply format-message-raw port codec prefix cmd
             (let lp ((p parameters)
                      (l '()))
               (cond ((null? p)
                      (reverse l))
                     ((null? (cdr p))
                      (let ((param (parameter->bytevector (car p) t)))
                        (lp (cdr p)
                            (cons (u8-list->bytevector
                                   (map (lambda (b)
                                          (if (memv b '(#x0a #x0d #x00))
                                              #x20
                                              b))
                                        (bytevector->u8-list param)))
                                  l))))
                     (else
                      (lp (cdr p) (cons (car p) l))))))))

;;; Procedures for parsing prefixes and so on. These deal only with
;;; strings.

  (define (extended-prefix? p)
    (and (string? p)
         (string-index p #\!)
         (string-index p #\@)
         #t))

  ;; This function splits an extended prefix.

  ;; (prefix-split "nickname!username@hostname")
  ;; => "nickname"
  ;; => "username"
  ;; => "hostname"
  (define (prefix-split prefix)
    (let* ((ex (string-index prefix #\!))
           (at (string-index prefix #\@ ex)))
      (values (substring prefix 0 ex)
              (substring prefix (+ 1 ex) at)
              (substring prefix (+ 1 at) (string-length prefix)))))

  (define (prefix-nick prefix)
    (let-values (((nick user host) (prefix-split prefix)))
      nick))

  (define (char-ascii-upcase c)
    (let ((i (char->integer c)))
      (if (<= 97 i 122)
          (integer->char (+ (- i 97) 65))
          c)))

  (define (char-rfc1459-upcase c)
    ;; ISO646-SE2, Swedish ASCII, except ` and @ are left alone.
    (let ((i (char->integer c)))
      (if (<= 97 i 126)
          (integer->char (+ (- i 97) 65))
          c)))

  (define (char-strict-rfc1459-upcase c)
    (let ((i (char->integer c)))
      (if (<= 97 i 125)
          (integer->char (+ (- i 97) 65))
          c)))

  (define (string-upcase-irc str mapping)
    (case mapping
      ((rfc1459)
       (string-map char-rfc1459-upcase str))
      ((ascii)
       (string-map char-ascii-upcase str))
      ((strict-rfc1459)
       (string-map char-strict-rfc1459-upcase str))
      (else
       (string-upcase str))))

  (define (char-ascii-downcase c)
    (let ((i (char->integer c)))
      (if (<= 65 i 90)
          (integer->char (+ (- i 65) 97))
          c)))

  (define (char-rfc1459-downcase c)
    (let ((i (char->integer c)))
      (if (<= 65 i 94)
          (integer->char (+ (- i 65) 97))
          c)))

  (define (char-strict-rfc1459-downcase c)
    (let ((i (char->integer c)))
      (if (<= 65 i 93)
          (integer->char (+ (- i 65) 97))
          c)))

  (define (string-downcase-irc str mapping)
    (case mapping
      ((rfc1459)
       (string-map char-rfc1459-downcase str))
      ((ascii)
       (string-map char-ascii-downcase str))
      ((strict-rfc1459)
       (string-map char-strict-rfc1459-downcase str))
      (else
       (string-downcase str))))

  (define string-irc=?
    (case-lambda
      ((x y mapping)
       (string=? (string-downcase-irc x mapping)
                 (string-downcase-irc y mapping)))
      ((x y)
       (string-irc=? x y 'rfc1459))))

  ;; Wildcard matching as per section 2.5 of RFC2812. Suitable for
  ;; matching masks like foo*!*@example.com against prefixes. Uses
  ;; lots of evil pruning and backtracking that makes it good enough
  ;; for many real-world patterns and inputs.
  (define (irc-match? pattern input)
    (define (avancez pattern input plen ilen)
      (let lp ((p 0) (i 0) (p* #f) (i* #f))
        ;; (write (list (and (< p plen) (substring pattern p plen))
        ;;              (and (< i ilen) (substring input i ilen))
        ;;              (and p* (substring pattern p* plen))
        ;;              (and i* (substring input i* ilen))))
        ;; (newline)
        (let ((pc (and (not (= p plen)) (char-ascii-downcase (string-ref pattern p))))
              (ic (and (not (= i ilen)) (char-ascii-downcase (string-ref input i)))))
          (cond ((not ic)               ;no more input
                 (cond ((not pc) #t)    ;no more pattern
                       ((eqv? pc #\*)
                        (lp (+ p 1) i p* i*))
                       ((eqv? i* ilen) #f) ;can't backtrack
                       (i*                 ;backtrack
                        (lp p* i* p* (+ i* 1)))
                       (else #f)))    ;more pattern, but no more input
                ((and pc (or (char=? ic pc)
                             (char=? pc #\?)) ;wildone
                      (not (char=? #\* ic pc)))
                 (lp (+ p 1) (+ i 1) p* i*)) ;pattern and input matched
                ;; Pattern and input didn't match, or end of pattern
                ((eqv? pc #\*)          ;wildmany
                 (or (= (+ p 1) plen)  ;* at the end matches all input
                     (lp (+ p 1) i (+ p 1) i)))
                ((and (eqv? pc #\\)     ;escapes
                      (not (= (+ p 1) plen))
                      (char=? ic (char-ascii-downcase (string-ref pattern (+ p 1)))))
                 (lp (+ p 2) (+ i 1) p* i*))
                ((and pc (not (char=? pc #\\))
                      (not (string-index input pc i)))
                 #f)                    ;prune (seems to work pretty well for IRC)
                ((eqv? p p*)            ;backtrack
                 (lp p* (+ i 1) p* i*))
                (p*                     ;backtrack
                 (lp (if (char=? ic (char-ascii-downcase (string-ref pattern p*)))
                         (+ p* 1)       ;prune
                         p*)
                     (+ i 1) p* i*))
                (else #f)))))         ;more input, but no more pattern
    (let ((plen (string-length pattern))
          (ilen (string-length input)))
      (if (and (not (zero? plen))
               (not (zero? ilen))
               (not (memv (string-ref pattern (- plen 1)) '(#\? #\*)))
               (not (char=? (char-ascii-downcase (string-ref pattern (- plen 1)))
                            (char-ascii-downcase (string-ref input (- ilen 1))))))
          #f                            ;prune
          (avancez pattern input plen ilen))))       

  ;; http://www.irc.org/tech_docs/005.html

  ;; (parse-isupport '("CHANLIMIT=#&:100" "CHANNELLEN=50" "EXCEPTS=e" "INVEX=I"
  ;;                   "CHANMODES=eIb,k,l,imnpst" "KNOCK" "AWAYLEN=160" "ELIST=CMNTU"
  ;;                   "SAFELIST" "are supported by this server"))
  ;; =>
  ;; '((CHANLIMIT . ((#\# . 100) (#\& . 100))) (CHANNELLEN . 50)
  ;;   (EXCEPTS . #\e) (INVEX . #\I)
  ;;   (CHANMODES . ("eIb" "k" "l" "imnpst")) (KNOCK . #t)
  ;;   (AWAYLEN . 160) (ELIST . (#\C #\M #\N #\T #\U))
  ;;   (SAFELIST . #t))

  ;; (parse-isupport '("CALLERID" "CASEMAPPING=rfc1459" "DEAF=D" "KICKLEN=160" "MODES=4"
  ;;                   "NICKLEN=15" "PREFIX=(ohv)@%+" "STATUSMSG=@%+" "TOPICLEN=350"
  ;;                   "NETWORK=foo" "MAXLIST=beI:200" "MAXTARGETS=4" "CHANTYPES=#&"
  ;;                   "are supported by this server"))
  ;; =>
  ;; '((CALLERID . #t) (CASEMAPPING . rfc1459) (DEAF . #\D)
  ;;   (KICKLEN . 160) (MODES . 4) (NICKLEN . 15)
  ;;   (PREFIX . ((#\o . #\@) (#\h . #\%) (#\v . #\+)))
  ;;   (STATUSMSG . (#\@ #\% #\+)) (TOPICLEN . 350) (NETWORK . "foo")
  ;;   (MAXLIST . ((#\b . 200) (#\e . 200) (#\I . 200)))
  ;;   (MAXTARGETS . 4) (CHANTYPES . (#\# #\&)))
  (define (parse-isupport args)
    (define (mode-ref arg def)
      (if (null? (cdr arg)) def (string-ref (cadr arg) 0)))
    (define (parse pv)
      (let ((pv (string-split pv #\= 1)))
        (let ((parameter (string->symbol (car pv))))
          (cons parameter
                (case parameter
                  ((CASEMAPPING) (string->symbol (cadr pv)))
                  ((MODES
                    MAXCHANNELS NICKLEN MAXBANS TOPICLEN
                    KICKLEN CHANNELLEN SILENCE AWAYLEN
                    MAXTARGETS WATCH
                    MONITOR)            ;ratbox
                   (if (null? (cdr pv)) +inf.0 (string->number (cadr pv))))
                  ((INVEX) (mode-ref pv #\I))
                  ((EXCEPTS) (mode-ref pv #\e))
                  ((DEAF) (mode-ref pv #\D))
                  ((CALLERID) (mode-ref pv #\g))
                  ((CHANMODES)
                   (append-map (lambda (modes type)
                                 (map cons* (string->list modes)
                                      (make-list (string-length modes) type)))
                               (string-split (cadr pv) #\,)
                               '(address ;takes a nick or address
                                 always  ;always has a parameter
                                 only   ;only has a parameter when set
                                 never))) ;never has a parameter
                  ((CHANTYPES ELIST STATUSMSG) (string->list (cadr pv)))
                  ((CHANLIMIT MAXLIST)
                   (append-map (lambda (x)
                                 (let ((chars:number (string-split x #\: 1)))
                                   (map cons* (string->list (car chars:number))
                                        (make-list (string-length
                                                    (car chars:number))
                                                   (string->number
                                                    (cadr chars:number) 10)))))
                               (string-split (cadr pv) #\,)))
                  ((PREFIX)
                   (let ((m/s (string-split (cadr pv) #\) 1 1)))
                     (map cons* (string->list (car m/s))
                          (string->list (cadr m/s)))))
                  (else
                   ;; Don't rely on the format of these ones
                   (if (null? (cdr pv)) #t (cadr pv))))))))
    (map parse (drop-right args 1)))

  ;; http://www.irc.org/tech_docs/draft-brocklesby-irc-isupport-03.txt
  (define (isupport-defaults)
    (parse-isupport
     '("CASEMAPPING=rfc1459" "CHANNELLEN=200" "CHANTYPES=#&"
       "MODES=3" "NICKLEN=9" "PREFIX=(ov)@+"
       "CHANMODES=beIqd,k,lfJ,imnpst"   ;nicked from irssi
       "are the defaults")))

  ;; TODO: wildcard expression matcher

  ;; TODO: assistance with conforming to the maximum message length

  ;; TODO: parse channel modes according to CHANMODES and PREFIX

;;; Client-To-Client Protocol

  ;; Btw, nobody seems to support the full feature set of CTCP. A
  ;; common limitation is to only permit one CTCP per message.

  ;; http://www.irchelp.org/irchelp/rfc/ctcpspec.html

  (define (ctcp-message? msg)
    (and (>= (string-length msg) 2)
         (char=? #\x01 (string-ref msg 0))
         (char=? #\x01 (string-ref msg (- (string-length msg) 1)))))

  ;; TODO: CTCP parsing and formatting



  )
