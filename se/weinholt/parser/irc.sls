;; -*- mode: scheme; coding: utf-8 -*-
;; An IRC parser library useful for both IRC clients and servers.
;; Copyright © 2008 Göran Weinholt <goran@weinholt.se>
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

;; (1 0 0) - Unreleased - Initial version.

;;; Versioning scheme

;; The version is made of (major minor patch) sub-versions.

;; The `patch' sub-version will be incremented when bug fixes have
;; been made, that do not introduce new features or break old ones.

;; The `minor' is incremented when new features are implemented.

;; The `major' is incremented when old features may no longer work
;; without changes to the code that imports this library.

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

;; Should follow RFC 2812 and RFC 2813.

(library (se weinholt parser irc (1 0 0))
    (export irc-format-condition? irc-parse-condition?
            parse-message parse-message-bytevector
            format-message-raw format-message-and-verify
            format-message-with-whitewash
            extended-prefix? prefix-split prefix-nick
            swe-ascii-string-ci=?)
    (import (rnrs)
            (rnrs mutable-strings))

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

  (define string-index
    (case-lambda
      ((s c start end)
       (let lp ((i start))
         (cond ((= end i)
                #f)
               ((char=? (string-ref s i) c)
                i)
               (else
                (lp (+ i 1))))))
      ((s c start)
       (string-index s c start (string-length s)))
      ((s c)
       (string-index s c 0 (string-length s)))))

  (define (string-map f s)
    (do ((ret (make-string (string-length s)))
         (i 0 (+ i 1)))
        ((= i (string-length s))
         ret)
      (string-set! ret i (f (string-ref s i)))))

  (define (string-delete s charset)
    (list->string
     (filter (lambda (c) (not (memv c charset)))
             (string->list s))))

  (define bytevector-u8-index
    (case-lambda
      ((bv c start end)
       (let lp ((i start))
         (cond ((= end i)
                #f)
               ((= (bytevector-u8-ref bv i) c)
                i)
               (else
                (lp (+ i 1))))))
      ((bv c start)
       (bytevector-u8-index bv c start (bytevector-length bv)))
      ((bv c)
       (bytevector-u8-index bv c 0 (bytevector-length bv)))))

  (define (subbytevector bv start end)
    (let ((ret (make-bytevector (- end start))))
      (bytevector-copy! bv start
                        ret 0 (- end start))
      ret))

  (define (bytevector->ascii-string bv)
    (do ((ret (make-string (bytevector-length bv)))
         (i 0 (+ i 1)))
        ((= i (bytevector-length bv))
         ret)
      (string-set! ret i (integer->char (bytevector-u8-ref bv i)))))

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
       (call-with-values
           (lambda () (if (string-index msg #\: 0 1)
                          (let ((idx (string-index msg #\space 1)))
                            (values (substring msg 1 idx)
                                    (+ idx 1)))
                          (values remote-server 0)))
         (lambda (prefix start)
           (define (args-done args)
             (let* ((args (reverse args))
                    (cmd (car args)))
               (when (> (length (cdr args)) 15)
                 (parse-error 'parse-message
                              "Too many parameters"
                              prefix cmd args))
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
                        (lpc (+ end 1))))))))))
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
       (call-with-values
           (lambda () (if (bytevector-u8-index msg (char->integer #\:)
                                               bvstart (min (+ bvstart 1) bvend))
                          (let ((idx (bytevector-u8-index msg (char->integer #\space)
                                                          (+ bvstart 1) bvend)))
                            (values (subbytevector msg (+ bvstart 1) idx)
                                    (+ idx 1)))
                          (values remote-server bvstart)))
         (lambda (prefix start)
           (define (args-done args)
             (let* ((args (reverse args))
                    (cmd (bytevector->ascii-string (car args))))
               (when (> (length (cdr args)) 15)
                 (parse-error 'parse-message-binary
                              "Too many parameters"
                              prefix cmd args))
               (values (if (bytevector? prefix) (bytevector->ascii-string prefix) prefix)
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
                        (lpc (+ end 1))))))))))
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
    (define (do-format)
      (call-with-values open-bytevector-output-port
        (lambda (port extract)
          (apply format-message-raw port codec prefix cmd parameters)
          (extract))))
    (let ((bv (do-format))
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

;;; Routines for parsing prefixes and so on. These deal only with
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
    (call-with-values (lambda ()
                        (prefix-split prefix))
      (lambda (nick user host)
        nick)))

  ;; ISO646-SE2 is Swedish ASCII and the original IRC server uses this
  ;; encoding for nicknames. Many networks still do. Nicknames are
  ;; case insensitive, so the character "[" is the same as "{", and so
  ;; on. The "@" can't appear in nicks though, and in RFC2813 section
  ;; 3.2 that character (and "`") are not listed as equivalent.
  (define (swe-ascii-char-ci=? x y)
    (case x
      ((#\}) (or (char=? y #\}) (char=? y #\])))
      ((#\{) (or (char=? y #\{) (char=? y #\[)))
      ((#\|) (or (char=? y #\|) (char=? y #\\)))
      ;; ((#\`) (or (char=? y #\`) (char=? y #\@)))
      ((#\~) (or (char=? y #\~) (char=? y #\^)))

      ((#\]) (or (char=? y #\]) (char=? y #\})))
      ((#\[) (or (char=? y #\[) (char=? y #\{)))
      ((#\\) (or (char=? y #\\) (char=? y #\|)))
      ;; ((#\@) (or (char=? y #\@) (char=? y #\`)))
      ((#\^) (or (char=? y #\^) (char=? y #\~)))
      (else (char-ci=? x y))))

  ;; You should take care that the network you're on actually uses
  ;; ISO646-SE2 before you use this.
  (define (swe-ascii-string-ci=? x y)
    (and (= (string-length x) (string-length y))
         (let lp ((i 0))
           (cond ((= i (string-length x))
                  #t)
                 ((not (swe-ascii-char-ci=? (string-ref x i)
                                            (string-ref y i)))
                  #f)
                 (else
                  (lp (+ i 1)))))))

  ;; TODO: wildcard expression matcher

  ;; TODO: assistance with conforming to the maximum message length

  )



