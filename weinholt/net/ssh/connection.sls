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

;; RFC4254 The Secure Shell (SSH) Connection Protocol.
;; RFC4335 The Secure Shell (SSH) Session Channel Break Extension.

;; When creating a channel both parties specify a window size. When
;; data (or extended data) is sent over the channel you need to
;; subtract (bytevector-length (channel-data-value msg) from the
;; window size, and if the window size is zero then no data should be
;; sent (the peer can just ignore that data). The message
;; channel-window-adjust is used to increase the window size.

(library (weinholt net ssh connection (1 0 20101107))
  (export register-connection
          register-tcpip-forward

          make-global-request global-request?
          global-request-type
          global-request-want-reply?
          
          request-success? make-request-success
          request-failure? make-request-failure
          
          channel-open?
          channel-open-type channel-open-sender
          channel-open-initial-window-size channel-open-maximum-packet-size

          channel-open/direct-tcpip? make-channel-open/direct-tcpip 
          channel-open/forwarded-tcpip? make-channel-open/forwarded-tcpip 
          channel-open/session? make-channel-open/session 
          channel-open/x11? make-channel-open/x11 

          make-channel-open-failure

          channel-packet?
          channel-packet-recipient

          channel-open-confirmation? make-channel-open-confirmation
          channel-open-confirmation-sender
          channel-open-confirmation-initial-window-size
          channel-open-confirmation-maximum-packet-size

          channel-data? make-channel-data channel-data-value

          channel-extended-data? make-channel-extended-data
          channel-extended-data-value

          channel-eof? make-channel-eof
          channel-close? make-channel-close
          channel-success? make-channel-success
          channel-failure? make-channel-failure

          channel-request? make-channel-request
          channel-request-type channel-request-want-reply?
          
          channel-request/exec? make-channel-request/exec
          channel-request/exec-command

          channel-request/env? make-channel-request/env
          channel-request/env-name
          channel-request/env-value

          channel-request/pty-req? make-channel-request/pty-req
          channel-request/pty-req-term
          channel-request/pty-req-columns
          channel-request/pty-req-rows
          channel-request/pty-req-width
          channel-request/pty-req-height
          channel-request/pty-req-modes
          
          channel-request/shell? make-channel-request/shell
          
          channel-request/window-change? make-channel-request/window-change ;FIXME
          channel-request/x11-req? make-channel-request/x11-req ;FIXME

          channel-window-adjust? make-channel-window-adjust
          channel-window-adjust-amount

          terminal-modes->bytevector bytevector->terminal-modes

          ;; Reasons for channel-open-failure
          SSH-OPEN-ADMINISTRATIVELY-PROHIBITED
          SSH-OPEN-CONNECT-FAILED
          SSH-OPEN-UNKNOWN-CHANNEL-TYPE
          SSH-OPEN-RESOURCE-SHORTAGE
          ;; Types channel-extended-data
          SSH-EXTENDED-DATA-STDERR)
  (import (rnrs)
          (srfi :26 cut)
          (weinholt net buffer)
          (weinholt net ssh private (1))
          (weinholt struct pack))

  ;; Message numbers
  (define SSH-MSG-GLOBAL-REQUEST 80)
  (define SSH-MSG-REQUEST-SUCCESS 81)
  (define SSH-MSG-REQUEST-FAILURE 82)
  (define SSH-MSG-CHANNEL-OPEN 90)
  (define SSH-MSG-CHANNEL-OPEN-CONFIRMATION 91)
  (define SSH-MSG-CHANNEL-OPEN-FAILURE 92)
  (define SSH-MSG-CHANNEL-WINDOW-ADJUST 93)
  (define SSH-MSG-CHANNEL-DATA 94)
  (define SSH-MSG-CHANNEL-EXTENDED-DATA 95)
  (define SSH-MSG-CHANNEL-EOF 96)
  (define SSH-MSG-CHANNEL-CLOSE 97)
  (define SSH-MSG-CHANNEL-REQUEST 98)
  (define SSH-MSG-CHANNEL-SUCCESS 99)
  (define SSH-MSG-CHANNEL-FAILURE 100)

  (define (register-connection reg)
    (reg SSH-MSG-GLOBAL-REQUEST parse-global-request put-global-request)
    ;;(reg SSH-MSG-REQUEST-SUCCESS parse-request-success put-request-success)
    (reg SSH-MSG-REQUEST-FAILURE parse-request-failure put-request-failure)
    (reg SSH-MSG-CHANNEL-OPEN parse-channel-open put-channel-open)
    (reg SSH-MSG-CHANNEL-OPEN-CONFIRMATION parse-channel-open-confirmation put-channel-open-confirmation)
    (reg SSH-MSG-CHANNEL-OPEN-FAILURE parse-channel-open-failure put-channel-open-failure)
    (reg SSH-MSG-CHANNEL-WINDOW-ADJUST parse-channel-window-adjust put-channel-window-adjust)
    (reg SSH-MSG-CHANNEL-DATA parse-channel-data put-channel-data)
    (reg SSH-MSG-CHANNEL-EXTENDED-DATA parse-channel-extended-data put-channel-extended-data)
    (reg SSH-MSG-CHANNEL-EOF parse-channel-eof put-channel-eof)
    (reg SSH-MSG-CHANNEL-CLOSE parse-channel-close put-channel-close)
    (reg SSH-MSG-CHANNEL-REQUEST parse-channel-request put-channel-request)
    (reg SSH-MSG-CHANNEL-SUCCESS parse-channel-success put-channel-success)
    (reg SSH-MSG-CHANNEL-FAILURE parse-channel-failure put-channel-failure))

  (define (register-tcpip-forward reg)
    #f
    #;
    (reg SSH-MSG-REQUEST-SUCCESS parse-request-success/tcpip-forward
         put-request-success/tcpip-forward))
  
;;; Global requests

  (define-record-type global-request
    (parent ssh-packet)
    (fields type want-reply?)
    (protocol
     (lambda (p)
       (lambda (type want-reply?)
         ((p SSH-MSG-GLOBAL-REQUEST) type want-reply?)))))

  (define-record-type global-request/tcpip-forward
    (parent global-request)
    (fields address port)
    (protocol
     (lambda (p)
       (lambda (want-reply? address port)
         ((p "tcpip-forward" want-reply?) address port)))))

  (define-record-type global-request/cancel-tcpip-forward
    (parent global-request)
    (fields address port)
    (protocol
     (lambda (p)
       (lambda (want-reply? address port)
         ((p "cancel-tcpip-forward" want-reply?) address port)))))
  
  (define (parse-global-request b)
    (let* ((type (read-string b))
           (want-reply? (positive? (read-byte b))))
      (cond
        ((string=? type "tcpip-forward")
         (let* ((address (read-string b))
                (port (read-uint32 b)))
           (make-global-request/tcpip-forward
            type want-reply? address port)))
        ((string=? type "cancel-tcpip-forward")
         (let* ((address (read-string b))
                (port (read-uint32 b)))
           (make-global-request/cancel-tcpip-forward
            type want-reply? address port)))
        (else
         (make-global-request type want-reply?)))))

  (define (put-global-request p m)
    (put-u8 p SSH-MSG-GLOBAL-REQUEST)
    (let ((type (global-request-type m)))
      (put-bvstring p type)
      (put-u8 p (if (global-request-want-reply? m) 1 0))
      (cond ((or (string=? type "tcpip-forward")
                 (string=? type "cancel-tcpip-forward"))
             (put-record p m #f '(string uint32))))))
  
  (define-record-type request-success
    (parent ssh-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda ()
         ((p SSH-MSG-REQUEST-SUCCESS))))))

  ;; parse

  ;; put
  
  (define-record-type request-failure
    (parent ssh-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda ()
         ((p SSH-MSG-REQUEST-FAILURE))))))
  
  (define (parse-request-failure b)
    (make-channel-success))

  (define (put-request-failure p m)
    (put-u8 p SSH-MSG-REQUEST-FAILURE))

  
;;; Channel open

  (define-record-type channel-open
    (parent ssh-packet)
    (fields type sender initial-window-size maximum-packet-size)
    (protocol
     (lambda (p)
       (lambda (type sender initial-window-size maximum-packet-size)
         ((p SSH-MSG-CHANNEL-OPEN) type sender initial-window-size maximum-packet-size)))))

  (define (co-protocol type)
    (lambda (p)
      (lambda (sender initial-window-size maximum-packet-size . x)
        (apply (p type sender initial-window-size maximum-packet-size) x))))

  (define-record-type channel-open/direct-tcpip
    (parent channel-open)
    (fields connect-address connnect-port
            originator-address originator-port)
    (protocol (co-protocol "direct-tcpip")))

  (define-record-type channel-open/forwarded-tcpip
    (parent channel-open)
    (fields connected-address connnected-port
            originator-address originator-port)
    (protocol (co-protocol "forwarded-tcpip")))

  (define-record-type channel-open/session
    (parent channel-open)
    (fields)
    (protocol (co-protocol "session")))

  (define-record-type channel-open/x11
    (parent channel-open)
    (fields originator-address originator-port)
    (protocol (co-protocol "x11")))

  (define (parse-channel-open b)
    (let* ((type (read-string b))
           (sendchn (read-uint32 b))
           (initwnsz (read-uint32 b))
           (maxpktsz (read-uint32 b)))
      (define (parse-tcpip make)
        (let* ((addr1 (read-string b))
               (port1 (read-uint32 b))
               (addr2 (read-string b))
               (port2 (read-uint32 b)))
          (make sendchn initwnsz maxpktsz addr1 port1 addr2 port2)))
      (cond ((string=? type "direct-tcpip")
             (parse-tcpip make-channel-open/direct-tcpip))
            ((string=? type "forwarded-tcpip")
             (parse-tcpip make-channel-open/forwarded-tcpip))
            ((string=? type "session")
             (make-channel-open/session sendchn initwnsz maxpktsz))
            ((string=? type "x11")
             (let ((address (read-string b))
                   (port (read-uint32 b)))
               (make-channel-open/x11 sendchn initwnsz maxpktsz
                                      address port)))
            (else
             (make-channel-open type sendchn initwnsz maxpktsz)))))

  (define (put-channel-open p m)
    (put-u8 p (ssh-packet-type m))
    (put-record p m (record-type-descriptor channel-open)
                '(string uint32 uint32 uint32))
    (let ((type (channel-open-type m)))
      (cond ((string=? type "direct-tcpip")
             (put-record p m #f '(string uint32 string uint32)))
            ((string=? type "forwarded-tcpip")
             (put-record p m #f '(string uint32 string uint32)))
            ((string=? type "session"))
            ((string=? type "x11")
             (put-record p m #f '(string uint32))))))
  
;;; Packets intended for a specific channel

  (define-record-type channel-packet
    (parent ssh-packet)
    (fields recipient)
    (protocol
     (lambda (p)
       (lambda (type recipient)
         ((p type) recipient)))))
  
;;; Channel open confirmation

  (define-record-type channel-open-confirmation
    (parent channel-packet)
    (fields sender                      ;sender's channel id
            initial-window-size maximum-packet-size)
    (protocol
     (lambda (p)
       (lambda (recipient . x)
         (apply (p SSH-MSG-CHANNEL-OPEN-CONFIRMATION recipient) x)))))

  (define (parse-channel-open-confirmation b)
    (let* ((r (read-uint32 b))
           (s (read-uint32 b))
           (initwnsz (read-uint32 b))
           (maxpktsz (read-uint32 b)))
      (make-channel-open-confirmation r s initwnsz maxpktsz)))

  (define (put-channel-open-confirmation p m)
    (put-u8 p SSH-MSG-CHANNEL-OPEN-CONFIRMATION)
    (put-bytevector p (pack "!LLLL" (channel-packet-recipient m)
                            (channel-open-confirmation-sender m)
                            (channel-open-confirmation-initial-window-size m)
                            (channel-open-confirmation-maximum-packet-size m))))

;;; Channel open failure

  (define SSH-OPEN-ADMINISTRATIVELY-PROHIBITED 1)
  (define SSH-OPEN-CONNECT-FAILED 2)
  (define SSH-OPEN-UNKNOWN-CHANNEL-TYPE 3)
  (define SSH-OPEN-RESOURCE-SHORTAGE 4)

  (define-record-type channel-open-failure
    (parent channel-packet)
    (fields reason-code description language)
    (protocol
     (lambda (p)
       (lambda (recipient . x)
         (apply (p SSH-MSG-CHANNEL-OPEN-FAILURE recipient) x)))))

  (define (parse-channel-open-failure b)
    (let* ((r (read-uint32 b))
           (reason (read-uint32 b))
           (description (read-string b))
           (language (read-string b)))
      (make-channel-open-failure r reason description language)))

  (define (put-channel-open-failure p m)
    (put-u8 p SSH-MSG-CHANNEL-OPEN-FAILURE)
    (put-bytevector p (pack "!LL" (channel-packet-recipient m)
                            (channel-open-failure-reason-code m)))
    (put-bvstring p (channel-open-failure-description m))
    (put-bvstring p (channel-open-failure-language m)))

;;; Window adjust

  (define-record-type channel-window-adjust
    (parent channel-packet)
    (fields amount)
    (protocol
     (lambda (p)
       (lambda (recipient amount)
         ((p SSH-MSG-CHANNEL-WINDOW-ADJUST recipient) amount)))))

  (define (parse-channel-window-adjust b)
    (let* ((recipient (read-uint32 b))
           (amount (read-uint32 b)))
      (make-channel-window-adjust recipient amount)))

  (define (put-channel-window-adjust p m)
    (put-u8 p (ssh-packet-type m))
    (put-bytevector p (pack "!LL" (channel-packet-recipient m)
                            (channel-window-adjust-amount m))))

;;; Channel data

  ;; TODO: most packets will be channel-data, so it would be nice to
  ;; have a special case that makes handling these more efficient.

  (define-record-type channel-data
    (parent channel-packet)
    (fields value)
    (protocol
     (lambda (p)
       (lambda (recipient value)
         ((p SSH-MSG-CHANNEL-DATA recipient) value)))))

  (define (parse-channel-data b)
    (let* ((recipient (read-uint32 b))
           (data (read-bytevector b)))
      (make-channel-data recipient data)))

  (define (put-channel-data p m)
    (put-u8 p SSH-MSG-CHANNEL-DATA)
    (put-bytevector p (pack "!L" (channel-packet-recipient m)))
    (put-bvstring p (channel-data-value m)))

;;; Extended channel data

  (define SSH-EXTENDED-DATA-STDERR 1)

  (define-record-type channel-extended-data
    (parent channel-packet)
    (fields type value)
    (protocol
     (lambda (p)
       (lambda (recipient type value)
         ((p SSH-MSG-CHANNEL-EXTENDED-DATA recipient) type value)))))

  (define (parse-channel-extended-data b)
    (let* ((recipient (read-uint32 b))
           (type (read-uint32 b))
           (data (read-bytevector b)))
      (make-channel-extended-data recipient type data)))

  (define (put-channel-extended-data p m)
    (put-u8 p SSH-MSG-CHANNEL-EXTENDED-DATA)
    (put-bytevector p (pack "!LL" (channel-packet-recipient m)
                            (channel-extended-data-type m)))
    (put-bvstring p (channel-extended-data-value m)))

;;; Channel end of file

  (define-record-type channel-eof
    (parent channel-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda (recipient)
         ((p SSH-MSG-CHANNEL-EOF recipient))))))

  (define (parse-channel-eof b)
    (make-channel-eof (read-uint32 b)))

  (define (put-channel-eof p m)
    (put-u8 p SSH-MSG-CHANNEL-EOF)
    (put-bytevector p (pack "!L" (channel-packet-recipient m))))

;;; Channel close

  (define-record-type channel-close
    (parent channel-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda (recipient)
         ((p SSH-MSG-CHANNEL-CLOSE recipient))))))

  (define (parse-channel-close b)
    (make-channel-close (read-uint32 b)))

  (define (put-channel-close p m)
    (put-u8 p SSH-MSG-CHANNEL-CLOSE)
    (put-bytevector p (pack "!L" (channel-packet-recipient m))))

;;; Channel request

  (define-record-type channel-request
    (parent channel-packet)
    (fields type want-reply?)
    (protocol
     (lambda (p)
       (lambda (recipient type want-reply?)
         ((p SSH-MSG-CHANNEL-REQUEST recipient) type want-reply?)))))

  (define (cr-protocol type)
    (lambda (p)
      (lambda (recipient want-reply? . x)
        (apply (p recipient type want-reply?) x))))

  (define (cr-protocol/no-reply type)
    (lambda (p)
      (lambda (recipient . x)
        (apply (p recipient type #f) x))))

  (define-record-type channel-request/break
    (parent channel-request)
    (fields length)
    (protocol (cr-protocol "break")))

  (define-record-type channel-request/env
    (parent channel-request)
    (fields name value)
    (protocol (cr-protocol "env")))

  (define-record-type channel-request/exec
    (parent channel-request)
    (fields command)
    (protocol (cr-protocol "exec")))

  (define-record-type channel-request/exit-signal
    (parent channel-request)
    (fields name core-dumped? message language)
    (protocol (cr-protocol/no-reply "exit-signal")))

  (define-record-type channel-request/exit-status
    (parent channel-request)
    (fields value)
    (protocol (cr-protocol/no-reply "exit-status")))

  (define-record-type channel-request/pty-req
    (parent channel-request)
    (fields term columns rows width height modes)
    (protocol (cr-protocol "pty-req")))

  (define-record-type channel-request/shell
    (parent channel-request)
    (fields)
    (protocol (cr-protocol "shell")))

  (define-record-type channel-request/signal
    (parent channel-request)
    (fields name)
    (protocol (cr-protocol/no-reply "signal")))

  (define-record-type channel-request/subsystem
    (parent channel-request)
    (fields name)
    (protocol (cr-protocol "subsystem")))

  (define-record-type channel-request/window-change
    (parent channel-request)
    (fields columns rows width height)
    (protocol (cr-protocol/no-reply "window-change")))

  (define-record-type channel-request/x11-req
    (parent channel-request)
    (fields single-connection? protocol cookie screen)
    (protocol (cr-protocol "x11-req")))

  (define-record-type channel-request/xon-xoff
    (parent channel-request)
    (fields client-can-do?)
    (protocol (cr-protocol/no-reply "xon-xoff")))

  #;
  (define cr-types
    (list (list "env" make-channel-request/env 'can-reply '(string string))
          (list "exec" 'can-reply '(string))
          (list "exit-signal" #f '(string boolean string string))
          (list "exit-status" #f '(dword))
          (list "pty-req" )
          (list "shell" 'can-reply '())))

  (define (parse-channel-request b)
    (let* ((recipient (read-uint32 b))
           (type (read-string b))
           (want-reply? (positive? (read-byte b))))
      ;; TODO: more types
      (cond ((string=? type "break")
             (make-channel-request/break recipient want-reply?
                                         (read-uint32)))
            ((string=? type "env")
             (let* ((name (read-string b))
                    (value (read-string b)))
               (make-channel-request/env recipient
                                         want-reply?
                                         name value)))
            ((string=? type "exec")
             (make-channel-request/exec recipient want-reply?
                                        (read-bytevector b)))
            ((string=? type "exit-status")
             (let ((value (read-uint32 b)))
               (make-channel-request/exit-status recipient value)))
            ((string=? type "exit-signal")
             (let* ((name (read-string b))
                    (core-dumped? (and (positive? (read-byte b))
                                       'core-dumped))
                    (message (read-string b))
                    (language (read-string b)))
               (make-channel-request/exit-signal recipient name
                                                 core-dumped?
                                                 message
                                                 language)))
            ((string=? type "pty-req")
             (let ((TERM (read-string b)))
               (let-values (((columns rows width height)
                             (unpack "!u4L" (buffer-data b)
                                     (buffer-top b))))
                 (buffer-seek! b (format-size "!4L"))
                 (let ((modes (read-bytevector b)))
                   (make-channel-request/pty-req recipient
                                                 want-reply?
                                                 TERM
                                                 columns rows
                                                 width height
                                                 modes)))))
            ((string=? type "shell")
             (make-channel-request/shell recipient want-reply?))
            ((string=? type "x11-req")
             (let* ((single? (positive? (read-byte b)))
                    (proto (read-string b))
                    (cookie (read-string b))
                    (screen (read-uint32 b)))
               (make-channel-request/x11-req recipient want-reply?
                                             single? proto cookie screen)))
            (else
             (make-channel-request recipient type want-reply?)))))

  (define (put-channel-request p m)
    (put-u8 p SSH-MSG-CHANNEL-REQUEST)
    (put-bytevector p (pack "!L" (channel-packet-recipient m)))
    (put-bvstring p (channel-request-type m))
    (put-u8 p (if (channel-request-want-reply? m) 1 0))
    #;
    (cond ((assoc (channel-request-type m) cr-types) =>
           (lambda (encoding)
             (put-record p m #f (caddr encoding))))
          (else
           (error 'put-channel-request
                  "bug: can't encode this message"
                  m)))

    ;; TODO: more types
    (cond ((channel-request/break? m)
           (put-record p m #f '(uint32)))
          ((channel-request/env? m)
           (put-record p m #f '(string string)))
          ((channel-request/exec? m)
           (put-record p m #f '(string)))
          ((channel-request/pty-req? m)
           (put-record p m #f '(string uint32 uint32 uint32 uint32 string)))
          ((channel-request/shell? m))
          ((channel-request/window-change? m)
           (put-record p m #f '(uint32 uint32 uint32 uint32)))
          ((channel-request/xon-xoff? m)
           (put-record p m #f '(boolean)))
          (else
           (error 'put-channel-request "bug: can't encode this message"
                  m))))

  ;; (call-with-bytevector-output-port
  ;;   (lambda (p)
  ;;     (put-channel-request p (make-channel-request/exec 0 #t "ls"))))

;;; Channel success

  (define-record-type channel-success
    (parent channel-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda (recipient)
         ((p SSH-MSG-CHANNEL-SUCCESS recipient))))))

  (define (parse-channel-success b)
    (make-channel-success (read-uint32 b)))

  (define (put-channel-success p m)
    (put-u8 p SSH-MSG-CHANNEL-SUCCESS)
    (put-bytevector p (pack "!L" (channel-packet-recipient m))))

;;; Channel failure

  (define-record-type channel-failure
    (parent channel-packet)
    (fields)
    (protocol
     (lambda (p)
       (lambda (recipient)
         ((p SSH-MSG-CHANNEL-FAILURE recipient))))))

  (define (parse-channel-failure b)
    (make-channel-failure (read-uint32 b)))

  (define (put-channel-failure p m)
    (put-u8 p SSH-MSG-CHANNEL-FAILURE)
    (put-bytevector p (pack "!L" (channel-packet-recipient m))))

;;; Terminal modes

  ;; This encoding is used in the channel-request/pty-req that gets
  ;; sent to the server. RFC4254 has more on this. Modes are
  ;; represented as alists, (mnemonic . value).

  (define mnemonics
    '#(TTY_OP_END
       VINTR VQUIT VERASE VKILL VEOF VEOL VEOL2 VSTART
       VSTOP VSUSP VDSUSP VREPRINT VWERASE VLNEXT VFLUSH VSWTCH
       VSTATUS VDISCARD #f #f #f #f #f #f #f #f #f #f #f IGNPAR
       PARMRK INPCK ISTRIP INLCR IGNCR ICRNL IUCLC IXON IXANY
       IXOFF IMAXBEL #f #f #f #f #f #f #f #f ISIG ICANON XCASE
       ECHO ECHOE ECHOK ECHONL NOFLSH TOSTOP IEXTEN ECHOCTL
       ECHOKE PENDIN #f #f #f #f #f #f #f OPOST OLCUC ONLCR OCRNL
       ONOCR ONLRET #f #f #f #f #f #f #f #f #f #f #f #f #f #f CS7
       CS8 PARENB PARODD #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f TTY_OP_ISPEED TTY_OP_OSPEED #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
       #f #f #f #f))

  (define (bytevector->terminal-modes bv)
    (call-with-port (open-bytevector-input-port bv)
      (lambda (p)
        (let lp ((ret '()))
          (if (or (port-eof? p)
                  (zero? (lookahead-u8 p))
                  (<= 160 (lookahead-u8 p) 255))
              (reverse ret)
              (let* ((opcode (get-u8 p))
                     (value (get-unpack p "!L")))
                (lp (cons (cons (or (vector-ref mnemonics opcode) opcode)
                                value)
                          ret))))))))

  (define (warning who msg . irritants)
    (raise (condition
            (make-warning)
            (make-who-condition who)
            (make-message-condition msg)
            (make-irritants-condition irritants))))
  
  (define terminal-modes->bytevector
    (let ((ht (make-eq-hashtable)))
      (do ((op 0 (+ op 1)))
          ((= op (vector-length mnemonics)))
        (cond ((vector-ref mnemonics op) =>
               (cut hashtable-set! ht <> op))))
      (lambda (modes)
        (call-with-bytevector-output-port
          (lambda (out)
            (do ((modes modes (cdr modes)))
                ((null? modes) (put-u8 out 0))
              (cond ((hashtable-ref ht (caar modes) #f) =>
                     (lambda (opcode)
                       (put-bytevector out (pack "!uCL" opcode
                                                 (cdar modes)))))
                    (else
                     (warning 'terminal-modes->bytevector
                              "Unknown terminal mode mnemonic (try an integer instead?)"
                              (caar modes)))))))))))
