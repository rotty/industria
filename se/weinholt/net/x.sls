;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2008, 2009 Göran Weinholt <goran@weinholt.se>
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

;; X11 library

;; This library is not ready for any sort of use! It's just a
;; half-finished draft of a library.

;; Should conform to this specification:

;; X Window System Protocol
;;   X Consortium Standard
;; X Version 11, Release 6.9/7.0

;; Why does that document use Lisp syntax for hexadecimal numbers?

;; FIXME: Drop the x- prefix, the user can prefix it themselves if they like.
;; FIXME: angles in arcs should be in radians and converted to X's weird format

;; TODO: a synchronize function which does a GetInputFocus, waits for
;; a reply and discards it


;; This library will likely use lazy evaluation in order to minimize
;; the penalty for network latency. This is an example of how it might
;; work:

;; (intern-atom dpy "R6RS" #f)

;; The InternAtom request is put in the output queue. The return value
;; is an atom record, where the name field is "R6RS", the conn field
;; is the current connection, and the ID field is a promise record
;; containing the sequence number of the request.

;; When the corresponding answer arrives, the atom record is modified
;; such that the promise record is replaced with the ID as returned
;; from the server.

;; When an atom is passed to another request, e.g. change-property,
;; there is not yet a need to have the real ID. The procedure that
;; encodes change-property notices that the ID is a promise, and
;; registers itself as a callback for the reply associated with the
;; promise(s). When the reply has been received, the reply handler for
;; intern-atom updates the atom record and the callback for
;; change-property is called.

;; If you need to read the ID number of an atom yourself, and the ID
;; is currently a promise, the record accessor sees that and waits for
;; the reply from the X server.

;; When you call get-next-event, any replies from the server will be
;; processed in the above manner.

;; Since encoding of requests might be delayed while waiting for
;; replies, the sequence number of a request can't always be
;; determined until the request has been fully encoded and written to
;; the output port.


(library (se weinholt net x)
  (export (open-display))
  (import (rnrs))
  
  
;; Needed here: records with delay    

(define-record-type atom
  (fields name conn (mutable id atom-id atom-id-set!)))

(define-record-type promise
  (fields sequence-number k r))




;;; Utilities

(define (print . x) (for-each display x) (newline))

(define (seq from to)
  (if (= from to)
      '()
      (cons from (seq (+ from 1) to))))

(define (round4 x)
  ;; Round to next multiple of four
  (bitwise-and (+ x 3) -4))

(define (bool->u8 x)
  (if x 1 0))

;;; Delicious syntax to sweeten the protocol

(define-syntax define-x-struct
  (lambda (x)
    (syntax-case x ()
      ((_ struct-name fields ...)
       (with-syntax (((t) (generate-temporaries #'(struct-name))))
         (letrec ((make-accessor-name
                   (lambda (field-name)
                     (datum->syntax #'struct-name
                                    (string->symbol
                                     (string-append
                                      (symbol->string
                                       (syntax->datum #'struct-name))
                                      "-"
                                      (symbol->string
                                       (syntax->datum field-name)))))))
                  (ref
                   (lambda (type offset . base-offset)
                     (syntax-case type (u8 u16 u32 string8)
                       (u8 #`(read-u8 t #,offset))
                       (u16 #`(read-u16 t #,offset))
                       (u32 #`(read-u32 t #,offset))
                       ((string8 length)
                        #`(read-string8 t #,offset
                                        (#,(make-accessor-name #'length)
                                         t #,@base-offset))))))
                  (get-size
                   (lambda (type)
                     (syntax-case type (u8 u16 u32 string8)
                       (u8 1)
                       (u16 2)
                       (u32 4)
                       ((string8 length)
                        #`(round4 (#,(make-accessor-name #'length) t)))))))

           #`(begin
               #,@(let lp ((fields* #'(fields ...))
                           (offset '()))
                    (syntax-case fields* ()
                      (((type name) fields* ...)
                       #`((define #,(make-accessor-name #'name)
                            (case-lambda
                              ((t)
                               #,(ref #'type
                                      (cons #'+ offset)))
                              ((t base-offset)
                               #,(ref #'type
                                      (cons #'+ (cons #'base-offset offset))
                                      #'base-offset))))
                          #,@(lp #'(fields* ...)
                                 (cons (get-size #'type) offset))))
                      (((type) fields* ...)
                       (lp #'(fields* ...)
                           (cons (get-size #'type) offset)))
                      (() #`((define #,(make-accessor-name #'sizeof*)
                               (lambda (t)
                                 #,(cons #'+ offset))))))))))))))

;;; Data structures

;; Fields common to all replies
(define-x-struct reply
  (u8)
  (u8)
  (u16 sequence-number)
  (u32 length))

(define-record-type connection
  (fields inport outport inbuffer protocol-major-version protocol-minor-version
          release-number resource-id-base resource-id-mask motion-buffer-size
          maximum-request-length image-byte-order bitmap-format-bit-order
          bitmap-format-scanline-unit bitmap-format-scanline-pad min-keycode
          max-keycode vendor pixmap-formats roots
          default-root                  ;from the display's name
          (mutable next-resource-id)
          (mutable next-sequence-number)))

(define (connection-get-resource-id! display)
  ;; FIXME: this should support the case where some of the lower bits
  ;; in id-mask are zero. Should also check that we don't overrun the
  ;; ID space. Resource id's can also be freed...
  (let ((id (connection-next-resource-id display)))
    (connection-next-resource-id-set! display (+ id 1))
    id))

(define (connection-get-sequence-number! display)
  ;; FIXME: check that the wrap-around here is correct
  (let ((number (connection-next-sequence-number display)))
    (connection-next-sequence-number-set! display (bitwise-and (+ number 1) #xffff))
    number))

(define-record-type format
  (fields depth bits-per-pixel scanline-pad))

(define-record-type visualtype
  (fields visual-id class bits-per-rgb-value colormap-entries
          red-mask green-mask blue-mask))

(define-record-type screen
  (fields root default-colormap white-pixel black-pixel
          current-input-masks width-in-pixels height-in-pixels
          width-in-millimeters height-in-millimeters min-installed-maps
          max-installed-maps root-visual backing-stores save-unders root-depth
          allowed-depths))


(define-record-type depth
  (fields depth visualtypes))


(define (family->symbol f)
  (case f
    ((0) 'Internet)
    ((1) 'DECnet)
    ((2) 'Chaos)
    ((5) 'ServerInterpreted)
    ((6) 'Internet6)
    ((252) 'LocalHost)
    ((253) 'Krb5Principal)
    ((254) 'Netname)
    ((256) 'Local)                      ;UNIX domain socket
    ((65535) 'Wild)
    (else f)))

;; Atom IDs for these are from 1 to 68 inclusive
(define predefined-atoms
  '(PRIMARY SECONDARY ARC ATOM BITMAP CARDINAL COLORMAP CURSOR
            CUT_BUFFER0 CUT_BUFFER1 CUT_BUFFER2 CUT_BUFFER3 CUT_BUFFER4
            CUT_BUFFER5 CUT_BUFFER6 CUT_BUFFER7 DRAWABLE FONT INTEGER PIXMAP POINT
            RECTANGLE RESOURCE_MANAGER RGB_COLOR_MAP RGB_BEST_MAP RGB_BLUE_MAP
            RGB_DEFAULT_MAP RGB_GRAY_MAP RGB_GREEN_MAP RGB_RED_MAP STRING VISUALID
            WINDOW WM_COMMAND WM_HINTS WM_CLIENT_MACHINE WM_ICON_NAME WM_ICON_SIZE
            WM_NAME WM_NORMAL_HINTS WM_SIZE_HINTS WM_ZOOM_HINTS MIN_SPACE
            NORM_SPACE MAX_SPACE END_SPACE SUPERSCRIPT_X SUPERSCRIPT_Y SUBSCRIPT_X
            SUBSCRIPT_Y UNDERLINE_POSITION UNDERLINE_THICKNESS STRIKEOUT_ASCENT
            STRIKEOUT_DESCENT ITALIC_ANGLE X_HEIGHT QUAD_WIDTH WEIGHT POINT_SIZE
            RESOLUTION COPYRIGHT NOTICE FONT_NAME FAMILY_NAME FULL_NAME CAP_HEIGHT
            WM_CLASS WM_TRANSIENT_FOR))


;;; Input buffering

(define-record-type buffer
  (fields (immutable port)
          (mutable data)
          (mutable bottom))
  (protocol (lambda (p)
              (lambda (port)
                (p port (make-bytevector 8192) 0)))))

(define (buffer-read! buf n)
  (cond ((> (+ (buffer-bottom buf) n)
            (bytevector-length (buffer-data buf)))
         ;; Extend the buffer size
         (let* ((old (buffer-data buf))
                (new (make-bytevector (* (bytevector-length old) 2))))
           (buffer-data-set! buf new)
           (bytevector-copy! old 0
                             new 0 (buffer-bottom buf))
           (buffer-read! buf n)))
        (else
         (let ((bytes-read (get-bytevector-n! (buffer-port buf)
                                              (buffer-data buf)
                                              (buffer-bottom buf) n)))
           (cond ((eof-object? bytes-read)
                  (error 'buffer-read! "port closed, whyyyy!?"))
                 ((< bytes-read n)
                  (error 'buffer-read! "premature end of data!! yikes!"))
                 (else
                  (buffer-bottom-set! buf (+ (buffer-bottom buf) n))))))))

(define (buffer-reset! buf)
  (buffer-bottom-set! buf 0))

(define (read-generic buf ref size index)
  (when (> (+ index size) (buffer-bottom buf))
    (error 'read-generic "attempt to read past bottom of buffer" ref))
  (ref (buffer-data buf) index))

(define (read-u8 buf i) (read-generic buf bytevector-u8-ref 1 i))
(define (read-u16 buf i) (read-generic buf bytevector-u16-native-ref 2 i))
(define (read-u32 buf i) (read-generic buf bytevector-u32-native-ref 4 i))

(define (read-string8 buf start size)
  (when (> (+ start size) (buffer-bottom buf))
    (print buf)
    (error 'read-string8 "attempt to read past bottom of buffer" start size))
  (do ((i start (+ i 1))
       (j 0 (+ j 1))
       (s (make-string size)))
      ((= j size)
       s)
    (string-set! s j
                 (integer->char
                  (bytevector-u8-ref (buffer-data buf) i)))))

;;; Output

(define (put-s8 p i)
  (let ((x (make-bytevector 1)))
    (bytevector-s8-set! x 0 i)
    (put-bytevector p x)))

(define (put-s16 p i)
  (let ((x (make-bytevector 2)))
    (bytevector-s16-set! x 0 i (native-endianness))
    (put-bytevector p x)))

(define (put-u16 p i)
  (let ((x (make-bytevector 2)))
    (bytevector-u16-set! x 0 i (native-endianness))
    (put-bytevector p x)))

(define (put-u32 p i)
  (let ((x (make-bytevector 4)))
    (bytevector-u32-set! x 0 i (native-endianness))
    (put-bytevector p x)))


(define (put-string8 port s)
  (if (string? s)
      (let ((padding (- (round4 (string-length s))
                        (string-length s))))
        (put-bytevector port (string->utf8 s))
        (put-bytevector port (make-bytevector padding 0)))
      (let ((padding (- (round4 (bytevector-length s))
                        (bytevector-length s))))
        (put-bytevector port s)
        (put-bytevector port (make-bytevector padding 0)))))

(define (put-values p values names)
  (let lp ((mask 0)
           (i 0)
           (longs '())
           (names names))
    (cond ((null? names)
           (put-u32 p mask)
           (for-each (lambda (v)
                       ;; FIXME: is the signed handling correct?
                       (if (negative? v)
                           (put-s32 p v)
                           (put-u32 p v)))
                     (reverse longs)))
          ((assq (car names) values) =>
           (lambda (v)
             (lp (bitwise-ior mask (bitwise-arithmetic-shift-left 1 i))
                 (+ i 1)
                 (cons (cdr v) longs)
                 (cdr names))))
          (else
           (lp mask (+ i 1) longs (cdr names))))))

;;; X authority

(define-record-type authority
  (fields family address number name data))

(define (get-authority file)
  ;; The .Xauthority file is in big endian format.
  (define (really-get-bytevector-n port n)
    (let ((bv (get-bytevector-n port n)))
      (when (or (eof-object? bv) (< (bytevector-length bv) n))
        (error 'get-xauthority "Premature end of file" port))
      bv))
  (define (get-u16 port)
    (bytevector-u16-ref (really-get-bytevector-n port 2)
                        0 (endianness big)))
  (define (read-bv p)
    (really-get-bytevector-n p (get-u16 p)))
  (let ((p (open-file-input-port file)))
    (let lp ((entries '()))
      (cond ((eof-object? (lookahead-u8 p))
             (reverse entries))
            (else
             (let* ((family (get-u16 p))
                    (address (read-bv p))
                    (number (read-bv p))
                    (name (read-bv p))
                    (data (read-bv p)))
               (lp (cons (make-authority (family->symbol family)
                                         address
                                         (utf8->string number)
                                         (utf8->string name)
                                         data)
                         entries))))))))

;;; Connect to an X server

(define (open-display host port)
  (define-x-struct init-reply
    (u8 status)
    (u8 reason-length)
    (u16 protocol-major-version)
    (u16 protocol-minor-version)
    (u16 additional-data)
    ((string8 reason-length) reason)
    (u32 release-number)
    (u32 resource-id-base)
    (u32 resource-id-mask)
    (u32 motion-buffer-size)
    (u16 vendor-length)
    (u16 maximum-request-length)
    (u8 number-of-screens)
    (u8 number-of-formats)
    (u8 image-byte-order)
    (u8 bitmap-format-bit-order)
    (u8 bitmap-format-scanline-unit)
    (u8 bitmap-format-scanline-pad)
    (u8 min-keycode)
    (u8 max-keycode)
    (u32)
    ((string8 vendor-length) vendor))
  ;; followed by a list of FORMAT and a list of SCREEN
  (define (init-reply-image-byte-order->symbol n)
    (define x '#(LSBFirst MSBFirst))
    (if (< n (vector-length x))
        (vector-ref x n)
        n))
  (define (init-reply-bitmap-format-bit-order->symbol n)
    (define x '#(LeastSignificant MostSignificant))
    (if (< n (vector-length x))
        (vector-ref x n)
        n))
  (define-x-struct format
    (u8 depth)
    (u8 bits-per-pixel)
    (u8 scanline-pad)
    (u8)
    (u32))
  (let-values (((i o) (tcp-connect host port)))
    (let ((b (make-buffer i)))
      ;; (get-authority "SYS$LOGIN:DECW$XAUTHORITY.DECW$XAUTH")
      (let ((auth (car (get-authority "/home/weinholt/.Xauthority"))))
        (put-u8 o (case (native-endianness)
                    ((little) #x6C)
                    ((big) #x42)
                    (else (error 'open-display "Unsupported native endianness"
                                 (native-endianness)))))
        (put-u8 o #x00)                 ;unused
        (put-u16 o 11)                  ;major version
        (put-u16 o 0)                   ;minor version
        (put-u16 o (string-length (authority-name auth)))
        (put-u16 o (bytevector-length (authority-data auth)))
        (put-u16 o 0)                   ;unused
        (put-string8 o (authority-name auth))
        (put-string8 o (authority-data auth))

        (flush-output-port o))

      (buffer-read! b 8)
      (buffer-read! b (* 4 (init-reply-additional-data b)))

      (case (init-reply-status b)
        ((0)
         (error 'open-display "Connection to X server denied"
                (init-reply-reason b)))

        ((2)
         (error 'open-display "The X server demands further authorization"))

        ((1)
         (letrec ((get-screens
                   (lambda (num offset acc)
                     (define-x-struct screen
                                      (u32 root)
                                      (u32 default-colormap)
                                      (u32 white-pixel)
                                      (u32 black-pixel)
                                      (u32 current-input-masks)
                                      (u16 width-in-pixels)
                                      (u16 height-in-pixels)
                                      (u16 width-in-millimeters)
                                      (u16 height-in-millimeters)
                                      (u16 min-installed-maps)
                                      (u16 max-installed-maps)
                                      (u32 root-visual)
                                      (u8 backing-stores)
                                      (u8 save-unders)
                                      (u8 root-depth)
                                      (u8 number-of-depths))
                     (define (screen-backing-stores->symbol bs)
                       (define x '#(Never WhenMapped Always))
                       (if (< bs (vector-length x))
                           (vector-ref x bs)
                           bs))
                     ;; followed by a list of DEPTHs
                     (if (zero? num)
                         (list->vector (reverse acc))
                         (call-with-values
                           (lambda ()
                             (get-depths (screen-number-of-depths b offset)
                                         (+ offset (screen-sizeof* b))
                                         '()))
                           (lambda (offset* depths)
                             (get-screens (- num 1)
                                          offset*
                                          (cons (make-screen
                                                 (screen-root b offset)
                                                 (screen-default-colormap b offset)
                                                 (screen-white-pixel b offset)
                                                 (screen-black-pixel b offset)
                                                 (screen-current-input-masks b offset)
                                                 (screen-width-in-pixels b offset)
                                                 (screen-height-in-pixels b offset)
                                                 (screen-width-in-millimeters b offset)
                                                 (screen-height-in-millimeters b offset)
                                                 (screen-min-installed-maps b offset)
                                                 (screen-max-installed-maps b offset)
                                                 (screen-root-visual b offset)
                                                 (screen-backing-stores->symbol
                                                  (screen-backing-stores b offset))
                                                 (screen-save-unders b offset)
                                                 (screen-root-depth b offset)
                                                 depths)
                                                acc)))))))
                  (get-depths
                   (lambda (num offset acc)
                     (define-x-struct depth
                                      (u8 depth)
                                      (u8)
                                      (u16 number-of-visualtypes)
                                      (u32))
                     ;; followed by a list of VISUALTYPEs
                     (if (zero? num)
                         (values offset (reverse acc))
                         (call-with-values
                           (lambda ()
                             (get-visualtypes (depth-number-of-visualtypes b offset)
                                              (+ offset (depth-sizeof* b))
                                              '()))
                           (lambda (offset* visualtypes)
                             (get-depths (- num 1)
                                         offset*
                                         (cons (make-depth (depth-depth b offset)
                                                           visualtypes)
                                               acc)))))))
                  (get-visualtypes
                   (lambda (num offset acc)
                     (define-x-struct visualtype
                                      (u32 visual-id)
                                      (u8 class)
                                      (u8 bits-per-rgb-value)
                                      (u16 colormap-entries)
                                      (u32 red-mask)
                                      (u32 green-mask)
                                      (u32 blue-mask)
                                      (u32))
                     (define (visualtype-class->symbol class)
                       (define x '#(StaticGray GrayScale StaticColor PseudoColor TrueColor DirectColor))
                       (if (< class (vector-length x))
                           (vector-ref x class)
                           class))
                     (if (zero? num)
                         (values offset (reverse acc))
                         (get-visualtypes
                          (- num 1)
                          (+ offset (visualtype-sizeof* b))
                          (cons (make-visualtype
                                 (visualtype-visual-id b offset)
                                 (visualtype-class->symbol
                                  (visualtype-class b offset))
                                 (visualtype-bits-per-rgb-value b offset)
                                 (visualtype-colormap-entries b offset)
                                 (visualtype-red-mask b offset)
                                 (visualtype-green-mask b offset)
                                 (visualtype-blue-mask b offset))
                                acc))))))

           (let ((roots (get-screens (init-reply-number-of-screens b)
                                     (+ (init-reply-sizeof* b)
                                        (* (format-sizeof* b)
                                           (init-reply-number-of-formats b)))
                                     '())))
             (make-connection
              i o b
              (init-reply-protocol-major-version b)
              (init-reply-protocol-minor-version b)
              (init-reply-release-number b)
              (init-reply-resource-id-base b)
              (init-reply-resource-id-mask b)
              (init-reply-motion-buffer-size b)
              (init-reply-maximum-request-length b)
              (init-reply-image-byte-order->symbol
               (init-reply-image-byte-order b))
              (init-reply-bitmap-format-bit-order->symbol
               (init-reply-bitmap-format-bit-order b))
              (init-reply-bitmap-format-scanline-unit b)
              (init-reply-bitmap-format-scanline-pad b)
              (init-reply-min-keycode b)
              (init-reply-max-keycode b)
              (init-reply-vendor b)
              (map (lambda (x)
                     (make-format (format-depth b x)
                                  (format-bits-per-pixel b x)
                                  (format-scanline-pad b x)))
                   (map (lambda (o)
                          (+ (init-reply-sizeof* b) (* (format-sizeof* b) o)))
                        (seq 0 (init-reply-number-of-formats b))))
              roots
              1 ;FIXME: get the actual default from the connection string!
              (init-reply-resource-id-base b)
              1))))))))

;;; Error handling

(define-x-struct error
  (u8)
  (u8 code)
  (u16 sequence-number)
  (u32 value)
  (u16 minor-opcode)
  (u8 major-opcode)
  (u8)
  (u32) (u32) (u32) (u32) (u32))

(define-condition-type &x-error &error
  make-x-error x-error?
  (sequence-number x-error-sequence-number)
  (major-opcode x-error-major-opcode)
  (minor-opcode x-error-minor-opcode))

(define-condition-type &x-request-error &x-error
  make-x-request-error x-request-error?)

(define-condition-type &x-value-error &x-error
  make-x-value-error x-value-error?)

(define-condition-type &x-window-error &x-error
  make-x-window-error x-window-error?)

(define-condition-type &x-pixmap-error &x-error
  make-x-pixmap-error x-pixmap-error?)

(define-condition-type &x-atom-error &x-error
  make-x-atom-error x-atom-error?)

(define-condition-type &x-cursor-error &x-error
  make-x-cursor-error x-cursor-error?)

(define-condition-type &x-font-error &x-error
  make-x-font-error x-font-error?)

(define-condition-type &x-match-error &x-error
  make-x-match-error x-match-error?)

(define-condition-type &x-drawable-error &x-error
  make-x-drawable-error x-drawable-error?)

(define-condition-type &x-access-error &x-error
  make-x-access-error x-access-error?)

(define-condition-type &x-alloc-error &x-error
  make-x-alloc-error x-alloc-error?)

(define-condition-type &x-colormap-error &x-error
  make-x-colormap-error x-colormap-error?)

(define-condition-type &x-gcontext-error &x-error
  make-x-gcontext-error x-gcontext-error?)

(define-condition-type &x-idchoice-error &x-error
  make-x-idchoice-error x-idchoice-error?)

(define-condition-type &x-name-error &x-error
  make-x-name-error x-name-error?)

(define-condition-type &x-length-error &x-error
  make-x-length-error x-length-error?)

(define-condition-type &x-implementation-error &x-error
  make-x-implementation-error x-implementation-error?)

(define-condition-type &x-unknown-error &x-error
  make-x-unknown-error x-unknown-error?)

;; The errors are in order of code, starting with the invalid code
;; zero that is used when an unknown error code is returned.
(define error-codes
  (vector (list make-x-unknown-error #t "The X server returned an unknown error code")
          (list make-x-request-error #f "An invalid major or minor opcode was sent to the X server")
          (list make-x-value-error #t "An out of range numeric value was sent to the X server")
          (list make-x-window-error #t "An invalid WINDOW was sent to the X server")
          (list make-x-pixmap-error #t "An invalid PIXMAP was sent to the X server")
          (list make-x-atom-error #t "An invalid ATOM was sent to the X server")
          (list make-x-cursor-error #t "An invalid CURSOR was sent to the X server")
          (list make-x-font-error #t "An invalid FONT or FONTABLE (FONT or GCONTEXT) was sent to the X server")
          (list make-x-match-error #f "An invalid combination of arguments was sent in the request to the X server")
          (list make-x-drawable-error #t "An invalid DRAWABLE (WINDOW or PIXMAP) was sent to the X server")
          (list make-x-access-error #f "The X server denied access to the requested resource.")
          (list make-x-alloc-error #f "The X server could not allocate the resource (out of memory?)")
          (list make-x-colormap-error #t "An invalid COLORMAP was sent to the X server")
          (list make-x-gcontext-error #t "An invalid GCONTEXT was sent to the X server")
          (list make-x-idchoice-error #t "A resource ID was sent to the X server that was out of range or already in use")
          (list make-x-name-error #f "A font or color that does not exist was sent to the X server")
          (list make-x-length-error #f "The length of the request sent to the X server was too short or too long")
          (list make-x-implementation-error #f "The X server is deficient and did not fulfill the request")))

;; In order of major opcode
(define opcodes
  (vector #f 'create-window 'change-window-attributes
          'get-window-attributes 'destroy-window))

(define (raise-x-error b)
  (raise
   (let* ((code (error-code b))
          (e (vector-ref error-codes (if (< code (vector-length error-codes))
                                      code 0)))
          (major (error-major-opcode b))
          (who (vector-ref opcodes (if (< major (vector-length opcodes))
                                       major 0))))
     (let ((make-the-error (car e))
           (value-valid (cadr e))
           (msg (caddr e)))
       (condition
        (make-who-condition who)
        (make-message-condition msg)
        (make-the-error (error-sequence-number b)
                        (error-major-opcode b)
                        (error-minor-opcode b))
        (make-irritants-condition
         (if value-valid
             (error-value b)
             (if (zero? code) (error-code b) #f))))))))


;;; Requests

(define (send-request display major-opcode minor-opcode data)
  "Send an X request to the server and return the sequence number that
will be used in the reply or error."
  (let ((len (round4 (bytevector-length data))))
    (when (> len (* 4 #xfffe))
      ;; TODO: look at the BIG-REQUEST extension
      (error 'send-request "the request is too large to be encoded"))
    (let ((o (connection-outport display))
          (seq (connection-get-sequence-number! display)))
      (print "Sending at seqno " seq " now.")
      (put-u8 o major-opcode)
      (put-u8 o minor-opcode)           ;can be a data field
      (put-u16 o (+ 1 (/ len 4)))
      (put-bytevector o data)
      (put-bytevector o (make-bytevector (- len (bytevector-length data)) 0))
      (flush-output-port o)
      seq)))

(define (call-with-x-output display major-opcode minor-opcode proc)
  (call-with-values open-bytevector-output-port
    (lambda (o c)
      (proc o)
      (send-request display major-opcode minor-opcode (c)))))

(define (call-with-x-output/new display major-opcode minor-opcode proc reply)
  (call-with-values open-bytevector-output-port
    (lambda (o c)
      (proc o)
      (let ((seq (send-request display major-opcode minor-opcode (c))))
        (when reply
          (add-reply-handler! display seq reply))))))

(define (create-window display depth parent x y width height border-width class visual values)
  (let ((o (connection-outport display))
        (wid (connection-get-resource-id! display)))
    (put-u8 o 1)                        ;CreateWindow
    (put-u8 o depth)
    (put-u16 o (+ 8 (length values)))
    (put-u32 o wid)
    (put-u32 o parent)
    (put-u16 o x)
    (put-u16 o y)
    (put-u16 o width)
    (put-u16 o height)
    (put-u16 o border-width)
    (put-u16 o class)
    (put-u32 o visual)
    (put-values o values
                '(background-pixmap
                  background-pixel
                  border-pixmap
                  border-pixel
                  bit-gravity
                  win-gravity
                  backing-store
                  backing-planes
                  backing-pixel
                  override-redirect
                  save-under
                  event-mask
                  do-not-propagate-mask
                  colormap
                  cursor))
    (flush-output-port o)
    wid))

(define (x-change-window-attributes display window values)
  (let ((o (connection-outport display)))
    (put-u8 o 2)                        ;ChangeWindowAttributes
    (put-u8 o 0)
    (put-u16 o (+ 3 (length values)))
    (put-u32 o window)
    (put-values o values
                '(background-pixmap
                  background-pixel
                  border-pixmap
                  border-pixel
                  bit-gravity
                  win-gravity
                  backing-store
                  backing-planes
                  backing-pixel
                  override-redirect
                  save-under
                  event-mask
                  do-not-propagate-mask
                  colormap
                  cursor))
    (flush-output-port o)))

(define (x-destroy-window display window)
  (let ((o (connection-outport display)))
    (put-u8 o 4)                        ;DestroyWindow
    (put-u8 o 0)
    (put-u16 o 2)
    (put-u32 o window)
    (flush-output-port o)))

(define (x-map-window display window)
  (let ((o (connection-outport display)))
    (put-u8 o 8)                        ;MapWindow
    (put-u8 o 0)
    (put-u16 o 2)
    (put-u32 o window)
    (flush-output-port o)))

(define (x-unmap-window display window)
  (let ((o (connection-outport display)))
    (put-u8 o 10)                        ;UnmapWindow
    (put-u8 o 0)
    (put-u16 o 2)
    (put-u32 o window)
    (flush-output-port o)))

;; FIXME: displays should have an ATOM map. symbols should be usable
;; as atoms transparently, regardless of if they are interned or not.
;; atoms can not be uninterned... NUL bytes might not work in atoms.
;; they should be latin-1 apparently, but does utf8 work?


;;;
;;;
;;;
(define (intern-atom display name only-if-exists)
  ;; Lazy version
  (define-x-struct atom-reply
    (u32 atom))
  (call-with-x-output/new display 16 (bool->u8 only-if-exists)
    (lambda (o)
      (put-u16 o (string-length name))
      (put-u16 o 0)
      (put-string8 o name)
      (make-atom name ))
    
    (lambda (b r)
      (atom-id-set! r (atom-reply-atom b (reply-sizeof* b))))))

(define (x-intern-atom display name only-if-exists)
  (let ((o (connection-outport display)))
    (put-u8 o 16)                       ;InternAtom
    (put-u8 o (if only-if-exists 1 0))
    (put-u16 o (+ 2 (/ (round4 (string-length name)) 4)))
    (put-u16 o (string-length name))
    (put-u16 o 0)
    (put-string8 o name)
    (flush-output-port o)

    (let ((b (make-buffer (connection-inport display))))
      (buffer-read! b 32)
      (case (read-u8 b 0)
        ((1)
         ;; reply
         (buffer-read! b (* (reply-length b) 4))
         (read-u32 b 8))
        ((0)
         (raise-x-error b))
        (else
         (print "what is this? first byte: " (read-u8 b 0)))))))

(define (x-get-atom-name display atom)
  (define-x-struct get-atom-name-reply
    (u16 length-of-name)
    (u16) (u32) (u32) (u32) (u32) (u32)
    ((string8 length-of-name) name))
  (let ((o (connection-outport display)))
    (put-u8 o 17)                       ;GetAtomName
    (put-u8 o 0)
    (put-u16 o 2)
    (put-u32 o atom)
    (flush-output-port o)
    (let ((b (make-buffer (connection-inport display))))
      (buffer-read! b 32)
      (case (read-u8 b 0)
        ((1)
         ;; reply
;;          (print "got a reply... " (reply-sequence-number b))
         (buffer-read! b (* (reply-length b) 4))
         (get-atom-name-reply-name b (reply-sizeof* b)))
        ((0)
         (raise-x-error b))
        (else
         (print "what is this? first byte: " (read-u8 b 0)))))))

(define (x-change-property display mode window property type format data)
  (call-with-x-output display 18 mode
    (lambda (o)
      (put-u32 o window)
      (put-u32 o property)
      (put-u32 o type)
      (put-u8 o format)
      (put-bytevector o '#vu8(0 0 0))
      (put-u32 o (/ (bytevector-length data)
                    (case format
                      ((8) 1) ((16) 2) ((32) 4))))
      (put-bytevector o data))))

(define (create-gc display drawable values)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 55)                       ;CreateGC
    (put-u8 o 0)                        ;unused
    (put-u16 o (+ 4 (length values)))
    (put-u32 o cid)
    (put-u32 o drawable)
    (put-values o values
                '(function
                  plane-mask
                  foreground
                  background
                  line-width
                  line-style
                  cap-style
                  join-style
                  fill-style
                  fill-rule
                  tile
                  stipple
                  tile-stipple-x-origin
                  tile-stipple-y-origin
                  font
                  subwindow-mode
                  graphics-exposures
                  clip-x-origin
                  clip-y-origin
                  clip-mask
                  dash-offset
                  dashes
                  arc-mode))
    (flush-output-port o)
    cid))

(define (x-change-gc display gc values)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 56)                       ;ChangeGC
    (put-u8 o 0)                        ;unused
    (put-u16 o (+ 3 (length values)))
    (put-u32 o gc)
    (put-values o values
                '(function
                  plane-mask
                  foreground
                  background
                  line-width
                  line-style
                  cap-style
                  join-style
                  fill-style
                  fill-rule
                  tile
                  stipple
                  tile-stipple-x-origin
                  tile-stipple-y-origin
                  font
                  subwindow-mode
                  graphics-exposures
                  clip-x-origin
                  clip-y-origin
                  clip-mask
                  dash-offset
                  dashes
                  arc-mode))
    (flush-output-port o)))


(define (x-clear-area display window x y width height exposures)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 61)                       ;ClearArea
    (put-u8 o (if exposures 1 0))
    (put-u16 o 4)
    (put-u32 o window)
    (put-s16 o x)
    (put-s16 o y)
    (put-u16 o width)
    (put-u16 o height)
    (flush-output-port o)))

(define (x-poly-point display drawable gc coordinate-mode points)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 64)                       ;PolyPoint
    (put-u8 o coordinate-mode)
    (put-u16 o (+ 3 (length points)))
    (put-u32 o drawable)
    (put-u32 o gc)
    (for-each (lambda (p)
                (put-s16 o (car p))
                (put-s16 o (cdr p)))
              points)
    (flush-output-port o)))

(define (x-poly-line display drawable gc coordinate-mode points)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 65)                       ;PolyLine
    (put-u8 o coordinate-mode)
    (put-u16 o (+ 3 (length points)))
    (put-u32 o drawable)
    (put-u32 o gc)
    (for-each (lambda (p)
                (put-s16 o (car p))
                (put-s16 o (cdr p)))
              points)
    (flush-output-port o)))

(define (x-poly-segment display drawable gc segments)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 66)                       ;PolySegment
    (put-u8 o 0)
    (put-u16 o (+ 3 (* 2 (length segments))))
    (put-u32 o drawable)
    (put-u32 o gc)
    (for-each (lambda (p)
                (put-s16 o (car p))     ;x1
                (put-s16 o (cadr p))    ;y1
                (put-s16 o (caddr p))   ;x2
                (put-s16 o (cadddr p))) ;y2
              segments)
    (flush-output-port o)))

(define (x-poly-rectangle display drawable gc rectangles)
  (let ((o (connection-outport display))
        (cid (connection-get-resource-id! display)))
    (put-u8 o 67)                       ;PolyRectangle
    (put-u8 o 0)
    (put-u16 o (+ 3 (* 2 (length rectangles))))
    (put-u32 o drawable)
    (put-u32 o gc)
    (for-each (lambda (p)
                (put-s16 o (car p))     ;x
                (put-s16 o (cadr p))    ;y
                (put-u16 o (caddr p))   ;width
                (put-u16 o (cadddr p))) ;height
              rectangles)
    (flush-output-port o)))

(define (x-poly-arc display drawable gc arcs)
  (call-with-x-output display 68 0
    (lambda (o)
      (let ((cid (connection-get-resource-id! display)))
        (put-u32 o drawable)
        (put-u32 o gc)
        (for-each (lambda (p)
                    (put-s16 o (list-ref p 0)) ;x
                    (put-s16 o (list-ref p 1)) ;y
                    (put-u16 o (list-ref p 2)) ;width
                    (put-u16 o (list-ref p 3)) ;height
                    (put-s16 o (list-ref p 4)) ;angle1
                    (put-s16 o (list-ref p 5))) ;angle2
                  arcs)))))

(define (x-fill-poly display drawable gc shape coordinate-mode points)
  (call-with-values open-bytevector-output-port
    (lambda (o c)
      (let ((cid (connection-get-resource-id! display)))
        (put-u32 o drawable)
        (put-u32 o gc)
        (put-u8 o shape)
        (put-u8 o coordinate-mode)
        (put-u16 o 0)
        (for-each (lambda (p)
                    (put-s16 o (car p))  ;x
                    (put-s16 o (cdr p))) ;y
                  points))
      (send-request display 69 0 (c)))))

(define (x-poly-fill-rectangle display drawable gc rectangles)
  (call-with-x-output display 70 0
    (lambda (o)
      (let ((cid (connection-get-resource-id! display)))
        (put-u32 o drawable)
        (put-u32 o gc)
        (for-each (lambda (p)
                    (put-s16 o (car p))     ;x
                    (put-s16 o (cadr p))    ;y
                    (put-u16 o (caddr p))   ;width
                    (put-u16 o (cadddr p))) ;height
                  rectangles)))))

(define (x-poly-fill-arc display drawable gc arcs)
  (call-with-x-output display 71 0
    (lambda (o)
      (let ((cid (connection-get-resource-id! display)))
        (put-u32 o drawable)
        (put-u32 o gc)
        (for-each (lambda (p)
                    (put-s16 o (list-ref p 0)) ;x
                    (put-s16 o (list-ref p 1)) ;y
                    (put-u16 o (list-ref p 2)) ;width
                    (put-u16 o (list-ref p 3)) ;height
                    (put-s16 o (list-ref p 4)) ;angle1
                    (put-s16 o (list-ref p 5))) ;angle2
                  arcs)))))

(define (x-list-extensions display)
  ;; expects an answer
  (let ((o (connection-outport display)))
    (put-u8 o 99)                       ;ListExtensions
    (put-u8 o 0)                        ;unused
    (put-u16 o 1)
    (flush-output-port o)))

(define (x-change-keyboard-control display values)
  ;; Keyword arguments would be somewhat useful here
  (let ((o (connection-outport display)))
    (put-u8 o 102)                      ;ChangeKeyboardControl
    (put-u8 o 0)                        ;unused
    (put-u16 o (+ 2 (length values)))

    (put-values o values
                '(key-click-percent
                  bell-percent
                  bell-pitch
                  bell-duration
                  led
                  led-mode
                  key
                  auto-repeat-mode))
    
    (flush-output-port o)
    ))



(define (bell display percent)
  "Somehow there is a bell in every keyboard connected to an X
terminal. This procedure rings that bell. See XBell(3) in your UNIX
manual."
  (unless (<= -100 percent 100)
    (raise (condition
            (make-who-condition 'bell)
            (make-message-condition "Invalid percentage (must be between -100 and 100 inclusive)")
            (make-x-value-error #f 104 0)
            (make-irritants-condition percent))))
  (send-request display 104 (fxand #xff percent) '#vu8()))



(define-x-struct event
  (u8 code)
  (u8 detail)
  (u16 sequence-number))

(define (read-event display b)
  (print "event: " (event-code b)
         " detail: " (event-detail b)
         " sequence-number: " (event-sequence-number b)))

(define (get-next-thing display)
  (let ((b (connection-inbuffer display)))
    (buffer-reset! b)
    (buffer-read! b 32)
    (case (read-u8 b 0)
      ((1)
       ;; Reply
       (print "got a reply... " (reply-sequence-number b))
       (buffer-read! b (* (reply-length b) 4))
       )
      ((0)
       (raise-x-error b))
      (else
       ;; Event
       (read-event display b)))))

;; xtrace -k -d :0 -D localhost:0

(define dpy (open-display "localhost" "x11"))

(define screen (vector-ref (connection-roots dpy) 1))


(define red (create-gc dpy (screen-root screen) '((background . #xff0000))))

(define black (create-gc dpy (screen-root screen) '((background . #xffffff))))

(define cfx-background #xbbd7a6)

(define cfx-orange (create-gc dpy (screen-root screen)
                                '((foreground . #xf25d19))))

(define cfx-blue (create-gc dpy (screen-root screen)
                              '((foreground . #x254aa5))))

(define cfx-green (create-gc dpy (screen-root screen)
                               '((foreground . #x1aaf59))))


(define w (create-window dpy 0 (screen-root screen)
                           0 0 100 100
                           1
                           1
                           0
                           (list (cons 'background-pixel cfx-background)
                                 '(border-pixel . 0)
                                 '(bit-gravity . 1))))

(x-change-property dpy 0 w
                   (x-intern-atom dpy "_NET_WM_NAME" #f)
                   (x-intern-atom dpy "UTF8_STRING" #f)
                   8
                   (string->utf8 "X library for R6RS Scheme"))

;; (replace-property/utf8 w '_NET_WM_NAME "X library for R6RS Scheme")


(x-map-window dpy w)



(do ((points '() (cons (cons (random 300) (random 300)) points))
     (i 0 (+ i 1)))
    ((= i 50)
     (x-poly-line dpy w (vector-ref (vector cfx-green cfx-orange cfx-blue black)
                                    (random 4))
                  0 points)))

(x-poly-segment dpy w black '((0 0 10 10)
                              (2 0 12 10)
                              (4 0 14 10)
                              (6 0 16 10)))


(x-poly-rectangle dpy w cfx-orange '((0 0 10 10)
                                     (10 10 40 40)
                                     (50 50 100 100)
                                     ))



(x-poly-line dpy w cfx-orange 0 '((0 . 0) (10 . 10)))

(x-poly-line dpy w cfx-green 0 '((11 . 11) (30 . 30)))

(x-poly-line dpy w cfx-blue 0 '((31 . 31) (40 . 40)))

(x-poly-arc dpy w cfx-orange '((1 10 400 400 2000 3300)))

(x-fill-poly dpy w cfx-green 0 0 '((0 . 0) (300 . 0) (150 . 150)))

(x-poly-fill-rectangle dpy w cfx-green '((0 0 10 10)
                                         (10 10 10 10)
                                         (20 20 10 10)
                                         (30 30 10 10)))

(define (xdeg rad)
  ;; FIXME: modulo 2 pi?
  "Converts from radians to degrees scaled by 64, as used by X."
  (exact (round (* 64 360 (/ rad 2 (angle -1))))))

(define (deg->xdeg d) (exact (round (* 64 d))))

;; pacman
(x-poly-fill-arc dpy w cfx-orange (list (list 1 10 200 200
                                              (deg->xdeg 45)
                                              (deg->xdeg (- 360 45 45)))
                                        (list 200 105 10 10
                                             (deg->xdeg 0)
                                             (deg->xdeg 360))
                                        (list 250 105 10 10
                                             (deg->xdeg 0)
                                             (deg->xdeg 360))))

(x-clear-area dpy w 0 0 0 0 #f)         ;"clear screen"

(x-destroy-window dpy w)


(x-change-gc dpy cfx-orange '((function . 3)
                              (foreground . #xf25d19)
                              (background . #xbbd7a6)
                              (fill-style . 2)))


(x-change-window-attributes dpy w
                            (list (cons 'event-mask (bitwise-ior KeyPress KeyRelease))
                                  ))

(x-change-window-attributes dpy w
                            (list (cons 'event-mask (bitwise-xor #xFFFFFFFF #xFE000000))
                                  ))


(x-change-window-attributes dpy w
                            (list (cons 'event-mask #xFFFFFFFF)
                                  ))




(let lp ()
  (get-next-thing dpy)
  (lp))


(x-clear-area dpy w 0 0 0 0 #f)         ;"clear screen"


(get-next-thing dpy)

(x-change-keyboard-control dpy '((led-mode . 1)))



(x-intern-atom dpy "TEST" #f)

(do ((i 1 (+ i 1)))
    ((= i 69))
  (display (x-get-atom-name dpy i))
  (display " "))


(x-get-atom-name dpy 0)

;; event-mask
(define KeyPress #x00000001)
(define KeyRelease #x00000002)
(define ButtonPress #x00000004)
(define ButtonRelease #x00000008)
(define EnterWindow #x00000010)
(define LeaveWindow #x00000020)
(define PointerMotion #x00000040)
(define PointerMotionHint #x00000080)
(define Button1Motion #x00000100)
(define Button2Motion #x00000200)
(define Button3Motion #x00000400)
(define Button4Motion #x00000800)
(define Button5Motion #x00001000)
(define ButtonMotion #x00002000)
(define KeymapState #x00004000)
(define Exposure #x00008000)
(define VisibilityChange #x00010000)
(define StructureNotify #x00020000)
(define ResizeRedirect #x00040000)
(define SubstructureNotify #x00080000)
(define SubstructureRedirect #x00100000)
(define FocusChange #x00200000)
(define PropertyChange #x00400000)
(define ColormapChange #x00800000)
(define OwnerGrabButton #x01000000)
;; #xFE000000 must be zero

;; for set of pointer event: #xFFFF8003 unused but must be zero

;; for set of device event: #xFFFFC0B0 unused but must be zero


)
