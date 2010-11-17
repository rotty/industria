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

;; Old timey hex dumps

(library (weinholt text hexdump (1 0 20101107))
  (export hexdump)
  (import (rnrs)
          (only (srfi :13 strings) string-pad))

  ;; Mostly cp437. Perhaps there should be support for other character
  ;; sets here, but I like this. It is how NC used to show hex dumps
  ;; (in my part of the world anyhow) and because almost every byte
  ;; has a unique graphic it's sometimes easier to visually identify
  ;; the type of data.
  (define cp437 '#(#\. #;#\x2007 #\x263A #\x263B #\x2665 #\x2666 #\x2663
                   #\x2660 #\x2022 #\x25D8 #\x25CB #\x25D9 #\x2642
                   #\x2640 #\x266A #\x266B #\x263C #\x25BA #\x25C4
                   #\x2195 #\x203C #\x00B6 #\x00A7 #\x25AC #\x21A8
                   #\x2191 #\x2193 #\x2192 #\x2190 #\x221F #\x2194
                   #\x25B2 #\x25BC #\x0020 #\x0021 #\x0022 #\x0023
                   #\x0024 #\x0025 #\x0026 #\x0027 #\x0028 #\x0029
                   #\x002A #\x002B #\x002C #\x002D #\x002E #\x002F
                   #\x0030 #\x0031 #\x0032 #\x0033 #\x0034 #\x0035
                   #\x0036 #\x0037 #\x0038 #\x0039 #\x003A #\x003B
                   #\x003C #\x003D #\x003E #\x003F #\x0040 #\x0041
                   #\x0042 #\x0043 #\x0044 #\x0045 #\x0046 #\x0047
                   #\x0048 #\x0049 #\x004A #\x004B #\x004C #\x004D
                   #\x004E #\x004F #\x0050 #\x0051 #\x0052 #\x0053
                   #\x0054 #\x0055 #\x0056 #\x0057 #\x0058 #\x0059
                   #\x005A #\x005B #\x005C #\x005D #\x005E #\x005F
                   #\x0060 #\x0061 #\x0062 #\x0063 #\x0064 #\x0065
                   #\x0066 #\x0067 #\x0068 #\x0069 #\x006A #\x006B
                   #\x006C #\x006D #\x006E #\x006F #\x0070 #\x0071
                   #\x0072 #\x0073 #\x0074 #\x0075 #\x0076 #\x0077
                   #\x0078 #\x0079 #\x007A #\x007B #\x007C #\x007D
                   #\x007E #\x2302 #\x00C7 #\x00FC #\x00E9 #\x00E2
                   #\x00E4 #\x00E0 #\x00E5 #\x00E7 #\x00EA #\x00EB
                   #\x00E8 #\x00EF #\x00EE #\x00EC #\x00C4 #\x00C5
                   #\x00C9 #\x00E6 #\x00C6 #\x00F4 #\x00F6 #\x00F2
                   #\x00FB #\x00F9 #\x00FF #\x00D6 #\x00DC #\x00A2
                   #\x00A3 #\x00A5 #\x20A7 #\x0192 #\x00E1 #\x00ED
                   #\x00F3 #\x00FA #\x00F1 #\x00D1 #\x00AA #\x00BA
                   #\x00BF #\x2310 #\x00AC #\x00BD #\x00BC #\x00A1
                   #\x00AB #\x00BB #\x2591 #\x2592 #\x2593 #\x2502
                   #\x2524 #\x2561 #\x2562 #\x2556 #\x2555 #\x2563
                   #\x2551 #\x2557 #\x255D #\x255C #\x255B #\x2510
                   #\x2514 #\x2534 #\x252C #\x251C #\x2500 #\x253C
                   #\x255E #\x255F #\x255A #\x2554 #\x2569 #\x2566
                   #\x2560 #\x2550 #\x256C #\x2567 #\x2568 #\x2564
                   #\x2565 #\x2559 #\x2558 #\x2552 #\x2553 #\x256B
                   #\x256A #\x2518 #\x250C #\x2588 #\x2584 #\x258C
                   #\x2590 #\x2580 #\x03B1 #\x03B2 #\x0393 #\x03C0
                   #\x03A3 #\x03C3 #\x00B5 #\x03C4 #\x03A6 #\x0398
                   #\x03A9 #\x03B4 #\x221E #\x2205 #\x2208 #\x2229
                   #\x2261 #\x00B1 #\x2265 #\x2264 #\x2320 #\x2321
                   #\x00F7 #\x2248 #\x00B0 #\x2219 #\x00B7 #\x221A
                   #\x207F #\x00B2 #\x25A0 #\x00A0))

  (define (bytes p bv start end)
    (do ((i start (+ i 1)))
        ((= i (+ start 4)))
      (cond ((< i end)
             (let ((b (bytevector-u8-ref bv i)))
               (if (< b #x10) (display "0" p))
               (display (number->string b 16) p)
               (display #\space p)))
            (else (display "   " p)))))

  (define hexdump
    (case-lambda
      ((p bv)
       (hexdump p bv 0))
      ((p bv start)
       (hexdump p bv start (bytevector-length bv)))
      ((p bv start end prefix)
       (hexdump p bv start ""))
      ((p bv start end prefix)
       (hexdump p bv start "" "  "))
      ((p bv start end prefix suffix)
       (let ((p (or p (current-output-port))))
         (do ((i start (+ i 16)))
             ((>= i end))
           (display prefix p)
           (display (string-pad (number->string i 16) 5 #\0) p)
           (display "  " p)
           (bytes p bv i end) (display "│ " p)
           (bytes p bv (+ i 4) end) (display "│ " p)
           (bytes p bv (+ i 8) end) (display "│ " p)
           (bytes p bv (+ i 12) end) (display suffix p)
           (do ((j i (+ j 1)))
               ((or (= j (+ i 16)) (= j end)))
             (display (vector-ref cp437 (bytevector-u8-ref bv j)) p))
           (newline p)))))))
