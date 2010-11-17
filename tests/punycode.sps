#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2009, 2010 Göran Weinholt <goran@weinholt.se>
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
        (srfi :78 lightweight-testing)
        (weinholt text punycode))

;; Sample strings from RFC3492

(define-syntax test
  (lambda (x)
    (syntax-case x ()
      ((_ puny codes ...)
       #'(begin
           (check (punycode->string (string->utf8 puny)) =>
                  (list->string (map integer->char '(codes ...))))
           (check (string->punycode (list->string (map integer->char '(codes ...)))) =>
                  (string->utf8 puny)))))))

(test "egbpdaj6bu4bxfgehfvwxn"
      #x0644 #x064A #x0647 #x0645 #x0627 #x0628 #x062A #x0643 #x0644
      #x0645 #x0648 #x0634 #x0639 #x0631 #x0628 #x064A #x061F)

(test "ihqwcrb4cv8a8dqg056pqjye"
      #x4ED6 #x4EEC #x4E3A #x4EC0 #x4E48 #x4E0D #x8BF4 #x4E2D #x6587)

(test "ihqwctvzc91f659drss3x8bo0yb"
      #x4ED6 #x5011 #x7232 #x4EC0 #x9EBD #x4E0D #x8AAA #x4E2D #x6587)

(test "Proprostnemluvesky-uyb24dma41a"
      #x0050 #x0072 #x006F #x010D #x0070 #x0072 #x006F #x0073 #x0074
      #x011B #x006E #x0065 #x006D #x006C #x0075 #x0076 #x00ED #x010D
      #x0065 #x0073 #x006B #x0079)

(test "4dbcagdahymbxekheh6e0a7fei0b"
      #x05DC #x05DE #x05D4 #x05D4 #x05DD #x05E4 #x05E9 #x05D5 #x05D8
      #x05DC #x05D0 #x05DE #x05D3 #x05D1 #x05E8 #x05D9 #x05DD #x05E2
      #x05D1 #x05E8 #x05D9 #x05EA)

(test "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd"
      #x092F #x0939 #x0932 #x094B #x0917 #x0939 #x093F #x0928 #x094D
      #x0926 #x0940 #x0915 #x094D #x092F #x094B #x0902 #x0928 #x0939
      #x0940 #x0902 #x092C #x094B #x0932 #x0938 #x0915 #x0924 #x0947
      #x0939 #x0948 #x0902)

(test "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"
      #x306A #x305C #x307F #x3093 #x306A #x65E5 #x672C #x8A9E #x3092
      #x8A71 #x3057 #x3066 #x304F #x308C #x306A #x3044 #x306E #x304B)

(test "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c"
      #xC138 #xACC4 #xC758 #xBAA8 #xB4E0 #xC0AC #xB78C #xB4E4 #xC774
      #xD55C #xAD6D #xC5B4 #xB97C #xC774 #xD574 #xD55C #xB2E4 #xBA74
      #xC5BC #xB9C8 #xB098 #xC88B #xC744 #xAE4C)

(test "b1abfaaepdrnnbgefbadotcwatmq2g4l"
      #x043F #x043E #x0447 #x0435 #x043C #x0443 #x0436 #x0435 #x043E
      #x043D #x0438 #x043D #x0435 #x0433 #x043E #x0432 #x043E #x0440
      #x044F #x0442 #x043F #x043E #x0440 #x0443 #x0441 #x0441 #x043A
      #x0438)

(test "PorqunopuedensimplementehablarenEspaol-fmd56a"
      #x0050 #x006F #x0072 #x0071 #x0075 #x00E9 #x006E #x006F #x0070
      #x0075 #x0065 #x0064 #x0065 #x006E #x0073 #x0069 #x006D #x0070
      #x006C #x0065 #x006D #x0065 #x006E #x0074 #x0065 #x0068 #x0061
      #x0062 #x006C #x0061 #x0072 #x0065 #x006E #x0045 #x0073 #x0070
      #x0061 #x00F1 #x006F #x006C)

(test "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"
      #x0054 #x1EA1 #x0069 #x0073 #x0061 #x006F #x0068 #x1ECD #x006B
      #x0068 #x00F4 #x006E #x0067 #x0074 #x0068 #x1EC3 #x0063 #x0068
      #x1EC9 #x006E #x00F3 #x0069 #x0074 #x0069 #x1EBF #x006E #x0067
      #x0056 #x0069 #x1EC7 #x0074)

(test "3B-ww4c5e180e575a65lsy2b"
      #x0033 #x5E74 #x0042 #x7D44 #x91D1 #x516B #x5148 #x751F)

(test "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"
      #x5B89 #x5BA4 #x5948 #x7F8E #x6075 #x002D #x0077 #x0069 #x0074
      #x0068 #x002D #x0053 #x0055 #x0050 #x0045 #x0052 #x002D #x004D
      #x004F #x004E #x004B #x0045 #x0059 #x0053)

(test "Hello-Another-Way--fc4qua05auwb3674vfr0b"
      #x0048 #x0065 #x006C #x006C #x006F #x002D #x0041 #x006E #x006F
      #x0074 #x0068 #x0065 #x0072 #x002D #x0057 #x0061 #x0079 #x002D
      #x305D #x308C #x305E #x308C #x306E #x5834 #x6240)

(test "2-u9tlzr9756bt3uc0v"
      #x3072 #x3068 #x3064 #x5C4B #x6839 #x306E #x4E0B #x0032)

(test "MajiKoi5-783gue6qz075azm5e"
      #x004D #x0061 #x006A #x0069 #x3067 #x004B #x006F #x0069 #x3059
      #x308B #x0035 #x79D2 #x524D)

(test "de-jg4avhby1noc0d"
      #x30D1 #x30D5 #x30A3 #x30FC #x0064 #x0065 #x30EB #x30F3 #x30D0)

(test "d9juau41awczczp"
      #x305D #x306E #x30B9 #x30D4 #x30FC #x30C9 #x3067)

(test "-> $1.00 <--"
      #x002D #x003E #x0020 #x0024 #x0031 #x002E #x0030 #x0030 #x0020
      #x003C #x002D)


(check-report)
