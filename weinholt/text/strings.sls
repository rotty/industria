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


(library (weinholt text strings (0 0 20090827))
  (export string-split)
  (import (rnrs)
          (only (srfi :13 strings) string-index))

  ;; > (string-split "foo bar" #\space)
  ;; ("foo" "bar")

  ;; > (string-split "foo  bar" #\space)
  ;; ("foo" "" "bar")

  ;; > (string-split "" #\space)
  ;; ("")

  ;; > (string-split "foo bar baz" #\space 1)
  ;; ("foo" "bar baz")

  (define string-split
    (case-lambda
      ((str c max start end)
       (cond ((zero? max)
              (list (substring str start end)))
             ((string-index str c start end) =>
              (lambda (i)
                (cons (substring str start i)
                      (string-split str c (- max 1) (+ i 1) end))))
             (else
              (list (substring str start end)))))
      ((str c max start)
       (string-split str c max start (string-length str)))
      ((str c max)
       (string-split str c max 0 (string-length str)))
      ((str c)
       (string-split str c -1 0 (string-length str)))))

  )
