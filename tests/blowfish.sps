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

(import (weinholt crypto blowfish)
        (srfi :78 lightweight-testing)
        (rnrs))

;; Test vectors from http://www.schneier.com/code/vectors.txt

(define (test key* plaintext*)
  (let ((key (make-bytevector 8))
        (plaintext (make-bytevector 8)))
    (bytevector-u64-set! key 0 key* (endianness big))
    (bytevector-u64-set! plaintext 0 plaintext* (endianness big))
    (let ((enc (make-bytevector 8 0))
          (dec (make-bytevector 8 0)))
      (let* ((sched (expand-blowfish-key key))
             (desched (reverse-blowfish-schedule sched)))
        (blowfish-encrypt! plaintext 0 enc 0 sched)
        (blowfish-decrypt! enc 0 dec 0 desched)
        (clear-blowfish-schedule! sched)
        (clear-blowfish-schedule! desched)
        (and (equal? dec plaintext)
             (bytevector-u64-ref enc 0 (endianness big)))))))

(check (test #x0000000000000000 #x0000000000000000) => #x4EF997456198DD78)
(check (test #xFFFFFFFFFFFFFFFF #xFFFFFFFFFFFFFFFF) => #x51866FD5B85ECB8A)
(check (test #x3000000000000000 #x1000000000000001) => #x7D856F9A613063F2)
(check (test #x1111111111111111 #x1111111111111111) => #x2466DD878B963C9D)
(check (test #x0123456789ABCDEF #x1111111111111111) => #x61F9C3802281B096)
(check (test #x1111111111111111 #x0123456789ABCDEF) => #x7D0CC630AFDA1EC7)
(check (test #x0000000000000000 #x0000000000000000) => #x4EF997456198DD78)
(check (test #xFEDCBA9876543210 #x0123456789ABCDEF) => #x0ACEAB0FC6A0A28D)
(check (test #x7CA110454A1A6E57 #x01A1D6D039776742) => #x59C68245EB05282B)
(check (test #x0131D9619DC1376E #x5CD54CA83DEF57DA) => #xB1B8CC0B250F09A0)
(check (test #x07A1133E4A0B2686 #x0248D43806F67172) => #x1730E5778BEA1DA4)
(check (test #x3849674C2602319E #x51454B582DDF440A) => #xA25E7856CF2651EB)
(check (test #x04B915BA43FEB5B6 #x42FD443059577FA2) => #x353882B109CE8F1A)
(check (test #x0113B970FD34F2CE #x059B5E0851CF143A) => #x48F4D0884C379918)
(check (test #x0170F175468FB5E6 #x0756D8E0774761D2) => #x432193B78951FC98)
(check (test #x43297FAD38E373FE #x762514B829BF486A) => #x13F04154D69D1AE5)
(check (test #x07A7137045DA2A16 #x3BDD119049372802) => #x2EEDDA93FFD39C79)
(check (test #x04689104C2FD3B2F #x26955F6835AF609A) => #xD887E0393C2DA6E3)
(check (test #x37D06BB516CB7546 #x164D5E404F275232) => #x5F99D04F5B163969)
(check (test #x1F08260D1AC2465E #x6B056E18759F5CCA) => #x4A057A3B24D3977B)
(check (test #x584023641ABA6176 #x004BD6EF09176062) => #x452031C1E4FADA8E)
(check (test #x025816164629B007 #x480D39006EE762F2) => #x7555AE39F59B87BD)
(check (test #x49793EBC79B3258F #x437540C8698F3CFA) => #x53C55F9CB49FC019)
(check (test #x4FB05E1515AB73A7 #x072D43A077075292) => #x7A8E7BFA937E89A3)
(check (test #x49E95D6D4CA229BF #x02FE55778117F12A) => #xCF9C5D7A4986ADB5)
(check (test #x018310DC409B26D6 #x1D9D5C5018F728C2) => #xD1ABB290658BC778)
(check (test #x1C587F1C13924FEF #x305532286D6F295A) => #x55CB3774D13EF201)
(check (test #x0101010101010101 #x0123456789ABCDEF) => #xFA34EC4847B268B2)
(check (test #x1F1F1F1F0E0E0E0E #x0123456789ABCDEF) => #xA790795108EA3CAE)
(check (test #xE0FEE0FEF1FEF1FE #x0123456789ABCDEF) => #xC39E072D9FAC631D)
(check (test #x0000000000000000 #xFFFFFFFFFFFFFFFF) => #x014933E0CDAFF6E4)
(check (test #xFFFFFFFFFFFFFFFF #x0000000000000000) => #xF21E9A77B71C49BC)
(check (test #x0123456789ABCDEF #x0000000000000000) => #x245946885754369A)
(check (test #xFEDCBA9876543210 #xFFFFFFFFFFFFFFFF) => #x6B5C5A9C5D9E0A5A)

(define (testv keylen key*)
  (let ((key (make-bytevector keylen))
        (plaintext (make-bytevector 8)))
    (bytevector-uint-set! key 0 key* (endianness big) keylen)
    (bytevector-u64-set! plaintext 0 #xFEDCBA9876543210 (endianness big))
    (let ((enc (make-bytevector 8 0))
          (dec (make-bytevector 8 0)))
      (let* ((sched (expand-blowfish-key key))
             (desched (reverse-blowfish-schedule sched)))
        (blowfish-encrypt! plaintext 0 enc 0 sched)
        (blowfish-decrypt! enc 0 dec 0 desched)
        (clear-blowfish-schedule! sched)
        (clear-blowfish-schedule! desched)
        (and (equal? dec plaintext)
             (bytevector-u64-ref enc 0 (endianness big)))))))

(check (testv 1 #xF0) => #xF9AD597C49DB005E)
(check (testv 2 #xF0E1) => #xE91D21C1D961A6D6)
(check (testv 3 #xF0E1D2) => #xE9C2B70A1BC65CF3)
(check (testv 4 #xF0E1D2C3) => #xBE1E639408640F05)
(check (testv 5 #xF0E1D2C3B4) => #xB39E44481BDB1E6E)
(check (testv 6 #xF0E1D2C3B4A5) => #x9457AA83B1928C0D)
(check (testv 7 #xF0E1D2C3B4A596) => #x8BB77032F960629D)
(check (testv 8 #xF0E1D2C3B4A59687) => #xE87A244E2CC85E82)
(check (testv 9 #xF0E1D2C3B4A5968778) => #x15750E7A4F4EC577)
(check (testv 10 #xF0E1D2C3B4A596877869) => #x122BA70B3AB64AE0)
(check (testv 11 #xF0E1D2C3B4A5968778695A) => #x3A833C9AFFC537F6)
(check (testv 12 #xF0E1D2C3B4A5968778695A4B) => #x9409DA87A90F6BF2)
(check (testv 13 #xF0E1D2C3B4A5968778695A4B3C) => #x884F80625060B8B4)
(check (testv 14 #xF0E1D2C3B4A5968778695A4B3C2D) => #x1F85031C19E11968)
(check (testv 15 #xF0E1D2C3B4A5968778695A4B3C2D1E) => #x79D9373A714CA34F)
(check (testv 16 #xF0E1D2C3B4A5968778695A4B3C2D1E0F) => #x93142887EE3BE15C)
(check (testv 17 #xF0E1D2C3B4A5968778695A4B3C2D1E0F00) => #x03429E838CE2D14B)
(check (testv 18 #xF0E1D2C3B4A5968778695A4B3C2D1E0F0011) => #xA4299E27469FF67B)
(check (testv 19 #xF0E1D2C3B4A5968778695A4B3C2D1E0F001122) => #xAFD5AED1C1BC96A8)
(check (testv 20 #xF0E1D2C3B4A5968778695A4B3C2D1E0F00112233) => #x10851C0E3858DA9F)
(check (testv 21 #xF0E1D2C3B4A5968778695A4B3C2D1E0F0011223344) => #xE6F51ED79B9DB21F)
(check (testv 22 #xF0E1D2C3B4A5968778695A4B3C2D1E0F001122334455) => #x64A6E14AFD36B46F)
(check (testv 23 #xF0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566) => #x80C7D7D45A5479AD)
(check (testv 24 #xF0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677) => #x05044B62FA52D080)

(check-report)
