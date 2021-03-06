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

(import (weinholt crypto sha-1)
        (rnrs))


(define (test/s expect . data)
  (let ((result (sha-1->string (apply sha-1 (map string->utf8 data)))))
    (unless (string-ci=? result expect)
      (error 'test "Bad result" result))))

(test/s "da39a3ee5e6b4b0d3255bfef95601890afd80709" "")
(test/s "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b" "A")
(test/s "801c34269f74ed383fc97de33604b8a905adb635" "AA")
(test/s "606ec6e9bd8a8ff2ad14e5fade3f264471e82251" "AAA")
(test/s "e2512172abf8cc9f67fdd49eb6cacf2df71bbad3" "AAAA")
(test/s "c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403" "AAAAA")
(test/s "2d2929e0f1bca99d9652924ce73b7969d33ff429" "AAAAAA")
(test/s "f9b2869de6cc9226b990d83f805ec83915cc9c85" "AAAAAAA")
(test/s "c08598945e566e4e53cf3654c922fa98003bf2f9" "AAAAAAAA")
(test/s "1cbbd7d768f77d4d3f24de43238979aa9fa1cd2f" "AAAAAAAAA")
(test/s "c71613a7386fd67995708464bf0223c0d78225c4" "AAAAAAAAAA")
(test/s "004537f3b1fd67347489185a1c4b55da58f6edca" "AAAAAAAAAAA")
(test/s "2b52d47ab698ccce79ab6d0552e98f87f8a3aebc" "AAAAAAAAAAAA")
(test/s "91dd8a106d38bd458250b80314a3b4837acfa85b" "AAAAAAAAAAAAA")
(test/s "9108c1fc03ff53527f9d9de94d9c151e697e154d" "AAAAAAAAAAAAAA")
(test/s "343ad63c4d45b81d945360c080b065c98c7a8351" "AAAAAAAAAAAAAAA")
(test/s "19b1928d58a2030d08023f3d7054516dbc186f20" "AAAAAAAAAAAAAAAA")
(test/s "9ee276acbf8a1257a58a5bad22bef8907e49cbf2" "AAAAAAAAAAAAAAAAA")
(test/s "3a8262b7c3b43877389d300986b0c0b1eedfdfbf" "AAAAAAAAAAAAAAAAAA")
(test/s "1a6372d15d776f9879d300e51ec145363cd63667" "AAAAAAAAAAAAAAAAAAA")
(test/s "ebd3d4adf97066c84b8ed17d6bd1e270818763e0" "AAAAAAAAAAAAAAAAAAAA")
(test/s "29ad0c6384182c5c2d4c953e200eed245467e503" "AAAAAAAAAAAAAAAAAAAAA")
(test/s "d088f3b187a0957d72b5d5645939bfc4302dffb8" "AAAAAAAAAAAAAAAAAAAAAA")
(test/s "293efde746444af8e7aff0ad1a57c874cdc50966" "AAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4f130f23896bd6d0e95f2a42b2cb83d17ac8f1a2" "AAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "a92b995e293d295c4bbab7043cccb030bef47488" "AAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "ed641f05795d5ee712d1e6ddc2d5146079db9dee" "AAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "82e757683db0b0417976c1661f7b020ae5225b80" "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "7b92fac2f01809101168d085e9f1ef059b131be4" "AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "41be845b8e19da10e18a6bd3105793484d22bd53" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "2a22d32e957a9de69c50e8f52872e2dbf1d0745c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "ca75e66a01a2b5b24f825f569d5ddeead3e50e4d" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "43d83b2e816a89cac876f16530b0b625585c8160" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "e04976c6e1ce44aa1840b07b57021c158a11eafc" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "609b3f4ee88fd429c53d51dca7ace87711e7d48f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4c911f83e9b42c92b8ea62135fa1bc0e727ce367" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "3c8a34351337e8f5376092d3f329767c8035344d" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "0b314daa55be9ff60f4337a25fef266036aed20c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "35309ec13ef8d90aaae172e4cf437eb16ddbf6d5" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "6784f01a2b317aeef2ac03660dafa3270f4d420e" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "5cdbb64242d8551a7cf583903fd7d5b72b277537" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "0e477417eecfe482fd137e4a038fb5cf6dc7be76" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "880b405e8e5059e3aa1797f662ff4a0cfcbce20b" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "885dd07854409bf8cf5443652fd6835c23423338" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "a7da128970268478e46f9585d0fb6297349b9675" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "06bf9b84f2cffdb4b343ef9b3ddd1847f9b6ce3c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4683b63a087f88e7ada2f6e3eceb4a0e9f7195a1" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "b459efc276e7c1e39f997ed6c9b4f692dafd30b5" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "8b2177f39b224cab2fb4df5ee4827fbe7115ce44" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "d52bcfb557dd3ed70968f8835ccff3c924885631" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "080316afb4e11d98120b29d1070ce749f1f0a32c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4456f6c537924b7d47e430050d92bf6949a1fba8" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "defc08198e86f88a007ca10f10d8af0d402ffdc3" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "55066b480654e5846549494b863e3cd34bae76eb" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "18b837ae2f9a204a7fea6d6a2ae5174365137861" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "5021b3d42aa093bffc34eedd7a1455f3624bc552" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "6b45e3cf1eb3324b9fd4df3b83d89c4c2c4ca896" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "e8d6ea5c627fc8676fa662677b028640844dc35c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "e0ed6b6f61dae4219379cf9fe19565150c8e6046" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "ba83959b9f4a8b3ca082d501e7b75ce73992e35f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "c9c4571630054c5466d19b5ea28069dc71c72b68" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "fc202c022fdc439b99892020e04fc93b4ee8448a" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "0dc94299f2d293a48173f9c78a882f8a9bffe3b0" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "0ec86b3f3ac34ad860fa8da56bcca03a54018049" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "826b7e7a7af8a529ae1c7443c23bf185c0ad440c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "eddee92010936db2c45d2c9f5fdd2726fcd28789" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "d0c9def032806d32bc485ea5493e34217d5091c9" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "01ae707f5f6574b061a4643f59c98277da6544a3" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4b4e4f859b006e5b0afe2dc2806bae2ab3cb55b0" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "049dbd0c7c40ce1a9a322531c994778cae8f3f0f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "d0929751861c93c786335ead7d5b5c066b3a8cb7" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "41f9070504f9c81abfbb614daaec3b26a2f9237e" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4fced99ee1b5cb0dd68a5c5a194b79dc70841d43" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "1268a031cf339eb68968e87334574862a95c4d48" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "b17654dfc615ef4a8dd86d53f5dee434bec61143" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "e106fa6de4ce5177f0d2fd4b7bae8478456dc25c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "ccf93ced5c9a95c23ae36936b7ebff088c991919" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "e5e8a4e450be9938b318a96a5f95b12733cb39be" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "c958795890d309b7add6d6432b510c297375e5d7" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "2d5d85dfd3361150e8bebe7cb730c08258206ba6" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "259c4c06d026726ced06b9d81cd3abcd5e936393" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "736545c3e47672f832d54171c88b213789160c8d" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "3da1e7b5188c2fdc84aa4e3b0b2c05c93f246e2f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "dbf2a20a9e1ebe314e8da8a678fdc6949750b9c4" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "bcc9fe3fff88ff66df70c1e53401a28c5873bd63" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "54c4ba90ae95dd2dda25ce8eaec645ac56052845" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "1e34b919b2b449c51c72c4922e7d4841405857f1" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "0ac5a64edb54535a9d71ccc853a1073a5f2001e6" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "792534345f64f4d8cd1457ce8edf3e067cb5666f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "9a2f2b83877c65c955ab6a6c239357fac93609a5" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "5cd33462b7a8ffbf17dda2b61911377658a96f26" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "768bbe547a68238aecbbdddf78f517227e6ea98b" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "b70f0297e92d4b1f5ae01618d7ed6aafc2dd8404" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "6675ab9c5ca21f903e070ea1a217ac655584cf55" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "84e94d95ec69d965d0b36ca3a9ce5dcd4ec84bab" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "4e3872621039b359e7371bb9810430a5a2c78195" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "81ad592e1a48b35db67cf02705566315f2c149d1" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "39ba29cf0bc73595d1476abaa413ac968cdf8fa2" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "436bab78a2b10f04528d408c922fcdfba069419c" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "7a4a9ae537ebbbb826b1060e704490ad0f365ead" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")



(test/s "30b86e44e6001403827a62c58b08893e77cf121f" "AAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAA")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f"
        "" "" "" "" "" "AAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAA" "AAAA")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f"
        "" "" "" "AAAAAAAAAAAAAAAAAAAAA" "" "AAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAA" "AAAA" "")
(test/s "30b86e44e6001403827a62c58b08893e77cf121f"
        "" "" "AAAAAAAAAAAAAAAAAAAAA" "" "AAAAAAAAAAAAAAAAAAAA" "A" "AAAAAAAAAAAAAAAAAA" "AAAA" "")

(define (test/o expect string start end)
  (let ((state (make-sha-1)))
    (sha-1-update! state (string->utf8 string) start end)
    (sha-1-finish! state)
    (unless (string-ci=? (sha-1->string state) expect)
      (error 'test/o "Wrong hash"
             (sha-1->string state) expect ))))

(test/o "3a8262b7c3b43877389d300986b0c0b1eedfdfbf" "xAAAAAAAAAAAAAAAAAAyy" 1 19)
(test/o "3a8262b7c3b43877389d300986b0c0b1eedfdfbf" "xxAAAAAAAAAAAAAAAAAAyy" 2 20)


;; From RFC 3174

(let ((tests '(("A9993E364706816ABA3E25717850C26C9CD0D89D" 1
                "abc")
               ("84983E441C3BD26EBAAE4AA1F95129E5E54670F1" 1
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
               ("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F" 1000000
                "a")
               ("DEA356A2CDDD90C7A7ECEDC5EBB563934F460452" 10
                "0123456701234567012345670123456701234567012345670123456701234567")))
      (state (make-sha-1)))
  (for-each (lambda (expect rep data)
              (sha-1-clear! state)
              (do ((data (string->utf8 data))
                   (i 0 (+ i 1)))
                  ((= i rep))
                (sha-1-update! state data))
              (sha-1-finish! state)
              (unless (string-ci=? (sha-1->string state) expect)
                (error 'rfc3174-test "Wrong hash"
                       (sha-1->string state) expect)))
            (map car tests)
            (map cadr tests)
            (map caddr tests)))


;; From RFC 2202, (in which some tests are repeated due to some weird
;; typesetting error)

(define (test-hmac expect key data)
  (let ((result (sha-1->string (hmac-sha-1 key data))))
    (unless (string-ci=? result expect)
      (error 'test-hmac "bad result" result expect))))


(test-hmac "b617318655057264e28bc0b6fb378c8ef146be00"
           (make-bytevector 20 #x0b)
           (string->utf8 "Hi There"))

(test-hmac "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
           (string->utf8 "Jefe")
           (string->utf8 "what do ya want for nothing?"))

(test-hmac "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
           (make-bytevector 20 #xaa)
           (make-bytevector 50 #xdd))

(test-hmac "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
           #vu8(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08 #x09 #x0a #x0b #x0c
                     #x0d #x0e #x0f #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18 #x19)
           (make-bytevector 50 #xcd))

(test-hmac "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
           (make-bytevector 20 #x0c)
           (string->utf8 "Test With Truncation")) ;; not testing truncation...
;; digest-96 = 0x4c1a03424b55e07fe7f27be1

(test-hmac "aa4ae5e15272d00e95705637ce8a3b55ed402112"
           (make-bytevector 80 #xaa)
           (string->utf8 "Test Using Larger Than Block-Size Key - Hash Key First"))

(test-hmac "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
           (make-bytevector 80 #xaa)
           (string->utf8 "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"))
