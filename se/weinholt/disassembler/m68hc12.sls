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

;; Disassembler for the Motorola 68HC12, 68HCS12, etc. Sometimes
;; called CPU12.

;; XXX: There are some unimplemented parts of the ISA, e.g. the TFR
;; postbyte and the addressing modes are probably completely wrong.

;; TODO: Fix raise-UD to raise the same condition as the x86
;; disassembler.

(library (se weinholt disassembler m68hc12)
  (export get-instruction)
  (import (except (rnrs) get-u8))

  (define (map-in-order f l)
    (if (null? l)
        '()
        (cons (f (car l))
              (map-in-order f (cdr l)))))

  (define (raise-UD why)
    (error 'raise-UD "undefined opcode" why))

;;; Port input
  (define (really-get-bytevector-n port n collect tag)
    (let ((bv (get-bytevector-n port n)))
      (unless (eof-object? bv)
        (if collect (apply collect tag (bytevector->u8-list bv))))
      (when (or (eof-object? bv) (< (bytevector-length bv) n))
        (raise-UD "End of file inside instruction"))
      bv))

  (define (get-u8 port)
    (bytevector-u8-ref (really-get-bytevector-n port 1 #f #f)
                       0))

  (define (get-u8/collect port collect tag)
    (bytevector-u8-ref (really-get-bytevector-n port 1 collect tag)
                       0))

  (define (get-s8/collect port collect tag)
    (bytevector-s8-ref (really-get-bytevector-n port 1 collect tag)
                       0))

  (define (get-s16/collect port collect tag)
    (bytevector-s16-ref (really-get-bytevector-n port 2 collect tag)
                        0 (endianness big)))

  (define (get-u16/collect port collect tag)
    (bytevector-u16-ref (really-get-bytevector-n port 2 collect tag)
                        0 (endianness big)))

;;; CPU12 Opcode tables

  (define opcodes
    '#((bgnd) (mem) (iny) (dey)
       loop (jmp mem) (jmp opr16a) (bsr rel8)
       (inx) (dex) (rtc) (rti)
       (bset idx12 msk8) (bclr idx12 msk8)
       (brset idx12 msk8 rel8) (brclr idx12 msk8 rel8)
       ;; 10
       (andcc opr8i) (ediv) (mul) (emul) (orcc opr8i)
       (jsr mem)
       (jsr opr16a)
       (jsr opr8a)
       opcodes-18
       (leay mem) (leax mem) (leas mem)
       (bset opr16a msk8) (bclr opr16a msk8)
       (brset opr16a msk8 rel8) (brclr opr16a msk8 rel8)
       ;; 20
       (bra rel8) (brn rel8) (bhi rel8) (bls rel8)
       (bcc rel8) (bcs rel8) (bne rel8) (beq rel8)
       (bvc rel8) (bvs rel8) (bpl rel8) (bmi rel8)
       (bge rel8) (blt rel8) (bgt rel8) (ble rel8)
       ;; 30
       (pulx) (puly) (pula) (pulb) (pshx) (pshy) (psha) (pshb)
       (pulc) (pshc) (puld) (pshd) (wavr) (rts) (wai) (swi)
       ;; 40
       (nega) (coma) (inca) (deca) (lsra) (rola) (rora) (asra) (asla) (lsrd)
       (call opr16i page) (call mem page) ;FIXME: 4B takes no 'page' with indirect addressing
       (bset opr8a msk8) (bclr opr8a msk8)
       (brset opr8a msk8 rel8) (brclr opr8a msk8 rel8)
       ;; 50
       (negb) (comb) (inbc) (decb) (lsrb) (rolb) (rorb) (asrb) (aslb) (asld)
       (staa opr8a) (stab opr8a) (std opr8a) (sty opr8a) (stx opr8a) (sts opr8a)
       ;; 60
       (neg mem) (com mem) (inc mem) (dec mem) (lsr mem)
       (rol mem) (ror mem) (asr mem) (asl mem) (clr mem)
       (staa mem) (stab mem) (std mem) (sty mem) (stx mem) (sts mem)
       ;; 70
       (neg opr16a) (com opr16a) (inc opr16a) (dec opr16a) (lsr opr16a)
       (rol opr16a) (ror opr16a) (asr opr16a) (asl opr16a) (clr opr16a)
       (staa opr16a) (stab opr16a) (std opr16a) (sty opr16a) (stx opr16a) (sts opr16a)
       ;; 80
       (suba opr8i) (cmpa opr8i) (sbca opr8i) (subd opr8i)
       (anda opr8i) (bita opr8i) (ldaa opr8i) (clra)
       (eora opr8i) (adca opr8i) (oraa opr8i) (adda opr8i)
       (cpd opr8i) (cpy opr8i) (cpx opr8i) (cps opr8i)
       ;; 90
       (suba opr8a) (cmpa opr8a) (sbca opr8a) (subd opr8a)
       (anda opr8a) (bita opr8a) (ldaa opr8a) (tsta)
       (eora opr8a) (adca opr8a) (oraa opr8a) (adda opr8a)
       (cpd opr8a) (cpy opr8a) (cpx opr8a) (cps opr8a)
       ;; A0
       (suba mem) (cmpa mem) (sbca mem) (subd mem)
       (anda mem) (bita mem) (ldaa mem) (nop)
       (eora mem) (adca mem) (oraa mem) (adda mem)
       (cpd mem) (cpy mem) (cpx mem) (cps mem)
       ;; B0
       (suba opr16a) (cmpa opr16a) (sbca opr16a) (subd opr16a)
       (anda opr16a) (bita opr16a) (ldaa opr16a) tfr
       (eora opr16a) (adca opr16a) (oraa opr16a) (adda opr16a)
       (cpd opr16a) (cpy opr16a) (cpx opr16a) (cps opr16a)
       ;; C0
       (subb opr8i) (cmpb opr8i) (sbcb opr8i) (addd opr8i)
       (andb opr8i) (bitb opr8i) (ldab opr8i) (clrb)
       (eorb opr8i) (adcb opr8i) (orab opr8i) (addb opr8i)
       (ldd opr8i) (ldy opr8i) (ldx opr8i) (lds opr8i)
       ;; D0
       (subb opr8a) (cmpb opr8a) (sbcb opr8a) (addd opr8a)
       (andb opr8a) (bitb opr8a) (ldab opr8a) (tstb)
       (eorb opr8a) (adcb opr8a) (orab opr8a) (addb opr8a)
       (ldd opr8a) (ldy opr8a) (ldx opr8a) (lds opr8a)
       ;; E0
       (subb mem) (cmpb mem) (sbcb mem) (addd mem)
       (andb mem) (bitb mem) (ldab mem) (tst mem)
       (eorb mem) (adcb mem) (orab mem) (addb mem)
       (ldd mem) (ldy mem) (ldx mem) (lds mem)
       ;; F0
       (subb opr16a) (cmpb opr16a) (sbcb opr16a) (addd opr16a)
       (andb opr16a) (bitb opr16a) (ldab opr16a) (tst opr16a)
       (eorb opr16a) (adcb opr16a) (orab opr16a) (addb opr16a)
       (ldd opr16a) (ldy opr16a) (ldx opr16a) (lds opr16a)))

  (define opcodes-18
    '#((movw* oprx0_xysp opr16i)        ;operands reversed
       (movw* oprx0_xysp opr16a)        ;operands reversed
       (movw oprx0_xysp oprx0_xysp)
       (movw oprx16 opr16a)
       (movw opr16a opr16a)
       (movw oprx0_xysp opr16a)
       (aba) (daa)
       ;; 18 08
       (movb* oprx0_xysp opr8i)         ;operands reversed
       (movb* oprx0_xysp opr16a)        ;operands reversed
       (movb oprx0_xysp oprx0_xysp)
       (movb opr8i opr16a)
       (movb opr16a opr16a)
       (movb oprx0_xysp opr16a)
       (tab) (tba)
       ;; 18 10
       (idiv) (fdiv) (emacs opr16a) (emuls)
       (edivs) (idivs) (sba) (dba)
       (maxa mem) (mina mem) (emaxd mem) (emind mem)
       (maxm mem) (minm mem) (emaxm mem) (eminm mem)
       ;; 18 20
       (lbra rel16) (lbrn rel16) (lbhi rel16) (lbls rel16)
       (lbcc rel16) (lbcs rel16) (lbne rel16) (lbeq rel16)
       (lbvc rel16) (lbvs rel16) (lbpl rel16) (lbmi rel16)
       (lbge rel16) (lblt rel16) (lbgt rel16) (lble rel16)
       ;; 18 30
       #f #f #f #f #f #f #f #f #f #f    ;traps
       (rev) (revw) (wav) (tbl oprx0_xysp) (stop) (etbl oprx0_xysp)))

;;; Tests for various address mode post byte encodings

  (define (xb-indexed-indirect? xb)     (fx=? (fxand xb #b11100111) #b11100011)) ;[n,r]
  (define (xb-d-indexed-indirect? xb)   (fx=? (fxand xb #b11100111) #b11100111)) ;[D,r]
  (define (xb-constant-offset? xb)      (fx=? (fxand xb #b11100100) #b11100000)) ;n,r -n,r
  (define (xb-accumulator-offset? xb)   (fx=? (fxand xb #b11100100) #b11100100)) ;A,r B,r D,r
  (define (xb-5bit-constant-offset? xb) (fx=? (fxand xb #b00100000) #b00000000)) ;,r n,r -n,r
  (define (xb-pre/post-inc/dec? xb)     (fx=? (fxand xb #b00100000) #b00100000)) ;n,-r n,+r n,r- n,r+

  (define (xb-oprx0_xysp? xb)
    (and (not (fx=? (fxand xb #b11100011) #b11100011)) ;[n,r] or [D,r]
         (not (xb-constant-offset? xb))
         (or (xb-pre/post-inc/dec? xb)
             (xb-5bit-constant-offset? xb)
             (xb-accumulator-offset? xb))))

;;;

  (define (get-memory xb port collect)
    (define (lookup-xysp reg)
      (case reg ((#b00) 'x) ((#b01) 'y) ((#b10) 'sp) ((#b11) 'pc)))
    (cond ((xb-indexed-indirect? xb)
           ;; 16-bit offset indexed-indirect (points to a pointer).
           (list (list (get-u16/collect port collect 'disp)
                       (lookup-xysp (fxbit-field xb 3 5)))))

          ((xb-d-indexed-indirect? xb)
           ;; Accumulator D offset indexed-indirect (points to a pointer).
           (list (list 'd (lookup-xysp (fxbit-field xb 3 5)))))

          ((xb-constant-offset? xb)
           ;; Constant offset
           (list (if (fxbit-set? xb 1)
                     (get-s16/collect port collect 'disp)
                     (let ((disp (get-u8/collect port collect 'disp)))
                       ;; 9-bit offset
                       (if (fxbit-set? xb 0)
                           (- disp #x100) ;TODO: verify
                           disp)))
                 (lookup-xysp (fxbit-field xb 3 5))))

          ((xb-accumulator-offset? xb)
           ;; Accumulator offset
           (let ((rr (lookup-xysp (fxbit-field xb 3 5)))
                 (aa (case (fxbit-field xb 0 2)
                       ((#b00) 'a)
                       ((#b01) 'b)
                       ((#b10) 'd))))
             (list aa rr)))

          ((xb-5bit-constant-offset? xb)
           ;; 5-bit constant offset
           (let ((disp (if (fxbit-set? xb 4)
                           (- (fxbit-field xb 0 4) #x10)
                           (fxbit-field xb 0 4)))
                 (reg (lookup-xysp (fxbit-field xb 6 8))))
             (if (zero? disp)
                 (list reg)
                 (list disp reg))))

          ((xb-pre/post-inc/dec? xb)
           ;; Auto precrement, preincrement, postdecrement,
           ;; or postincrement. Crummy syntax here.
           (let ((disp (fx+ 1 (fxbit-field xb 0 3)))
                 (reg (lookup-xysp (fxbit-field xb 6 8))))
             (if (fxbit-set? xb 3)
                 (list (if (fxbit-set? xb 4) 'post- 'pre-) (- 9 disp) reg)
                 (list (if (fxbit-set? xb 4) 'post+ 'pre+) disp reg))))))

  (define (get-instruction port collect)
    (define (get-operand am)
      (case am
        ((rel8)
         (list (get-s8/collect port collect 'offset) 'pc))
        ((rel16)
         (list (get-s16/collect port collect 'offset) 'pc))

        ((opr8i page)
         (get-u8/collect port collect 'immediate))
        ((opr16i oprx16)
         (get-u16/collect port collect 'immediate))

        ((opr8a)
         (list (get-u8/collect port collect 'disp)))
        ((opr16a)
         (list (get-u16/collect port collect 'disp)))

        ((oprx0_xysp)
         (let ((xb (get-u8/collect port collect 'disp)))
           (unless (xb-oprx0_xysp? xb)
             (raise-UD "Unallowed addressing mode"))
           (get-memory xb port collect)))

        ((idx12)
         ;; oprx0_xysp; oprx9,xysp; oprx16,xysp
         (let ((xb (get-u8/collect port collect 'disp)))
           (when (or (xb-indexed-indirect? xb)
                     (xb-d-indexed-indirect? xb))
             (raise-UD "Unallowed addressing mode"))
           (get-memory (get-u8/collect port collect 'disp) port collect)))

        ((mem)
         (get-memory (get-u8/collect port collect 'disp) port collect))

        (else (list 'fixme am))))
    (define (get-operands opcode-table opcode)
      (let ((instr (and (> (vector-length opcode-table) opcode)
                        (vector-ref opcode-table opcode))))
        (cond ((not instr)
               (list 'trap opcode))
              ((eq? instr 'tfr)
               ;; FIXME: This byte specifies two registers
               (get-u8)
               (list 'tfr 'fixme1 'fixme2))
              ((eq? instr 'loop)
               (let* ((lb (fxand #b11110111 (get-u8/collect port collect 'opcode)))
                      (off (get-u8/collect port collect 'offset))
                      (sign (fxbit-field lb 4 5))
                      (reg (case (fxbit-field lb 0 3)
                             ((#b000) 'a)
                             ((#b001) 'b)
                             ((#b010
                               #b011) (raise-UD "Bad register in loop primitive postbyte" lb))
                             ((#b100) 'd)
                             ((#b101) 'x)
                             ((#b110) 'y)
                             ((#b111) 'sp)))
                      (op (case (fxbit-field lb 5 8)
                            ((0) 'dbeq)
                            ((1) 'dbne)
                            ((2) 'tbeq)
                            ((3) 'tbne)
                            ((4) 'ibeq)
                            ((5) 'ibne)
                            (else (raise-UD "Unknown operation in loop primitive postbyte" lb)))))
                 (list op reg (list '+ 'pc (if (zero? sign) off (- off #x100))))))
              ((memq (car instr) '(movb* movw*))
               ;; Fix for instructions with reversed operand order.
               ;; Also, on the MC68HC2 an offset needs to be added to
               ;; PC-relative offsets for these instructions, but that
               ;; is not done... see their reference manual.
               (cons (if (eq? (car instr) 'movb*) 'movb 'movw)
                     (reverse (map-in-order get-operand (cdr instr)))))
              (else
               (cons (car instr)
                     (map-in-order get-operand (cdr instr)))))))
    (let ((opcode (lookahead-u8 port)))
      (cond ((eof-object? opcode)
             (eof-object))
            ((eqv? opcode #x18)
             (get-u8/collect port collect 'opcode)
             (get-operands opcodes-18 (get-u8/collect port collect 'opcode)))
            (else
             (get-operands opcodes (get-u8/collect port collect 'opcode)))))))
