;; -*- mode: scheme; coding: utf-8 -*-
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

(library (se weinholt assembler x86-operands (1 0 0))
    (export registers lookup-register
            register?
            register-name register-type register-index
            memory?
            memory-addressing-mode memory-datasize memory-segment
            memory-disp memory-SIB memory-ModR/M memory-REX
            expression?
            expression-operand-size
            build-expression eval-expression expression-in-range?
            translate-operands)
    (import (rnrs)
            (se weinholt assembler x86-misc (1 0 (>= 0))))

;;; Register operands

  (define register-list
    '( ;; 8-bit encodable without REX
      (al 8 0)
      (cl 8 1)
      (dl 8 2)
      (bl 8 3)
      ;; only reachable without REX
      (ah norex8 4)
      (ch norex8 5)
      (dh norex8 6)
      (bh norex8 7)

      ;; 8-bit encodable with REX
      (spl rex8 4)
      (bpl rex8 5)
      (sil rex8 6)
      (dil rex8 7)
      (r8b rex8 8)
      (r9b rex8 9)
      (r10b rex8 10)
      (r11b rex8 11)
      (r12b rex8 12)
      (r13b rex8 13)
      (r14b rex8 14)
      (r15b rex8 15)
      ;; aliases
      (r8l rex8 8)
      (r9l rex8 9)
      (r10l rex8 10)
      (r11l rex8 11)
      (r12l rex8 12)
      (r13l rex8 13)
      (r14l rex8 14)
      (r15l rex8 15)

      ;; 16-bit
      (ax 16 0)
      (cx 16 1)
      (dx 16 2)
      (bx 16 3)
      (sp 16 4)
      (bp 16 5)
      (si 16 6)
      (di 16 7)
      (r8w 16 8)
      (r9w 16 9)
      (r10w 16 10)
      (r11w 16 11)
      (r12w 16 12)
      (r13w 16 13)
      (r14w 16 14)
      (r15w 16 15)

      ;; 32-bit
      (eax 32 0)
      (ecx 32 1)
      (edx 32 2)
      (ebx 32 3)
      (esp 32 4)
      (ebp 32 5)
      (esi 32 6)
      (edi 32 7)
      (r8d 32 8)
      (r9d 32 9)
      (r10d 32 10)
      (r11d 32 11)
      (r12d 32 12)
      (r13d 32 13)
      (r14d 32 14)
      (r15d 32 15)

      ;; 64-bit
      (rax 64 0)
      (rcx 64 1)
      (rdx 64 2)
      (rbx 64 3)
      (rsp 64 4)
      (rbp 64 5)
      (rsi 64 6)
      (rdi 64 7)
      (r8 64 8)
      (r9 64 9)
      (r10 64 10)
      (r11 64 11)
      (r12 64 12)
      (r13 64 13)
      (r14 64 14)
      (r15 64 15)

      ;; 64-bit vector
      (mm0 mm 0)
      (mm1 mm 1)
      (mm2 mm 2)
      (mm3 mm 3)
      (mm4 mm 4)
      (mm5 mm 5)
      (mm6 mm 6)
      (mm7 mm 7)
      ;; aliases:
      (mmx0 mm 0)
      (mmx1 mm 1)
      (mmx2 mm 2)
      (mmx3 mm 3)
      (mmx4 mm 4)
      (mmx5 mm 5)
      (mmx6 mm 6)
      (mmx7 mm 7)

      ;; 128-bit vector
      (xmm0 xmm 0)
      (xmm1 xmm 1)
      (xmm2 xmm 2)
      (xmm3 xmm 3)
      (xmm4 xmm 4)
      (xmm5 xmm 5)
      (xmm6 xmm 6)
      (xmm7 xmm 7)
      (xmm8 xmm 8)
      (xmm9 xmm 9)
      (xmm10 xmm 10)
      (xmm11 xmm 11)
      (xmm12 xmm 12)
      (xmm13 xmm 13)
      (xmm14 xmm 14)
      (xmm15 xmm 15)

      ;; 256-bit vector
      (ymm0 ymm 0)
      (ymm1 ymm 1)
      (ymm2 ymm 2)
      (ymm3 ymm 3)
      (ymm4 ymm 4)
      (ymm5 ymm 5)
      (ymm6 ymm 6)
      (ymm7 ymm 7)
      (ymm8 ymm 8)
      (ymm9 ymm 9)
      (ymm10 ymm 10)
      (ymm11 ymm 11)
      (ymm12 ymm 12)
      (ymm13 ymm 13)
      (ymm14 ymm 14)
      (ymm15 ymm 15)

      ;; Segment registers
      (es sreg 0)
      (cs sreg 1)
      (ss sreg 2)
      (ds sreg 3)
      (fs sreg 4)
      (gs sreg 5)

      ;; Control registers
      (cr0 creg 0)
      (cr1 creg 1)
      (cr2 creg 2)
      (cr3 creg 3)
      (cr4 creg 4)
      (cr5 creg 5)
      (cr6 creg 6)
      (cr7 creg 7)
      (cr8 creg 8)
      (cr9 creg 9)
      (cr10 creg 10)
      (cr11 creg 11)
      (cr12 creg 12)
      (cr13 creg 13)
      (cr14 creg 14)
      (cr15 creg 15)

      ;; Debug registers
      (dr0 dreg 0)
      (dr1 dreg 1)
      (dr2 dreg 2)
      (dr3 dreg 3)
      (dr4 dreg 4)
      (dr5 dreg 5)
      (dr6 dreg 6)
      (dr7 dreg 7)
      (dr8 dreg 8)
      (dr9 dreg 9)
      (dr10 dreg 10)
      (dr11 dreg 11)
      (dr12 dreg 12)
      (dr13 dreg 13)
      (dr14 dreg 14)
      (dr15 dreg 15)

      ;; x87 registers
      (st0 x87 0)
      (st1 x87 1)
      (st2 x87 2)
      (st3 x87 3)
      (st4 x87 4)
      (st5 x87 5)
      (st6 x87 6)
      (st7 x87 7)

      ;; For RIP relative addressing only
      (rip rel -1)))

  (define-record-type register
    (fields name type index)
    (nongenerative
     register-cc91dcaf-8e9e-4a25-8bf4-9fe54711046f))

  (define registers
    (let ((tmp (make-eq-hashtable)))
      (for-each (lambda (x)
                  (hashtable-set! tmp (car x)
                                  (apply make-register x)))
                register-list)
      tmp))

  (define (lookup-register name . default)
    (or (hashtable-ref registers name #f)
        (if (null? default)
            (error 'lookup-register
                   "Unknown register" name)
            (car default))))

;;; Memory operands

  (define-record-type memory
    (fields addressing-mode datasize segment
            disp SIB ModR/M REX)
    (nongenerative
     memory-255030a2-5e9b-4ad1-9967-3e7a33f47e54))

  (define (encode-memory addressing-mode datasize segment
                         disp scale index base)
    (define (rBP/13? x) (and x (fx=? #b101 (fxand #b111 (register-index x)))))
    (define (rSP/12? x) (and x (fx=? #b100 (fxand #b111 (register-index x)))))
    (define (rIP? x) (and x (eq? 'rip (register-name x))))
    (define (disp32 x) (number->bytevector x 32))
    (define (disp8 x) (number->bytevector x 8))
    (define rsp #b100)
    (define rbp #b101)
    (define (ret mod r/m disp scale index base)
      (let ((X (fxarithmetic-shift-right index 3))
            (B (fxarithmetic-shift-right (fxior r/m base) 3)))
        (make-memory addressing-mode datasize segment
                     disp
                     (and scale (make-sib scale index base))
                     (make-modr/m mod 0 r/m)
                     (if (zero? (+ X B))
                         0
                         (fxior #x40 (fxior (fxarithmetic-shift-left X 1)
                                            B))))))
    (case addressing-mode
      ((32 64)
       (cond ((or (rIP? base)
                  (and (not index) (not base)
                       (= addressing-mode 32)))
              ;; [rIP+disp32] in 64-bit mode
              ;; [disp32] in 32-bit mode
              (ret #b00 rbp
                   (disp32 disp)
                   #f 0 0))

             ;; [rSP] [r12]
             ((and (rSP/12? base) (zero? disp) (not index))
              (ret #b00 rsp
                   #f
                   1 rsp (register-index base)))

             ;; [rSP+base] [r12+base]
             ((and (rSP/12? base) (not index))
              (if (bitwidth<= disp 7 7)
                  (ret #b01 (register-index base)
                       (disp8 disp)
                       1 rsp (register-index base))
                  (ret #b10 (register-index base)
                       (disp32 disp)
                       1 rsp (register-index base))))

             ((and (not index) (not base))
              ;; [disp32] in 64-bit mode
              (ret #b00 rsp
                   (disp32 disp)
                   1 rsp rbp))

             ((and (rBP/13? base) (not index))
              ;; [rBP] [rBP+disp8] [rBP+disp32]
              ;; [r13] [r13+disp8] [r13+disp32]
              (if (bitwidth<= disp 7 7)
                  (ret #b01 (register-index base)
                       (disp8 disp)
                       #f 0 0)
                  (ret #b10 (register-index base)
                       (disp32 disp)
                       #f 0 0)))

             ((and base (zero? disp) (not index))
              ;; [reg]
              (ret #b00 (register-index base)
                   #f
                   #f 0 0))

             ((and base (not index))
              ;; [reg+disp8] [reg+disp32]
              (if (bitwidth<= disp 7 7)
                  (ret #b01 (register-index base)
                       (disp8 disp)
                       #f 0 0)

                  (ret #b10 (register-index base)
                       (disp32 disp)
                       #f 0 0)))

             ((and index (not base))
              ;; [reg*scale+disp]
              (ret #b00 rsp
                   (disp32 disp)
                   scale (register-index index) rbp))

             (index
              ;; [reg*scale+rbp] [reg*scale+r13]
              ;; [reg*scale+reg] [reg*scale+disp8+reg] [reg*scale+disp32+reg]
              (cond ((and (zero? disp) (not (rBP/13? base)))
                     (ret #b00 rsp
                          #f
                          scale (register-index index) (register-index base)))
                    ((bitwidth<= disp 7 7)
                     (ret #b01 rsp
                          (disp8 disp)
                          scale (register-index index) (register-index base)))
                    (else
                     (ret #b10 rsp
                          (disp32 disp)
                          scale (register-index index) (register-index base)))))

             (else
              (error 'encode-memory
                     "Unimplemented addressing mode"
                     addressing-mode datasize segment
                     disp scale index base))))
      (else
       (error 'encode-memory "16-bit memory addressing is not supported"))))

  (define (translate-memory ref mode)
    ;; Translates from list form to record form (via encode memory).
    (define who 'translate-memory)
    (let ((addressing-mode mode)
          (segment #f)
          (base #f)
          (disp 0)
          (scale 1)
          (index #f))
      (define (set-base! reg)
        (set! addressing-mode (register-type reg))
        (when base
          (error who "Multiple base registers are not possible"
                 base reg ref))
        (set! base reg))
      (define (set-index! reg)
        (set! addressing-mode (register-type reg))
        (when index
          (error who "Multiple index registers are not possible"
                 index reg ref))
        (set! index reg))
      (define (bad-reg reg)
        (error who "This register isn't permitted in addressing forms"
               reg ref))
      (define wordsize
        (fxarithmetic-shift-right mode 3))
      (for-each
       (lambda (x)
         (cond ((eq? x 'wordsize)
                (set! disp (+ disp wordsize)))

               ((integer? x)
                (set! disp (+ disp x)))

               ((and (list? x) (eq? (car x) '*)
                     (exists symbol? (cdr x)))
                (for-each (lambda (s/i)
                            (cond ((eq? s/i 'wordsize)
                                   (set! scale (* scale wordsize)))
                                  ((integer? s/i)
                                   (set! scale (* scale s/i)))
                                  ((symbol? s/i)
                                   (let ((index (lookup-register s/i)))
                                     (case (register-type index)
                                       ((32 64)
                                        (set-index! index))
                                       (else
                                        (error who "Impossible index register"
                                               index ref)))))
                                  (else
                                   (error who "Unknown scale or index"
                                          s/i ref))))
                          (cdr x)))

               ((symbol? x)
                ;; A register!
                (let ((reg (lookup-register x)))
                  (case (register-type reg)
                    ((64)
                     (if base
                         (set-index! reg)
                         (set-base! reg)))
                    ((32)
                     (if base
                         (set-index! reg)
                         (set-base! reg)))
                    ((16)
                     (case (register-name reg)
                       ((bx bp)
                        (set-base! reg))
                       ((si di)
                        (set! index reg))
                       (else
                        (bad-reg reg))))
                    ((rel)
                     (set-base! reg)
                     (set! addressing-mode 64))
                    ((sreg)
                     (when segment
                       (error who "Multiple segment overrides are not possible"
                              segment reg ref))
                     (set! segment reg))
                    (else
                     (bad-reg reg)))))

               (else
                (error who "Unknown addressing mode"
                       x ref))))
       (cdr ref))

      (when (and base index (eq? (register-name base) 'rip))
        (error who "RIP-relative addressing combined with an index register is not possible"
               base index ref))

      (when (and index (memq (register-name index) '(esp rsp)))
        (error who "ESP/RSP can't be used as an index register"
               index ref))

      (when (and base index
                 (not (eqv? (register-type base)
                            (register-type index))))
        (error who "Base and index registers must be of the same size"
               base index ref))

      (when (not (memq scale '(1 2 4 8)))
        (error who "Only scales 1, 2, 4 or 8 are possible"
               scale ref))

      (case mode
        ((16 32)
         (when (= addressing-mode 64)
           (error who "64-bit addressing modes require 64-bit mode" ref))))

      (case addressing-mode
        ((16)
         (when (= mode 64)
           (error who "16-bit addressing modes are not possible in 64-bit mode"
                  ref))
         (when (and disp (not (<= (- (expt 2 15)) disp (- (expt 2 15) 1))))
           (error who "Displacements are at most 16 bits signed in 16-bit mode"
                  disp ref)))
        ((32 64)
         (when (and disp (not (<= (- (expt 2 31)) disp (- (expt 2 31) 1))))
           (error who "Displacements are at most 32 bits signed in 32-bit and 64-bit mode"
                  disp ref))))

      (when (and segment (= mode 64) (not (memv (register-index segment) '(4 5))))
        (error who "Only FS and GS are valid segment overrides in 64-bit mode" segment))

      (encode-memory addressing-mode
                     (case (car ref)
                       ((mem8+) 8)
                       ((mem16+) 16)
                       ((mem32+) 32)
                       ((mem64+) 64)
                       ((mem128+) 128)
                       ((mem256+) 256)
                       ((mem+) #f)
                       ;; FIXME: fill this in
                       (else
                        (error 'translate-memory
                               "Invalid memory operation"
                               ref)))
                     segment
                     disp
                     scale
                     index
                     base)))

;;; Expressions

  ;; These should possibly be called relocations.

  ;; One assumption that makes things a lot easier, is that if an
  ;; expression contains labels then it will not fit in an 8 or 16 bit
  ;; wide encoding.

  (define empty-hashtable (make-eq-hashtable))

  (define-record-type expression
    (fields operand-size rel? code))
  (define expression-mode expression-operand-size)

  (define (eval-expr expr mode labels)
    ;; Returns an integer, or, #f if some labels could not be found.
    (let eval-expr ((expr expr))
      (cond ((integer? expr) expr)
            ((eq? expr 'wordsize) (fxarithmetic-shift-right mode 3))
            ((symbol? expr) (hashtable-ref labels expr #f))
            (else
             (let ((operands (map eval-expr (cdr expr))))
               (and (for-all number? operands)
                    (case (car expr)
                      ((+) (apply + operands))
                      ((-) (apply - operands)))))))))

  (define (build-expression op mode)
    (define (check-syntax op)
      (cond ((or (integer? op) (symbol? op)))
            ((list? op)
             (unless (and (memq (car op) '(+ -)) (>= (length op) 2))
               (error 'build-expression "Bad assembler operand" op))
             (when (and (eqv? (cadr op) '(eip rip))
                        (not (integer? (caddr op)))
                        (not (null? (cdddr op))))
               (error 'build-expression "Bad rip-relative assembler operand" op)))
            (for-each check-syntax (cdr op))))
    (check-syntax op)
    (if (and (list? op) (eqv? (cadr op) '(eip rip)))
        (make-expression (if (eq? (cadr op) 'rip) 64 32)
                         #t (caddr op))
        (make-expression #f #f (or (eval-expr op mode empty-hashtable)
                                   op))))

  (define (eval-expression expression labels)
    (eval-expr (expression-code expression)
               (expression-mode expression)
               labels))

  (define (expression-in-range? expression min max)
    (cond ((eval-expression expression empty-hashtable) =>
           (lambda (v)
             (<= min v max)))
          (else #f)))


;;   (let ((labels (make-eq-hashtable)))
;;     (hashtable-set! labels 'start 0)
;;     (hashtable-set! labels 'end 40)
;;     (eval-expression (build-expression '(- end start) 64) labels))

;;;

  (define (translate-operands operands mode)
    (map (lambda (op)
           (cond ((or (register? op) (memory? op) (expression? op))
                  op)

                 ((integer? op)
                  (build-expression op mode))

                 ((symbol? op)
                  (cond ((lookup-register op #f) =>
                         (lambda (reg)
                           (when (and (not (= mode 64))
                                      (or (> (register-index reg) 7)
                                          (eq? (register-type reg) 'rex8)))
                             (error 'translate-operands
                                    "This register is only reachable in 64-bit mode" op))
                           reg))
                        (else
                         (build-expression op mode))))

                 ((list? op)
                  (if (memq (car op) '(+ -))
                      (build-expression op mode)
                      (translate-memory op mode)))

                 (else
                  (error 'translate-operands
                         "Invalid assembler operand"
                         op operands))))
         operands))


  )
