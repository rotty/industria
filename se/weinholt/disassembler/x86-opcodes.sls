;; -*- mode: scheme; coding: utf-8 -*-
;; Opcode table for the Intel 80x86 processor
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

;; (1 1 0) - Unreleased - Added opsyntax for test registers and a few
;; AMD Geode instructions. All could not be added, since they conflict
;; with newer AMD instructions.

;; (1 1 1) - Unreleased - Export lists of instructions that work with
;; the LOCK/REP/REPZ prefixes and branch hints.

;; (1 1 2) - Unreleased - Remove the operand size suffix from ins,
;; outs, movs, lods, stos, cmps, and scas. Fix the xlat alias.

;;; Versioning scheme

;; The version is made of (major minor patch) sub-versions.

;; The `patch' sub-version will be incremented when corrections to the
;; table are made that don't introduce new table or operand syntax.
;; New mnemonics can be introduced at this level.

;; The `minor' is incremented when new operand syntax is introduced.

;; The `major' is incremented when the table syntax changes.

;;; Table syntax

;; <table> --> #(<entry>[256])  ; the index is an opcode byte

;; <entry> --> <table>
;;    | <instr>
;;    | <prefix-set>
;;    | <group>
;;    | <datasize>
;;    | <addrsize>
;;    | <mode>
;;    | <sse>
;;    | <vex>
;;    | <mem/reg>
;;    | #f

;; <instr> --> (<mnemonic> <operand>*)

;; <prefix-set> --> (*prefix* <prefix-name>+)

;; <prefix-name> --> operand | address
;;     | cs | ds | es | fs | gs | ss
;;     | lock | repz | repnz
;;     | rex | rex.w | rex.r | rex.x | rex.b

;; <group> --> #(Group <name>
;;                     <reg-vector for ModR/M.mod=0, 1 or 2>
;;                     <reg-vector for ModR/M.mod=3>*)

;; <reg-vector> --> #(<reg-entry>[8])  ; the index is ModR/M.reg

;; <reg-entry> --> #(<entry>[8])  ; the index is ModR/M.R/M
;;    | <instr>
;;    | <datasize>
;;    | <addrsize>
;;    | <mode>
;;    | <sse>
;;    | <vex>
;;    | #f

;; <datasize> --> #(Datasize <entry for 16-bit data>
;;                           <entry for 32-bit data>
;;                           <entry for 64-bit data>)

;; <addrsize> --> #(Datasize <entry for 16-bit addressing>
;;                           <entry for 32-bit addressing>
;;                           <entry for 64-bit addressing>)

;; <mode> --> #(Mode <entry for 16/32-bit mode>
;;                   <entry for 64-bit mode>)

;; <sse> --> #(Prefix <entry for no prefix>
;;                    <entry for F3 prefix>
;;                    <entry for 66 prefix>
;;                    <entry for F2 prefix>)

;; <vex> --> #(VEX <entry for no VEX prefix>
;;                 <entry for VEX.128 prefix>
;;                 <entry for VEX.256 prefix>*)

;; <mem/reg> --> #(Mem/reg <entry for memory operand in ModR/M>
;;                         <entry for register operand>)

;; <name> is a string. <mnemonic> and <operand> are symbols.

;;; Operand syntax

;; The abbreviations here are the same as in the Intel manual,
;; appendix A. Uppercase letters are addressing methods, lower case
;; letters specify operand type. There are some differences though:

;; Normally the operand syntax will have initial upper case letters
;; for designating an addressing method, but where this is not the
;; case a single * has been prepended.

;; Where the appendix has used e.g. "Ev" and noted that the operand
;; size is forced to 64 bits in long mode, "Eq/w" has been substituted
;; for the long mode instruction.

;; "1" has been changed to "*unity", so that all operands are written
;; as symbols.

;; For Intel AVX instructions, the opcode syntaxes K, KW, WK, B, BW,
;; WB, In have been used and are not official.

;; For AMD SSE5, the Z, VW and WV opcode syntaxes are not official
;; either.

(library (se weinholt disassembler x86-opcodes (1 1 2))
    (export opcodes pseudo-mnemonics mnemonic-aliases
            lock-instructions
            branch-hint-instructions
            rep-instructions
            repz-instructions)
    (import (rnrs))

  (define lock-instructions
    '(adc add and btc btr bts cmpxchg cmpxchg8b
          cmpxchg16b dec inc neg not or sbb sub
          xadd xchg xor))

  ;; TODO: Can these use hints? loopnz loopz loop jcxz jecxz jrcxz
  (define branch-hint-instructions
    '(jo jno jb jnb jz jnz jbe jnbe js jns jp jnp jl
         jnl jle jnle))

  (define rep-instructions
    '(ins outs movs lods stos
          ;; VIA PadLock:
          montmul xsha1 xsha256
          xstore xcryptecb
          xcryptcbc xcryptctr
          xcryptcfb xcryptofb))

  (define repz-instructions
    '(cmps scas))

  ;; (mnemonic immediate pseudo-op). This table contains a list of
  ;; pseudo-ops, where `mnemonic' is used in the opcode table,
  ;; `immediate' specifies a value for the immediate operand, and
  ;; `pseudo-op' is a programmer-friendly name. The immediate listed
  ;; is always the last operand in an instruction. Note that some
  ;; instructions have two encodings: one with a register and one with
  ;; an immediate.

  ;; For the *3dnow* mnemonic the rule is that if an immediate is not
  ;; listed here, it is an illegal opcode. For the other mnemonics an
  ;; unlisted immediate normally means the original mnemonic should be
  ;; shown, with immediates preserved.

  ;; Examples:
  ;; (*3dnow* mm0 mm1 #xFF) => invalid opcode
  ;; (*3dnow* mm0 mm1 #x94) <=> (pfmin mm0 mm1)
  ;; (vpermil2ps xmm0 xmm1 xmm3 xmm4 3) <=> (vpermilmo2ps xmm0 xmm1 xmm3 xmm4)
  ;; (vpermil2ps xmm0 xmm1 xmm3 xmm4 15) <=> (vpermil2ps xmm0 xmm1 xmm3 xmm4 15)
  ;; (aam #x0a) <=> (aam)
  (define pseudo-mnemonics
    '((*3dnow* #x0C pi2fw)
      (*3dnow* #x0D pi2fd)
      (*3dnow* #x1C pf2iw)
      (*3dnow* #x1D pf2id)
      (*3dnow* #x80 pfnacc)
      (*3dnow* #x8E pfpnacc)
      (*3dnow* #x90 pfcmpge)
      (*3dnow* #x94 pfmin)

      (*3dnow* #x96 pfrcp)
      (*3dnow* #x97 pfrsqrt)
      (*3dnow* #x9A pfsub)
      (*3dnow* #x9E pfadd)
      (*3dnow* #xA0 pfcmpgt)
      (*3dnow* #xA4 pfmax)
      (*3dnow* #xA6 pfrcpit1)
      (*3dnow* #xA7 pfrsqit1)
      (*3dnow* #xAA pfsubr)
      (*3dnow* #xAA pfacc)
      (*3dnow* #xB0 pfcmpeq)
      (*3dnow* #xB4 pfmul)
      (*3dnow* #xB6 pfrcpit2)
      (*3dnow* #xB7 pmulhrw)
      (*3dnow* #xBB pswapd)
      (*3dnow* #xBF pavgusb)

      ;; These two are from AMD Geode:
      (*3dnow* #x86 pfrcpv)
      (*3dnow* #x87 pfrsqrtv)

      (aam #x0A aam)
      (aad #x0A aad)

      (vpermil2pd #b0000 vpermiltd2pd)
      (vpermil2pd #b0001 vpermiltd2pd)
      (vpermil2pd #b0010 vpermilmo2pd)
      (vpermil2pd #b0011 vpermilmz2pd)

      (vpermil2ps #b0000 vpermiltd2ps)
      (vpermil2ps #b0001 vpermiltd2ps)
      (vpermil2ps #b0010 vpermilmo2ps)
      (vpermil2ps #b0011 vpermilmz2ps)

      (pclmulqdq #b00000000 pclmullqlqdq)
      (pclmulqdq #b00000001 pclmulhqlqdq)
      (pclmulqdq #b00010000 pclmullqhqdq)
      (pclmulqdq #b00010001 pclmulhqhqdq)

      (cmppd 0 cmpeqpd)
      (cmppd 1 cmpltpd)
      (cmppd 2 cmplepd)
      (cmppd 3 cmpunordpd)
      (cmppd 4 cmpneqpd)
      (cmppd 5 cmpnltpd)
      (cmppd 6 cmpnlepd)
      (cmppd 7 cmpordpd)
      (vcmppd #x00 vcmpeqpd)
      (vcmppd #x01 vcmpltpd)
      (vcmppd #x02 vcmplepd)
      (vcmppd #x03 vcmpunordpd)
      (vcmppd #x04 vcmpneqpd)
      (vcmppd #x05 vcmpnltpd)
      (vcmppd #x06 vcmpnlepd)
      (vcmppd #x07 vcmpordpd)
      (vcmppd #x08 vcmpeq_uqpd)
      (vcmppd #x09 vcmpngepd)
      (vcmppd #x0a vcmpngtpd)
      (vcmppd #x0b vcmpfalsepd)
      (vcmppd #x0c vcmpneq_oqpd)
      (vcmppd #x0d vcmpgepd)
      (vcmppd #x0e vcmpgtpd)
      (vcmppd #x0f vcmptruepd)
      (vcmppd #x10 vcmpeq_ospd)
      (vcmppd #x11 vcmplt_oqpd)
      (vcmppd #x12 vcmple_oqpd)
      (vcmppd #x13 vcmpunord_spd)
      (vcmppd #x14 vcmpneq_uspd)
      (vcmppd #x15 vcmpnlt_uqpd)
      (vcmppd #x16 vcmpnle_uqpd)
      (vcmppd #x17 vcmpord_spd)
      (vcmppd #x18 vcmpeq_uspd)
      (vcmppd #x19 vcmpnge_uqpd)
      (vcmppd #x1a vcmpngt_uqpd)
      (vcmppd #x1b vcmpfalse_ospd)
      (vcmppd #x1c vcmpneq_ospd)
      (vcmppd #x1d vcmpge_oqpd)
      (vcmppd #x1e vcmpgt_oqpd)
      (vcmppd #x1f vcmptrue_uspd)

      (cmpps 0 cmpeqps)
      (cmpps 1 cmpltps)
      (cmpps 2 cmpleps)
      (cmpps 3 cmpunordps)
      (cmpps 4 cmpneqps)
      (cmpps 5 cmpnltps)
      (cmpps 6 cmpnleps)
      (cmpps 7 cmpordps)
      (vcmpps #x00 vcmpeqps)
      (vcmpps #x01 vcmpltps)
      (vcmpps #x02 vcmpleps)
      (vcmpps #x03 vcmpunordps)
      (vcmpps #x04 vcmpneqps)
      (vcmpps #x05 vcmpnltps)
      (vcmpps #x06 vcmpnleps)
      (vcmpps #x07 vcmpordps)
      (vcmpps #x08 vcmpeq_uqps)
      (vcmpps #x09 vcmpngeps)
      (vcmpps #x0a vcmpngtps)
      (vcmpps #x0b vcmpfalseps)
      (vcmpps #x0c vcmpneq_oqps)
      (vcmpps #x0d vcmpgeps)
      (vcmpps #x0e vcmpgtps)
      (vcmpps #x0f vcmptrueps)
      (vcmpps #x10 vcmpeq_osps)
      (vcmpps #x11 vcmplt_oqps)
      (vcmpps #x12 vcmple_oqps)
      (vcmpps #x13 vcmpunord_sps)
      (vcmpps #x14 vcmpneq_usps)
      (vcmpps #x15 vcmpnlt_uqps)
      (vcmpps #x16 vcmpnle_uqps)
      (vcmpps #x17 vcmpord_sps)
      (vcmpps #x18 vcmpeq_usps)
      (vcmpps #x19 vcmpnge_uqps)
      (vcmpps #x1a vcmpngt_uqps)
      (vcmpps #x1b vcmpfalse_osps)
      (vcmpps #x1c vcmpneq_osps)
      (vcmpps #x1d vcmpge_oqps)
      (vcmpps #x1e vcmpgt_oqps)
      (vcmpps #x1f vcmptrue_usps)

      (cmpsd 0 cmpeqsd)
      (cmpsd 1 cmpltsd)
      (cmpsd 2 cmplesd)
      (cmpsd 3 cmpunordsd)
      (cmpsd 4 cmpneqsd)
      (cmpsd 5 cmpnltsd)
      (cmpsd 6 cmpnlesd)
      (cmpsd 7 cmpordsd)
      (vcmpsd #x00 vcmpeqsd)
      (vcmpsd #x01 vcmpltsd)
      (vcmpsd #x02 vcmplesd)
      (vcmpsd #x03 vcmpunordsd)
      (vcmpsd #x04 vcmpneqsd)
      (vcmpsd #x05 vcmpnltsd)
      (vcmpsd #x06 vcmpnlesd)
      (vcmpsd #x07 vcmpordsd)
      (vcmpsd #x08 vcmpeq_uqsd)
      (vcmpsd #x09 vcmpngesd)
      (vcmpsd #x0a vcmpngtsd)
      (vcmpsd #x0b vcmpfalsesd)
      (vcmpsd #x0c vcmpneq_oqsd)
      (vcmpsd #x0d vcmpgesd)
      (vcmpsd #x0e vcmpgtsd)
      (vcmpsd #x0f vcmptruesd)
      (vcmpsd #x10 vcmpeq_ossd)
      (vcmpsd #x11 vcmplt_oqsd)
      (vcmpsd #x12 vcmple_oqsd)
      (vcmpsd #x13 vcmpunord_ssd)
      (vcmpsd #x14 vcmpneq_ussd)
      (vcmpsd #x15 vcmpnlt_uqsd)
      (vcmpsd #x16 vcmpnle_uqsd)
      (vcmpsd #x17 vcmpord_ssd)
      (vcmpsd #x18 vcmpeq_ussd)
      (vcmpsd #x19 vcmpnge_uqsd)
      (vcmpsd #x1a vcmpngt_uqsd)
      (vcmpsd #x1b vcmpfalse_ossd)
      (vcmpsd #x1c vcmpneq_ossd)
      (vcmpsd #x1d vcmpge_oqsd)
      (vcmpsd #x1e vcmpgt_oqsd)
      (vcmpsd #x1f vcmptrue_ussd)

      (cmpss 0 cmpeqss)
      (cmpss 1 cmpltss)
      (cmpss 2 cmpless)
      (cmpss 3 cmpunordss)
      (cmpss 4 cmpneqss)
      (cmpss 5 cmpnltss)
      (cmpss 6 cmpnless)
      (cmpss 7 cmpordss)
      (vcmpss #x00 vcmpeqss)
      (vcmpss #x01 vcmpltss)
      (vcmpss #x02 vcmpless)
      (vcmpss #x03 vcmpunordss)
      (vcmpss #x04 vcmpneqss)
      (vcmpss #x05 vcmpnltss)
      (vcmpss #x06 vcmpnless)
      (vcmpss #x07 vcmpordss)
      (vcmpss #x08 vcmpeq_uqss)
      (vcmpss #x09 vcmpngess)
      (vcmpss #x0a vcmpngtss)
      (vcmpss #x0b vcmpfalsess)
      (vcmpss #x0c vcmpneq_oqss)
      (vcmpss #x0d vcmpgess)
      (vcmpss #x0e vcmpgtss)
      (vcmpss #x0f vcmptruess)
      (vcmpss #x10 vcmpeq_osss)
      (vcmpss #x11 vcmplt_oqss)
      (vcmpss #x12 vcmple_oqss)
      (vcmpss #x13 vcmpunord_sss)
      (vcmpss #x14 vcmpneq_usss)
      (vcmpss #x15 vcmpnlt_uqss)
      (vcmpss #x16 vcmpnle_uqss)
      (vcmpss #x17 vcmpord_sss)
      (vcmpss #x18 vcmpeq_usss)
      (vcmpss #x19 vcmpnge_uqss)
      (vcmpss #x1a vcmpngt_uqss)
      (vcmpss #x1b vcmpfalse_osss)
      (vcmpss #x1c vcmpneq_osss)
      (vcmpss #x1d vcmpge_oqss)
      (vcmpss #x1e vcmpgt_oqss)
      (vcmpss #x1f vcmptrue_usss)))

  ;; A mapping from common alternative mnemonics to the mnemonics
  ;; used in the opcodes table.
  (define mnemonic-aliases
    '((wait . fwait)
      (sal . shl)
      (xlat . xlatb)
      (loope . loopz)
      (loopne . loopnz)
      (jnae . jb)
      (jae . jnb)
      (je . jz)
      (jne . jnz)
      (jna . jbe)
      (ja . jnbe)
      (jpe . jp)
      (jpo . jnp)
      (jnge . jl)
      (jge . jnl)
      (jng . jle)
      (jg . jnle)
      (setnae . setb)
      (setae . setnb)
      (sete . setz)
      (setne . setnz)
      (setna . setbe)
      (seta . setnbe)
      (setpe . setp)
      (setpo . setnp)
      (setnge . setl)
      (setge . setnl)
      (setng . setle)
      (setg . setnle)
      (cmovnae . cmovb)
      (cmovae . cmovnb)
      (cmove . cmovz)
      (cmovne . cmovnz)
      (cmovna . cmovbe)
      (cmova . cmovnbe)
      (cmovpe . cmovp)
      (cmovpo . cmovnp)
      (cmovnge . cmovl)
      (cmovge . cmovnl)
      (cmovng . cmovle)
      (cmovg . cmovnle)
      (int1 . icebp)
      (setalc . salc)))

  (define opcodes
    '#((add Eb Gb)
       (add Ev Gv)
       (add Gb Eb)
       (add Gv Ev)
       (add *AL Ib)
       (add *rAX Iz)
       #(Mode (push *ES) #f)
       #(Mode (pop *ES) #f)
       ;; 08
       (or Eb Gb)
       (or Ev Gv)
       (or Gb Eb)
       (or Gv Ev)
       (or *AL Ib)
       (or *rAX Iz)
       #(Mode (push *CS) #f)

       ;; 0F: Two-byte opcodes
       #(#(Group "Group 6"
                 #((sldt Rv/Mw) (str Rv/Mw) (lldt Ew) (ltr Ew)
                   (verr Ew) (verw Ew) (jmpe Ev) #f))
         #(Group "Group 7"
                 #((sgdt Ms) (sidt Ms) (lgdt Ms) (lidt Ms)
                   (smsw Rv/Mw) #f (lmsw Ew) (invlpg Mb))
                 #(#(#f (vmcall) (vmlaunch) (vmresume) (vmxoff)
                        #f #f #f)
                   #((monitor) (mwait) #f #f #f #f #f #f)
                   #((xgetbv) (xsetbv) #f #f #f #f #f #f)
                   #((vmrun) (vmmcall) (vmload) (vmsave)
                     (stgi) (clgi) (skinit) (invlpga))
                   (smsw Rv/Mw)
                   #f
                   (lmsw Ew)
                   #(#(Mode #f (swapgs)) (rdtscp) #f #f #f #f #f #f)))
         (lar Gv Ew)
         (lsl Gv Ew)
         #f
         #(Mode #f (syscall))
         (clts)
         #(Mode #f (sysret))
         ;; 0F 08
         (invd)
         (wbinvd)
         #f
         (ud2)
         #f
         #(Group "Group P"
                 #((prefetch Mb) (prefetchw Mb)
                   ;; Reserved aliases:
                   (prefetch Mb) (prefetchw Mb)
                   (prefetch Mb) (prefetch Mb)
                   (prefetch Mb) (prefetch Mb)))
         (femms)
         (*3dnow* Pq Qq Ib)
         ;; 0F 10
         #(Prefix #(VEX (movups Vps Wps) (vmovups Vps Wps))
                  #(VEX (movss Vss Wss)
                        #(Mem/reg (vmovss Vss Mq) (vmovss Vss Bss Wss))
                        #f)
                  #(VEX (movupd Vpd Wpd) (vmovupd Vpd Wpd))
                  #(VEX (movsd Vsd Wsd)
                        #(Mem/reg (vmovsd Vsd Mq) (vmovsd Vsd Bsd Wsd))
                        #f))
         #(Prefix #(VEX (movups Wps Vps) (vmovups Wps Vps))
                  #(VEX (movss Wss Vss)
                        #(Mem/reg (vmovss Mq Wss) (vmovss Wss Bss Vss))
                        #f)
                  #(VEX (movupd Wpd Vpd) (vmovupd Wpd Vpd))
                  #(VEX (movsd Wsd Vsd)
                        #(Mem/reg (vmovsd Mq Vsd) (vmovsd Wsd Bsd Vsd))
                        #f))
         #(Prefix #(VEX #(Mem/reg (movlps Vps Mq) (movhlps Vps Uq))
                        #(Mem/reg (vmovlps Vps Bps Mq) (vmovhlps Vps Bps Uq))
                        #f)
                  #(VEX (movsldup Vps Wps) (vmovsldup Vps Wps))
                  #(VEX (movlpd Vsd Mq) (vmovlpd Vsd Bsd Mq))
                  #(VEX (movddup Vpd Wsd) (vmovddup Vpd Wsd)))
         #(Prefix #(VEX (movlps Mq Vps) (vmovlps Mq Vps) #f)
                  #f
                  #(VEX (movlpd Mq Vsd) (vmovlpd Mq Vsd) #f)
                  #f)
         #(Prefix #(VEX (unpcklps Vps Wq) (vunpcklps Vps Bps Wq)) #f
                  #(VEX (unpcklpd Vpd Wq) (vunpcklpd Vpd Bpd Wq)) #f)
         #(Prefix #(VEX (unpckhps Vps Wq) (vunpckhps Vps Bps Wq)) #f
                  #(VEX (unpckhpd Vpd Wq) (vunpckhpd Vpd Bpd Wq)) #f)
         #(Prefix #(VEX #(Mem/reg (movhps Vps Mq) (movlhps Vps Uq))
                        #(Mem/reg (vmovhps Vps Bps Mq) (vmovlhps Vps Bps Uq))
                        #f)
                  #(VEX (movshdup Vps Wps) (vmovshdup Vps Wps))
                  #(VEX (movhpd Vsd Mq) (vmovhpd Vsd Bsd Mq) #f)
                  #f)
         #(Prefix #(VEX (movhps Mq Vps) (vmovhps Mq Vps) #f) #f
                  #(VEX (movhpd Mq Vsd) (vmovhpd Mq Vsd) #f) #f)
         ;; 0F 18
         #(Group "Group 16"
                 #((prefetchnta Mb) (prefetcht0 Mb)
                   (prefetcht1 Mb)  (prefetcht2 Mb)
                   ;; Reserved for future use:
                   (prefetchnta Mb) (prefetchnta Mb)
                   (prefetchnta Mb) (prefetchnta Mb))
                 #(#f #f #f #f #f #f #f #f))
         (nop Ev)
         (nop Ev)
         (nop Ev)
         (nop Ev)
         (nop Ev)
         (nop Ev)
         (nop Ev)
         ;; 0F 20
         (mov Rd/q Cd/q)
         (mov Rd/q Dd/q)
         (mov Cd/q Rd/q)
         (mov Dd/q Rd/q)
         ;; 0F 24: AMD SSE5 instructions (also MOV r32,tr)
         #((fmaddps Zps Zps WVps VWps)
           (fmaddpd Zpd Zpd WVpd VWpd)
           (fmaddss Zss Zss WVss VWss)
           (fmaddsd Zsd Zsd WVsd VWsd)
           (fmaddps Zps WVps VWps Zps)
           (fmaddpd Zpd WVpd VWpd Zpd)
           (fmaddsd Zss WVss VWss Zss)
           (fmaddsd Zsd WVsd VWsd Zsd)
           ;; 0F 24 08
           (fmsubps Zps Zps WVps VWps)
           (fmsubpd Zpd Zpd WVpd VWpd)
           (fmsubss Zss Zss WVss VWss)
           (fmsubsd Zsd Zsd WVsd VWsd)
           (fmsubps Zps WVps VWps Zps)
           (fmsubpd Zpd WVpd VWpd Zpd)
           (fmsubsd Zss WVss VWss Zss)
           (fmsubsd Zsd WVsd VWsd Zsd)
           ;; 0F 24 10
           (fnmaddps Zps Zps WVps VWps)
           (fnmaddpd Zpd Zpd WVpd VWpd)
           (fnmaddss Zss Zss WVss VWss)
           (fnmaddsd Zsd Zsd WVsd VWsd)
           (fnmaddps Zps WVps VWps Zps)
           (fnmaddpd Zpd WVpd VWpd Zpd)
           (fnmaddsd Zss WVss VWss Zss)
           (fnmaddsd Zsd WVsd VWsd Zsd)
           ;; 0F 24 18
           (fnmsubps Zps Zps WVps VWps)
           (fnmsubpd Zpd Zpd WVpd VWpd)
           (fnmsubss Zss Zss WVss VWss)
           (fnmsubsd Zsd Zsd WVsd VWsd)
           (fnmsubps Zps WVps VWps Zps)
           (fnmsubpd Zpd WVpd VWpd Zpd)
           (fnmsubsd Zss WVss VWss Zss)
           (fnmsubsd Zsd WVsd VWsd Zsd)
           ;; 0F 24 20
           (permps Zps Zps WVps VWps)
           (permpd Zpd Zpd WVpd VWpd)
           (pcmov Zdq Zdq WVdq VWdq)
           (pperm Zdq Zdq WVdq VWdq)
           (permps Zpd WVpd VWpd Zpd)
           (permpd Zpd WVpd VWpd Zpd)
           (pcmov Zdq WVdq VWdq Zdq)
           (pperm Zdq WVdq VWdq Zdq)
           ;; 0F 24 28
           #f #f #f #f #f #f #f #f
           ;; 0F 24 30
           #f #f #f #f #f #f #f #f
           ;; 0F 24 38
           #f #f #f #f #f #f #f #f
           ;; 0F 24 40
           (protb Zdq WVdq VWdq)
           (protw Zdq WVdq VWdq)
           (protd Zdq WVdq VWdq)
           (protq Zdq WVdq VWdq)
           (pshlb Zdq WVdq VWdq)
           (pshlw Zdq WVdq VWdq)
           (pshld Zdq WVdq VWdq)
           (pshlq Zdq WVdq VWdq)
           ;; 0F 24 48
           (pshab Zdq WVdq VWdq)
           (pshaw Zdq WVdq VWdq)
           (pshad Zdq WVdq VWdq)
           (pshaq Zdq WVdq VWdq)
           #f #f #f #f
           ;; 0F 24 50
           #f #f #f #f #f #f #f #f
           ;; 0F 24 58
           #f #f #f #f #f #f #f #f
           ;; 0F 24 60
           #f #f #f #f #f #f #f #f
           ;; 0F 24 68
           #f #f #f #f #f #f #f #f
           ;; 0F 24 70
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 24 80
           #f
           #f
           #f
           #f
           #f
           (pmacssww Zpd Vdq Wdq Zpd)
           (pmacsswd Zpd Vdq Wdq Zpd)
           (pmacssdql Zpd Vdq Wdq Zpd)
           ;; 0F 24 88
           #f #f #f #f
           #f
           #f
           (pmacssdd Zpd Vdq Wdq Zpd)
           (pmacssdqh Zpd Vdq Wdq Zpd)
           ;; 0F 24 90
           #f #f #f #f
           #f
           (pmacsww Zdq Vdq Wdq Zdq)
           (pmacswd Zdq Vdq Wdq Zdq)
           (pmacsdql Zdq Vdq Wdq Zdq)
           ;; 0F 24 98
           #f #f #f #f
           #f
           #f
           (pmacsdd Zdq Vdq Wdq Zdq)
           (pmacsdqh Zdq Vdq Wdq Zdq)
           ;; 0F 24 A0
           #f #f #f #f
           #f
           #f
           (pmadcsswd Zdq Vdq Wdq Zdq)
           #f
           ;; 0F 24 A8
           #f #f #f #f #f #f #f #f
           ;; 0F 24 B0
           #f #f #f #f
           #f
           #f
           (pmadcswd Zdq Vdq Wdq Zdq)
           #f
           ;; 0F 24 B8
           #f #f #f #f #f #f #f #f
           ;; 0F 24 C0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 24 D0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 24 E0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 24 F0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f)
         #(#f #f #f #f #f #f #f #f
           ;; 0F 25 08
           #f #f #f #f #f #f #f #f
           ;; 0F 25 10
           #f #f #f #f #f #f #f #f
           ;; 0F 25 18
           #f #f #f #f #f #f #f #f
           ;; 0F 25 20
           #f #f #f #f #f #f #f #f
           ;; 0F 25 28
           #f #f #f #f
           (comps Zps Vps Wps Ib)
           (compd Zpd Vpd Wpd Ib)
           (comss Zss Vss Wss Ib)
           (comsd Zsd Vsd Wsd Ib)
           ;; 0F 25 30
           #f #f #f #f #f #f #f #f
           ;; 0F 25 38
           #f #f #f #f #f #f #f #f
           ;; 0F 25 40
           #f #f #f #f #f #f #f #f
           ;; 0F 25 48
           #f #f #f #f
           (pcomb Zdq Vdq Wdq Ib)
           (pcomw Zdq Vdq Wdq Ib)
           (pcomd Zdq Vdq Wdq Ib)
           (pcomq Zdq Vdq Wdq Ib)
           ;; 0F 25 50
           #f #f #f #f #f #f #f #f
           ;; 0F 25 58
           #f #f #f #f #f #f #f #f
           ;; 0F 25 60
           #f #f #f #f #f #f #f #f
           ;; 0F 25 68
           #f #f #f #f
           (pcomub Zdq Vdq Wdq Ib)
           (pcomuw Zdq Vdq Wdq Ib)
           (pcomud Zdq Vdq Wdq Ib)
           (pcomuq Zdq Vdq Wdq Ib)
           ;; 0F 25 70
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 80
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 90
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 A0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 B0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 C0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 D0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 E0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 25 F0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f)
         (mov Td Ed)
         #f
         ;; 0F 28
         #(Prefix #(VEX (movaps Vps Wps) (vmovaps Vps Wps))
                  #f
                  #(VEX (movapd Vpd Wpd) (vmovapd Vpd Wpd))
                  #f)
         #(Prefix #(VEX (movaps Wps Vps) (vmovaps Vps Wps))
                  #f
                  #(VEX (movapd Wpd Vpd) (vmovapd Wpd Vpd))
                  #f)
         #(Prefix (cvtpi2ps Vps Qq)
                  #(VEX (cvtsi2ss Vss Ed/q)
                        (vcvtsi2ss Vss Bss Ed/q)
                        #f)
                  (cvtpi2pd Vpd Qq)
                  #(VEX (cvtsi2sd Vsd Ed/q)
                        (vcvtsi2sd Vsd Bsd Ed/q)
                        #f))
         #(Prefix #(VEX (movntps Mdq Vps)
                        (vmovntps Mdq Vps)
                        #f)
                  (movntss Md Vss)
                  #(VEX (movntpd Mdq Vpd)
                        (vmovntpd Mdq Vpd)
                        #f)
                  (movntsd Mq Vsd))
         #(Prefix (cvttps2pi Pq Wps)
                  #(VEX (cvttss2si Gd/q Wss)
                        (vcvttss2si Gd/q Wss)
                        #f)
                  (cvttpd2pi Pq Wpd)
                  #(VEX (cvttsd2si Gd/q Wsd)
                        (vcvttsd2si Gd/q Wsd)
                        #f))
         #(Prefix (cvtps2pi Pq Wps)
                  #(VEX (cvtss2si Gd/q Wss)
                        (vcvtss2si Gd/q Wss)
                        #f)
                  (cvtpd2pi Pq Wpd)
                  #(VEX (cvtsd2si Gd/q Wsd)
                        (vcvtsd2si Gd/q Wsd)
                        #f))
         #(Prefix #(VEX (ucomiss Vss Wss) (vucomiss Vss Wss) #f)
                  #f
                  #(VEX (ucomisd Vsd Wsd) (vucomisd Vsd Wsd) #f)
                  #f)
         #(Prefix #(VEX (comiss Vps Wps)
                        (vcomiss Vps Wps)
                        #f)
                  #f
                  #(VEX (comisd Vpd Wsd)
                        (vcomisd Vpd Wsd)
                        #f)
                  #f)
         ;; 0F 30
         (wrmsr)
         (rdtsc)
         (rdmsr)
         (rdpmc)
         #(Mode (sysenter) #f)
         #(Mode (sysexit) #f)
         #f
         (getsec)
         ;; 0F 38: Three-byte opcode
         #(#(Prefix (pshufb Pq Qq) #f #(VEX (pshufb Vdq Wdq) (vpshufb Vdq Bdq Wdq) #f) #f)
           #(Prefix (phaddw Pq Qq) #f #(VEX (phaddw Vdq Wdq) (vphaddw Vdq Bdq Wdq) #f) #f)
           #(Prefix (phaddd Pq Qq) #f #(VEX (phaddd Vdq Wdq) (vphaddd Vdq Bdq Wdq) #f) #f)
           #(Prefix (phaddsw Pq Qq) #f #(VEX (phaddsw Vdq Wdq) (vphaddsw Vdq Bdq Wdq) #f) #f)
           #(Prefix (pmaddubsw Pq Qq) #f #(VEX (pmaddubsw Vdq Wdq) (vpmaddubsw Vdq Bdq Wdq) #f) #f)
           #(Prefix (phsubw Pq Qq) #f #(VEX (phsubw Vdq Wdq) (vphsubw Vdq Bdq Wdq) #f) #f)
           #(Prefix (phsubd Pq Qq) #f #(VEX (phsubd Vdq Wdq) (vphsubd Vdq Bdq Wdq) #f) #f)
           #(Prefix (phsubsw Pq Qq) #f #(VEX (phsubsw Vdq Wdq) (vphsubsw Vdq Bdq Wdq) #f) #f)
           ;; 0F 38 08
           #(Prefix (psignb Pq Qq) #f #(VEX (psignb Vdq Wdq) (vpsignb Vdq Bdq Wdq) #f) #f)
           #(Prefix (psignw Pq Qq) #f #(VEX (psignw Vdq Wdq) (vpsignw Vdq Bdq Wdq) #f) #f)
           #(Prefix (psignd Pq Qq) #f #(VEX (psignd Vdq Wdq) (vpsignd Vdq Bdq Wdq) #f) #f)
           #(Prefix (pmulhrsw Pq Qq) #f #(VEX (pmulhrsw Vdq Wdq) (vpmulhrsw Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX #f (vpermilps Vps Bps Wps)) #f)
           #(Prefix #f #f #(VEX #f (vpermilpd Vpd Bpd Wpd)) #f)
           #(Prefix #f #f #(VEX #f (vtestps Vps Wps)) #f)
           #(Prefix #f #f #(VEX #f (vtestpd Vpd Wpd)) #f)
           ;; 0F 38 10
           #(Prefix #f #f (pblendvb Vdq Wdq) #f)
           #f #f #f
           #(Prefix #f #f (blendvps Vdq Wdq) #f)
           #(Prefix #f #f (blendvpd Vdq Wdq) #f)
           #f
           #(Prefix #f #f #(VEX (ptest Vdq Wdq) (vptest Vdq Wdq)) #f)
           ;; 0F 38 18
           #(Prefix #f #f #(VEX #f (vbroadcastss Vss Md)) #f)
           #(Prefix #f #f #(VEX #f #f (vbroadcastsd Vsd Mq)) #f)
           #(Prefix #f #f #(VEX #f #f (vbroadcastf128 Vsd Mdq)) #f)
           #f
           #(Prefix (pabsb Pq Qq) #f
                    #(VEX (pabsb Vdq Wdq) (vpabsb Vdq Wdq) #f) #f)
           #(Prefix (pabsw Pq Qq) #f
                    #(VEX (pabsw Vdq Wdq) (vpabsw Vdq Wdq) #f) #f)
           #(Prefix (pabsd Pq Qq) #f
                    #(VEX (pabsd Vdq Wdq) (vpabsd Vdq Wdq) #f) #f)
           #f
           ;; 0F 38 20
           #(Prefix #f #f #(VEX (pmovsxbw Vdq Udq/Mq) (vpmovsxbw Vdq Udq/Mq) #f) #f)
           #(Prefix #f #f #(VEX (pmovsxbd Vdq Udq/Md) (vpmovsxbd Vdq Udq/Md) #f) #f)
           #(Prefix #f #f #(VEX (pmovsxbq Vdq Udq/Mw) (vpmovsxbq Vdq Udq/Mw) #f) #f)
           #(Prefix #f #f #(VEX (pmovsxwd Vdq Udq/Md) (vpmovsxwd Vdq Udq/Md) #f) #f)
           #(Prefix #f #f #(VEX (pmovsxwq Vdq Udq/Mq) (vpmovsxwq Vdq Udq/Mq) #f) #f)
           #(Prefix #f #f #(VEX (pmovsxdq Vdq Udq/Mq) (vpmovsxdq Vdq Udq/Mq) #f) #f)
           #f #f
           ;; 0F 38 28
           #(Prefix #f #f #(VEX (pmuldq Vdq Wdq) (vpmuldq Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pcmpeqq Vdq Wdq) (vpcmpeqq Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (movntdqa Vdq Mdq) (vmovntdqa Vdq Mdq) #f) #f)
           #(Prefix #f #f #(VEX (packusdw Vdq Wdq) (vpackusdw Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX #f (vmaskmovps Vdq Bps Mps)) #f)
           #(Prefix #f #f #(VEX #f (vmaskmovpd Vdq Bpd Mpd)) #f)
           #(Prefix #f #f #(VEX #f (vmaskmovps Mps Bdq Vps)) #f)
           #(Prefix #f #f #(VEX #f (vmaskmovpd Mpd Bdq Vpd)) #f)
           ;; 0F 38 30
           #(Prefix #f #f #(VEX (pmovzxbw Vdq Udq/Mq) (vpmovzxbw Vdq Udq/Mq) #f) #f)
           #(Prefix #f #f #(VEX (pmovzxbd Vdq Udq/Md) (vpmovzxbd Vdq Udq/Md) #f) #f)
           #(Prefix #f #f #(VEX (pmovzxbq Vdq Udq/Mw) (vpmovzxbq Vdq Udq/Mw) #f) #f)
           #(Prefix #f #f #(VEX (pmovzxwd Vdq Udq/Mq) (vpmovzxwd Vdq Udq/Mq) #f) #f)
           #(Prefix #f #f #(VEX (pmovzxwq Vdq Udq/Md) (vpmovzxwq Vdq Udq/Md) #f) #f)
           #(Prefix #f #f #(VEX (pmovzxdq Vdq Udq/Mq) (vpmovzxdq Vdq Udq/Mq) #f) #f)
           #f
           #(Prefix #f #f #(VEX (pcmpgtq Vdq Wdq) (vpcmpgtq Vdq Bdq Wdq) #f) #f)
           ;; 0F 38 38
           #(Prefix #f #f #(VEX (pminsb Vdq Wdq) (vpminsb Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pminsd Vdq Wdq) (vpminsd Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pminuw Vdq Wdq) (vpminuw Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pminud Vdq Wdq) (vpminud Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pmaxsb Vdq Wdq) (vpmaxsb Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pmaxsd Vdq Wdq) (vpmaxsd Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pmaxuw Vdq Wdq) (vpmaxuw Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (pmaxud Vdq Wdq) (vpmaxud Vdq Bdq Wdq) #f) #f)
           ;; 0F 38 40
           #(Prefix #f #f #(VEX (pmulld Vdq Wdq) (vpmulld Vdq Bdq Wdq) #f) #f)
           #(Prefix #f #f #(VEX (phminposuw Vdq Wdq) (vphminposuw Vdq Wdq) #f) #f)
           #f #f #f #f #f #f
           ;; 0F 38 48
           #f #f #f #f #f #f #f #f
           ;; 0F 38 50
           #f #f #f #f #f #f #f #f
           ;; 0F 38 58
           #f #f #f #f #f #f #f #f
           ;; 0F 38 60
           #f #f #f #f #f #f #f #f
           ;; 0F 38 68
           #f #f #f #f #f #f #f #f
           ;; 0F 38 70
           #f #f #f #f #f #f #f #f
           ;; 0F 38 78
           #f #f #f #f #f #f #f #f
           ;; 0F 38 80
           #(Prefix #f
                    #f
                    #(Mode (invept Gd Mdq)
                           (invept Gq Mdq))
                    #f)
           #(Prefix #f
                    #f
                    #(Mode (invvpid Gd Mdq)
                           (invvpid Gq Mdq))
                    #f)
           #f #f #f #f #f #f
           ;; 0F 38 88
           #f #f #f #f #f #f #f #f
           ;; 0F 38 90
           #f #f #f #f #f #f #f #f
           ;; 0F 38 98
           #f #f #f #f #f #f #f #f
           ;; 0F 38 A0
           #f #f #f #f #f #f #f #f
           ;; 0F 38 A8
           #f #f #f #f #f #f #f #f
           ;; 0F 38 B0
           #f #f #f #f #f #f #f #f
           ;; 0F 38 B8
           #f #f #f #f #f #f #f #f
           ;; 0F 38 C0
           #f #f #f #f #f #f #f #f
           ;; 0F 38 C8
           #f #f #f #f #f #f #f #f
           ;; 0F 38 D0
           #f #f #f #f #f #f #f #f
           ;; 0F 38 D8
           #f #f #f
           #(Prefix #f #f (aesimc Vdq Wdq) #f)
           #(Prefix #f #f (aesenc Vdq Wdq) #f)
           #(Prefix #f #f (aesenclast Vdq Wdq) #f)
           #(Prefix #f #f (aesdec Vdq Wdq) #f)
           #(Prefix #f #f (aesdeclast Vdq Wdq) #f)
           ;; 0F 38 E0
           #f #f #f #f #f #f #f #f
           ;; 0F 38 E8
           #f #f #f #f #f #f #f #f
           ;; 0F 38 F0
           #(Prefix (movbe Gv Mv)
                    #f
                    #f
                    (crc32 Gd Eb))
           #(Prefix (movbe Mv Gv)
                    #f
                    #f
                    (crc32 Gd Ev))
           #f #f #f #f #f #f
           ;; 0F 38 F8
           #f #f #f #f #f #f #f #f)
         (dmint)
         ;; 0F 3A: Three-byte opcode (also RDM in AMD Geode)
         #(#f
           #f
           #f
           #f
           #(Prefix #f #f #(VEX #f (vpermilps Vps Wps Ib)) #f)
           #(Prefix #f #f #(VEX #f (vpermilpd Vpd Wpd Ib)) #f)
           #(Prefix #f #f #(VEX #f #f (vperm2f128 Vdq Bdq Wdq Ib)) #f)
           #f
           ;; 0F 3A 08
           #(Prefix #f #f #(VEX (roundps Vdq Wdq Ib) (vroundps Vdq Wdq Ib)) #f)
           #(Prefix #f #f #(VEX (roundpd Vdq Wdq Ib) (vroundpd Vdq Wdq Ib)) #f)
           #(Prefix #f #f #(VEX (roundss Vss Wss Ib) (vroundss Vss Bss Wss Ib) #f) #f)
           #(Prefix #f #f #(VEX (roundsd Vsd Wsd Ib) (vroundsd Vsd Bsd Wsd Ib) #f) #f)
           #(Prefix #f #f #(VEX (blendps Vdq Wdq Ib) (vblendps Vdq Bdq Wdq Ib)) #f)
           #(Prefix #f #f #(VEX (blendpd Vdq Wdq Ib) (vblendpd Vdq Bdq Wdq Ib)) #f)
           #(Prefix #f #f #(VEX (pblendw Vdq Wdq Ib) (vpblendw Vdq Bdq Wdq Ib) #f) #f)
           #(Prefix (palignr Vq Qq Ib) #f
                    #(VEX (palignr Vdq Wdq Ib)
                          (vpalignr Vdq Bdq Wdq Ib)
                          #f)
                    #f)
           ;; 0F 3A 10
           #f #f #f #f
           #(Prefix #f #f #(VEX (pextrb Rd/Mb Vdq Ib) (vpextrb Rd/Mb Vdq Ib) #f) #f)
           #(Prefix #f #f #(VEX (pextrw Rd/Mw Vdq Ib) (vpextrw Rd/Mw Vdq Ib) #f) #f)
           #(Prefix #f
                    #f
                    #(Datasize #f
                               #(VEX (pextrd Ed Vdq Ib) (vpextrd Ed Vdq Ib) #f)
                               #(VEX (pextrq Eq Vdq Ib) (vpextrq Eq Vdq Ib) #f))
                    #f)
           #(Prefix #f #f #(VEX (extractps Ed Vdq Ib)
                                (vextractps Ed Vdq Ib)
                                #f)
                    #f)
           ;; 0F 3A 18
           #(Prefix #f #f #(VEX #f #f (vinsertf128 Vdq Bdq Wdq/128 Ib)) #f)
           #(Prefix #f #f #(VEX #f #f (vextractf128 Wdq/128 Bdq Ib)) #f)
           #f
           #f
           #f
           #f
           #f
           #f
           ;; 0F 3A 20
           #(Prefix #f #f
                    #(VEX (pinsrb Vdq Rd/Mb Ib)
                          (vpinsrb Vdq Bdq Rd/Mb Ib)
                          #f)
                    #f)
           #(Prefix #f #f
                    #(VEX (insertps Vdq Udq/Md Ib)
                          (vinsertps Vdq Bdq Udq/Md Ib)
                          #f)
                    #f)
           #(Prefix #f
                    #f
                    #(Datasize #f
                               #(VEX (pinsrd Vdq Ed Ib) (vpinsrd Vdq Bdq Ed Ib) #f)
                               #(VEX (pinsrq Vdq Eq Ib) (vpinsrq Vdq Bdq Eq Ib) #f))
                    #f)
           #f #f #f #f #f
           ;; 0F 3A 28
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 30
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 38
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 40
           #(Prefix #f #f #(VEX (dpps Vps Wps Ib) (vdpps Vps Bps Wpd Ib)) #f)
           #(Prefix #f #f #(VEX (dppd Vpd Wpd Ib) (vdppd Vpd Bpd Wpd Ib) #f) #f)
           #(Prefix #f #f #(VEX (mpsadbw Vdq Wdq Ib) (vmpsadbw Vdq Bdq Wdq Ib) #f) #f)
           #f
           #(Prefix #f #f (pclmulqdq Vdq Wdq Ib) #f)
           #f
           #f
           #f
           ;; 0F 3A 48
           #(Prefix #f #f #(VEX #f (vpermil2ps Vps Bps WKps KWps In)) #f)
           #(Prefix #f #f #(VEX #f (vpermil2pd Vpd Bpd WKpd KWpd In)) #f)
           #(Prefix #f #f #(VEX #f (vblendvps Vps Bps Wps Kps)) #f)
           #(Prefix #f #f #(VEX #f (vblendvpd Vpd Bpd Wpd Kpd)) #f)
           #(Prefix #f #f #(VEX #f (vpblendvb Vdq Bdq Wdq Kdq)) #f)
           #f
           #f
           #f
           ;; 0F 3A 50
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 58
           #f
           #f
           #f
           #f
           #(Prefix #f #f #(VEX #f (vfmaddsubps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfmaddsubpd Vpd Kpd WBpd BWpd)) #f)
           #(Prefix #f #f #(VEX #f (vfmsubaddps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfmsubaddpd Vpd Kpd WBpd BWpd)) #f)
           ;; 0F 3A 60
           #(Prefix #f #f #(VEX (pcmpestrm Vdq Wdq Ib) (vpcmpestrm Vdq Wdq Ib) #f) #f)
           #(Prefix #f #f #(VEX (pcmpestri Vdq Wdq Ib) (vpcmpestri Vdq Wdq Ib) #f) #f)
           #(Prefix #f #f #(VEX (pcmpistrm Vdq Wdq Ib) (vpcmpistrm Vdq Wdq Ib) #f) #f)
           #(Prefix #f #f #(VEX (pcmpistri Vdq Wdq Ib) (vpcmpistri Vdq Wdq Ib) #f) #f)
           #f #f #f #f
           ;; 0F 3A 68
           #(Prefix #f #f #(VEX #f (vfmaddps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfmaddpd Vpd Kpd WBpd BWpd)) #f)
           #(Prefix #f #f #(VEX #f (vfmaddss Vss Kss WBss BWss) #f) #f)
           #(Prefix #f #f #(VEX #f (vfmaddsd Vsd Ksd WBsd BWsd) #f) #f)
           #(Prefix #f #f #(VEX #f (vfmsubps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfmsubpd Vpd Kpd WBpd BWpd)) #f)
           #(Prefix #f #f #(VEX #f (vfmsubss Vss Kss WBss BWss) #f) #f)
           #(Prefix #f #f #(VEX #f (vfmsubsd Vsd Ksd WBsd BWsd) #f) #f)
           ;; 0F 3A 70
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 78
           #(Prefix #f #f #(VEX #f (vfnmaddps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfnmaddpd Vpd Kpd WBpd BWpd)) #f)
           #(Prefix #f #f #(VEX #f (vfnmaddss Vss Kss WBss BWss) #f) #f)
           #(Prefix #f #f #(VEX #f (vfnmaddsd Vsd Ksd WBsd BWsd) #f) #f)
           #(Prefix #f #f #(VEX #f (vfnmsubps Vps Kps WBps BWps)) #f)
           #(Prefix #f #f #(VEX #f (vfnmsubpd Vpd Kpd WBpd BWpd)) #f)
           #(Prefix #f #f #(VEX #f (vfnmsubss Vss Kss WBss BWss) #f) #f)
           #(Prefix #f #f #(VEX #f (vfnmsubsd Vsd Ksd WBsd BWsd) #f) #f)
           ;; 0F 3A 80
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 88
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 90
           #f #f #f #f #f #f #f #f
           ;; 0F 3A 98
           #f #f #f #f #f #f #f #f
           ;; 0F 3A A0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A A8
           #f #f #f #f #f #f #f #f
           ;; 0F 3A B0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A B8
           #f #f #f #f #f #f #f #f
           ;; 0F 3A C0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A C8
           #f #f #f #f #f #f #f #f
           ;; 0F 3A D0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A D8
           #f #f #f #f #f #f #f
           #(Prefix #f #f (aeskeygenassist Vdq Wdq Ib) #f)
           ;; 0F 3A E0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A E8
           #f #f #f #f #f #f #f #f
           ;; 0F 3A F0
           #f #f #f #f #f #f #f #f
           ;; 0F 3A F8
           #f #f #f #f #f #f #f #f)
         #f #f #f #f #f
         ;; 0F 40
         (cmovo Gv Ev)
         (cmovno Gv Ev)
         (cmovb Gv Ev)
         (cmovnb Gv Ev)
         (cmovz Gv Ev)
         (cmovnz Gv Ev)
         (cmovbe Gv Ev)
         (cmovnbe Gv Ev)
         ;; 0F 48
         (cmovs Gv Ev)
         (cmovns Gv Ev)
         (cmovp Gv Ev)
         (cmovnp Gv Ev)
         (cmovl Gv Ev)
         (cmovnl Gv Ev)
         (cmovle Gv Ev)
         (cmovnle Gv Ev)
         ;; 0F 50
         #(Prefix #(VEX (movmskps Gd Ups) (vmovmskps Gd Ups)) #f
                  #(VEX (movmskpd Gd Upd) (vmovmskpd Gd Upd)) #f)
         #(Prefix #(VEX (sqrtps Vps Wps) (vsqrtps Vps Wps))
                  #(VEX (sqrtss Vss Wss) (vsqrtss Vss Bss Wss) #f)
                  #(VEX (sqrtpd Vpd Wpd) (vsqrtpd Vpd Wpd))
                  #(VEX (sqrtsd Vsd Wsd) (vsqrtsd Vsd Bsd Wsd) #f))
         #(Prefix #(VEX (rsqrtps Vps Wps) (vrsqrtps Vps Wps))
                  #(VEX (rsqrtss Vss Wss) (vrsqrtss Vss Bss Wss) #f)
                  #f #f)
         #(Prefix #(VEX (rcpps Vps Wps) (vrcpps Vps Wps))
                  #(VEX (rcpss Vss Wss) (vrcpss Vss Bss Wss) #f)
                  #f #f)
         #(Prefix #(VEX (andps Vps Wps) (vandps Vps Bps Wps)) #f
                  #(VEX (andpd Vpd Wpd) (vandpd Vpd Bpd Wpd)) #f)
         #(Prefix #(VEX (andnps Vps Wps) (vandnps Vpd Bpd Wpd)) #f
                  #(VEX (andnpd Vpd Wpd) (vandnpd Vpd Bpd Wpd)) #f)
         #(Prefix #(VEX (orps Vps Wps) (vorps Vps Bps Wps)) #f
                  #(VEX (orpd Vpd Wpd) (vorpd Vpd Bpd Wpd)) #f)
         #(Prefix #(VEX (xorps Vps Wps) (vxorps Vps Bps Wps)) #f
                  #(VEX (xorpd Vpd Wpd) (vxorpd Vpd Bpd Wpd)) #f)
         ;; 0F 58
         #(Prefix #(VEX (addps Vps Wps)
                        (vaddps Vps Bps Wps))
                  #(VEX (addss Vss Wss)
                        (vaddss Vss Bss Wss)
                        #f)
                  #(VEX (addpd Vpd Wpd)
                        (vaddpd Vpd Bpd Wpd))
                  #(VEX (addsd Vsd Wsd)
                        (vaddsd Vsd Bsd Wsd)
                        #f))
         #(Prefix #(VEX (mulps Vps Wps) (vmulps Vps Bps Wps))
                  #(VEX (mulss Vss Wss) (vmulss Vss Bss Wss) #f)
                  #(VEX (mulpd Vpd Wpd) (vmulpd Vpd Bpd Wpd))
                  #(VEX (mulsd Vsd Wsd) (vmulsd Vsd Bsd Wsd) #f))
         #(Prefix #(VEX (cvtps2pd Vpd Wps)
                        (vcvtps2pd Vpd Wps/128))
                  #(VEX (cvtss2sd Vsd Wss)
                        (vcvtss2sd Vsd Bdq Wss)
                        #f)
                  #(VEX (cvtpd2ps Vps Wpd)
                        (vcvtpd2ps Vps Wpd))
                  #(VEX (cvtsd2ss Vss Wsd)
                        (vcvtsd2ss Vss Bdq Wsd)))
         #(Prefix #(VEX (cvtdq2ps Vps Wdq)
                        (vcvtdq2ps Vps Wdq))
                  #(VEX (cvttps2dq Vdq Wps)
                        (vcvttps2dq Vdq Wps))
                  #(VEX (cvtps2dq Vdq Wps)
                        (vcvtps2dq Vdq Wps))
                  #f)
         #(Prefix #(VEX (subps Vps Wps) (vsubps Vps Bps Wps))
                  #(VEX (subss Vss Wss) (vsubss Vss Bss Wss) #f)
                  #(VEX (subpd Vpd Wpd) (vsubpd Vpd Bpd Wpd))
                  #(VEX (subsd Vsd Wsd) (vsubsd Vsd Bsd Wsd) #f))
         #(Prefix #(VEX (minps Vps Wps) (vminps Vps Bps Wps))
                  #(VEX (minss Vss Wss) (vminss Vss Bss Wss) #f)
                  #(VEX (minpd Vpd Wpd) (vminpd Vpd Bpd Wpd))
                  #(VEX (minsd Vsd Wsd) (vminsd Vsd Bsd Wsd) #f))
         #(Prefix #(VEX (divps Vps Wps) (vdivps Vps Bps Wps))
                  #(VEX (divss Vss Wss) (vdivss Vss Bss Wss) #f)
                  #(VEX (divpd Vpd Wpd) (vdivpd Vpd Bpd Wpd))
                  #(VEX (divsd Vsd Wsd) (vdivsd Vsd Bsd Wsd) #f))
         #(Prefix #(VEX (maxps Vps Wps) (vmaxps Vps Bps Wps))
                  #(VEX (maxss Vss Wss) (vmaxss Vss Bss Wss) #f)
                  #(VEX (maxpd Vpd Wpd) (vmaxpd Vpd Bpd Wpd))
                  #(VEX (maxsd Vsd Wsd) (vmaxsd Vsd Bsd Wpd) #f))
         ;; 0F 60
         #(Prefix (punpcklbw Pq Qd) #f #(VEX (punpcklbw Vdq Wq) (vpunpcklbw Vdq Bdq Wq) #f) #f)
         #(Prefix (punpcklwd Pq Qd) #f #(VEX (punpcklwd Vdq Wq) (vpunpcklwd Vdq Bdq Wq) #f) #f)
         #(Prefix (punpckldq Pq Qd) #f #(VEX (punpckldq Vdq Wq) (vpunpckldq Vdq Bdq Wq) #f) #f)
         #(Prefix (packsswb Pq Qq) #f #(VEX (packsswb Vdq Wdq) (vpacksswb Vdq Bdq Wdq) #f) #f)
         #(Prefix (pcmpgtb Pq Qq) #f #(VEX (pcmpgtb Vdq Wdq) (vpcmpgtb Vdq Bdq Wdq) #f) #f)
         #(Prefix (pcmpgtw Pq Qq) #f #(VEX (pcmpgtw Vdq Wdq) (vpcmpgtw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pcmpgtd Pq Qq) #f #(VEX (pcmpgtd Vdq Wdq) (vpcmpgtd Vdq Bdq Wdq) #f) #f)
         #(Prefix (packuswb Pq Qq) #f #(VEX (packuswb Vdq Wdq) (vpackuswb Vdq Wdq) #f) #f)
         ;; 0F 68
         #(Prefix (punpckhbw Pq Qd) #f #(VEX (punpckhbw Vdq Wq) (vpunpckhbw Vdq Bdq Wq) #f) #f)
         #(Prefix (punpckhwd Pq Qd) #f #(VEX (punpckhwd Vdq Wq) (vpunpckhwd Vdq Bdq Wq) #f) #f)
         #(Prefix (punpckhdq Pq Qd) #f #(VEX (punpckhdq Vdq Wq) (vpunpckhdq Vdq Bdq Wq) #f) #f)
         #(Prefix (packssdw Pq Qq) #f #(VEX (packssdw Vdq Wdq) (vpackssdw Vdq Bdq Wdq) #f) #f)
         #(Prefix #f #f #(VEX (punpcklqdq Vdq Wq) (vpunpcklqdq Vdq Bdq Wq) #f) #f)
         #(Prefix #f #f #(VEX (punpckhqdq Vdq Wq) (vpunpckhqdq Vdq Bdq Wq) #f) #f)
         #(Prefix #(Datasize #f
                             (movd Pq Ed)
                             (movq Pq Eq))
                  #f
                  #(Datasize #f
                             #(VEX (movd Vdq Ed) (vmovd Vdq Ed) #f)
                             #(VEX (movq Vdq Eq) (vmovq Vdq Eq) #f))
                  #f)
         #(Prefix (movq Pq Qq)
                  #(VEX (movdqu Vdq Wdq) (vmovdqu Vdq Wdq))
                  #(VEX (movdqa Vdq Wdq) (vmovdqa Vdq Wdq))
                  #f)
         ;; 0F 70
         #(Prefix (pshufw Pq Qq Ib)
                  #(VEX (pshufhw Vdq Wdq Ib) (vpshufhw Vdq Wdq Ib) #f)
                  #(VEX (pshufd Vdq Wdq Ib) (vpshufd Vdq Wdq Ib) #f)
                  #(VEX (pshuflw Vdq Wdq Ib) (vpshuflw Vdq Wdq Ib) #f))
         #(Group "Group 12"
                 #(#f #f #f #f #f #f #f #f)
                 #(#f #f
                      #(Prefix (psrlw Nq Ib) #f #(VEX (psrlw Udq Ib) (vpsrlw Bdq Udq Ib) #f) #f) #f
                      #(Prefix (psraw Nq Ib) #f #(VEX (psraw Udq Ib) (vpsraw Bdq Udq Ib) #f) #f) #f
                      #(Prefix (psllw Nq Ib) #f #(VEX (psllw Udq Ib) (vpsllw Bdq Udq Ib) #f) #f) #f))
         #(Group "Group 13"
                 #(#f #f #f #f #f #f #f #f)
                 #(#f #f
                      #(Prefix (psrld Nq Ib) #f #(VEX (psrld Udq Ib) (vpsrld Bdq Udq Ib) #f) #f) #f
                      #(Prefix (psrad Nq Ib) #f #(VEX (psrad Udq Ib) (vpsrad Bdq Udq Ib) #f) #f) #f
                      #(Prefix (pslld Nq Ib) #f #(VEX (pslld Udq Ib) (vpslld Bdq Udq Ib) #f) #f) #f))
         #(Group "Group 14"
                 #(#f #f #f #f #f #f #f #f)
                 #(#f #f
                      #(Prefix (psrlq Nq Ib) #f #(VEX (psrlq Udq Ib) (vpsrlq Bdq Udq Ib) #f) #f)
                      #(Prefix #f            #f #(VEX (psrldq Udq Ib) (vpsrldq Bdq Udq Ib) #f) #f)
                      #f #f
                      #(Prefix (psllq Nq Ib) #f #(VEX (psllq Udq Ib) (vpsllq Bdq Udq Ib) #f) #f)
                      #(Prefix #f #f #(VEX (pslldq Udq Ib) (vpslldq Bdq Udq Ib) #f) #f)))
         #(Prefix (pcmpeqb Pq Qq) #f #(VEX (pcmpeqb Vdq Wdq) (vpcmpeqb Vdq Bdq Wdq) #f) #f)
         #(Prefix (pcmpeqw Pq Qq) #f #(VEX (pcmpeqw Vdq Wdq) (vpcmpeqw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pcmpeqd Pq Qq) #f #(VEX (pcmpeqd Vdq Wdq) (vpcmpeqd Vdq Bdq Wdq) #f) #f)
         #(Prefix #(VEX (emms) (vzeroupper) (vzeroall)) #f #f #f)
         ;; 0F 78
         #(Prefix #(Mode (vmread Ed Gd) ;SVDC sr, m80 on AMD Geode
                         (vmread Eq Gq))
                  #f
                  #(Group "Group 17"
                          #((extrq Vdq Ib Ib)
                            #f #f #f #f #f #f #f))
                  (insertq Vdq Uq Ib Ib))
         #(Prefix #(Mode (vmwrite Gd Ed) ;RSDC sr, m80 on AMD Geode
                         (vmwrite Gq Eq))
                  #f
                  (extrq Vdq Uq)
                  (insertq Vdq Udq))
         ;; 0F 7A: AMD SSE5 (also SVLDT m80 on AMD Geode)
         #(#f #f #f #f #f #f #f #f
           ;; 0F 7A 08
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 10
           (frczps Vps Wps)
           (frczpd Vpd Wpd)
           (frczss Vss Wss)
           (frczsd Vsd Wsd)
           #f #f #f #f
           ;; 0F 7A 18
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 20
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 28
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 30
           (cvtph2ps Vps Wdq)
           (cvtps2ph Wdq Vps)
           #f #f #f #f #f #f
           ;; 0F 7A 38
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 40
           #f
           (phaddbw Vdq Wdq)
           (phaddbd Vdq Wdq)
           (phaddbq Vdq Wdq)
           #f #f
           (phaddwd Vdq Wdq)
           (phaddwq Vdq Wdq)
           ;; 0F 7A 48
           #f #f #f
           (phadddq Vdq Wdq)
           #f #f #f #f
           ;; 0F 7A 50
           #f
           (phaddubw Vdq Wdq)
           (phaddubd Vdq Wdq)
           (phaddubq Vdq Wdq)
           #f #f
           (phadduwd Vdq Wdq)
           (phadduwq Vdq Wdq)
           ;; 0F 7A 58
           #f #f #f
           (phaddudq Vdq Wdq)
           #f #f #f #f
           ;; 0F 7A 60
           #f
           (phsubbw Vdq Wdq)
           (phsubwd Vdq Wdq)
           (phsubdq Vdq Wdq)
           #f #f #f #f
           ;; 0F 7A 68
           #f #f #f #f #f #f #f #f
           ;; 0F 7A 70
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A 80
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A 90
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A A0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A B0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A C0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A D0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A E0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
           ;; 0F 7A F0
           #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f)
         ;; AMD SSE5 (RSLDT m80 on AMD Geode)
         #(#f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f
              ;; 0F 7B 40
              (protb Vpd Wdq Ib)
              (protw Vpd Wdq Ib)
              (protd Vpd Wdq Ib)
              (protq Vpd Wdq Ib)
              #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f #f
              #f #f #f #f #f #f #f #f #f #f)
         #(Prefix (svts Mem80)
                  #f
                  #(VEX (haddpd Vpd Wpd) (vhaddpd Vpd Bpd Wpd))
                  #(VEX (haddps Vps Wps) (vhaddps Vps Bps Wps)))
         #(Prefix (rsts Mem80)
                  #f
                  #(VEX (hsubpd Vpd Wpd) (vhsubpd Vpd Bpd Wpd))
                  #(VEX (hsubps Vps Wps) (vhsubps Vps Bps Wps)))
         #(Prefix #(Datasize #f
                             (movd Ed Pq)
                             (movq Eq Pq))
                  #(VEX (movq Vq Wq) (vmovq Vq Wq) #f)
                  #(Datasize #f
                             #(VEX (movd Ed Vdq) (vmovd Ed Vdq) #f)
                             #(VEX (movq Eq Vdq) (vmovq Eq Vdq) #f))
                  #f)
         #(Prefix (movq Qq Pq)
                  #(VEX (movdqu Wdq Vdq) (vmovdqu Wdq Vdq))
                  #(VEX (movdqa Wdq Vdq) (vmovdqa Wdq Vdq))
                  #f)
         ;; 0F 80
         (jo Jz)
         (jno Jz)
         (jb Jz)
         (jnb Jz)
         (jz Jz)
         (jnz Jz)
         (jbe Jz)
         (jnbe Jz)
         ;; 0F 88
         (js Jz)
         (jns Jz)
         (jp Jz)
         (jnp Jz)
         (jl Jz)
         (jnl Jz)
         (jle Jz)
         (jnle Jz)
         ;; 0F 90
         (seto Eb)
         (setno Eb)
         (setb Eb)
         (setnb Eb)
         (setz Eb)
         (setnz Eb)
         (setbe Eb)
         (setnbe Eb)
         ;; 0F 98
         (sets Eb)
         (setns Eb)
         (setp Eb)
         (setnp Eb)
         (setl Eb)
         (setnl Eb)
         (setle Eb)
         (setnle Eb)
         ;; 0F A0
         (push *FS)
         (pop *FS)
         (cpuid)
         (bt Ev Gv)
         (shld Ev Gv Ib)
         (shld Ev Gv *CL)
         #(Group "VIA PadLock Group"
                 #(#f #f #f #f #f #f #f #f)
                 #((montmul) (xsha1) (xsha256)
                   #f #f #f #f #f))
         #(Group "VIA PadLock Group"
                 #(#f #f #f #f #f #f #f #f)
                 #((xstore) (xcryptecb)
                   (xcryptcbc) (xcryptctr)
                   (xcryptcfb) (xcryptofb)
                   #f #f))
         ;; 0F A8
         (push *GS)
         (pop *GS)
         (rsm)
         (bts Ev Gv)
         (shrd Ev Gv Ib)
         (shrd Ev Gv *CL)
         #(Group "Group 15"
                 #((fxsave M) (fxrstor M)
                   #(VEX (ldmxcsr Md) (vldmxcsr Md) #f)
                   #(VEX (stmxcsr Md) (vstmxcsr Md) #f)
                   (xsave M) (xrstor M) #f (clflush Mb))
                 #(#f #f #f #f #f (lfence) (mfence) (sfence)))
         (imul Gv Ev)
         ;; 0F B0
         (cmpxchg Eb Gb)
         (cmpxchg Ev Gv)
         (lss Gv Mp)
         (btr Ev Gv)
         (lfs Gv Mp)
         (lgs Gv Mp)
         (movzx Gv Eb)
         (movzx Gv Ew)
         ;; 0F B8
         #(Prefix (jmpe Jz) (popcnt Gv Ev) #f #f)
         #(Group "Group 10"
                 #(#f #f #f #f #f #f #f #f))
         #(Group "Group 8"
                 #(#f #f #f #f
                      (bt Ev Ib) (bts Ev Ib)
                      (btr Ev Ib) (btc Ev Ib)))
         (btc Ev Gv)
         (bsf Gv Ev)
         #(Prefix (bsr Gv Ev) (lzcnt Gv Ev) #f #f)
         (movsx Gv Eb)
         (movsx Gv Ew)
         ;; 0F C0
         (xadd Eb Gb)
         (xadd Ev Gv)
         #(Prefix #(VEX (cmpps Vps Wps Ib)
                        (vcmpps Vps Bps Wps Ib))
                  #(VEX (cmpss Vss Wss Ib)
                        (vcmpss Vss Bss Wss Ib)
                        #f)
                  #(VEX (cmppd Vpd Wpd Ib)
                        (vcmppd Vpd Bpd Wpd Ib))
                  #(VEX (cmpsd Vsd Wsd Ib)
                        (vcmpsd Vsd Bsd Wsd Ib)
                        #f))
         (movnti Md/q Gd/q)
         #(Prefix (pinsrw Pq Ew Ib) #f
                  #(VEX (pinsrw Vdq Rd/Mw Ib) (vpinsrw Vdq Bdq Rd/Mw Ib) #f) #f)
         #(Prefix (pextrw Gd Nq Ib) #f
                  #(VEX (pextrw Gd Udq Ib) (vpextrw Gd Udq Ib) #f) #f)
         #(Prefix #(VEX (shufps Vps Wps Ib) (vshufps Vps Bps Wps Ib)) #f
                  #(VEX (shufpd Vpd Wpd Ib) (vshufpd Vpd Bpd Wpd Ib)) #f)
         #(Group "Group 9"
                 #(#f #(Datasize #f
                                 (cmpxchg8b Mq)
                                 (cmpxchg16b Mdq))
                      #f #f #f #f
                      #(Prefix (vmptrld Mq) (vmxon Mq) (vmclear Mq) #f)
                      (vmptrst Mq))
                 #(#f #f #f #f #f #f #f #f))
         ;; 0F C8
         (bswap *rAX/r8)
         (bswap *rCX/r9)
         (bswap *rDX/r10)
         (bswap *rBX/r11)
         (bswap *rSP/r12)
         (bswap *rBP/r13)
         (bswap *rSI/r14)
         (bswap *rDI/r15)
         ;; 0F D0
         #(Prefix #f #f
                  #(VEX (addsubpd Vpd Wpd)
                        (vaddsubpd Vpd Bpd Wpd))
                  #(VEX (addsubps Vps Wps)
                        (vaddsubps Vps Bps Wps)))
         #(Prefix (psrlw Pq Qq) #f #(VEX (psrlw Vdq Wdq) (vpsrlw Vdq Bdq Wdq) #f) #f)
         #(Prefix (psrld Pq Qq) #f #(VEX (psrld Vdq Wdq) (vpsrld Vdq Bdq Wdq) #f) #f)
         #(Prefix (psrlq Pq Qq) #f #(VEX (psrlq Vdq Wdq) (vpsrlq Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddq Pq Qq) #f #(VEX (paddq Vdq Wdq) (vpaddq Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmullw Pq Qq) #f #(VEX (pmullw Vdq Wdq) (vpmullw Vdq Bdq Wdq) #f) #f)
         #(Prefix #f
                  (movq2dq Vdq Nq)
                  #(VEX (movq Wq Vq) (vmovq Wq Vq) #f)
                  (movdq2q Pq Nq))
         #(Prefix (pmovmskb Gd Nq) #f #(VEX (pmovmskb Gd Udq) (vpmovmskb Gd Udq) #f) #f)
         ;; 0F D8 (also SMINT)
         #(Prefix (psubusb Pq Qq) #f #(VEX (psubusb Vdq Wdq) (vpsubusb Vdq Bdq Wdq) #f) #f)
         #(Prefix (psubusw Pq Qq) #f #(VEX (psubusw Vdq Wdq) (vpsubusw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pminub Pq Qq) #f #(VEX (pminub Vdq Wdq) (vpminub Vdq Bdq Wdq) #f) #f)
         #(Prefix (pand Pq Qq) #f #(VEX (pand Vdq Wdq) (vpand Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddusb Pq Qq) #f #(VEX (paddusb Vdq Wdq) (vpaddusb Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddusw Pq Qq) #f #(VEX (paddusw Vdq Wdq) (vpaddusw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmaxub Pq Qq) #f #(VEX (pmaxub Vdq Wdq) (vpmaxub Vdq Bdq Wdq) #f) #f)
         #(Prefix (pandn Pq Qq) #f #(VEX (pandn Vdq Wdq) (vpandn Vdq Bdq Wdq) #f) #f)
         ;; 0F E0
         #(Prefix (pavgb Pq Qq) #f #(VEX (pavgb Vdq Wdq) (vpavgb Vdq Bdq Wdq) #f) #f)
         #(Prefix (psraw Pq Qq) #f #(VEX (psraw Vdq Wdq) (vpsraw Vdq Bdq Wdq) #f) #f)
         #(Prefix (psrad Pq Qq) #f #(VEX (psrad Vdq Wdq) (vpsrad Vdq Bdq Wdq) #f) #f)
         #(Prefix (pavgw Pq Qq) #f #(VEX (pavgw Wdq Wdq) (vpavgw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmulhuw Pq Qq) #f #(VEX (pmulhuw Vdq Wdq) (vpmulhuw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmulhw Pq Qq) #f #(VEX (pmulhw Vdq Wdq) (vpmulhw Vdq Bdq Wdq) #f) #f)
         #(Prefix #f
                  #(VEX (cvtdq2pd Vpd Wq) (vcvtdq2pd Vpd Wq/128))
                  #(VEX (cvttpd2dq Vq Wpd) (vcvttpd2dq Vq/128 Wpd))
                  #(VEX (cvtpd2dq Vq Wpd) (vcvtpd2dq Vq/128 Wpd)))
         #(Prefix (movntq Mq Pq) #f
                  #(VEX (movntdq Mdq Vdq) (vmovntdq Mdq Vdq) #f) #f)
         ;; 0F E8
         #(Prefix (psubsb Pq Qq) #f #(VEX (psubsb Vdq Wdq) (vpsubsb Vdq Bdq Wdq) #f) #f)
         #(Prefix (psubsw Pq Qq) #f #(VEX (psubsw Vdq Wdq) (vpsubsw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pminsw Pq Qq) #f #(VEX (pminsw Vdq Wdq) (vpminsw Vdq Bdq Wdq) #f) #f)
         #(Prefix (por Pq Qq) #f #(VEX (por Vdq Wdq) (vpor Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddsb Pq Qq) #f #(VEX (paddsb Vdq Wdq) (vpaddsb Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddsw Pq Qq) #f #(VEX (paddsw Vdq Wdq) (vpaddsw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmaxsw Pq Qq) #f #(VEX (pmaxsw Vdq Wdq) (vpmaxsw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pxor Pq Qq) #f #(VEX (pxor Vdq Wdq) (vpxor Vdq Bdq Wdq) #f) #f)
         ;; 0F F0
         #(Prefix #f #f #f #(VEX (lddqu Vpd Mdq) (vlddqu Vpd Mdq)))
         #(Prefix (psllw Pq Qq) #f #(VEX (psllw Vdq Wdq) (vpsllw Vdq Bdq Wdq) #f) #f)
         #(Prefix (pslld Pq Qq) #f #(VEX (pslld Vdq Wdq) (vpslld Vdq Bdq Wdq) #f) #f)
         #(Prefix (psllq Pq Qq) #f #(VEX (psllq Vdq Wdq) (vpsllq Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmuludq Pq Qq) #f #(VEX (pmuludq Vdq Wdq) (vpmuludq Vdq Bdq Wdq) #f) #f)
         #(Prefix (pmaddwd Pq Qq) #f #(VEX (pmaddwd Vdq Wdq) (vpmaddwd Vdq Bdq Wdq) #f) #f)
         #(Prefix (psadbw Pq Qq) #f #(VEX (psadbw Vdq Wdq) (vpsadbw Vdq Bdq Wdq) #f) #f)
         #(Prefix (maskmovq Pq Nq) #f
                  #(VEX (maskmovdqu Vdq Udq)
                        (vmaskmovdqu Vdq Udq)
                        #f)
                  #f)
         ;; 0F F8
         #(Prefix (psubb Pq Qq) #f #(VEX (psubb Vdq Wdq) (vpsubb Vdq Bdq Wdq) #f) #f)
         #(Prefix (psubw Pq Qq) #f #(VEX (psubw Vdq Wdq) (vpsubw Vdq Bdq Wdq) #f) #f)
         #(Prefix (psubd Pq Qq) #f #(VEX (psubd Vdq Wdq) (vpsubd Vdq Bdq Wdq) #f) #f)
         #(Prefix (psubq Pq Qq) #f #(VEX (psubq Vdq Wdq) (vpsubq Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddb Pq Qq) #f #(VEX (paddb Vdq Wdq) (vpaddb Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddw Pq Qq) #f #(VEX (paddw Vdq Wdq) (vpaddw Vdq Bdq Wdq) #f) #f)
         #(Prefix (paddd Pq Qq) #f #(VEX (paddd Vdq Wdq) (vpaddd Vdq Bdq Wdq) #f) #f)
         #f)
       ;; end of two-byte opcode table

       ;; 10
       (adc Eb Gb)
       (adc Ev Gv)
       (adc Gb Eb)
       (adc Gv Ev)
       (adc *AL Ib)
       (adc *rAX Iz)
       #(Mode (push *SS) #f)
       #(Mode (pop *SS) #f)
       ;; 18
       (sbb Eb Gb)
       (sbb Ev Gv)
       (sbb Gb Eb)
       (sbb Gv Ev)
       (sbb *AL Ib)
       (sbb *rAX Iz)
       #(Mode (push *DS) #f)
       #(Mode (pop *DS) #f)
       ;; 20
       (and Eb Gb)
       (and Ev Gv)
       (and Gb Eb)
       (and Gv Ev)
       (and *AL Ib)
       (and *rAX Iz)
       (*prefix* es)
       #(Mode (daa) #f)
       ;; 28
       (sub Eb Gb)
       (sub Ev Gv)
       (sub Gb Eb)
       (sub Gv Ev)
       (sub *AL Ib)
       (sub *rAX Iz)
       (*prefix* cs)
       #(Mode (das) #f)
       ;; 30
       (xor Eb Gb)
       (xor Ev Gv)
       (xor Gb Eb)
       (xor Gv Ev)
       (xor *AL Ib)
       (xor *rAX Iz)
       (*prefix* ss)
       #(Mode (aaa) #f)
       ;; 38
       (cmp Eb Gb)
       (cmp Ev Gv)
       (cmp Gb Eb)
       (cmp Gv Ev)
       (cmp *AL Ib)
       (cmp *rAX Iz)
       (*prefix* ds)
       #(Mode (aas) #f)
       ;; 40
       #(Mode (inc *eAX) (*prefix* rex))
       #(Mode (inc *eCX) (*prefix* rex rex.b))
       #(Mode (inc *eDX) (*prefix* rex rex.x))
       #(Mode (inc *eBX) (*prefix* rex rex.x rex.b))
       #(Mode (inc *eSP) (*prefix* rex rex.r))
       #(Mode (inc *eBP) (*prefix* rex rex.r rex.b))
       #(Mode (inc *eSI) (*prefix* rex rex.r rex.x))
       #(Mode (inc *eDI) (*prefix* rex rex.r rex.x rex.b))
       ;; 48
       #(Mode (dec *eAX) (*prefix* rex rex.w))
       #(Mode (dec *eCX) (*prefix* rex rex.w rex.b))
       #(Mode (dec *eDX) (*prefix* rex rex.w rex.x))
       #(Mode (dec *eBX) (*prefix* rex rex.w rex.x rex.b))
       #(Mode (dec *eSP) (*prefix* rex rex.w rex.r))
       #(Mode (dec *eBP) (*prefix* rex rex.w rex.r rex.b))
       #(Mode (dec *eSI) (*prefix* rex rex.w rex.r rex.x))
       #(Mode (dec *eDI) (*prefix* rex rex.w rex.r rex.x rex.b))
       ;; 50
       (push *rAX/r8)
       (push *rCX/r9)
       (push *rDX/r10)
       (push *rBX/r11)
       (push *rSP/r12)
       (push *rBP/r13)
       (push *rSI/r14)
       (push *rDI/r15)
       ;; 58
       (pop *rAX/r8)
       (pop *rCX/r9)
       (pop *rDX/r10)
       (pop *rBX/r11)
       (pop *rSP/r12)
       (pop *rBP/r13)
       (pop *rSI/r14)
       (pop *rDI/r15)
       ;; 60
       #(Mode #(Datasize (pushaw)
                         (pushad)
                         #f)
              #f)
       #(Mode #(Datasize (popaw)
                         (popad)
                         #f)
              #f)
       #(Mode (bound Gv Ma)
              #f)
       #(Mode (arpl Ew Gw)
              (movsxd Gv Ed))
       (*prefix* fs)
       (*prefix* gs)
       (*prefix* operand)
       (*prefix* address)
       ;; 68
       #(Mode (push Iz)
              (push Iz-f64))
       (imul Gv Ev Iz)
       (push Ib)
       (imul Gv Ev Ib)
       (ins Yb *DX)
       (ins Yz *DX)
       (outs *DX Xb)
       (outs *DX Xz)
       ;; 70
       (jo Jb)
       (jno Jb)
       (jb Jb)
       (jnb Jb)
       (jz Jb)
       (jnz Jb)
       (jbe Jb)
       (jnbe Jb)
       ;; 78
       (js Jb)
       (jns Jb)
       (jp Jb)
       (jnp Jb)
       (jl Jb)
       (jnl Jb)
       (jle Jb)
       (jnle Jb)
       ;; 80
       #(Group "Group 1"
               #((add Eb Ib) (or Eb Ib) (adc Eb Ib) (sbb Eb Ib)
                 (and Eb Ib) (sub Eb Ib) (xor Eb Ib) (cmp Eb Ib)))
       #(Group "Group 1"
               #((add Ev Iz) (or Ev Iz) (adc Ev Iz) (sbb Ev Iz)
                 (and Ev Iz) (sub Ev Iz) (xor Ev Iz) (cmp Ev Iz)))
       #(Mode #(Group "Redundant Group 1"
                      #((add Eb Ib) (or Eb Ib) (adc Eb Ib) (sbb Eb Ib)
                        (and Eb Ib) (sub Eb Ib) (xor Eb Ib) (cmp Eb Ib)))
              #f)
       #(Group "Group 1"
               #((add Ev IbS) (or Ev IbS) (adc Ev IbS) (sbb Ev IbS)
                 (and Ev IbS) (sub Ev IbS) (xor Ev IbS) (cmp Ev IbS)))
       (test Eb Gb)
       (test Ev Gv)
       (xchg Eb Gb)
       (xchg Ev Gv)
       ;; 88
       (mov Eb Gb)
       (mov Ev Gv)
       (mov Gb Eb)
       (mov Gv Ev)
       (mov Ev Sw)
       (lea Gv M)
       (mov Sw Ew)
       #(Group "Group 1A"
               #(#(Mode (pop Ev) (pop Eq/w))
                 #f #f #f #f #f #f #f))
       ;; 90
       (*nop*)
       (xchg *rCX/r9 *rAX)
       (xchg *rDX/r10 *rAX)
       (xchg *rBX/r11 *rAX)
       (xchg *rSP/r12 *rAX)
       (xchg *rBP/r13 *rAX)
       (xchg *rSI/r14 *rAX)
       (xchg *rDI/r15 *rAX)
       ;; 98
       #(Datasize (cbw) (cwde) (cdqe))
       #(Datasize (cwd) (cdq) (cqo))
       #(Mode (callf Ap) #f)
       (fwait)
       #(Mode #(Datasize (pushfw)
                         (pushfd)
                         #f)
              #(Datasize (pushfw)
                         (pushfq)
                         (pushfq)))
       #(Mode #(Datasize (popfw)
                         (popfd)
                         #f)
              #(Datasize (popfw)
                         (popfq)
                         (popfq)))
       (sahf)
       (lahf)
       ;; A0
       (mov *AL Ob)
       (mov *rAX Ov)
       (mov Ob *AL)
       (mov Ov *rAX)
       (movs Yb Xb)
       (movs Yv Xv)
       (cmps Xb Yb)
       (cmps Xv Yv)
       ;; A8
       (test *AL Ib)
       (test *rAX Iz)
       (stos Yb *AL)
       (stos Yv *rAX)
       (lods *AL Xb)
       (lods *rAX Xv)
       (scas *AL Yb)
       (scas *rAX Yv)
       ;; B0
       (mov *AL/R8L Ib)
       (mov *CL/R9L Ib)
       (mov *DL/R10L Ib)
       (mov *BL/R11L Ib)
       (mov *AH/R12L Ib)
       (mov *CH/R13L Ib)
       (mov *DH/R14L Ib)
       (mov *BH/R15L Ib)
       ;; B8
       (mov *rAX/r8 Iv)
       (mov *rCX/r9 Iv)
       (mov *rDX/r10 Iv)
       (mov *rBX/r11 Iv)
       (mov *rSP/r12 Iv)
       (mov *rBP/r13 Iv)
       (mov *rSI/r14 Iv)
       (mov *rDI/r15 Iv)
       ;; C0
       #(Group "Shift Group 2"
               #((rol Eb Ib) (ror Eb Ib) (rcl Eb Ib)
                 (rcr Eb Ib) (shl Eb Ib) (shr Eb Ib) #f (sar Eb Ib)))
       #(Group "Shift Group 2"
               #((rol Ev Ib) (ror Ev Ib) (rcl Ev Ib)
                 (rcr Ev Ib) (shl Ev Ib) (shr Ev Ib) #f (sar Ev Ib)))
       (ret Iw)
       (ret)
       #(Mode (les Gz Mp) #f)           ;Three byte VEX prefix
       #(Mode (lds Gz Mp) #f)           ;Two byte VEX prefix
       #(Group "Group 11"
               #((mov Eb Ib) #f #f #f #f #f #f #f))
       #(Group "Group 11"
               #((mov Ev Iz) #f #f #f #f #f #f #f))
       ;; C8
       (enter Iw Ib)
       (leave)
       (retf Iw)
       (retf)
       (int3)
       (int Ib)
       #(Mode (into) #f)
       #(Datasize (iretw)
                  (iretd)
                  (iretq))
       ;; D0
       #(Group "Shift Group 2"
               #((rol Eb *unity) (ror Eb *unity) (rcl Eb *unity) (rcr Eb *unity)
                 (shl Eb *unity) (shr Eb *unity) #f (sar Eb *unity)))
       #(Group "Shift Group 2"
               #((rol Ev *unity) (ror Ev *unity) (rcl Ev *unity) (rcr Ev *unity)
                 (shl Ev *unity) (shr Ev *unity) #f (sar Ev *unity)))
       #(Group "Shift Group 2"
               #((rol Eb *CL) (ror Eb *CL) (rcl Eb *CL)
                 (rcr Eb *CL) (shl Eb *CL) (shr Eb *CL) #f (sar Eb *CL)))
       #(Group "Shift Group 2"
               #((rol Ev *CL) (ror Ev *CL) (rcl Ev *CL)
                 (rcr Ev *CL) (shl Ev *CL) (shr Ev *CL) #f (sar Ev *CL)))
       #(Mode (aam Ib) #f)
       #(Mode (aad Ib) #f)
       #(Mode (salc) #f)
       (xlatb)
       ;; D8: x87 escape
       #(Group "x87 D8"
               #((fadd Md)
                 (fmul Md)
                 (fcom Md)
                 (fcomp Md)
                 (fsub Md)
                 (fsubr Md)
                 (fdiv Md)
                 (fdivr Md))
               #((fadd *st0 *st)
                 (fmul *st0 *st)
                 (fcom *st0 *st)
                 (fcomp *st0 *st)
                 (fsub *st0 *st)
                 (fsubr *st0 *st)
                 (fdiv *st0 *st)
                 (fdivr *st0 *st)))
       #(Group "x87 D9"
               #((fld Md)
                 #f
                 (fst Md)
                 (fstp Md)
                 (fldenv M)
                 (fldcw Mw)
                 (fnstenv M)
                 (fnstcw Mw))
               #((fld *st0 *st)
                 (fxch *st0 *st)
                 #((fnop) #f #f #f #f #f #f #f)
                 #f
                 #((fchs) (fabs) #f #f (ftst) (fxam) #f #f)
                 #((fld1) (fldl2t) (fldl2e) (fldpi) (fldlg2) (fldln2) (fldz) #f)
                 #((f2xm1) (fyl2x) (fptan) (fpatan) (fxtract) (fprem1) (fdecstp) (fincstp))
                 #((fprem) (fyl2xp1) (fsqrt) (fsincos) (frndint) (fscale) (fsin) (fcos))))
       #(Group "x87 DA"
               #((fiadd Md)
                 (fimul Md)
                 (ficom Md)
                 (ficomp Md)
                 (fisub Md)
                 (fisubr Md)
                 (fidiv Md)
                 (fidivr Md))
               #((fcmovb *st0 *st)
                 (fcmove *st0 *st)
                 (fcmovbe *st0 *st)
                 (fcmovu *st0 *st)
                 #f
                 #(#f (fucompp) #f #f #f #f #f #f)
                 #f
                 #f))
       #(Group "x87 DB"
               #((fild Md)
                 (fisttp Md)
                 (fist Md)
                 (fistp Md)
                 #f
                 (fld Mem80)
                 #f
                 (fstp Mem80))
               #((fcmovnb *st0 *st)
                 (fcmovne *st0 *st)
                 (fcmovnbe *st0 *st)
                 (fcmovnu *st0 *st)
                 #(#f #f (fnclex) (fninit) #f #f #f #f)
                 (fucomi *st0 *st)
                 (fcomi *st0 *st)
                 #f))
       #(Group "x87 DC"
               #((fadd Mq)
                 (fmul Mq)
                 (fcom Mq)
                 (fcomp Mq)
                 (fsub Mq)
                 (fsubr Mq)
                 (fdiv Mq)
                 (fdivr Mq))
               #((fadd *st *st0)
                 (fmul *st *st0)
                 #f
                 #f
                 (fsub *st *st0)
                 (fsubr *st *st0)
                 (fdivr *st *st0)
                 (fdiv *st *st0)))
       #(Group "x87 DD"
               #((fld Mq)
                 (fisttp Mq)
                 (fst Mq)
                 (fstp Mq)
                 (frstor M)
                 #f
                 (fnsave M)
                 (fnstsw Mw))
               #((ffree *st)
                 #f
                 (fst *st)
                 (fstp *st)
                 (fucom *st *st0)
                 (fucomp *st)
                 #f
                 #f))
       #(Group "x87 DE"
               #((fiadd Mw)
                 (fimul Mw)
                 (ficom Mw)
                 (ficomp Mw)
                 (fisub Mw)
                 (fisubr Mw)
                 (fidiv Mw)
                 (fdivr Mw))
               #((faddp *st *st0)
                 (fmulp *st *st0)
                 #f
                 #(#f (fcompp) #f #f #f #f #f #f)
                 (fsubrp *st *st0)
                 (fsubp *st *st0)
                 (fdivrp *st *st0)
                 (fdivp *st *st0)))
       #(Group "x87 DF"
               #((fild Mw)
                 (fisttp Mw)
                 (fist Mw)
                 (fistp Mw)
                 (fbld Mem80)
                 (fild Mq)
                 (fbstp Mem80)
                 (fistp Mq))
               #(#f
                 #f
                 #f
                 #f
                 #((fnstsw AX) #f #f #f #f #f #f #f)
                 (fucomip *st0 *st)
                 (fcomip *st0 *st)
                 #f))
       ;; E0
       (loopnz Jb)
       (loopz Jb)
       (loop Jb)
       #(Mode #(Addrsize (jcxz Jb)
                         (jecxz Jb)
                         #f)
              #(Addrsize #f
                         (jecxz Jb)
                         (jrcxz Jb)))
       (in *AL Ib)
       (in *eAX Ib)
       (out Ib *AL)
       (out Ib *eAX)
       ;; E8
       (call Jz)
       (jmp Jz)
       #(Mode (jmpf Ap) #f)
       (jmp Jb)
       (in *AL *DX)
       (in *eAX *DX)
       (out *DX *AL)
       (out *DX *eAX)
       ;; F0
       (*prefix* lock)
       (icebp)
       (*prefix* repnz)
       (*prefix* repz)
       (hlt)
       (cmc)
       #(Group "Unary Group 3"
               #((test Eb Ib) (test Eb Ib) (not Eb) (neg Eb)
                 (mul Eb) (imul Eb) (div Eb) (idiv Eb)))
       #(Group "Unary Group 3"
               #((test Ev Iz) (test Ev Iz) (not Ev) (neg Ev)
                 (mul Ev) (imul Ev) (div Ev) (idiv Ev)))
       ;; F8
       (clc) (stc)
       (cli) (sti)
       (cld) (std)
       #(Group "Group 4"
               #((inc Eb) (dec Eb) #f #f #f #f #f #f))
       #(Group "Group 5"
               #((inc Ev)
                 (dec Ev)
                 #(Mode (call Ev)
                        (call Eq/w))
                 (callf Mp)
                 #(Mode (jmp Ev)
                        (jmp Eq/w))
                 (jmpf Mp)
                 #(Mode (push Ev)
                        (push Eq/w))
                 #f)))))
