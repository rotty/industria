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

;; Routines for reading the Executable and Linkable Format (ELF)

;; Work in progress!

;; http://www.caldera.com/developers/gabi/

(library (weinholt binfmt elf (0 0 20090823))
  (export is-elf-image?
          open-elf-image-file
          elf-input-file-port
          elf-input-file-word-size
          elf-input-file-endianness
          elf-input-file-os-abi
          elf-input-file-abi-version
          elf-input-file-type
          elf-input-file-machine
          elf-input-file-entry
          elf-input-file-phoff
          elf-input-file-shoff
          elf-input-file-flags
          elf-input-file-ehsize
          elf-input-file-phentsize
          elf-input-file-phnum
          elf-input-file-shentsize
          elf-input-file-shnum
          elf-input-file-shstrndx

          EM-NONE EM-M32 EM-SPARC EM-386 EM-68K EM-88K EM-860
          EM-MIPS EM-MIPS-RS3-LE EM-PARISC EM-SPARC32PLUS EM-PPC
          EM-PPC64 EM-S390 EM-ARM EM-SPARCV9 EM-IA-64 EM-X86-64
          EM-names

          elf-section-header-name
          elf-section-header-type
          elf-section-header-flags
          elf-section-header-addr
          elf-section-header-offset
          elf-section-header-size
          elf-section-header-link
          elf-section-header-info
          elf-section-header-addralign
          elf-section-header-entsize

          elf-input-file-section-by-name)
  (import (rnrs)
          (weinholt struct pack (1 (>= 0))))

;;; Utilities

  (define elf-magic #x7f454c46)

  (define (print . x) (for-each display x) (newline))

  (define (file f)
    (if (input-port? f) f (open-file-input-port f)))

  (define (asciiz->string bv offset)
    (let lp ((l '()) (offset offset))
      (let ((byte (bytevector-u8-ref bv offset)))
        (if (zero? byte)
            (list->string (reverse (map integer->char l)))
            (lp (cons byte l) (+ offset 1))))))

  (define (read-unpack p fmt)
    (unpack fmt (get-bytevector-n p (format-size fmt))))

;;;

  (define (is-elf-image? f)
    "Takes a filename or a binary input port and returns #t if the
file looks like an ELF image."
    (let* ((f (file f))
           (pos (port-position f)))
      (set-port-position! f 0)
      (let ((bv (get-bytevector-n f 16)))
        (set-port-position! f pos)
        (and (bytevector? bv)
             (= (bytevector-length bv) 16)
             (call-with-values (lambda () (unpack "!LCCC9x" bv))
               (lambda (magic word-size endian version)
                 (and (= magic elf-magic)
                      (<= 1 word-size 2)
                      (<= 1 endian 2)
                      (= version 1))))))))

  (define ET-NONE 0)
  (define ET-REL 1)
  (define ET-EXEC 2)
  (define ET-DYN 3)
  (define ET-CORE 4)
  (define ET-LOOS #xfe00)
  (define ET-HIOS #xfeff)
  (define ET-LOPROC #xff00)
  (define ET-HIPROC #xffff)

  ;; There's a gigantic list of architectures that is missing here
  (define EM-NONE 0)
  (define EM-M32 1)
  (define EM-SPARC 2)
  (define EM-386 3)
  (define EM-68K 4)
  (define EM-88K 5)
  (define EM-860 7)
  (define EM-MIPS 8)
  (define EM-MIPS-RS3-LE 10)
  (define EM-PARISC 15)
  (define EM-SPARC32PLUS 18)
  (define EM-PPC 20)
  (define EM-PPC64 21)
  (define EM-S390 22)
  (define EM-ARM 40)
  (define EM-SPARCV9 43)
  (define EM-IA-64 50)
  (define EM-X86-64 62)

  (define EM-names
    (list (cons EM-NONE "No machine")
          (cons EM-M32 "AT&T WE32100")
          (cons EM-SPARC "SPARC")
          (cons EM-386 "Intel 80386")
          (cons EM-68K "Motorola 68000")
          (cons EM-88K "Motorola 88000")
          (cons EM-860 "Intel 80860")
          (cons EM-MIPS "MIPS I Architecture")
          (cons EM-MIPS-RS3-LE "MIPS RS3000 Little-endian")
          (cons EM-PARISC "Hewlett-Packard PA-RISC")
          (cons EM-SPARC32PLUS "Enhanced instruction set SPARC")
          (cons EM-PPC "PowerPC")
          (cons EM-PPC64 "64-bit PowerPC")
          (cons EM-S390 "IBM System/390 Processor")
          (cons EM-ARM "Advanced RISC Machines ARM")
          (cons EM-SPARCV9 "SPARC V9")
          (cons EM-IA-64 "Intel IA-64 Processor Architecture")
          (cons EM-X86-64 "AMD x86-64 architecture")))

  (define ELFOSABI-NONE 0)
  (define ELFOSABI-SYSV 0)
  (define ELFOSABI-HPUX 1)
  (define ELFOSABI-NETBSD 2)
  (define ELFOSABI-SOLARIS 6)
  (define ELFOSABI-AIX 7)
  (define ELFOSABI-IRIX 8)
  (define ELFOSABI-FREEBSD 9)
  (define ELFOSABI-TRU64 10)
  (define ELFOSABI-MODESTO 11)
  (define ELFOSABI-OPENBSD 12)
  (define ELFOSABI-OPENVMS 13)
  (define ELFOSABI-NSK 14)
  (define ELFOSABI-AROS 15)

  (define ELFOSABI-names
    (list (cons ELFOSABI-NONE "UNIX System V ABI")
          (cons ELFOSABI-HPUX "Hewlett-Packard HP-UX")
          (cons ELFOSABI-NETBSD "NetBSD")
          (cons ELFOSABI-SOLARIS "Sun Solaris")
          (cons ELFOSABI-AIX "AIX")
          (cons ELFOSABI-IRIX "IRIX")
          (cons ELFOSABI-FREEBSD "FreeBSD")
          (cons ELFOSABI-TRU64 "Compaq TRU64 UNIX")
          (cons ELFOSABI-MODESTO "Novell Modesto")
          (cons ELFOSABI-OPENBSD "Open BSD")
          (cons ELFOSABI-OPENVMS "Open VMS")
          (cons ELFOSABI-NSK "Hewlett-Packard Non-Stop Kernel")
          (cons ELFOSABI-AROS "Amiga Research OS")))

  (define SHT-NULL 0)
  (define SHT-PROGBITS 1)
  (define SHT-SYMTAB 2)
  (define SHT-STRTAB 3)
  ;; ...

  ;; Special section indexes
  (define SHN-UNDEF 0)
  ;; ...

  (define-record-type elf-input-file
    (fields port word-size endianness os-abi abi-version
            type machine ehsize
            entry flags shstrndx
            phoff phentsize phnum
            shoff shentsize shnum))

  (define (open-elf-image-file fn)
    (let ((port (file fn)))
      (unless (is-elf-image? port)
        (error 'open-file-image-file "Not an ELF image" fn))
      (set-port-position! port 0)
      (call-with-values (lambda () (read-unpack port "4xCCxCC7x"))
        (lambda (word-size endianness os-abi abi-version)
          (call-with-values
              (lambda ()
                (read-unpack port
                             (if (= word-size 1)
                                 (if (= endianness 1)
                                     "<SSLLLLLSSSSSS" ">SSLLLLLSSSSSS")
                                 (if (= endianness 1)
                                     "<SSLQQQLSSSSSS" ">SSLQQQLSSSSSS"))))
            (lambda (type machine version entry phoff shoff flags
                          ehsize phentsize phnum shentsize shnum shstrndx)
              (make-elf-input-file
               port word-size endianness os-abi abi-version
               type machine ehsize
               entry flags shstrndx
               phoff phentsize phnum
               shoff shentsize shnum)))))))

  (define-record-type elf-section-header
    (fields name type flags addr offset size link info addralign entsize))

  (define (elf-input-file-section-header image index)
    (unless (or (< index 0) (< index (elf-input-file-shnum image)))
      (error 'elf-input-file-section-header "Index out of bounds" index))
    (let ((port (elf-input-file-port image)))
      (set-port-position! port (+ (elf-input-file-shoff image)
                                  (* (elf-input-file-shentsize image) index)))
      (call-with-values (lambda ()
                          (let ((bv (get-bytevector-n port
                                                      (elf-input-file-shentsize image))))
                            (if (= (elf-input-file-word-size image) 1)
                                (if (= (elf-input-file-endianness image) 1)
                                    (unpack "<10L" bv)
                                    (unpack ">10L" bv))
                                (if (= (elf-input-file-endianness image) 1)
                                    (unpack "<LL4QLLQQ" bv)
                                    (unpack ">LL4QLLQQ" bv)))))
        make-elf-section-header)))

  (define-record-type elf-program-header
    (fields type flags offset vaddr paddr filesz memsz align))

  (define (elf-input-file-program-header image index)
    (unless (or (< index 0) (< index (elf-input-file-phnum image)))
      (error 'elf-input-file-program-header "Index out of bounds" index))
    (let ((port (elf-input-file-port image)))
      (set-port-position! port (+ (elf-input-file-phoff image)
                                  (* (elf-input-file-phentsize image) index)))
      (call-with-values (lambda ()
                          (let ((bv (get-bytevector-n port
                                                      (elf-input-file-phentsize image))))
                            (if (= (elf-input-file-word-size image) 1)
                                (if (= (elf-input-file-endianness image) 1)
                                    (unpack "<8L" bv)
                                    (unpack ">8L" bv))
                                (if (= (elf-input-file-endianness image) 1)
                                    (unpack "<2L6Q" bv)
                                    (unpack ">2L6Q" bv)))))
        make-elf-program-header)))

  (define (elf-input-file-read-section image sh)
    ;; XXX: missing sanity checks
    (let ((port (elf-input-file-port image)))
      (set-port-position! port (elf-section-header-offset sh))
      (get-bytevector-n port (elf-section-header-size sh))))

  (define (elf-input-file-section-names image)
    ;; FIXME: check for special section indexes and everything else
    ;; required for shstrndx...
    (let ((i (elf-input-file-shstrndx image)))
      (and (not (= SHN-UNDEF i))
           (let ((shstrtab (elf-input-file-section-header image i))
                 (port (elf-input-file-port image)))
             (unless (= (elf-section-header-type shstrtab) SHT-STRTAB)
               (error 'elf-input-file-section-name
                      "Corrupt ELF: shstrtab not a string table" shstrtab))
             (set-port-position! port (elf-section-header-offset shstrtab))
             (get-bytevector-n port (elf-section-header-size shstrtab))))))

  (define (elf-input-file-section-by-name image name)
    (let ((section-names (elf-input-file-section-names image)))
      (let lp ((i 0))
        (if (= i (elf-input-file-shnum image))
            #f
            (let ((sh (elf-input-file-section-header image i)))
              (if (string=? name (asciiz->string section-names
                                                 (elf-section-header-name sh)))
                  sh
                  (lp (+ i 1))))))))

  )
