#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
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

(import (weinholt crypto x509)
        (weinholt crypto sha-1)
        (weinholt text base64)
        (srfi :19 time)
        (srfi :39 parameters)
        (srfi :78 lightweight-testing)
        (rnrs))

(define (->cert str)
  (let-values (((type bv) (get-delimited-base64
                           (open-string-input-port str))))
    (certificate-from-bytevector bv)))

;; Examples referenced in RFC 5280 at this URL:
;; <http://csrc.nist.gov/groups/ST/crypto_apps_infra/documents/pkixtools/>

(define rfc3280-cert1                   ;DSA
  (->cert "-----BEGIN CERTIFICATE-----
MIICuzCCAnugAwIBAgIBETAJBgcqhkjOOAQDMCoxCzAJBgNVBAYTAlVTMQwwCgYD
VQQKEwNnb3YxDTALBgNVBAsTBE5JU1QwHhcNOTcwNjMwMDAwMDAwWhcNOTcxMjMx
MDAwMDAwWjAqMQswCQYDVQQGEwJVUzEMMAoGA1UEChMDZ292MQ0wCwYDVQQLEwRO
SVNUMIIBuDCCASwGByqGSM44BAEwggEfAoGBALaLD5Qrms6lJcby7fz7lTKsARIz
ueAcrZCbvEhUnvOUdzwscTVV5v5PIsvV2D6JkzNN/L1PQWQ+ophw7DG0UN7r8Zgo
Csk+RLP9IpeWg9AYo+O9NVv/7qMhcmp7ltq5Px5akK8k1iDwDSGn1AK5GvysIfue
lJ5LQkWearJIY/5DAhUAsg2wsQHfDGYk/BOSulX3fVd0geUCgYEAmr9GsfU/RD3J
pWX7kcCOR/EKwwFHwkRCNqmSgd5XxeBohlgAex/5m3ehxRClgJF4UVE89vz8zEbG
gXiShD30kz0MOH4aW5lOqxRk9gwhIk4oCJySuWafQOiV9tUxKu85omLHsm2eWMQ6
qBGBhG2v+LQZtMIRrtAiO6ogf+4eVxgDgYUAAoGBALWeH0kER9Hb9TrdygR16N11
9puKsZfWWWmC0wNN/Ts2X0ry0U7BB/XRKtN4d2NW6pZhTUILeh37q5Gkzt7vd8jl
7yCupihIr75pw2qlMPLCudmCK33ZxIQf3g3oVNcbmS6z0Ij21mObp+IOgtQ7imgb
BlYxWQtJ65ml1YFBe8lVozIwMDAdBgNVHQ4EFgQUhsqlIoFi760KibytckEsKUn0
hlYwDwYDVR0TAQH/BAUwAwEB/zAJBgcqhkjOOAQDAy8AMCwCFEMbzyklRcBOUud9
1vyxZkyDzy13AhQLW5okEZjo84aQBPYIqeGNpcw61A==
-----END CERTIFICATE-----"))

(define rfc3280-cert2                   ;DSA
  (->cert "-----BEGIN CERTIFICATE-----
MIIC2jCCApmgAwIBAgIBEjAJBgcqhkjOOAQDMCoxCzAJBgNVBAYTAlVTMQwwCgYD
VQQKEwNnb3YxDTALBgNVBAsTBE5JU1QwHhcNOTcwNzMwMDAwMDAwWhcNOTcxMjAx
MDAwMDAwWjA9MQswCQYDVQQGEwJVUzEMMAoGA1UEChMDZ292MQ0wCwYDVQQLEwRO
SVNUMREwDwYDVQQDEwhUaW0gUG9sazCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQC2
iw+UK5rOpSXG8u38+5UyrAESM7ngHK2Qm7xIVJ7zlHc8LHE1Veb+TyLL1dg+iZMz
Tfy9T0FkPqKYcOwxtFDe6/GYKArJPkSz/SKXloPQGKPjvTVb/+6jIXJqe5bauT8e
WpCvJNYg8A0hp9QCuRr8rCH7npSeS0JFnmqySGP+QwIVALINsLEB3wxmJPwTkrpV
931XdIHlAoGBAJq/RrH1P0Q9yaVl+5HAjkfxCsMBR8JEQjapkoHeV8XgaIZYAHsf
+Zt3ocUQpYCReFFRPPb8/MxGxoF4koQ99JM9DDh+GluZTqsUZPYMISJOKAickrlm
n0DolfbVMSrvOaJix7JtnljEOqgRgYRtr/i0GbTCEa7QIjuqIH/uHlcYA4GEAAKB
gDC2dfd8IDGuOLt+DSuroJxL3yDVJBM8zZjlX2y3wbpKuqmVgFPwDXLcMzf0AQv1
BB+dLh9i2IQ6myUJWi3IRo4r1PUNO8ctxmy5mMElOkROjsqVYTV8zhUxXCMTHqIF
0XokHMvTcgmQ/5udKMChCuxGnw240NzQGKYrXvmPtZW+oz4wPDAZBgNVHREEEjAQ
gQ53cG9sa0BuaXN0LmdvdjAfBgNVHSMEGDAWgBSGyqUigWLvrQqJvK1yQSwpSfSG
VjAJBgcqhkjOOAQDAzAAMC0CFDaXy+O0LOG7YanTzCTMIpKf9PWHAhUAq8l5r9IW
HKnjaKkUELSgLv8iWnM=
-----END CERTIFICATE-----"))

#;
(define rfc3280-cert3                   ;RSA
  (->cert "-----BEGIN CERTIFICATE-----
MIICjjCCAfegAwIBAgICAQAwDQYJKoZIhvcNAQEFBQAwKjELMAkGA1UEBhMCVVMx
DDAKBgNVBAsTA2dvdjENMAsGA1UEChMETklTVDAeFw05NjA1MjEwOTU4MjZaFw05
NzA1MjEwOTU4MjZaMD0xCzAJBgNVBAYTAlVTMQwwCgYDVQQLEwNnb3YxDTALBgNV
BAoTBE5JU1QxETAPBgNVBAMTCFRpbSBQb2xrMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDhauQDMJcCPPQQ87UeTX8Ue/b10HjppIrwo3Xs7bZWln+ImYWa8j5o
d4frntGfwLQX3KuJI6QdfhYjTE+oTfUxuHyq4xpJCfRLJtsnZzCCEgFK6Rq2wQxT
i2z8L3pD7DM2fjKye9WqzwEUxhLsE/ItFHqLIVgUE0xGo5ryFpX/IwIDAQABo4Gv
MIGsMD8GA1UdEQQ4MDaGNGh0dHA6Ly93d3cuaXRsLm5pc3QuZ292L2Rpdjg5My9z
dGFmZi9wb2xrL2luZGV4Lmh0bWwwHwYDVR0SBBgwFoYUaHR0cDovL3d3dy5uaXN0
Lmdvdi8wHwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBqSiCELDIwFwYDVR0gBBAw
DjAMBgpghkgBZQMCATAJMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOB
gQCOjjZWeIu/oTl1Fy7jENyDK2g0Uhz2bB1SXlQgEF5MqUD5S3Kegrlh3Osypb2x
sUj5mwG766+bg/ZSjLBtfNCaOVQ+bSBvzdDevidfIE+2qw31t+G6tN/fPdT27QH7
bsuYWaxB+0icH/ZbRuAp4nbsxDoK/JLFwNKpydMpUodlMw==
-----END CERTIFICATE-----"))

(define rfc3280bis-cert1                ;RSA
  (->cert "-----BEGIN CERTIFICATE-----
MIICPjCCAaegAwIBAgIBETANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQB
GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBs
ZSBDQTAeFw0wNDA0MzAxNDI1MzRaFw0wNTA0MzAxNDI1MzRaMEMxEzARBgoJkiaJ
k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYDVQQDEwpF
eGFtcGxlIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC15dtKHCqW88j
LoBwOe7bb9Ut1WpPejQt+SJyR3Ad74DpyjCMAMSabltFtG6l5myUDfqR6UD8JZ3H
t2gZVo8RcGrX8ckRTzp+P5mNbnaldF9epFVT5cdoNlPHHTsSpoX+vW6hyt81UKwI
17m0flz+4qMs0SOEqpjAm2YYmmhH6QIDAQABo0IwQDAdBgNVHQ4EFgQUCGivhTPI
OUp6+IKTjnBqSiCELDIwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQEFBQADgYEAbPgCdKZh4mQEplQMbHITrTxH+/ZlE6mFkDPqdqMm
2fzRDhVfKLfvk7888+I+fLlS/BZuKarh9Hpv1X/vs5XK82aIg06hNUWEy7ybuMit
xV5G2QsOjYDhMyvcviuSfkpDqWrvimNhs25HOL7oDaNnXfP6kYE8krvFXyUl63zn
2KE=
-----END CERTIFICATE-----"))

(define rfc3280bis-cert2                ;RSA
  (->cert "-----BEGIN CERTIFICATE-----
MIICcTCCAdqgAwIBAgIBEjANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQB
GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBs
ZSBDQTAeFw0wNDA5MTUxMTQ4MjFaFw0wNTAzMTUxMTQ4MjFaMEMxEzARBgoJkiaJ
k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYDVQQDEwpF
bmQgRW50aXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhauQDMJcCPPQQ
87UeTX8Ue/b10HjppIrwo3Xs7bZWln+ImYWa8j5od4frntGfwLQX3KuJI6QdfhYj
TE+oTfUxuHyq4xpJCfRLJtsnZzCCEgFK6Rq2wQxTi2z8L3pD7DM2fjKye9WqzwEU
xhLsE/ItFHqLIVgUE0xGo5ryFpX/IwIDAQABo3UwczAhBgNVHREEGjAYgRZlbmQu
ZW50aXR5QGV4YW1wbGUuY29tMB0GA1UdDgQWBBQXe5Iw/0TWZuGQECJsFk/AjkHd
bTAfBgNVHSMEGDAWgBQIaK+FM8g5Snr4gpOOcGpKIIQsMjAOBgNVHQ8BAf8EBAMC
BsAwDQYJKoZIhvcNAQEFBQADgYEAACAoNFtoMgG7CjYOrXHFlRrhBM+urcdiFKQb
NjHA4gw92R7AANwQoLqFb0HLYnq3TGOBJl7SgEVeM+dwRTs5OyZKnDvyJjZpCHm7
+5ZDd0thi6GrkWTg8zdhPBqjpMmKsr9z1E3kWORi6rwgdJKGDs6EYHbpc7vHhdOR
RepiXc0=
-----END CERTIFICATE-----"))

#;
(define rfc3280bis-cert3                ;DSA
  (->bv "-----BEGIN CERTIFICATE-----
MIIDjjCCA06gAwIBAgICAQAwCQYHKoZIzjgEAzBHMRMwEQYKCZImiZPyLGQBGRYD
Y29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMORXhhbXBsZSBE
U0EgQ0EwHhcNMDQwNTAyMTY0NzM4WhcNMDUwNTAyMTY0NzM4WjBHMRMwEQYKCZIm
iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMO
RFNBIEVuZCBFbnRpdHkwggG3MIIBLAYHKoZIzjgEATCCAR8CgYEAtosPlCuazqUl
xvLt/PuVMqwBEjO54BytkJu8SFSe85R3PCxxNVXm/k8iy9XYPomTM038vU9BZD6i
mHDsMbRQ3uvxmCgKyT5Es/0il5aD0Bij4701W//uoyFyanuW2rk/HlqQryTWIPAN
IafUArka/Kwh+56UnktCRZ5qskhj/kMCFQCyDbCxAd8MZiT8E5K6Vfd9V3SB5QKB
gQCav0ax9T9EPcmlZfuRwI5H8QrDAUfCREI2qZKB3lfF4GiGWAB7H/mbd6HFEKWA
kXhRUTz2/PzMRsaBeJKEPfSTPQw4fhpbmU6rFGT2DCEiTigInJK5Zp9A6JX21TEq
7zmiYseybZ5YxDqoEYGEba/4tBm0whGu0CI7qiB/7h5XGAOBhAACgYAwtnX3fCAx
rji7fg0rq6CcS98g1SQTPM2Y5V9st8G6SrqplYBT8A1y3DM39AEL9QQfnS4fYtiE
OpslCVotyEaOK9T1DTvHLcZsuZjBJTpETo7KlWE1fM4VMVwjEx6iBdF6JBzL03IJ
kP+bnSjAoQrsRp8NuNDc0BimK175j7WVvqOByjCBxzA5BgNVHREEMjAwhi5odHRw
Oi8vd3d3LmV4YW1wbGUuY29tL3VzZXJzL0RTQWVuZGVudGl0eS5odG1sMCEGA1Ud
EgQaMBiGFmh0dHA6Ly93d3cuZXhhbXBsZS5jb20wHQYDVR0OBBYEFN0lZpZDq3gR
Q0T+lRb52ba3AmaNMB8GA1UdIwQYMBaAFIbKpSKBYu+tCom8rXJBLClJ9IZWMBcG
A1UdIAQQMA4wDAYKYIZIAWUDAgEwCTAOBgNVHQ8BAf8EBAMCB4AwCQYHKoZIzjgE
AwMvADAsAhRlVwc03dzKzF70AvRWQixe4bM7gAIUYPQxF8r0z//u9Ain2bJhvrHD
2r8=
-----END CERTIFICATE-----"))

(define cert1 rfc3280bis-cert1)

(print-certificate cert1)
(check (decipher-certificate-signature cert1 cert1)
       =>
       '(sha-1
         #vu8(40 133 68 67 27 139 209 192 46 100 229 224 59 71 75 231 162 201 27 29)))
(check (sha-1->bytevector (sha-1 (certificate-tbs-data cert1)))
       =>
       #vu8(40 133 68 67 27 139 209 192 46 100 229 224 59 71 75 231 162 201 27 29))

(check (validate-certificate-path (list cert1) "Example CA"
                                  (date->time-utc (make-date 0 0 0 0 24 12 2004 0))
                                  cert1)
       =>
       'ok)


(define cert2 rfc3280bis-cert2)

(print-certificate cert2)
(check (validate-certificate-path (list cert1 cert2) "End Entity"
                                  (date->time-utc (make-date 0 0 0 0 24 12 2004 0))
                                  cert1)
       =>
       'ok)

(check (decipher-certificate-signature cert2 cert1)
       =>
       '(sha-1
         #vu8(0 46 123 152 4 85 233 72 143 151 119 59 247 169 178 151 164 80 223 122)))

(check (sha-1->bytevector (sha-1 (certificate-tbs-data cert2)))
       =>
       #vu8(0 46 123 152 4 85 233 72 143 151 119 59 247 169 178 151 164 80 223 122))


;; Test CA-procedure parameter
(parameterize ((CA-procedure
                (lambda (issuer)
                  (write issuer)
                  (newline)
                  (cond ((assq 'commonName issuer) =>
                         (lambda (cn)
                           (if (string=? (cdr cn) "Example CA")
                               cert1
                               #f)))
                        (else #f)))))
  (check (validate-certificate-path (list cert1 cert2) "End Entity"
                                    (date->time-utc (make-date 0 0 0 0 24 12 2004 0)))
         =>
         'ok))

(check (validate-certificate-path (list cert1 cert2) "End Entity"
                                  (date->time-utc (make-date 0 0 0 0 24 12 2004 0)))
       =>
       'root-certificate-not-found)

;; Use current time, so the cert has expired
(parameterize ((CA-procedure (lambda (issuer) cert1)))
  (check (validate-certificate-path (list cert1 cert2) "End Entity")
         =>
         'expired))

;; common-name doesn't match cert1
(parameterize ((CA-procedure (lambda (issuer) cert1)))
  (check (validate-certificate-path (list cert1 cert2) "Example CA"
                                    (date->time-utc (make-date 0 0 0 0 24 12 2004 0)))
         =>
         'bad-common-name))
(parameterize ((CA-procedure (lambda (issuer) cert1)))
  (check (validate-certificate-path (list cert1 cert2) "Terrible Example"
                                    (date->time-utc (make-date 0 0 0 0 24 12 2004 0)))
         =>
         'bad-common-name))

;; cert1 doesn't have to be in the chain
(parameterize ((CA-procedure (lambda (issuer) cert1)))
  (check (validate-certificate-path (list cert2) "End Entity"
                                    (date->time-utc (make-date 0 0 0 0 24 12 2004 0)))
         =>
         'ok))

;;; DSA

(display "DSA\n")

(parameterize ((CA-procedure (lambda (issuer) rfc3280-cert1)))
  (check (validate-certificate-path (list rfc3280-cert2)
                                    "Tim Polk"
                                    (date->time-utc (make-date 0 0 0 0 29 11 1997 0)))
         =>
         'ok))

;;; keyUsage extension


(check (certificate-key-usage
        (->cert
         "-----BEGIN CERTIFICATE-----
MIIBIzCB3qADAgECAgkArDSAdtdRpl4wDQYJKoZIhvcNAQEEBQAwFjEUMBIGA1UE
AxMLZXhhbXBsZS5jb20wHhcNMTAwNjI1MDY0MTE4WhcNMTAwNzI1MDY0MTE4WjAW
MRQwEgYDVQQDEwtleGFtcGxlLmNvbTBMMA0GCSqGSIb3DQEBAQUAAzsAMDgCMQDD
yGIRTV5ThI1oHxXmevAPVcnRt662vUxOkHbYNFADgioyvil7yU2yWT03Jg64qUcC
AwEAAaMfMB0wCgYDVR0OBAMEAUIwDwYDVR0PAQH/BAUDAwf/gDANBgkqhkiG9w0B
AQQFAAMxAK5hdyrlT1xmbviZQIGloDVwh/mZiol7wRRXihWW6DbCYl5DitPIs670
hySJOXuJXw==
-----END CERTIFICATE-----"))
         =>
         '(digitalSignature
           nonRepudiation keyEncipherment dataEncipherment
           keyAgreement keyCertSign cRLSign encipherOnly
           decipherOnly))

(check (certificate-key-usage
        (->cert
         "-----BEGIN CERTIFICATE-----
MIIBIzCB3qADAgECAgkAkLoFP6AvtMgwDQYJKoZIhvcNAQEEBQAwFjEUMBIGA1UE
AxMLZXhhbXBsZS5jb20wHhcNMTAwNjI1MDY0NzUwWhcNMTAwNzI1MDY0NzUwWjAW
MRQwEgYDVQQDEwtleGFtcGxlLmNvbTBMMA0GCSqGSIb3DQEBAQUAAzsAMDgCMQDQ
JUJcfYBNyvNy0khhrXRmSJcYLGnr5II0pL5LlaV2N/RtB8TFgjSUT9DrralLbocC
AwEAAaMfMB0wCgYDVR0OBAMEAUIwDwYDVR0PAQH/BAUDAweAgDANBgkqhkiG9w0B
AQQFAAMxAIAJc333w34K5p3uL3R9hXD5CfeE+kY3oMsVVPbqxeReY3227NYQ1NOV
nC8M1SWK0A==
-----END CERTIFICATE-----"))
         =>
         '(digitalSignature decipherOnly))

(check (certificate-key-usage
        (->cert
         "-----BEGIN CERTIFICATE-----
MIIBIjCB3aADAgECAgkA6pFTW48cyOkwDQYJKoZIhvcNAQEEBQAwFjEUMBIGA1UE
AxMLZXhhbXBsZS5jb20wHhcNMTAwNjI1MDY1MzQzWhcNMTAwNzI1MDY1MzQzWjAW
MRQwEgYDVQQDEwtleGFtcGxlLmNvbTBMMA0GCSqGSIb3DQEBAQUAAzsAMDgCMQC3
GfrNQwYuUo5GLkPJzLwkBtXxFf3VlmEX5EQYwh7BdZiimCE8T6JZFCl2ZexW3UMC
AwEAAaMeMBwwCgYDVR0OBAMEAUIwDgYDVR0PAQH/BAQDAgBVMA0GCSqGSIb3DQEB
BAUAAzEApcvwEruE7glgWNJKK5xnb1NjsyrnKtl1xqcTL5KgycQkIDt41IY8qaku
dEtSKxxN
-----END CERTIFICATE-----"))
         =>
         '(nonRepudiation dataEncipherment keyCertSign encipherOnly))

(check (certificate-key-usage
        (->cert
         "-----BEGIN CERTIFICATE-----
MIIBIzCB3qADAgECAgkAh0NNxVKKxc8wDQYJKoZIhvcNAQEEBQAwFjEUMBIGA1UE
AxMLZXhhbXBsZS5jb20wHhcNMTAwNjI1MDY1NDM4WhcNMTAwNzI1MDY1NDM4WjAW
MRQwEgYDVQQDEwtleGFtcGxlLmNvbTBMMA0GCSqGSIb3DQEBAQUAAzsAMDgCMQCm
z/PKtn/TfnXEvkaeaKj7rdGKOOA4A8IJLcf1js09pUxh3lf2SCcGIZ5Cm/e9vYcC
AwEAAaMfMB0wCgYDVR0OBAMEAUIwDwYDVR0PAQH/BAUDAweqgDANBgkqhkiG9w0B
AQQFAAMxAAYJ8MJMzmyST9eOFOyf1iZwRNLZL8qqvwr8pgBmFk1E2JoTzP1Qsm88
Y192xYC07A==
-----END CERTIFICATE-----"))
         =>
         '(digitalSignature keyEncipherment keyAgreement cRLSign decipherOnly))


(check-report)

