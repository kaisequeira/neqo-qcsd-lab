"""Compare real retained code; no installed-runtime or qualification pass is mocked."""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import zlib
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_schedule as schedule


LANES = "src/qcsd_lab/rapid_lane_evidence.py"
ROLLING = "src/qcsd_lab/rapid_rolling_capture.py"
NEW_HELPER = "src/qcsd_lab/rapid_rolling_schedule.py"


# Only these exact historical control definitions/regions are overlaid. All
# protected Source and Native bytes come from the checked-in current baseline.
# This fixture is never executed, and requires no historical Git object.
SOURCE083_CONTROLS_SHA256 = "3465ef6744727a169c5ff0222faa7c99e40f19e8409501a641c9c61bf5161d48"
SOURCE083_CONTROLS_B85 = (
    "c-ri}4R_nfktq6CFrM5sVUx5Z%d$;}+11#}j9xsJSCX@Lp3K7ok)Vt<MKA;@S>w@ve_bElUEOGape!f*?zuThECP-GsIIQA@A~>+"
    "l1<a%LGSB>e~gN8XPTVD-}xfD$Y#lO2ychQr)1~Z-h<wQz1^+z7hBt-?a}DzWcTIh+1|@^_xWgB{odOf?`*vsJxxY?=g)Q~yOZam"
    "^y%*2?j)TgTa(@07o(jQdk@+V7U@Nn&v3wGwfv+8THbV)i)2>J^Tkq)5k=V~YPF(8GS9}tQ8Hhy7U?jZ=c7;2AAjh_`Q<!WX6M;d"
    "eLh^QX3OkSH;Q9ucXk$ieDJ5QZZB8qqEMsXetZ!1`|ADGp89Jrcoi)_rL&K-Nd4!>==4(>&63Nsm?xt&N~ZZNjV{y#mqj$oBO1d@"
    "y&D~;`8=IPnR=a!maAkMo#(6BSofCAmg#KSjwY+=G#X8lqKK~2(K25|$!r`g)F=uXY4i{EVK&Ls{L~jkHcr))GWGXma*?)mU#lXU"
    "UBFzUBAq9TWSLHHqRArvU5#HXSL2(g$X5%PwCWlrq_<H&KVM|yi?mDq5omBd!)!KRE&Bkl|9pM&W_Y~+{_xH4;Qi6-Uxsh@KfF`_"
    "9KL)1;k4ILprfzVCfyap4Te5Gdi(b9-Op8nPck`)&hKI#qSM>J$m!@)u3BST-b<dj+KYdzGPNO5`ei=NM%gm@loX#jxSP@WG#`DA"
    "rpan1cV7+gmw($aeScBkY`Zg*lUn5YvVfJgo~(++lk;r$WPYQ1nmvs=hf!w~J^VP!F5wtN|6SxW^P{*aKF-uOUq%Y&KTWgqh+n){"
    "KR>E=SIKmhMt%IMJI#}E(Nf=Zlf}i=+4dm*I8!T9IG2vqaZab>LN)#R@j;=UeSFXcXsC(NUxcmlZ$A7VAKa?>Od`|o&cN<(kJjpq"
    "(oM$Wmg+oB#@Q?_is7Y#<dUH9@j;B;&GKcGDXcD*$!wIia3SqzoQ;;TLSBXDOL`VZKlJ_ndm6%-IzJ~j#WKA-P&?3ach}#th(R#U"
    "CX;l5^8i37kl;XP8ZLv6Gn^^F3Z9&OPHzU$L`_Qlq0VTe#u+EeWN3k>$q*ej@!~Qcucq=r`XwE$mg<=Bv-p-r>#pXi)3jAA7cJP`"
    "mKi$ksuQpFBlhONgIy*HoN2-RkER)Hox-qWaYK*JlOi1wFmTy%gY8sgS-_=YBM0UvdYg&gx1(uR&}JsHo0iukQ+w7{q-#N|f}gM~"
    "{4(z8a~0m>d^!bcI7(oR5l*SlXE;g}>Lk;2jH5^SM7_9JO_N1ru@C!|FsD(~Nz17j%mf?oMBwl#aNxGU^VlpLmj$o8Susq`i+s9L"
    "{o$fNKInE8l~7&bd$os1mLvJaI9s%0yI2Ml00Z6@H<xOmpIa`7TJUi@dZc?*+g-%vPDY>9HKESTLN5k8ah@tzepEyRk>umYh5loU"
    "{^$X!tlJ84+`N4-q*TLSLr0yz1zv+$O4~7CD0)Na?j4wc|2BBe2HwsUia@4g+^9m&pL*fFdsuyG)ZJ>adau|EN$W3@Ij~7lXX%mq"
    ">mvH|pZ{DM2j^t&GWmwr{V6Z#M)bQo+ZqJF(-5itaC=ZOAe>}H0gApxK?Gu{i3V%1^Zyw1c2xJTqH!L&;q4%g`>jsrN+G~yTI$J;"
    "bK9$av&hZi9V^C+{sPVwU@%OU%S6$)@o=neYlYtYk9rk#I<s_noi9GCqo)|UP6x<YC!Z+}>f=W}>rSUogc(`Ve7;mI)koJIg*I1e"
    "e=ihk(CH|Q=!_TnJlcQz*7;I#&goRGDqmc5VM5*fdX_HwnyUu1s%x$2S=z@{cW~8e)O0e<E<P>2FIPpnK;Yr3v)NVtS<%7aDjNgb"
    "+=mzHq4#+@yHa1j|LydbqjztP-ktu}@!{#gPrscWygqt!(BH0U{eJ)Sm%hI<248QV6pK;tYh>%*?*F8ix}#IC1Btk|^<SSHeK>x7"
    "F#Pr4bpOr%>3$!1D8-yC(kB|mPlzIPk$bA`?C{t9pAUv_4u3v4fhi%IJ@kPk$bchm046J(_vb6{8diGSd!nX<2pjCvKO2D_6;WT@"
    "%yUJwq9+O;X`NSUDGu)lUCITlVI<|Pzgxcbk<UadQnT;URQaye)KIgZiZRIG=EU7&-hw&_y=hf&r)|sEjS>as>|)jzY)PA?sv$1X"
    "zIlp#?X*a1=8fVO0lElJnl_<&>hk^fSinY?5D2CEjf1f@*A*-ZWDzBK^UKaCS7?<_JIIAirwQ<(jsy<hRN*~e6KkdL{uVT2`HZd&"
    "A>O@K;@!dP)5D{8>d#*lVLANi@a^I0Zz$q<GFxaUbI&#C)4TV)IjigI{v|Tv%?y*@W-&gJ5FaiTzp2?t7oFTkJMc(gO<NvcJkB-j"
    "r+foEioWETJ)D;r%y~6;8COeOBSj(95m4)j8~|IPIw`Y&3Ly)1ec**25Mgm}xTS~ZH_NnW0ed@7Zs4VmO8AK*uz}d98mlYNwCrA_"
    "$f~BJG@CDn%bR(sWl(AcWDw~q-N9GSI(AJRM(qv}f(}o-bG2>ACW}8B){7K&`6?YQ^OnJb=n05s`D~J1JfTr^zeJ+cgz6dXO`yzk"
    "j8?O;;ulbvWG6zCFr1W{JYWN}*S>H%0NEP^QuBf^1;u7U7Tkg}7BX3WZb$aH;n?X_yumto8K{s`v&<D?ScsLd{4Du<GaP}n^cJq="
    "CyLBGju^uNTNQVcVmQx>>`N=QKq{SIu?+c6AL~+kA)x7VE8B$6uirwRV^7?xJkPR^_9Lgq(($g7^a!w8TREcDDsfVcF-z02L_h~1"
    "@~B&gWy>s?x`*DGns@jG==j_4sRn#49p<{r?`p@K<2x??Q(}?RS-4OY#wBD)fjse2JW?jn#I%OPd6kXRnU#8Bt@fPxZ-Yoeq}KUP"
    "o?A!J)uzU3g>n+!aqfarqVQ4DE&!BOxFz#xqKFD@7U&he4d&|qXCRY-qT2!#w3ds@bet(3j@8}{=t<=Rs>wRAiVsMsFiqt-N=wA9"
    "20W!@N~II@yiT=PrCIb9ivhi2Tr;%MF`79v*D;n=j6n^f9+%ZOYCw57bPK`7OFG@beM_fxS9HTu4X3E`Hfna|IjXg~zU<{i9RF~f"
    "T_Dh~Q+!m>mvago6!4CDc~IHb>Ai|6!Husb9G)r>dRh0yni1;fyjI8P?X=+wBoScqo6mQ{0${8FEw;p<W??S(P=|6Js{sfEu#YRB"
    "3d|3zc{Tey%ddf3t6=-&t@@1|Sudav|Ndr=kQ)A<V)|I8DMmGWwXR?5=Bsr5_}<a=>o3B({%XDr4J40re^pw3SG#{dTKxbM?kV@J"
    "s4>fD>TaG^Yxirl?`7FuYc)`hR-y5bqW}K;(+|f7O74GmdVKVDc=+z*bpP$!eNYCVN}-9;-kk+6)m7h@bqBS|1-P~PRbSHpWre=m"
    "3aE_Yb<)MUezxoTG0JzL2d!6|^uxoM3EfKR(e(rf&2I;lo5%%rDjfnE&$(v5`|GC>yC!;T@bLH7H+clR{EtEJY0&slv6_<kqdclL"
    "fP~%!O(6A~0GMbzGCb+H(O$T^y=}|4>5uNs1oJIM7;9LmFv67I3$sg*i8NLiZ<ueg!rav$(a0omXR|>-;n~iM_8MJhQ18xaXol#}"
    "k%)agJYOzaUz&~$vMDqgeGZSH1WARA%&F-vO$W3rls35!W_;R1(g!*tx5_Hmu*QA|ctM_Azmk<gogzQ06fLYew??PxvAhlx*XqOa"
    "qN{d1TjaAd&jbf^=!+SK&FNJ=cxE{2?Bj#A);I)9c#B*7D|V$Eb?QA-K(S%2COA=lRs)XZ0IL)5A<5ow<N{QX=_o_S2Jg0URATBY"
    "QOnG|j-`>8W{{U*K1be5lk7qJ0XX@o6-+zhtWf=pK0WA}XNr|fF4QJ1vk@3u%wu((T_#iKkr8|p7XhP~7x`*Q&UemJ)0}<3{P$=X"
    "BQoN@DpKGXWedg5euec+b6^k^t2oBPXCHME`?Tn{3^<;2J(9(@UfHJfe*akA0|#%1zZ{*M4#`*@vLx9%vhp)#Ql31javUV+MtZ?f"
    "K2H}3cyqqTIYyVOVi}!-2c~6)33-xp#ccu!b)5zk&aD=+XvgJAEJPj?Na|)BYa^fc9aH-5_I9L+KK)A{<O|ze^Evi=x=k!sV}WPd"
    "Ft8p4pk>;iaZR0uOK?f;T$MUt&KyoiHe01G6kwmfl*b$l%Afogy<ep2PQC))FF>4!pcK5ySz`!re+AyQ`Sc3B#^AK`j<MJkUFWN*"
    "@!BOkMps*q9!aaHcmeR4y3W*hD|)Gj(SNIk52XfjoX*o3Tue&%=^EgbRsr|zPkiN8U#|hnJsWq`tvbo0KS!;n?Pz<u(l)mv+&@F+"
    "Ml?zli_sH(!;)!=$;eP6dUt-qG#sQ^-Jvx{)C~{Akq&C6c4*n!YO`*QJ0ZbV3;D5k<7;>Xr-d^jDLpvrAvv%Q<1XzzNb16q)IP17"
    "|3gO>{mYYadi7)m?%X?n`L}Hs?@`8`L=XR0@lk&#H{Cn*TN2$hFJD1uN?yv0zJKZC0SBbi*yv#3t4Oh`5lo&4D(DQ5GffeJ4gFf?"
    ">S9E|3%rh)0k}k`U`@6x$+{J!-zE3t!|z>6Q5=`)F?(-^ZkLb)cf~FAr&i4!#6%`cYU>8KXVjj<S5X<C^?~Zn^LcAKeysQ*^oCN)"
    "4RNn#IM1QxQZWgy@c&!!Ltg>%A4a~%WmuYD<+|`cWXcjp1UjMmL}SZZ?+YNpd%JCvNstzbp86GjIcywsP`Lf|Hnu(!(plNIYCG=d"
    ";ziu~s!^skN&>ARYl0d4HdSgEXjdMyP62|R`a(Gvbg@U5YgAdHP7tntvh)F0U~GP3?Ol8bc378G{v944EEf5qWoQ<N_#l+nuOsGw"
    "L1ICVgwa$H`*CDN8^wkiHMV1SWbLe+3Y!~UuU_@hV_1#q<}qPQ_k3?x(ZGDni|+D|IPR(m&|gfXw;53_le0|>Bq~e<7p^&O@Z2Dx"
    "QrVb*!3`x9BhvV%AK@Z;>XAey{;JDcOX>GNC`RvCAp?q17~GSnLz)(!Ecqr*p2a`QU!uly$I^<RNbslDB2A{~-rfPV3`}4LSu^Jo"
    "BP@j4KQ--{s=wu407mrVDgF2%>P%dsYvyu`Ev&XfH66Q6X%2q7iYBOS)Y60k*J`>fo_u`ZbE^z<bJNbVX}+}3xBd*O+XA7lqpuk1"
    "g<|+;DS*QcQoRKN$2LHk$iGXq67C!B!%F0sWDC{SI5RrE&6#T^2D#I*fi=~8+UYQQiu=LGu7J?_rxyKLtS%YL!u>bt>TBiO|MkD3"
    "N4FAn%i@+ffWwnt_SGkJ+!?(pJ1%oCVN64j5tuZ|k39r;twcdsabloY0;{SBVuHxDM(1283AXPM`xr&&Oau{x`{Gm66i+gBH++e<"
    "0`?kz0+N*g*D7}sKBM6d8dyWvNOb)POhku&J?a1Hp}JZgMxe2dI*TYc5LhOIFVsaO%>!0_QPoYAlpBTn$Lp=ujn!qNkR_yR(_WQ)"
    "CkhU#tu>|n)5R*aw`My<yOx63!|GM29>XxjI6;_9Edcrz?{KL`k^-5@*yz?_i22HIIGz<lxXqeCP;;OfeighYxHoXGU|oOcMF4D$"
    "i3~Hr1HO58GCV$beQ@~xbcmrDp^o(=c<t6=vuS^Pt3FX3cIJwaGg@6uaTKo%L>lZo?nIos1m^)CphvnPJj5{;4|)%Nj83of=rT=;"
    "6)=eWB0|k_1iK9cL+vQIf~ofxt7M@_+^iezD|!44*_tj_OVs)(G2usbVnH|oP7-}!i%;ov`YM{G87j^%&`WHImipx)nM|^gy37^u"
    "(&#)Vi8`MY(P)|%5H{^ewU)R#Y+OUxSGD=UjdG{Zb;H*L<Ez17Wo{qp+A^Y*q1f2^>Y2wk5i(-rxcR66<K1eSF35VLt|0S0D)!00"
    "qO(|RcL0MxtJz7Hla7L`y1F`7yVXJ0=H6q7lvElyz#m*fDWdS|nQjT@o+1!z?TGT|DYgcv>p^PwlzG=#J!E}8^m{`y%tIujQ94&R"
    "tPU9*o8Qw#-WjRC6pStuZ@N$zN-(v{D;n_+5caMp!IP_G@nm^9e<J+vv{mI#E!A&l6?dVnWTbuo@xUPl&;kJPZ~q1_--chh>us$r"
    "lj3u<_5ArOqA{;uMZM@R!B1nCYBE}UNk@^}bT}E`{`oJV9vUelz$mIH3|mIWee~)Q#QzmZ(EYsVPM~3HGFH#<hEb33iHr}L<kM+>"
    "t=)f${$CSCrG=IPKIond4^NH{er8ElQPfLy6{84mo~*L*4=}(*x>SFPNDtk?uSahVybgZoZ{>SiTTVYSn8pwNZRcT;{ht2N-!gsL"
    "e#Yrl+x*C8x$2WbH~5|Y8(!5!kQjtc#tN?#X~u*L;8(qx70D!xz}CA2{t=v`(#2&~6iDMA7!7S{kJ-8w+T;m#@3UdzLxo9SofD^R"
    "t#pnwanZBQuV)3_Fd%2q(R#(W_zL<#rHpVoGGl5JCxr_~e{L3vw9YKQuv)Pe<R@_uG`3b>wDhuPR$XW{<*xX;IQz`rfb3*;XV2uy"
    "j0Z4;=kfQgZphW%ej%r{3K>&UMRNV|ym<oO^`00O$7YOyjj>KVtP6`e`(F28B}bsQjJeKj;5aA+(FuH$wjC>;w}Qu2OK^j+gO7z9"
    "Qh4HLRXr+<B4JdUJen{}K4(k)8Od)$ww=8ryZ@bMvl<@WO>`0810Nrv0M3e>tO3=Fw%!5_@uD<{Z{Q8erOvKZh@{L@ZH@%J&X&<Z"
    "Y^|4g?-gb5j<gnSiN8P*>dn#Xza1P8k3O8f|8Qy*NAHgh{`&Ut=U-0QPlEmAG<WFv%CV5utVe^1%^d71eCF2r+S!J8ajXkz&dVNk"
    "-{ehKm1Q7I5Vr=k-!|~VyT`l)WmMbPhfnn6`|_<f;e~d>s_Ck(F2EVoZ?4sTHe#kNGgED&RMgnoCpUFQtg>8!#R&*?s}yei<l_Sb"
    "rbSiWxpwHLcshtnJ^~d638PtFcet%SdgFUho#%Wu{$85d?ZA~*x1u-iP7LY$cH*ac6Blrh@KJ`lCZulz;`hzuk3o*gvw%bKJtcLy"
    "3kkfdEAqXjXSqK@cvn(rH^^CIBWlPegT7iz@3MI^9xu|OAZLa}x=xbYj4YakDq(A?I~uPRpjjG@)S&>^OC}B>YPJLFi$!uR^OQVh"
    "Zuz5H=tPO***{k45Hw9i3oyzE^=SO;f4#MgDOmD##xiKya{`+=l8e6U)i@Nux#zH9_3vCQ0s_s|=Wb*#_Ja{)eHc`F%kWFiGa*;5"
    "*4oa`!P$wHH2jq3pZju=tctO@2!H59_C!UyE)%T@Bw3V|-1r0307_`M1$70)rMFCaLGQys9AyOu`Y(-srLwhD%$&(F)f?JZ@f1_W"
    "n2=B%ism_koSDfE+9p{aH1yxD_xz9>Rr0O|B`&9WORutgRq)L~()qRVK@lVNs&Wge_I9q*bOsO9zU-{UA{eJoQrHw8relLZFk+ie"
    "W?!}P;{EK%*igIAEYdFIb-e`F?AGGrgR`Xb`&Q@W;Bo8UduQFw!2FIMDWrf;akJl<upQnOc=PAJhD%_hG|hm4oi7bJ>1OjG|EXKY"
    "+Ew(2{;uh>wtZF%FQ)l<GA+jj)<M*!ADO9f#wn<v=d1H+Hi{14U+qToOoqnt=A)i$=8~osr_EqAmL{~eI;hrzr<UOgaY9YlFSVRo"
    "Y0|Q{#C$abk`ZL5IDbR-d)knfvdp&diU@FvjrnZRqnc?EFhe9)Nj4=os|L6h>o*ZnNx+KlqLBR3ugpQK6)$bAc2VPk*022q$Xqr~"
    "N67-GN8#W^7k~f*VfcdSF%&VjM1lH)hl-_%Ux}aF=4W6uXc5O{WuM+-t?TpbIAVV3vS0erP0lEh?C{Nr#jyW6I#$n4Sfy8L_Ti_u"
    "hp&h44o;!nnpVdOdu>-{GGs7Syiei3VGcR;YN3!W{1JDD(MA<t1>d0()&{R)2!r`ayd8cpnx@HYH6I2{s@gZygpP1iWC({~)4&@9"
    "eD}<|Lfv_A^6BN4c@E(?({!1NM-z1-aA&zK4K+mm={&v2W{QhiqI|+%$hm;qIO?LavHcr*N<~PiXp_xK#3zIoIt5^;sk7^4-5pI_"
    "uX8+H=JR}-U)&5A>1BRJs<IFSVY~&nSE(tFI4adnJmBw+D!MQXx2=1-1PM}2njedL=-D&`J{)2;X2Ee|>n$&0Tb+)LDK$AS$U$A3"
    "4l8H)%BUA#83%AXK-6H19u00IQd&O359F+)vU8!0jZK&8iqsJJl+4EYWMbSUJeaSWMUzdC(Yg0B2L}V2%s>O!MkzNv7cL>ZUu@T!"
    "0)_SWgYATyAq>|fw;s(&0WNUZ@hSM)2$yf&IPBm)>xDPpYrO&Mp<uU|z%Wr<QSm86LUE=`C5A^2YluHg^4~u`co-f0@59rQ`HLiO"
    "g*;o)cEGj;f=1YT3Ep)6)M|M>J&v|xLvIwwX6nuI%aB-D;U<!MH$QZD`-I;c@3IAW2d6{ZkL&=UUpvGty5nn}a?P9+kGn`4S-_}e"
    "!Hg0A>Mrxo>1_BZ{nC266UPs0fIxOu#-TpDuNb8W`?37#PaOds1nzBRmx6yN^+)e&`wQ_XrGDsLZ9hLozXFzWS&fBtKhi{{%YJ1T"
    "<fmo@^)y(`xL8e<)H6y<?T~R+C^k_`Kb>)^ka?y<5LGAWD~|4EYB<Q-nDEH?IR-B-Os$XfN?l{uaF@Yrf^URi0ngykbX8<mQ2t~2"
    "Nj<!vPK?_efv;Nucukh_IeN)~L2bNHy)AfIalMP0d%dme9qn}*ZeHdMqT(p|X=0^`)H;e(QUmJ`sk`to^QIQaxV)j37lnk7mCI8|"
    "t~pNb#j|GDvT?u3o!Jo?VXB5NR_8OO9?tEhHr&87!}1tQ;t($rskVOj^=pd=X!r2_{;%EFm{l~|in}M+@$K!y`h9R2J#@nyR*;Es"
    "M}mZuQ+L-7Te~j=m<C<?guAv85#2_cttGN~cyo*>RkuAKAAJ3aVWGT7?`Zia=~B_8i$ecKjdv3qRjqDszkY?iCVdh7N@wHS25>SG"
    "rrdDrZ&1B{>vkYbPL*4GzPF1It8AcCg_7U<=EwA2u*OH*br7h&meqYf2Afdjy7j$cTi)lwy%TkRs~&F#7f;hrp@tB82ar+c(_|#x"
    "@~uD-2EwAae&G!}B;Ao!(UlcQPcbL4!<s&do(^h;kTI5cBbdn0w}%JsPKU4Gf2bI1`~Jo{I)44j!O7|I{^`+i&4@c|Mr>m3F5A1c"
    "!t49kyPX!AZwv;te24fXXK7XAexDGfZwpfTKO;<O-5FR1o67fY4AWhsm@1C~;M01?$c?;-YYfKd?>?S6FRQIMeoAk3=GE)QcFf-T"
    "sB^GMDIPsn9FCIUOol9Bd<1-|93j>iXIhZucxWm@+EP=}W(e8{T8Xh;a!2s{@y7>hGahR@Tgmva$$_u&AQcEuiBCR~)Zml2RgKXR"
    ")-9>D!U3X-{jFDlr+@y_*B_nxH`M6yW2Ewu`iN{p=Iio@1LHobsQP%^Vb}Yz1~v*!Sn7f7T(;eu*=5pZ)y6dtd+eJ$!jq3B2{5^n"
    "Dwr96jFR{oDng{=-mw^w`Qa5M@;<CV8OSs0boHdZ`Ic(FxE2d_^msa355?!L8#+*BOaKe@3>pc7eW_u>AeWkQx4#fjNa+^_>vbu)"
    "sM{Y95w|y?yjr7+sC1}h!dFp>%9}R?Jc_6U{23@w752ueaR1^gBySJiuysIlpNH@J>twr%F8_9L{O;iG@brJXW{3Oik>_~w;iq>8"
    "r~S>Ox~iTbE!*D@PJc11@xi+{?~e}Ooz~B~xBYVK<<{LsI5~KITrvNW+QILBZRhAn_=I}yEWfOupFjoHM46c4pOlDNBS{e>w$TVj"
    "Kb;&L|6O6lPlxZ`K!Tl$A%u`zQ?spJx6`vw@Xw3uqo~;}b!%j0XT(l~FAK<=vSL2Wev%ZQDU2G_&nPf<uzso0_f<(;y?=+^w;jC_"
    "#y!@!Og3|jykKQ2rgC~1x!QGzm!5$jWn5WY%CfmHWmAurHS$?ASIqC@c=-)p=WMOOv|Q|QZrw0@gL<zgr0@LD;}N_nnd8(=(Y)5$"
    "9O$y7!VGwz$kdf}CUsI(`>|xgUxhnbr$=_bw@xippSw!QN~4ngzT(cV7*~F|MimyzSU8LJ(<yr7tWf|@L8bAJRfcq9mUotFhetJ@"
    "U92#MuFEn4k9q4S)Zui<^l4L-w0Abmuv!hbX?)1P;-sR@w{%or={2U~enm*gt4LAr;LBY&$DG%qe>Ql<u4P64>+LITmWLN4V`k_f"
    "4K+?$JK8DpIvcka>VGr!ziYsu_5zKcW{BsHvq#T*+dJ^jK%-~2=&LCSKf1Gw-|=L+$sE!~wjljoD;xJ=80?qE(D#@fW^d4D9tqaU"
    "o_Otip=e97#4JYk#kMIaqt|<elOFWdN{s(FE#8@kAtyK=b7cDn0BaIcu)z9&D+=a)qO(AA$v#a^MVCdN|81Kc(0{Zsy|~>B^A}rZ"
    "&F))atmvDEZP(i}hy>3Daa&tF0Y**=fzI|I-YBN1;-HpZ3m-=(bgYT9XgP0nD2mMze;sGy#3mb(9C|AVz89oYMSbfAao(?)>UQl^"
    "x9g|6-EgYgYo==7yW1hq#HY)w;9jKD6p|F*AsJf;p=>N5<xvlM(u7Wz>m7<dNaKEM3(|SXH`3#hwAbin;D4$1j?x8|UThB>eNh9~"
    "pr~R9_p<?|im8r3wzQ}Ule`W?%C!og$Od<)8OL>xv^wT5nIgscINen7Tj{l}_P{!BE5>4`#3*o2nxI4W2|B!DQvPH8Zh+bp|25?J"
    "c&#Qzx>Ha2seL)clKhZzvohoIX(zKLYJ5{?u*bp`EW)TCOgU59t7(2wRBw-?T>DEv4?~T+#d4fO=F@1WzEQeZ2-TJL%qgFYP8p+p"
    "U8toVshaIQU}I4p*4<6l6E!?O3K9=|&(Zaso?E{6a(Fv@X{F9<)AviRI)5R*O;1<f!0R?V-*qyR9$+;C1bw(x#Pas%;kScVT#)6>"
    "zaMzl4srh*P`{#jcj$Hd;d<}ieK$Pk<sd`yjoT4)T5dSdH*bn`x@fw%HJ)(Iw#N9)Rqf6HXhF3NX4Q7_DXElLGgriT3imMaaD6Fe"
    "LG9dZrXE&Et{~uXQ_F2QJ%eOJFe4m59R?>|vI1&vdkY0ZxC4S??G4B}3=MS1WREL+f(#3H2cZyJ#z`{>Ia<_Tke-?{JUy9we1O;d"
    "*PTwLaODY@bM;5ewVFDdUhf67FMaq$jF1*CO|RMGZR(ZT;Zo;ZN$O6*oK|OsxuqHg$uAfdxN%DzxXep)vbe!PEwN@sd;y>}2#2gu"
    "`Fh68kmN!vRn<n7CRZUM*su@JUCHbK@TXgb?<$Es+phv~F_jG6IvEIuD5hyTk4(p=kO&an67H-DHwWvgP$K<<9{sCh?l|S$2YA+t"
    "jQ{i3X*NkmH=}8)060=N(&CTvRW=>}!7&eiC_Xj2N;{)Z$z+0=F0wBjU>%D;sDSqky)wVl6*JEjDdflMO8%oF+5R7aB-MX_-Ssm4"
    "L(M~V_D7=V*3IwfACqjUrZt)79TcSh7)_I+;J+ca=6sQ#r})=Zy8OgHmua!Qjm{M9SpilQ-EMcF6J*{ZsBUlD&FbVl=zV=KPSG*~"
    "Ugq#qN#Nsbsh|uA6zB)$NbKRg(2gFpBR4@Fy@>umx)=5FAFckwsQCv+>N(W_K!>lnTH`AUv&RU<i9+-ug2ZyO6g>M!sPR`MZjl#Q"
    "DH*2LrLL%3a#QS6s@*YV4#Yaem7(xdN+NQ~Wl)9$I0K;^3BVaFmKjWL2uTr~0>Y-$g{58EJE!2<zS^RRmG<BXD(Vo!xWceoyxBB?"
    "0EF3+8@bipZk>4g=BXNLvortzww;c3Q*Zs)(&m>x{q6lhsq%IpVS~G<K|6AiAyl-&ZP{tuJ%hEjbKNG;wari=Hx1Vt>;j^=8)Y4^"
    "nL>@WYm%kYalt7kjG)YzY|`JD_8N2DGuL;2>Q11hb|2CjV2VjR7el$GmZHgO)KtRHTeGZlZBG~%mcWwG$gt_JtBSGfGR%FEKtdf$"
    "{h5o_1C6T4ISKbA;4HgtQLWl~ok`)AL$t0pG#&KqQ*#P{!JAQB`nDZGK~CAMTdK|}hiOM{Wlja&uB}te#Tm!hg(Bv$<4ne#1b~a>"
    "IF}1b0orp3P&E!Z5DK^(n$o1E9w!BlUtpQ+esspB7b4T*H&*9Tj7B>$;G{}C>RN)5Bb8@cOr3eTJ7KPSB#GyVU06a<Au&Xkg66W{"
    "!DP^isbD++wc?!%Vw)%kle3n;(TRdk>xXqWIfO$&wefc8H1dkgm|bAqAw>w5ZCwNv2|s6lXE*V4#mc6Nw*q)X438j6RU9)m6Ir~*"
    "YN5l?YOz3h1;B3(fq<qQ12;Etyv$$jg!o?4-#{{#MGB)|rNd=T2u{`CY#Ve)L(tMw=7u)}EO!~Dg<4WtARA(GxrdK}Mt)csz*v)H"
    "#5mDr*yjJz5O5dGQgzDPxHIjj$RHrHkA1D%9<1GCjzco$6w=+{YB_3A|8SQ>7+N|WCP;dtKUaQXX$o5Pi%;gG4af+>O>xRtbJHpI"
    "Qdj=h0b{BzJ^Dn!()`f3UJD@OB8ooiHU%{DYwDEsY-hn^EsrW)V#goeogV&rF#OxWZzs2n*KMwFeE>_zqF916Sj32CrtIYXx={QH"
    "CLIDq#uDX2N~_GkiqOFnK<&W6e&|iSSmx>>R{50#bjY=d9qK1ZQrotD|91Z!a&xiUHD=?dYojm60j2?o($KariMzBCy;sv0pNlij"
    "T^XvFymk!W@y$8F9Z(b0JnHMy58!TwY@j-N=#T1Eq0q0$fXUo2w0Y)E+_XzT)2Y}FwX4WLZfPbHk2Nxt&$de6ignZYpt0(xh7U?j"
    "9llCP6Z&dHcL)kiFn5*-2~dn#^dwS{`--!5LIrNSH<#1Efc0Y;H5CkIAZ<D}uj9>6lBUE&?iAuu`6zRMcD6bNREp5RvJnw_5av#_"
    "_XVz*pW%`{%5B^<1c6ZqguAB%LH;r($zU_a-dxwo3>Gt9&8JxJB}xnn<;<RQ{P7inlSADG-Yi<`wzo_VMb<OO1{LkkZU%ho^k7Fc"
    "<VoGrlGhO+M_cpo$SbE`mZ5vAnj!X>HqBq@w0hSLwV~Yo<|isOQ6RU#mKpJqYc6=nR7ycd%jR(JRT4(^;hFeouufJ0ZORb)DnK^C"
    "-)Z5qE#jiavrPB3S|7LXG8kGGs_jUq8$5Ccnqc5poKnGnS-2ffSj;b)a4s66k$VRRc^90si2R9bmg({%cHfxYQhPAuwpD9pH1^-t"
    "^FD;=d?PVZDwO{Z{_`@KsV^3ky3=ds;4YmTjs7yut*`l0@i6ddU(kUfxx(9+c#6E}@~4QQ>RBu~3DK>tTxvhy>JYLDE45iJZp2>S"
    "fC4~AUMK=Ll`nNB(kP!|$|0Pct|IF5>=SBLgcy2nZcsTF`$g@X+ca=pyI&JS)rZlXEhPDaJ-IaP3cb@?KpJwh74#BSinuFf&Eath"
    "1wk-ji1AsAFwO%B1q9G#MNW)n8*h{Uh6;u1;402*9HDozR2&k%8Wx=eb>i9yQHRW+19a(M!IY!FNTm$G*IM5iXZUik<dboR0^I@Y"
    "W`Nt6b{55H&Od892zl?JzGQ-JRf|KQgJ8&{vEZAr)n90}k};W3U7D7jftKgEIYrRGPV;-!-LLq}@Lq<(M5K#AHpJCNA&uiWBSp8L"
    "L}ivlC~Aw<WsBGH#-^a*MSXlAgO*fhu<P9V1pOSjVWX*dcrW@o{x8--VL>BjF9;@aSxZ_w@rgV0Cn2`1W;vFQ`^PdgX^16mHfPX>"
    "_+JBd)3TxOb$j9Sk(}B!^ih|J)j?j5mcNm499&t&=sz?DsGW<2=MMs&aZsh>!L6BYmyi26PYH(k^(?|9?r<$Db}*kI_jkR>uvQwU"
    "bq-w7kjdM%Wk|IL^ACW?V^hm8)~T1cjG*><GQ(!Sr<gxL2O0iybaL81d=Gj*__KHTzH5pr5>@T%azh|Qz&E$OuN(vnfHgtHQDqdd"
    "J=ENjpd!DhHk5M*5QCV%gD=ZP@(X>8+MY9#Z1j{G?E(wmBBB~fKC+N*Wpp6FAOT=zDx;JOF%U8*IH!6R>nN>Zc4a0n=8IP?mtM{l"
    ">y8Kp9N;zV=Mt@LEey1F)g9)O@>O5vKmvDmQ#i>bS7#~rfTP&}o3LE()bJa5FxJ${!s&+l`hf<toRL1Pp~3xn>vx4oKuvBKZPw0c"
    "Kmm{89bX+_7Fp*Da@V}Y>o62N6<1{shc?2hg#t5-$i&=h4a;vwnDX1<C)5`k5w&SD`V8g7k>wa`Kryi)M{4ZU7i$>`;Mig;M|T8B"
    "jI1Uph)f|0W-`5}j(ysog_=N*K+*Y&Cq*+TNM_U~xA`K!N@odLF-VFu_8n7{f+>giT85D5@7Q|5St1Nk48w-RWJ&jM=8f>z7!|d#"
    "fD`s1d~D4evrAIz08+oT?z<Mm3e_ycD45jfSZvl>gGgd8Jr=-qUl{9AAZW-l3~2$=;n}sEc@A|DedfJz*lmhKT7GIEQ|b=`qL!^6"
    "h)b24+5jOAsUw{4Q6WKpHT!z4GQ;2t>#1wD(b45N)E>LHhE2HIxj>;TJ=dJTo3YNygOQjg$~qssKYIPk@a_JGcj}+Rcke%(Vm5ty"
    "F!Y(~mzlqIxPQk6%Rp#gh7~3qg}L**05KJ?O9KeqctE<%u8>P@1@P6Vk4B%eDLMJIttQpOra^!src<Uy)pIxll~8s8T7w}Xeue5B"
    "bBXES6}vptox2qtJS;M;jFN~1EVUT~I^7N@(kh#40;|d<Uhh9RD^xt}n9b_J#W~-)O2CZ_fpzvA*j0P);Yv%K5&8z`EvDT-EmsH?"
    "m`ds9j6U;xnvHJC?c=sCQ=yHplrG9w+aOh{wITKHnYOr?qnG2M1T`Xr0M9CPEa^qncKCJ`Z6Gsj&pJJTOO&%zdRKqa0uWNC?Y8E;"
    "iDj-oP0U4vNIV01C{XsliSVpHaDk6n_^z4uPIp7!z|D<HBfN2yFu#rBw&Q)Fug<LjdJsod|Ebo{lU3h#^R%uT)TLEX6|__m234a?"
    "9N&$!{R=nDs@lyJt9e<~keXNdSkOjlOP1fW<iB(q@l4vF9hOYDb)H&j#BB^%1cnUv;r3ty(E>#CF=7gDIVH0O-wyT~fSk~t>D<2Q"
    "S2E=-CYj@*>*3hniDg26axwvH6I}U3DY^4AQ??m05r9S`pm?ul<Pk#yHKvt-qlYCvpN8JtYzpO@1Sn_-eSO(%PGXt5@O3aIqdUK0"
    "pVkWJVApGjhhxKYc%2^|uVa+$^i)C+M6jXRdx#((4r8nCGB879w}dkec?Ywz1>Gp8g9tL4bNv^rG&Gs9rf4Di3YU!ZYRa$UxCiPS"
    "$50-q4(9l%-D=-Rwzms$2z6)x+;rKB?;s)7nKY!|(YH%RZDUlhs&)YJWxDh`@b^eB99%%8h}_!1^+6Iu^$208zvxQQkO3jD4|3%P"
    "^E^zN09WlFBj1oO%D}bLK?7I^?2nm(epq;G$H}T|ZVANpB3&j+g;Kh4JMs;UExls&C5MQEp*wqiTfUZbb6t9VX#4TjpDz7I=)qVq"
    "IbjF$?p?%PZT(y=rp0`kEn6h0#9ercu6wXLdI$^Dy?51D2{QPk`Xu%Ye0t`nkQoo@o5GbPptG?$kFz3mz|YSbL7&@J0G~0s5b%=^"
    "jj~9Cu7=eSKy}9q!xX8Gh9{C9xP}zHsknIXt*h|E_1-#8%zUWyeXkgEN+a3}nCD=zmly-jZ{bI~W`(T6L&S%VzCtg~gcr#*O_BNs"
    "2NE^Uq4|m(4FtuC_3e9m>na)5)crhLFs4+WIiVW8G8fY}I!9tP=>;^Uze>>^TH_(OEF4q(7Ja(om1ls+gb`&W)#8Jmy{AgEK%=_m"
    "PI`nWZ8!F$XSW(dSoA5<#}J#aeFhJ1TpEQrfn+pF=NQ_%pv1zf8BT8t`YlF~Ob3Vw6vY^4_y(<rx2U((m1WMMUI}Y$ooBe;Lq~Bd"
    "z1{UgvzQ+0z(IvO(0&BmCWMyYrK$j0sD<h;MUc|K4OT)21g^jcvkC<?1xJx?uE8iM&^*Iq$EV>nI44BQ>)c2Kd}ArmdjjPn(EV3v"
    "9wHQkUTMAiEa$7K<k?W~L2m#qbiG4!hnimwD99!ye)`T3=CgtA)b!VGG#wBi;=#J869+q_`v6?eiabHs1%CZQHHYe$!aZ*_{6?rd"
    "(*-h~p;o95Fs(KW1kwS~rVc5HKeO~2?8b&a#UicQ>>_%boR@_mGL|8v73jVxrr}=V8P;mr2q`X;8*P>)GdcS8WD72XLj};$iw&Kb"
    "eJgF*G$sh06ZK`DlRu~N(^agseRUUKPr;*z{Zj{doPoOn+TWSOWm0Pk$r^Hm>Rj<Nn|QzdBX&kK3JI6vx+*`jOC{Q<cpWt-b$N<M"
    "SurebE~nY-b1UA^zN984cL`KLvosyk>cu>wd0tQ`X;5}|qP2uPB_Fp5U04&Uv&bpZYL22NBcM|aIsGUR#T`fsC1xse`AA%mWZ3~Q"
    "{^eX<c&v{SUXby?|5S5S^otd3`gEdi5>QT8-4z}IKHyOV>!!uGvo*>i>{F=9tMo{bFT)ri5_^Di`Fl2R@h;G+(59S?SPv~gfUd0W"
    "<j_5?JQ;NR!ZGn3J<x;cQN)q17!YVakUxKbihu#%>)uWP#ReQUE_ueo09>hCd-iML9{pa3KMjAjalAoYh{1&4!Jr80@}Mx!uO$cg"
    "@|U+nBJQ9!sU&;GCBkvkcOC71guW43qw`#yVo65OO|w91B5BB{41!Iv)YP8?7b>_7(+oT@x@9Tc#b7N($UehJjnj1+dWcsx1GjuH"
    "?y!HOLx1n;BxyRS^z`|wk^l~{k-vGLZVD580OUKF0t0iSU1LiEt2n>pxgCli(vW2^v){LcUdiX&B@J2t5TOMjV;M<^G)7qF6hm@9"
    "eesALixm#_btF(&I<G<>n!tMW5!9+0g#_(Fme<^R2%E23&qIbRka)Yvd67?7OR#XDsAVMFTKWIhQ2<!(T8>X2L2elBi5<v%(2KSM"
    "$q#y7<bO$O6yi3y(pLuDu8GX6%dF5VL98kaN(4T|wVI125N<LEZ-Bnl%%lf_^~i|(o{tu+o{*a3QkznrUZ}WdGIirI>og2*)K3}Q"
    "C_gsBO7d&E<&>9L+D{XOfz(XdOb3LMuC9lkp-O>Mhq5w(e>tvSj#_|4Xg`1oWpWWOvDPJuV{R};3W5<d;hKvf+fFy+_+oQyle;JO"
    "Zhu)7JNYr0<V&W!q@pkR<t1E>>O(a$Whus2p}~ba;_y>ad?NaCmvD@-^G?_nF>qoGELFj)4V64zM&lZ4BO{p&O3m_X$2lOZ_p?!;"
    "rI&b+Xj#yb7brVKiJz)@uEl7vI{2)EpBZ;Wr`vB-q3Ik92tAmX)rr(hDgg30F6C-4DCp*Du$U>i4XljNkJkEcUSR$)`yE?X`w}^@"
    "F9SR?o<R=tBzAAip!;7aWT$M~vP=!Jovl(&(!IX4sqN_GbpQC2?mNmh<<N0Do~U!BKQXP3!{#~HlrN_G9R?49>rouuWj_@_Kykd3"
    "spqO$2@9FHJU?^5@RBcI4Aq=V-5D)k__#y|e5}Fn`Zu&q?K+Ku7_K|8$A@QOA5`i0k$Tz>1TkgYYHONduvIiCtiLtE83&5W-9+cv"
    "0&c$|8m|@@2*OegNi$kUHi9r{C_POzv{_5Yc-3uY5e`w}x)b|^FHu3Ct9HC8z4be&gw<U=#c|$23KBqA6ZU4Qe<&(X2hCM-p71%x"
    "AE{|PMwHyZX5E#!P0B8kXJw+n{%OedVD3>79WI`<T#m<vhBxJY*rZ_S^pHIhMY>968G^h5V>%wUsu&1Ov7DqWZuB{V5?eV~rNOs>"
    "?|QAP_?ioY(-rC@Hfu4lA}^yjgtEsv=0~>+FhA?~m(T&FO|52#?uR)cril^(R9qpom#gds+`0hqGBq15kRzXK25DD~5x1+uOYIK1"
    "sZmzTVSWxSddv^VuH~MYWM+yAW8xAPY++I*QMM%*f)F3zbGh+tDHvFuA7>tCE{^Ch;*GeQa=zE-_~7*L_~2J4EmvZ39zCK}!?g7j"
    "89{CEa2=jhu-Vu_%~t3QkK4|i(S~k*X&k%*e>Y#`pr$b}cz=BK`rzcG9soAYbr}LAsE*iM!n<T_s#QLFFtx>EHP@23XIo|zxfdXL"
    "-BR-YUej~XFl5VA1@HtQT?gQMj7J3qV#{Z}ft<3FB%5NUX%V+J=W4oau!7{G$$7q5lGSxJOE5kr9UFssAYH@8PWE?pu-9Jf8r$fK"
    "uejFY+H_0S(6m8c=@+;VqSny~DwEs7D$tJpmfrARr#Ex`@R)cQ{1szB6Z|F9S<t5FJGFk7*F&1DXyxM_BZlx=)i)g;*Grh}T+VW8"
    "m6x;65PFo*zp4p>K=ZZI6mzs9RO0Rs@224py{i-r!k`k8Z>Yt6d*ToWX;?b6H82zDKCINDRmV=QXU7OOJdn{}jiz~_z+R)lVl^8_"
    "oi$Xmp=GXlbm6!1itLXMH;Kbq7%qn79%|8Q${x9QQ<d7fOgkI0Lky<~^BqgkChP!+MrM1RBPU9DXmF3C>%=A3(_lGsZ^nU0UF_1="
    "JJHy050XSAL$1pU%Bmxja>q1fb=lc9Q8{8*gEVGbR8Ht<hGwIZvqYb!>(~JL!hJ$)zIH3c%|!zh$a1u;eLcG~xz&(U*_m1&4OPv6"
    "Qf+y0`(y#7zg{g>H(JebB`PTw8z7<5*Z4c!i@X~k`NJE`u!0t)(0y^+i@xHcTX~fM#WTS>`E|)fwnEm_xySH(=a?tcX^ZB>kDP!8"
    "bcG13cU%s*LJ1Hea6XOL^!|ekJTzm0uKuLM@u#`YKo{8in6lk)@_z7C=wy=)I_q?nc}F`tbihrmjN=tIGF0kVbO8FVWEM~i3@x-<"
    "1v|u{`yYm>TwcQ0<WgG>y5_rlZ8UZ$zZNI7y<@7Y&F{~;R4W@N26w!>n78yobgJ@t%X2MKn>cakx^y+y?;ak$J2~Bd`*#2I@aP>K"
    ")zSo-^a_>0Uqc`2&tKoG-hMiKdwBX=ZI2t>jB6wRn=C#Ugs-~9@c;4Za$d-wUL8_j8_-)3$g2~nu<L`v#N5$jaoa}U_TlIBrto8?"
    "H_G9#K1S5p!{NcZzkAeOhv4-c2BMVZx|<Y3aGLzm0yVKBDGGP7Ob@`IQ{pRZUi~Vcq7h~&qKY3Ko_dE9O*~+~1wD&fud2D9+>3o~"
    "dC>LlNRAtspmG{9o$N9YYOhTqtcT`-YLgI^;6C8P&mX%Nq4-h~Q8I_S^pl=BqL9e7dUrvnHa+VdRn_WCic16}fC#D~bw>aHh>R0-"
    "H5wxXGfwM*6yw`}d9?=iJZn;Mp#jCeTOkGnaW@%rfGSU^rs9Ro88)T3Tl)zH3~+soc4VKM5Cty1QDP8t8&}6WI!#gW?1!rv6mY84"
    "II#~8IH*epN`$r4aol_k5~J)?cuXBx$PtWGd;1(E9(v?NQP_bk18W4*ChlI9S+C<tqu#J4{;hO>p`K(Ya`*MVCHrNm|M9GFmbpFw"
    "V5tktU5GP~AznDiax_gKWDvhBcPj~~P2#ah<{#i*Z`(F;4Muv?wXO*8)A7sg=abRy_RF2|)17p0{Pe}k7rT?)=i|}y?Y(4sG#Vx6"
    "&vssHO?I}<)7_mHd(Zc_UZl^`r^(aF_U_JuaH%UKY5J&E6uK&BJJvaDEAk-sqSr*vP7M9FH-*_Sp*dTwlze*TXYlragB;O)i{zd@"
    "zy~L4W7-ka_R=?v^+eOIxz62j`0i9&a<u;t&0T&W>Our_rSK<2H{Tw<JJ|pEKz50)uc*JMO5*QCeRzQ$plzWJq|MuAQ>?o#WFQca"
    "-RvvMUmu!IeGm*94m1d>iay}lJ362sJlhIbeD7N{Pz5bK6R#{<xRI`tW}~4sXMS4>Nq|xDt_XJ}nUbs+TBn{;M?fZ8Lz^aIZGUmi"
    "Zp%~+4Wb~75ef02uEL4VzUQ#58}KmAmUhQ_Qfun^m}&Y2eI`*2&*K!L3U0qwf5vv@*Pn_0-1i%YNkpmKO<4#jcU4g-XXEWRRd3+v"
    "6Nf_zp=PCT0GgGna#Ubcky97<Yxa$-^yh@QR({SX2=2tAg;l@u_;~6Le+A0_`j>;(e;b~>K0bVZ+D&o5R_x?6iiW_Dw5S4vYu>Hd"
    "N3t2~^GaRV<~pWpU2LtNpHvcKGo($>jFIrTgH(3IxS()=T}@b>Gp#nuZ=kbNpWqFwute$`xPXL+h4XqS7gQl`R3uRjgp2k2(cYT7"
    "LgApgvo1{GWpzF9Bj<3lHx^x>wtP-ZQEN(m;E*-vqSbu^K~^t{f<NHrU7fTJvPIZNPG$%4ee5?p;th@|4b4QFv!LQ3O%qI#lrAB3"
    "3@f{WMmCaj*X27%GgMw2#?BE0>JgD6)=az=7lXlAD-9hxawPm{?RF1qBTcI18_b>v4C4aQTQ7+7HJNo}K8^Y{@EI}@%;z_7Dl|wb"
    "GXar2652#?GiL)Vp}ChNT2~)H1LRElQ3r1^la1r7rpcfz?#l1{Hv`8>g{4xfVl>0KF9s!fHSkUN{h;gyRntfKJr2(`|JWN@e&oN="
    "Ls~sf%Q@{qi-%JOz!csK&<D=(_mzo+PKzVU9g~dcSF5!m28XFqStPu1%HgZ}1~gweQN5KnUbwj#LR90Djn9>&s!nLZP0NVvwh50|"
    "u8d{w(q_jqbgh=M#p*MptAJ6n(h*yCbF#jbCCVz{Mtd_vZ0YjOvlTC$<80L-aua&K!rH!cj)(#|DhOP|uyfGtPMq2H;RDAZ;Y~Z^"
    "=AphGJwmfbs>zT-(%JYjOg`LB>%JMd!V_LZb?q^?Q+X7!)_uK=oe5VHh;Jsk62{Zye5fszHI(<vZRz%LSK|5&G}S>_%gHVCAz=aZ"
    "f&LLbHH9dDI(Cvff_z@$L~?C$Q?!68mdmOI`r~F53-noYsz>vIwWTelH`c?1QU`(KBl3_DlZH&h=VNl8Wy@-Ebj+_QlMSy=kN5xj"
    "*TdJtzaG9lIEkY_(7E7lO5W0b@de_fmT8-FtDUBS1?F?EZk1+$(o0d`xl*&r7nsB(n`xgBpt0#}nk=N?ZepHI0Hs6ON~^Y5=Dl)J"
    ")B{WnpHX=x?s6D5Jq7MI*l*=?Z(-)7Y)nr}``RNe_OHiB|L?)O;oqMP-ya_V$_-C`*;ijTq-@S%HK)(1PaQ`0K&n@YZE$7Uih9OF"
    "lj2St8V`%mSh9)2!N*|ddIra3DegYOWJ%1ZxRU~#OuwAE326dRDXA@)&6CmR7KU2bg0O<3IoM!JFm9qsk$IgeSEVySYwkm*FLLz1"
    "9y13Ct$U@y-#&SE{9C+qk0POjCy^t83cc1??KjYF4gT|FsW1!^S~Y+f8Y&bt#3DIcN;y-?jSyuWuR}RHa@8y;x=XYvYuI;Gl+*xk"
    "i^aGtl0cSV-vPg}vaTWyP9t(PbcA#63A4vD1XR$2mJJ>LV)^9OO4L4Zv^*W|krg@!zG5{JPg`E5QEklG46Id-izUg3Khk+K701tc"
    "Y`RyOk|T=YT+w%vy0y03Qaadn#a4zl-S!=a&g5UB9b!xG86r{iPlZ(NaE&48Db_tyt<~W8SlF)0J{3MVzJ8I4ZMdkvX;%RW*IiM0"
    "a-u;%>Dg#f6<yq6GWtT3{cS2>ubG~wQV6LU8r__u9An7kHGmp9xCb&&KWLpA81Fu3bFxrmmzU`{gM15ORz7XJ%JNm=7;=NRRWRbA"
    "BGAF5<a!LvesU`!;@D(^L$~QA;iFT`i54qnM5M~C7eSfy1?MO}H&O+#jwsxf{o>Yhj&&oj%gOx=glnhGlS~kX#i<_}5JU1jF6d(8"
    "huYjxg6IbLD_H>Y{!4U~TUIJ#l}gJZc~ciqvB8d2j%cOOUyH5waW$?wL)-yV?*&_fewg8H5)q#bcdD9C*D#|vHzGKpT8Qk+L%U|e"
    "o}HLP7v(}*)DT~k6cx=lS;jJ5T;jmG>lvgs)e+Qk=UjKP^;OBetasWI$WMkBa07y_deVu9^~b&F*JM6d#9sRP2%n(}lyYt_l9im?"
    "($$`*>kKj9*C*%ydb#}n(aVL>L)t9kjt#YuZ^Qo?&MpmoT`<e*oxD||KR5S@xx=<O4l2f!+hF@lS)WS9eJO>t(ItpSl%ve@Pp-@#"
    "e6Cqc=Y3F+^mID`3fcUMnJB*MQxsyXO=?@CUJEeMCdks~QCfjn)x|1S1yh79^O4Cv;kXx^rxDwVu2R(e^M;S3708j%@)PDl&{rxJ"
    "8>~`rNFUL_N}4EL{%2^IOgPwPYM*dlgw=vR`vb+*NYGHsZ7SJ%)7nh@44Di|-vlIJx(!1mhN`WHb+kI{tU-T;OBwxhJv9DBo*Mc;"
    "w+)B^J0IdTO<qNOzSUV@&5G50j*kDBGCyA}J?o&c=r6(W1?|d~11)6mL0UuC0&%^<f@0H%HS4V+r<Ra`<m`a20^?CDHj=D2qHVDr"
    "vL%@#*Ec~)>QF5VB!$$Z?}k?p@WwAXlz#@@r<6>Tj&4R%MZu?OGF#34OQh-S!vd|yUv()$DM<z`(=P^pz4U3NxTZ656+%3!?crM|"
    "^kani&H?o?0ifCy(v+~nnqqNo)InJ0D+r<PMnA(nf_{I+>XO6}%mb9ou5!h;b;E?;vL;`{84b1Ks27#f8U+>|R|C>&o&r%vGP6_F"
    "K>m)$wU|^hoKQ9OqOYZJ)#{@wgIH?-;@y|weC#?^G{-Mh587Q^O!ISfZXba~jd*yu(A%mYE_a!M%DMi+n*@24F!q~35&*;<XR!uI"
    "-u)v$#`3P_7@{B(;d)JY{t}oguYTp$La$d_I&J}<3rZ~SJ`cKC5Gx{|22#y>P8Q_~PeH$ma=EBd*S<SNpv0u~pb&K?1Brn>SBatX"
    "WL<XQTkYK7ct@CRGo=P=cPxy5qOz^o%a*OOJB(pd9S<T?)z4&Z^8Bvd#1P-l3qCk-&=0)#{XE=ny{Ol3@}sPEpVY_p?mm;Ehi`P0"
    "6g|~@M>g|_G(_rN-5_fPnQ8|}B1|Q3$A7&Cc>^a$?SflrKJJySn6>UPJzsRK9LwedsphH5++tj%5(+Uo6*kUZi20L6PzuTh&Ob0c"
    "i41z}X%%|u9Mo&idlgFD+hz*&Fus=vn01PK(3bNavf+kp9f3C?bH}50RJW+c#WS_aR^e&3lmX?6JmmRQeM;HM91O(h_&||OQyY};"
    "1zv_JG#RhSn^9FUlHZ853GGng6@P&t4u#p)c7Q8!UpZueU)lT60Y}N08*r|&m$&3SV(I0l14HC3%W1Ig=b{xkB<xMf*hwi1_zHE?"
    "B$$8$MY@OK)KSum)#5BLmADxb0Bg)l0-gb!r5b)km#4yDYn0+CrW0L4c1xwKCC#o0JvAw^(wc{?u`1R(r|)XYI?DOWAR|JD(g0mO"
    ">v+b1j$C%<YDdwc?_r%|tItp-dJp+0Y+yi=UH)^;ME^G>%)cfjOeGCyc=mcSJrpaU*7$R5kPa@;`>jnIPvx7`#*XvRXC3cgBIi1t"
    "#ijmhmM*~=k$%pA0O=;`<YN{>{XmV?887lV{Z=zkf0Wh(4GXoA5N6uRbzH?PSL0lF=8Nn~2>=(s22-D_f+hzh5=G$@Sy^RcC8YKE"
    "*9HEn8fbYrpKw=C)Ze|ub$gZ<st5HCpi{fZeoy;*yO&01K*xe&30cEI31|eu4@Jfrb)xgdjh}EpL-;X*xYN1Hrz`T=#w=&5v04EA"
    "v&fyX-Jl#t?t1^*=`Tm`-l)y~uj9khgP(poJ$QZe=75qoZqq8MjY6_toJ>Hn4mIdzip9uH)x&u8cK@g0@zK$#^KsyWR(yJL^x^pR"
    "!SL6E)BQL5r~6!;WK}GlV5%R?h0}ptIMkKS6&vh};{4wn{(Nw9x`EX5=uzoJYBn<vN#XC4`buw-+KAi!SKNtPvqLNno6q!D%f-z+"
    "&$M&>6NT2a)+^QF6Gcg$%x{*T^4U|J7`MSfO2|BdkIUH)+A;xRptNBr@!$a2ZBBD5%D0FoA@<t2OLTUjG7pS=cv*OAUWNWGMS!MX"
    ")D1el!J6~Nq(O=d3fsWCtL&4-#*fufZA|J^pXa*mffF05+m7X&*H&=`t^!^T$0=p0a5Cur7#-vMFmxnM7En%BmX<}Y2(GjQP3Aek"
    "M{O9qR6;ToASeF`^{6W=m+{P_eiSJ6>dM2?OkzHCO268t71g)vYPllk<&|<(z*wp)Q**0zWnFEqrn-XG9(MJsGKY&?Q)I_0m2$1@"
    ")40U7*HmuhM{*519YM84Ka>^0$#bf{1=p{Z<=ovosG65CG*Pe;NC^6y(-Ofx5G`Sv4bS_A<U0&cytXG16bDxi_R~NUyuRZ%?@ort"
    "2d@tlowGgLli;PEi{0|ywRuh|v8jn>_gjQc-di`ft>WI^9=`iIklmKt{6%8hAc+qpvJH6;Y?#?rIGEHG;L}ztEjW7_|ISQ(R>yv{"
    "iNHO$jl1eBVwRus?cJv#%BGK4Ftx-CQ>U`_G1U=MavXf=kP3rmZCgfB?OfX@{;}g%!0C^q-;#^4YpeZ~(vSa>vC}$rX~CFxil{YH"
    ")&RYBvi|8_i0L>px&SYQeYqTg9DdV^Gh|@aTL3Amf;XB>gWpp0V4SA&j>Bb`Xi%HVX&HSrQ@edd9_CPBBKm5Fyp3jQIxd7m#W+hY"
    "l*o~}#pf*_N&O*97Pz{YHLJSR?#QB5%b0Z@;*I&bn*Mdd7E+g*j80)r@HJ*B0v<`1q~N0QI<$zKSDe7(%heKSVn?{3Djte@{V7*7"
    ")iWp}C0XLP1?Ve51=+R{&Wfl&8J?8nTgM-9p#-Ud`La`RWc-v)p_~&jdFY*E;#1fG#AIhhA8(W8CbD&bxW7a6ZC1DWLZKI=Q;;P$"
    "f$BuppEC5)QIG)!7~c!-5{ZL^;a#|3h*D-KZIo4~KL5dL_IZ|H&$#TBP258tZO+}^owNN8T<zU5wKdJj7UEUDcOEu_0XFYi^Q32!"
    "Y*8$2tyt1wq9-tWGUK^J9;S>6!UVqFtgW-ZehW8la-13V;J#9qne6dAyHaX_3Ma^mMP_l!QjhA~`t@m@%`#0_&VjK{H#{)rsF(%X"
    "xtf!b&)@>ZxVqJhLh8`N7lK6nusV?!I27NcJsFJ9W<un`a+;+Cm!BcIH0gky`U`d#lpbA9P3LKl9-nSONBOy%me{=0=T+vIyI(iu"
    "U|O)c1amcR%)!1k@oBaph4<mrY<t_tuQ|AilAFb?m%ZA}{pb4^l**6=914WIWN3-2Ds^+r^+L%3+#GQ|KkC3u#baFFdTX=8N#wDv"
    "^gV-_?mTt6ZKs~PMEBZ?A#Ra%0T$Uq?6^YuRpy6oongEodgiuhRN~dy;P4T5ia&==cvU8I{U#L7$z^hClFOfu)7@t~>G>$#n>-tD"
    "@4OuEjz=$&XXoeX=*1*SN9XDG%NJW|l04tr+8OVrJ6kWt+b@&x(-)KHqtVNX<no#|)0cZVzx<`5$1GUDpDidR@04It-KfhMQlcy_"
    "@bB*a;$j7=^!NCtrDb2$V}Cdt=cC~;mY;$x5=z$NH<YI_BRO~UDbEzC?zgn_6!DatRVMr0=Czqjvx`sKMo8u0=?4^A*N?%MnEs|>"
    "b@Fd*Nlv-$F|(^wO~rXMhVtlf?Fu>_ksGy*DIojrt?XI#k<Jj*{0n_**3E`%Z#VCFG+z~KyT!@~rq|4%w`zo*w)7eP10NQMJ3?$w"
    "kGizkEH$hF`fZ6>B}C@>Y8sz42kR8XLGdb|Dgp#u*>2PoLAjUQ=KlO-DK$Mka(W1Ms~8pqBVlUM<Fu$#jU8<ogo^5vY%emiZ)r06"
    "KnR$SA+T=~^Oi<)nZZ83Cae?eG*!7qPM{?#n%afw8a4Xb!aQkP0}=UJH*<M>do?h#?ZQyg)l~5Zodh;-0S{QvM}Ww2Tn|b?KWgX0"
    "LK-&?Pm1QT;a(bwCD~|tR=;#AhQZybBVIoY(Lyl>JZM$J(&8rnZKkniHAHB8egqZCtmW}|h|LyLCfjbxFxn*W!`Wcl<cv`n)AvgZ"
    "*K9{zgFDrgEKOg6GnBhf=i=d_u3dH82zgXX9satlLP^1pY>`S7n#=l`NawaIa<h30-2hyn2|Z}*!@xX;J_c2#owe^&&r2qON<tA!"
    "t(AniS_)c=wHELVdbEhVqT1YgnS4g8F{SK)qY^>Jt@EjCGp3732SvdqgY(2fUqa`rY^qqTRNX8Tas}?U*1N1svW1RX)Gjm07|Ayd"
    "Lt6Jgoc?lj4CUj1#oX*}WUzuhhg)bG<l}_<+ACzu2h|ge{GzGnkmsf2FwZjK2IrJ29|THT04XVLtWCWN#VpfwW->wWuHrr#dMh%>"
    ">S4sZsStxXRmO1Wq{8yZi=BMKnOah%jR;L<%+<v$Rnt3C2hRG{Dh8%A&xC!{StgeD%4Qoc@6EfD2zqU_Dq_KacO=A8<MJb8*DBOO"
    "9VKoX{miC_nMAE=I&1OAxRM>r2&W$E*7VfLRu1VlsoWs#Dv>|cOdms*h;>@ns>IT=I-#C}GZ4(<D~~h|e{dU^-&u5aZ8a>4wLw80"
    "9_0(jq_pJX^!S20m0h|y+*GTf2}$8B<Vm*hbGp@@G9saR+hjUtbXHm9pr69}q1u*gMG7K=Snj@(NVd!#D-`0~b*v*Kq-a|#NUoA>"
    "3g(<42`_`-)yZ>h8$=@bWmF=Z+#828)kEKOEFNMCloD8JoFB<#<SJ>$>N>pA@##f$xhj@w?S;8y_;%6cm=vvSlTin=OhrklWh}wf"
    "e1)qYA@zvVpM?01I^tn;D^sIcnU-UE=2V26ye;Q*aJOu)uYkQ(ub|N}c39_+ctwLDn2da;WYPujvKFmkkIjWr^%|BFG8T2dVrS9g"
    "X!{m*;hIC1Zd7ohL6%i}f!$b}ydKKzg?S<wLHQl;vfR9lcOe|dtw$EUSRJqyY{$0pp{{CZFu$t0Bs*n-(nx{mG5STIl|Lu~nodp1"
    "D5>@f5>ekxdk|wtWsNp$^zzx>i=A|wY`xe`carmTw3EEt-ragWdU^iz#nbW2oxK;M(aYygUu>sOclNeN>e1edmwQilpKU+g+1;wp"
    "hIy8*ieigeL#h+2>EEq%1|3`)Be$2|Oa%4dIi?T+W|r-@q8m*pG2e}COTSw~y#Ceg-@@(y<eV7Cc(0c#k^1qHJ?<PZO$Xe_v?*&s"
    "ES)e*p@auBY!{Wd{3kLRVqvjOhcAehk~j8Bj@fHVRjgaUx~dhBGmm*GGTVV#TyJjag$?@Xfsi4JW71L`{|b^$?ph_2_0M*n{df~2"
    "Ih10hB-q(o>+SwK?FTGUAED@_3!fUNG3y_O<`T@XqRSbO1BxzafESGWYOHmwq6z{>9^SUuNFRX%O*B%X*lOYM;8-fh5Ee6-t&;;0"
    "b!%#=u}xVH5osMGg!iyeD=Jt={iw8itw)b2jGXekL77>diawihbMP=6{_Wtm6Oxay0Il)K*X3ySYB&(495oJB1A?)cN5JvIA-RT7"
    "5{{YYdaE>_&lE#@C<CI&C_>ynJ17cm5_K%<nMLRwA6SJNI@C4qLg0z*#Cqo0qvphJwjDqTZ?O=vSP=jcB;uTPK17q^(`S%wbv{M4"
    "p0$k~d^b;|4;~pQu5!+(odR;|eyC<3|E=Em1*UMMGci0Bb7Bx-xsUPs*G_mo<^H2?ofpo)c>3t;%DRkpfN;4-dRJchARLkyuCf`N"
    "YN*1dfrQwKU_<c}8R4}R8J%)`OhqW+uSiVD3G^o`lao*}`bc<0t^{+~VBf<>#fcEt+h<BkTCbnVrieuYbKjE|LEasPa`;Y_pbDUw"
    "5zfmzAK)5nqHGNn?-`P&OOD*?ZPbZvvSR34d!>WcU0`2Zw>VH)gDI+7R4b64%h5zhEt?=C+PFgixWkl<dydXFtjV*ZEmM4;lf~C!"
    "NJa5(O$yg7tJd*L!DSEC5IUhD`E8MuMkO<?5Mu1<gRpm3t!Edc8`BWse2<E!yv&!z*L9hV(8WjV6iS&XjV9i?>@@b-6yy3@lxkVp"
    "gb{n>k?Iq#Cc0#b)uodEwU|X13;Zry^6*b~AcCesPb=ECX#BYC_slPhV<+s9spaljZn=gPc4$ggnVw>;oT^~1@v}2<2pN#tj^)+~"
    "`)jrJgKTD3)39Wht@|m`llht+K8~(uG}JCN3;Z!U6`r?-Tq+X9=`oXYC~NEXfT=%8TTjEk(w&idDZ2vEdXk`0Me)muxU*)I2(|SD"
    ")*jYR-n=_`aze>sQ76N?7M=Kspvs&R$GGuPYngmUa1Q%L*@?Q(Nj^;ZEOu)f!m3PaIq6WQww*>6I!2Azu;=(U9zs%_$SROU0>p}x"
    "D9yIe97K^EIpEChmKA3Ck!g<x0VfbC<sZjCwfuxXN|JFq;(8<CnT2lY^wd;1k^bn9+S(0N2e+HN8mJl)BA6#gxze`6w&7@+6a|vl"
    "26DG;EIvK!fZ|q5+$39qMp6-J_TwFs`g9NwFUst(3y0W|$_U;8^&Z^CrGhP5ywW>udM--x6?A-7?zY6{RkZ{B+tydUNLSA7LsJ{H"
    "F|$c*H1IV|k$i18!)M$Gj-kLjGDs<a;6XmiVxG^`m(D0aRt-e{!7j2@Q#soj$Q}6yZbzvlryp>V0<dmbWFr7WP4)%%nV*LCD=<m5"
    "ZT~n6eP2~JqVD{&i}eZ+TXiSE#E}ch7_?b!lXi8IVclu#c#jrYba-LckX|XZslW+VEhttp))<42n)`+uMCL%SvIvjL5{Ek|+qLIi"
    "o3|eGEV-%diP!Uvqxi%!S@XE-XTZ0q`-Evq!w9y{q6U`X5N}*G8F<kFXHJd*G&nFBazfG-pY~<x=z)-kT7?)l(K#-z9c@`4)rU?K"
    "J1nc9@MHbn4b9RQsGSBASy;|cf75b0Z|mth#xYX*+WP=w<0zzQYzkeq_{+9C-EwHArnS!PqIOb`)1|69KlGi}`t1g#+x6j^EB-h|"
    "N!%12pCMG15Ts`6cIx>!c#K=$P3B-fYMJ|t;Vy3(q^V{Jg<|B|mRHa_pjEgY=xUv-z5mb<26(2s#M%sz#~-d1Q^N0moCRs*pk1XH"
    "*2lv-X_=@Pq~ya=Z-&2WRb8yMPmitWJHOfz^7bh9t!dCFyXg4Zw$*P-bL&^GUnYU!uVqcQ{uyk(Ec1p3A0A?I5x|T=^~fW2Nc+bJ"
    "C-0Bmog560-o5>8_@5v4-yZ(;@HHlQ8J@g8dVkQCl+od;h8f@`@ITmL-+S%yf}9(la+4vChyULud9P0i&m4)fzem13S{DfbWiC-Z"
    "YDw0wl5f;&7QCa(2`20>CB1I1)~F()+BlG8y?)(IM#h?9lakC;)eqV7)hZ=Qax^kp5D=-4DE+-Qb~pw!*=jR3fV=U;0d>bf?FHyI"
    ";><~s3o7S$lI3UH_ghuj;gP89D$iLA8rN0Ht)Ffn#|wma1#B(=f1!WCEK$wxhTzmS+|3F$GYmQtEgJ!0!bbB(k6AOc8Iqs~6R4eq"
    "$6F|~&}q6KeSP$ZnLZF&6%8peVchLSdZHx`#LFVQT!<A5o~xWpphRwU<^$D5`Hj<6D7!Hv9}v%EdpF7L_p=!hFr}#oGw{s9`7SF="
    "CcP+Nl9c3?)R98Y)~pE$*ui|1uAxRvu_D)IJCq}^Pr)``o)(&hPKGW+R?#=Zm^R2sxaB8M(o8rgK~&>XzO1hg7uOFlU!rEb5bzHd"
    "`NLc7=)q;^faQjOBox6OD;XElPw)e~JJ#8RXLi;jw})~9bntG3uh3uFruD*ras9CzanLR1(+pxOdTM27+XML0r0B4|Z9L&}W~wuO"
    "qa;_z27*uty6x)rICGwVRLVYv-w&LvKkMxDu%)ml2Qo{2TLuzq%B1)7D|SuLJ+q~^p`=yi{9BYYfofEtF;u5Z5RdN6fH*G60k#_T"
    "SR9ZXuBfMD?eOq>P2dRDXTw_0(QJ0R=*vnlEtq`BohBD)aGsSj`v&+Hn<SJTeFttQiHzo&*J27@lN%o8>TtOpyww7{&z&z@t@Z$Q"
    "zCi#qQNj~sq<=knb8ym736G3~<kxuLK~h-F74g8TS(G|KWPW#SBCflWO&ibV5s|4BSvA94QB^C4yD}dK7%8uxmZ)IJ8`7uiQlkLy"
    "R5IfxT`|WW-kl!)dVrVaZ5t=ihyN2E!x-&j@0G$NqA|GTNPQ%ydM#uMfU+v4q{$AE0xN22XJ6Q@8D^%zjYhr#SJgmXYMaFVh;Dt2"
    "bY#*H$`=Yy7P*8cY}iBgmu4UXHb|*sfkpWa%4q;fDafcAeX~RdUQxp3r>Z(}o|cC4KEY{9t{YZ+bxsCZ7#FGfg?WcDr5<Pxtv_RZ"
    "Iw33VjaLhDCZ_ma(pR~4xC!)UW!Md@(jPtT%~w{e{2Fk9+p|otS1iG-v-50=g(nfq9r8kqLn%%TDK)1~hIu<#;<<_j&^za-pyX3g"
    "{^nlN<p#vSQV|?-U>4%Ve34(JGtfE9_<A$>N~t3zifz8u#&cPIG&FYk^so1TEPoRRH;JrikO?g*@Xmz?aZnp%d@599C3$gs%ygn1"
    "f3<#z0`ggBCe=(uIImtXV?i~---gIe5On;`cL6U}m#vanGt_Aqv1OGLVpPm!3y{zkJbT0Y{y?EFztLsg;XsGi3((`5s7+T(WD;lV"
    "_%|oRor!}h=e-Ncc;yUUR+NLoU}_7r1vOgZDyT~`e`SH0KSU2)`t#OFPNem+Tz);DgtHRKtoKcG_cY>R!pQ~Yjs#m&^C$r!W&?i3"
    "6b02A99pW`=SnyPx4Trf`;o5QQ&nUlSaf?6Y`Bw8QBx-qy_0;Ev%k&n>N1Z$DHK+JLkb~G+-2N{C_RcdI{=_gNG7y^mQd8n4--45"
    "uco_O;R6U9wr~JsJ$a=5h6G1+yL~&`%|<n!mkzJz%uICf{qWZ@V3?}Q>hh_w#e|B8knU}hTt>EXNQ;VnQN;)mA;X!AkbCqes6A<P"
    "EqFIWk+lB#mv*_zN$f`Q$$tHuLF7q{8z3CAsJPfr`((uy_7w%jnjIY_PcGdfv?hO;&Z}&lvB)n<(P~^T`UKO8Y}g*?O4v)G@2s77"
    "*i>gyf4lX-?eUbI_?2H;esyu%Hje&MU3=WQ;0N(q!zOJW2jSI~pIJKx>Z7R_9UWkXbR?h^T_=UE46B1C!6QS%(99KtevoxwqQoNm"
    "u3BrU1KvW0rU+)6@1W2tGJIgz3*Is2i0O-+^SR4PCYJjUJ}OOuPIRznAkA>QI(M*REy9GW9(?|1M0?00GJZ&h7tx{N-~=_)P)VRS"
    "as!NKw(8z@%XVu=dEv=nV#w7lg|DKwIfI6$Kx~eq&5~Z-WUa8S$TsaC&WK#>)3HvS32Z6FXa(-NDwpeFV|QyeD?<(Yv&L`Qa7b<e"
    "EO}>{1GO<IO~OooB{{=!+DziYN{o_?3kV)4oOo3}?qDA7(jwx)w_${ipElKFGzG<pN-x#*;sX%9GH0u4UIot^WV$!-N)7s^`eA{M"
    "LPJGm)!0qcyFM1w=i7)7mRv8|PWe{)5mI!P>#$ibcIet+!K~ZGIt~Ut)tj%FmfzEvRa2Q;mkt>Oa!)zPs3<4aWv`Uxi*fye{N1f^"
    "hiMjq87f*A_7f>xjjn>QLObYc1KU!~SE1c&uh*W1bV9XiueQ}(3B6RiO5xLXl{Vqw9Hwq<8i5LhOv#5t5<n5!=zw})=(!V<>bH_U"
    ")6NBI1By!9rEdeF&y`<@6r9k|s&>oA-y4gePegl->M+<r&F&7?iAW*kW^j--c(-;S->IZRfg2vY7JqCMqqFDr->k)e07e?mZM-W2"
    "uJomAnR1h;4UJ2&lVC;+wGY`C*9Bhc>%$YK0s)oAMQv@%yM|ttES)A>zs!kmPm8CT_`Wu`MSjg{nH7~tMq+2J+TMOba}feT9Qk#z"
    "0U$o1aOer}i}XTunJzeP#|ia-Fbfz1i)e16u!vX<&(5|6EVN6y6vyOUzr@De?#yj7P~xu>n~`5*27YX7AA?0lJ)eQsd5c1dgdX2)"
    "k!GZ2LSvXNyO&A^x#ibxyhfpEim9sk=Q)%-5Wk^_+*tg+q*&!Pq{rC<4U{NX%230JD=2s&73=sG<5!SjSut=Q_D~iv$+bONM5QBY"
    "dLgwrOhwP!*@C#Ov#gS^<OT}(K<?dx{kE(RE9c9vv>#Vkb8A&3oE~1Eem=Mti)5~tW5~gWp?w^|!g?>aVhX`Vd(wY{X)J69^K84f"
    "qUbG91|x;biy+7bQE2{J)0f`OO=xFM5eLA_&cT8`CdOIalkhh}(IXo=(vQH6^Oi!B6-8W;Nr)&iNu!dHOvoeI<N~$`l8*cwDQK(m"
    "BqS{&5f+!U66+Xp^;tVQcn6iUe$`32E4XegJi*=@%Fm@tj8@9GB)iWnKT^ZmW(CPE?Wj7G5Sd;mk3kWLLz8hCE**GknrlD8#=P`8"
    "R@rW=)&3%6%5gyk#f{kM$fx2nM;u-6v!<O#M5q?>#6V54KbBhc1jI$X5f9evSXqd;HF~H|t!}r_TBKK5zAAb_e3o<@H`scbiVat-"
    ")NQ3xuc9wYVL=KYcXaH7l4i$31Q`L>(cSDDBX(6tVFg?`KXVj-57C(-N@TeW%cQv=cbw}=b85WhQ778oz$ahKw)mXQ@kU|CAyS~}"
    "894R5sldJ7+Mu4MZY_c)_RU{1iq1g=%Aro`#LDA70MB8+2aP=D^8gWn4}ncIZK~s$1=}KUP=DtN0amtl#i+mp{E*|iwtxlV`8rWX"
    "&+}g+ya?R7OfSzBRrr+6IUB*0LIW51ELV*0O^Ix58qsM4>#CSe*ot8}Kbnr9j2&m&U>-FG*k$w%-+Od$d5~_6sJ<~s9gBfc3xYHN"
    "F_DU~#e5>LqRbVFD#UDY7Y{r!E!1T5%K`(`6B~knlZ5mZ9J&f+;nP{+<O|}n=&|?tWKuu^ERF}Zu?V4wIz`Bl$x)v%i({CD$PX+<"
    "wufpXa|SpQ@9XdfdZeIK(>AUPCiGXK<+Y94^$6W#xw6U_W8$x+cDXsZ*V8Sh5~745$RATYZ8-&vOx1BFz%!uG4jtWFDtcyQiMf;E"
    "VogMIUBI<x+16-cBprV@duGz5@L}0;uMGEf!NFyUL%|yI#FP9a>3Gk%py&e9i-^|`IbUR#$>L^6TZNfsH;qtUJBAPdb;4A$hZt%t"
    "#Jv^}iEX$!oQ1%HXC$IlE*998=r7T;t+3j#>Mlm@ZZIHRCJNA>2Qs`_rBxL}u~w&9!;6?(S{!Xyc91>+2!aF1R%e~<fqUkDaL-)4"
    "NwN@({D7o|$r2Ag)gA<?beXFkSC%*%>@NHyO>6fkj{YtBx^|B=6M4Jwg+da2;rO>BQ}m#eyvA^<j}1;ZIzpbNf360BtP_-w96sU)"
    "@x4v_VG;2RB0YmRG)?Dd{`2Q(=(pvKM0}7*q7)XQ%=<G>qy<s1<!O{yzG>@qxf&YxU2U@Dy`A$HFUH%GXHO@S7hBKM?aAor?$-9R"
    "7u!#_CX><5*4FNe-JQv3>-lJB_xba!-JR{1&t9A-lil6z^R0BRDp@ic71Mb>`c#B-B^xgy*EY0BSEjf}U6WQm9S=>uDV?T3n^1$*"
    "J&xwf4&Va&Vxl|9E6|%yK*)b${YN`IFwiH=#y*)Q7qD+?+_6*L<9v~gsl?>#568!#Ir{1N@XgN$s6e-y&&|rJW9j0Y7hMjA#jjr<"
    "{rZ0Y^zf&{w@||4;N9QjQYsyrZg?%9qnTnilMu<_Io3i3&sFO;WW&*IrLwpbCPbkhUglw`naK)7xK@l-gW>0Frh|BpGXk{fAj)*E"
    "o^{yYpaU#|I&Zpm4^FjnwNqlBq~omiRp4)j^4ow9?Yvk`vAT&Zu`51shZ(l*HV2z?@Q?JY>U*2{@xgz-K6x{IyZ_Vh@K>nn`R4HF"
    "gOgL&5*dg$3XaXwzmH)JZfe(80AB)i!(v^mNhE+$o6s=@oBiGLHmGiMK+;i=JI|(2fu*!N!IUGR$iZO4TEd{gS*d9fAIl&gxHjlZ"
    ";5DXWZ_HrXlQrj?_vU#2{o$M8>;3nqAC3=(uaDlH9v{6O9=<y{-GBQQbF(-HufgfBy36=L1N)mTq^r7?YrGweoHJx<c*dba=vIZU"
    "J&Z{aRiCvcy}8(v6cN90dtxtFNHu_J$e}q$a`bNLP<bTH2mK60pmdy3$q4I8J4>(4t%nzjNs#Z?&=rr|Yt6%VsaFvp*TXwr84_{)"
    "o|++$dv&M_1)X2Lq{kY|OtET&Y6)u$sF)J>HMi15>DGxUwDVMak2)wPAKo5F1C8Aqv9FwTf=@qsuo;YChc<T#y2dd3=Eh~v33qZQ"
    "ttXR*a({lSGL+dNRAbbgC{BE*<4^nmZ5{dMcc`4UgW=9W_4kmEU3VjTEW7v5W~qO1&ex9Oc3e;P-SmG>+KUZFY<SPqaNj%0?%w45"
    "S@QJRUh-_`{AIG2Y$sdk?u%zHpCwzn>CX0KXLs~`XYc7~^kO@G`QoYK$R{tJzu4M+_HySL7Vcf<`LuWvEavt<rC@KTqn-Fod0FE^"
    ">7=`@`@FN`b?_;j&if!`D?H@Pw9xKVM5!t<r4r{lzf5jSN@B>A99?YfShtL|b!_!H?r2-?9hc#rrqE)lf;)as7kP*6i2g0@lh~@!"
    "$+^4D)h^Uvq!SDqgmnZvO^bZRa|rdxkWXL_3@~%Pf`}9V5P6iVX)mucp&K<tnK0~oyB+PsPP&2eWG66NGQJS&Pj#4X!ypr0PNYXe"
    "Kc7f^@0;kt1A_aH97)ucR%B7#K<fW=?Pqo0n(`-?YLsjCvRzH4IqS@e4*!aq3~oJmN{h|Fps2=AR?}sFyGduT!B-6+$2Yc4YdW?f"
    "pXq>)%OuIB>_xT~&4fX>v%N`4Y5C#KH<rcr&ZSwh;?i`igRKDh|C}7X!(8rWZA}VPFBdni<bb71$s?!IO0Js;>>O@8@nrySzr{|l"
    "1%@(gSHIe+nMb9PAkWd`RHsFU)u1l}S-;Imqca9DPK#wx;tW_jK#=aTDT8eERPmKO>+w&ANordtx|NKZ1nkj&&hRsVOv7#NN<P~e"
    "v?IDXkm2i_Sq*nK7)uiLK9?%CPwFLmK!w>2DT}pY2#*^-QN*&0D(wJrv?V&oA3JeV*3fROFpe0zq!<mgI7kc&nrxaVCZB4?m3e$d"
    "53o_9cb({{uf&yPxm@5H+u$N7*JQ|6$Q*+q$EDA4#p1ijlGJiz`>uW{O9;z-*musb0?EqXNDQ<e1)@;{m*$|!5wknl?6m1Ey6a(c"
    "OpW2w)a;O?U%-7nY8{;*Qnm$xwxd%;*7?uBr8oT7F<n;tt5}_LiRJEz`4iv8pdr9AL#49R6Yaep$!fbA|9jC_DtUyxbcg7*Ivn1r"
    "=lBS3Rk$|##f@4mmf0z%7T?j%Ugd({LbJ+=C8-!&gWMujJ5-x;#7~3QMiiSZ`#Z5~KiH}jTFzfSf3~;1wY$ANnv6&1J1@4z>E7P+"
    "(PRt$JAQGVj$gb;(&x!!G<rT6KRw@iIiBoIo~GlM=P#e76JKc2u&=MI=ma2h$gz#?ud4oS5?WZ%h9o2O40XTPcfa#cmfj`{uTIde"
    "Hca&^*?#R^Y6h`IyVs0l%ZTbv!O&AX+1OhUhGLT-?_{~>qNcjKX(>IuDMeKZIj*n5>6*B?b1#J0_Wi^ZoX4~Win@J#(CtETrJ4Q~"
    "YLvQeTl_+21{06eIK|E7G@E^HHLm#0fItK9Iiw4js0l$ZX*Px6`B@6P4OtNEta-+fsk0}UU%fS^6kp3O#D)O!v&+xW0B^3X{Q1^a"
    "sj%Hy5bR!_t3lfi%(Z7onByJCM36qB&_kMszC^5oz%3z6)pivB?UahDt0HX5%=PqQ))o==(H^_OBx*YSl9^t)DzTnnl{TzbcZ3kX"
    "heXbXaqRYdKP8CM*;S--dW3TT2$d~||7*3ZYSzV?b_JBz(DngHZ)W=LuI8YTY8k7}>!Y`C4_;#icQo+yH>^Z1Kp?CUWGgy3`f&XE"
    "U<l8{-FlhXN}avmKi*f<dpq3!aQe&9G3caEe%V+1)Gy&ca2jvkoeYl;ULPF3KOI7Tg}%k)U`6_N^!_(B(7QKB?@s?q4R`R<Z>I;Z"
    "kKP<8$!|Lp*REq;hj7vByrLRq?4&{0>|3_9!MhvOylDdlmsS>8j)hEMx3k<##~W-(?(oNGf1&6V#JdY31>yD4r{oH<8AVrsfEdm7"
    "N$cPt8F#91Gy)KIWpA&Og%a|hr9M^<jUHdIP*6&c^tFmBT7ugoDAoX>nQMY+cbx^DG18iy|K;dJ?H%q4y2C}lE79a3@JX{BiGtv`"
    "9bp<Y^%q$-=Goj_Q$(iwqCO;7f0UOdk_*?lUgW)W1$H=Mkwhk-wOw6TG47%j;^Tua=Wt&s4wBxqgP&l1#o#CEjVFTXg$RcAJ$`uR"
    "LI%i92X&?h!k_m~4?>BQndmZ=XF$dw=RCDLef7UKucWURM6>MEKW%h(P+b&#-B}y^R<Is|iK|G_=Si|X=Eg3%P(Um-v+$)se5#h-"
    "*)B=K8}L0CJ>`*)W@4^6oL2Rty&^byjwn@!2`8{JJ6B~7C^^EHC{}+*h<)q*x%oXROQQDl5efDPv&1BrjD^DQ8!%KIzA=g-nlgmj"
    "=9u0|wGCz7hhYGML$VfB-O)aNtLqWU#<pS;HzzQR5+!On(T>zv`?<6;1`~BV@4X;1J}!cEp-|yES&Umnb}?IBwxi)>0XYc+NCtW1"
    "30mrcZN(L#p<-H}v*~nxVL=S>lrV^IQ&%+h8dJ58Q2_vrl$3vR`19erQ~HK}o*o?k8k(3Ue`nkaQeOIs{%P@xwq9+}G6wqqrdgcs"
    "b&?sErnUI5Y1=)VfGVsmRaq`Ej$YN}o>*0B43eLa&NbpC>kfSBEa-y0ck0?+O2KXw)xLALba9oty&qoKmi5%dLg?~?V0Ap7<8E{a"
    "KDLB`nC3@q|1{+U?7$O`l=u(T21JL1zy)Pe8mCkT2`KkO9m4z?y0IzioC2>JDFrKM4_ey{E_`nTdCMt}Oz<di2l9;Qen#pJS+pGW"
    "5Lc}=o5Yb~EOZVt=GDCmQ0q4u97IvNlK@~&BUhv?DXZwYqmlbbU3~}mC;RUBsx(Cd4L$u!KicZu3oX`^wUm3W0llrHvxbDm0iLWe"
    "eM8%a!rk?xEk7^P#npPTmJVI2q0G`qFAAw2v6!SnVsypgLO9ssJ04=>rF1N+g5p#%(r|>dLjY>6qgIKZ4`g*0p9HYR!5rH({{AQT"
    "LHl3eAVFFj&+4p`6T&_bZP00vmf0fhFeh&92UX@#p=Q3b=fZju>zys99=8wn0W)KnvB7ykuon+%)UxJlqY4$jO8QV~rKN2lKUlpR"
    "CI3z)<60%{%*rvVIOf365dOwi4J9B3A847(8(XZbU9sYN17%RP9MWyOTNbaIb>%&`7IgnABasmtnUDFtmLXjgzNxVW!yfS)b}Q!k"
    "w+bY12q+)vcCAS#c{$mA`h55K*3Q%9#j~wvlf9=~PscB}pQ}I4ch1wTt?};jWJmpP>-^cyvn_Rz>^y(Amp*&0{&T)pGU@0vNwpT8"
    "ArT2(44i(o?t#X#7$N8o&@<S4{8hlG%f662!lVpt7)&`t<tiwzWJjdr)%j;L_64FKA)C~W^JrK%vv%ZCbuGRa*DOuw^@Cuh4ki=!"
    "8+H@xxRo@xC;QN;Vu)qO45Sc1ya6KrzIGYr45VQg_*c8?`P)6{<jDPR8d>LBZ!~0eH~QdoSOMPDqp`l%d+m%pP&+23=bL+^j98W_"
    "v8m$j1j42~gt;N@_R}G2wBaHF;3n91ubbq}UK56IpMNt%(D^Q{|DfK%1*kh)nBXkzROro|$XK%@F7g3=BgCCRgYSIOntd%Yk#6|u"
    "Mp$3n4SGP|@dT;+>ucj%;<nLd!{yTf=}g`31(@+2q$!O=JP48$F?v&g)b|}y%iah5DLd>{Zp<APLwh2b0l_ESHeQov0_uh=!LUM<"
    "sUJyt=i2o9RcE0Bg!MzXNsBG<TDQ1+Jbd?k2y5U_MQOOyu)AdrTWC*HU?akFF_j;H#iJraE3M;Df1&K9`9m$58t0S-{8z{%URlaU"
    "7gQ~m1QG5()3J%E!4#s{7bQB<1xHCh)Dn#jzrx(Y?V2x~hT%x;s#-M!m&7mgqM=*4E?GFL+R@Tq3fJaQplDQ!Cm3MIeJ~{N(2t3I"
    "(p+U<Ll!g85JdboF&73hzQ}P6YL$39P77!NZ#=BX39D6hWGx4#>q&BeS@yfyZ%F3LS_Uskw65aN5NXO=FVaGWT{%hlYReXH?`>^0"
    "D-jojS%9PT7EUc%K^J>(_5BK%ARpQ1!B;a0WiCWu^N8qS!#O{L0Fw-(2Q<p&X9^ucz7CyhxjLyz(Edz=K$!vAna-MV_YEj9#+J&h"
    "As@EzU~Ia!A0uhk9xHC4<%Y;<I~7l<U+X**Kp3aYb!B9REOCnu0u>XQxsOXaXrb3PfB7Y^`}|Yj5|^paD{#tHeA5ad4{4$L9mErs"
    "@Vu%7o<|x8SzH{~_0Pq0(PLhNgzm8rPCJ=`5vSovWeQ<kO5tW`Qz7?IyO@q;8O+d78y}84%NpTRwvO93_v+eXN4cz7Vu{0X@iHa5"
    ">6kPAZB}g<1E=(8nj^!ML0{&OcW{ZFM)^eK0JlR1B5BAx>mAimzL>9yRyeT3&OdB}@cPsUja`~TeAUOul<EtV&O!=RK8@mhG(1Lk"
    "<^+P+BqXffS~6%Fw?y=eh)c7=${GOQ_55?LSsq^2hv}0e-2EKbDv3~sPMbX?e{;+|FAHA@xX9=xl1%!gxI20tgpv_`dhE-ni{VtP"
    "O7m8fnI@Z1{({aj@95eolEbK5zN1m^HJBTLgw1bZknlpkfyMBw1HH<lOQ|l9z!_s&#eCW($!I`2+^9dB_&|3^m91*+Op~X(+gmS_"
    "^WDi_GMPLd?`<W!FDK7NPoF=3zW03h>G{s{$&2%JXLLT=+1c9OnmkKiyxbcnJL&oPi<eK62e*)J%yG8(|E6SRr~|uP5)^!ypws6K"
    "EQ}LP5={(^EYmF0k}QnP%+ib#lM+pn(u^(5lPwKWlg*5bElrb^Y5_bGoI3"
)


def retained_controls(current):
    raw = zlib.decompress(base64.b85decode(SOURCE083_CONTROLS_B85))
    assert hashlib.sha256(raw).hexdigest() == SOURCE083_CONTROLS_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == 1
    assert value["source_commit"] == "083a4a4129f9fb8366f3aba5bf397c90ec62395c"
    assert set(value["files"]) == {"qcsd-lab", *schedule.V3_CONTROL_DEFINITIONS}
    result = dict(current)
    for path, item in value["files"].items():
        source = result[path]
        if path == "qcsd-lab":
            for name, start, end in schedule.control.SHELL_REGIONS:
                assert source.count(start) == source.count(end) == 1
                first, last = source.index(start), source.index(end)
                source = source[:first] + item["regions"][name].encode() + source[last:]
            starts = (b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )); then\n',
                b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )) || [[ "${rapid_capture_version}" == "v6" ]]; then\n')
            start = next(marker for marker in starts if source.count(marker) == 1)
            end = b"  # Docker's isolated client bridge"
            assert source.count(end) == 1
            source = source[:source.index(start)] + item["regions"]["authority-transport"].encode() + source[source.index(end):]
        else:
            lines = source.decode().splitlines(keepends=True)
            permitted = schedule.V3_CONTROL_DEFINITIONS[path]
            for node in reversed(ast.parse(source).body):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in permitted:
                    first = min([node.lineno, *[decorator.lineno for decorator in node.decorator_list]]) - 1
                    del lines[first:node.end_lineno]
            assert set(item["definitions"]) <= permitted
            source = ("".join(lines) + "\n\n" + "\n\n".join(item["definitions"].values())).encode()
            ast.parse(source, filename=path)
        result[path] = source
    return result



@pytest.fixture(scope="module")
def source_bytes():
    root = Path(__file__).resolve().parents[1]
    paths = {*root.joinpath("src/qcsd_lab").glob("*.py"),
             *root.joinpath("tools").glob("*.py"),
             *(root / name for name in qualification.IMPLEMENTATION_STATIC_FILES),
             *(root / relative for relative, _ in lanes.TRAFFIC_FILES.values()),
             root / ".dockerignore", root / "Dockerfile", root / "pyproject.toml", root / "uv.lock",
             root / "neqo-qcsd/Cargo.toml", root / "neqo-qcsd/Cargo.lock",
             root / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs"}
    result = {path.relative_to(root).as_posix(): path.read_bytes() for path in paths
              if path.relative_to(root).as_posix() != NEW_HELPER}
    # The new control helper is tested as an addition, never assigned to the
    # earlier installed source. The minimal Native fixture still uses real bytes.
    result.pop(NEW_HELPER, None)
    return retained_controls(result)


def test_actual_integrated_source_changes_only_named_control_units(source_bytes):
    root = Path(__file__).resolve().parents[1]
    current = {path: (root / path).read_bytes() for path in source_bytes}
    current[NEW_HELPER] = (root / NEW_HELPER).read_bytes()
    facts = schedule.source_changes(source_bytes, current, client_sha256="a" * 64)
    assert set(facts["changed_sources"]) >= {"qcsd-lab", LANES, ROLLING, NEW_HELPER}
    unchanged = schedule.source_changes(source_bytes, source_bytes, client_sha256="a" * 64)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert facts[key] == unchanged[key]


def definition(raw, name):
    matches = [node for node in ast.parse(raw).body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    assert len(matches) == 1, name
    return copy.deepcopy(matches[0])


def replace_definition(raw, name, *replacements):
    node = definition(raw, name)
    lines = raw.decode().splitlines(keepends=True)
    start = min([node.lineno, *(item.lineno for item in node.decorator_list)]) - 1
    replacement = "\n\n".join(ast.unparse(item) for item in replacements) + "\n"
    changed = ("".join(lines[:start]) + replacement + "".join(lines[node.end_lineno:])).encode()
    ast.parse(changed)
    assert changed != raw
    return changed


def body(text):
    return ast.parse(text).body


def factor_enrollment(raw):
    original = definition(raw, "verify_enrollment")
    worker = copy.deepcopy(original)
    worker.name = "_verify_enrollment"

    class RecursiveFacts(ast.NodeTransformer):
        def visit_Assign(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "verify_enrollment"):
                node.value.func.id = "_verify_enrollment"
                node.targets[0].elts.append(ast.Name(id="_", ctx=ast.Store()))
            return self.generic_visit(node)

    worker = RecursiveFacts().visit(worker)
    worker.body[-1] = body("return value, classes, policy")[0]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("batch, classes, _ = _verify_enrollment(path, _verified=_verified)\nreturn batch, classes")
    return replace_definition(raw, original.name, wrapper, worker)


def factor_sites(raw):
    original = definition(raw, "_sites")
    worker = copy.deepcopy(original)
    worker.name = "_sites_from_enrollment"
    worker.args.args = [ast.arg(arg=name) for name in ("batch", "all_classes", "qualifier_spec", "workload_root")]
    worker.args.defaults = []
    worker.args.kw_defaults = [None]
    worker.body = worker.body[1:]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("batch, all_classes = verify_enrollment(enrollment)\n"
                        "return _sites_from_enrollment(batch, all_classes, qualifier_spec, workload_root, require_current=require_current)")
    return replace_definition(raw, original.name, wrapper, worker)


def factor_bindings(raw):
    original = definition(raw, "_bindings")
    worker = copy.deepcopy(original)
    worker.name = "_bindings_from_enrollment"
    worker.args.args = [ast.arg(arg="enrollment"), ast.arg(arg="policy")]
    worker.body = [worker.body[-1]]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("_, _, policy = _verify_enrollment(enrollment)\n"
                        "return _bindings_from_enrollment(enrollment, policy)")
    return replace_definition(raw, original.name, wrapper, worker)


def checked(old, new):
    return schedule.source_changes(old, new, client_sha256="e" * 64)


def test_unchanged_real_sources_derive_complete_dependency_and_acquisition_groups(source_bytes):
    facts = checked(source_bytes, dict(source_bytes))
    assert set(facts) == {"changed_sources", "control_projection", "dependency_groups",
                          "acquisition_source_groups", "qualification_dependencies"}
    assert facts["changed_sources"] == {}
    assert {"measurement", "acceptance", "chaff", "traffic", "native"} <= set(facts["dependency_groups"])
    assert set(facts["acquisition_source_groups"]) == {
        "curated", "fallback", "navigation", "page", "preparation", "browser_policy", "collector", "attempt"}
    assert facts["qualification_dependencies"]


def test_real_enrollment_performance_factoring_preserves_protected_dependencies(source_bytes):
    new = dict(source_bytes)
    raw = factor_bindings(factor_sites(factor_enrollment(new[ROLLING])))
    new[ROLLING] = raw
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {ROLLING}
    unchanged = checked(source_bytes, source_bytes)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert facts[key] == unchanged[key]


def test_exact_named_parallel_intent_and_formal_guard_are_control_only(source_bytes):
    new = dict(source_bytes)
    node = definition(new[LANES], "prepare_lane_intent")
    # Represent the prospective explicit parallel opt-in without changing any
    # module import, constant, neighboring validator or historical receipt.
    node.body.insert(0, body("parallel_opt_in = actuator == 'parallel-formal-worker'")[0])
    new[LANES] = replace_definition(new[LANES], node.name, node)
    guard = b'"${rapid_capture_version}" != "v5" ||\n'
    assert new["qcsd-lab"].count(guard) == 1
    new["qcsd-lab"] = new["qcsd-lab"].replace(
        guard, b'( "${rapid_capture_version}" != "v5" && "${rapid_capture_version}" != "v6" ) ||\n')
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {LANES, "qcsd-lab"}
    assert facts["dependency_groups"] == checked(source_bytes, source_bytes)["dependency_groups"]


def test_only_registered_new_control_helper_is_an_allowed_addition(source_bytes):
    root = Path(__file__).resolve().parents[1]
    new = {**source_bytes, NEW_HELPER: (root / NEW_HELPER).read_bytes()}
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {NEW_HELPER}


@pytest.mark.parametrize("path", [
    "neqo-qcsd/neqo-bin/src/qcsd/mod.rs",
    "neqo-qcsd/Cargo.lock",
    "config/defense-params/buflo-live.json",
    "src/qcsd_lab/capture_session.py",
    "src/qcsd_lab/fidelity.py",
    "src/qcsd_lab/chaff_qualification.py",
    "src/qcsd_lab/class_acquisition.py",
    "src/qcsd_lab/cdp_targets.py",
    "src/qcsd_lab/rapid_site_admission.py",
])
def test_native_traffic_measurement_acceptance_chaff_and_acquisition_changes_reject(source_bytes, path):
    assert path in source_bytes
    new = dict(source_bytes)
    # Byte-sensitive inventories must reject even a Rust/traffic comment; the
    # Python mutation is executable eager state, not an ignored AST comment.
    suffix = b"\nSCHEDULING_REUSE_UNDECLARED = True\n" if path.endswith(".py") else b"\n// changed protected bytes\n"
    new[path] += suffix
    with pytest.raises(ValueError):
        checked(source_bytes, new)


@pytest.mark.parametrize("addition", [b"\nimport shutil as scheduling_transport\n", b"\nSCHEDULING_GUARD = False\n"])
def test_named_control_file_does_not_exempt_imports_or_constants(source_bytes, addition):
    new = {**source_bytes, LANES: source_bytes[LANES] + addition}
    with pytest.raises(ValueError):
        checked(source_bytes, new)


def test_unlisted_validator_in_a_control_file_stays_protected(source_bytes):
    new = dict(source_bytes)
    node = definition(new[LANES], "_validate_image_proof")
    node.body.insert(0, body("return ()")[0])
    new[LANES] = replace_definition(new[LANES], node.name, node)
    with pytest.raises(ValueError):
        checked(source_bytes, new)


@pytest.mark.parametrize("path", ["src/qcsd_lab/unreviewed_schedule.py", "tools/unreviewed_schedule.py"])
def test_arbitrary_new_source_file_cannot_enter_the_bridge(source_bytes, path):
    new = {**source_bytes, path: b"def bypass():\n    return True\n"}
    with pytest.raises(ValueError):
        checked(source_bytes, new)


def test_shell_bytes_outside_named_parallel_regions_remain_protected(source_bytes):
    new = dict(source_bytes)
    new["qcsd-lab"] += b"\nexit 0 # unreviewed capture bypass\n"
    with pytest.raises(ValueError):
        checked(source_bytes, new)
