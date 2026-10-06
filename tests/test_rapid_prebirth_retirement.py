"""Engineering fixtures for an unstarted worker's preserved failed batch.

Image, admission and canary primitives expose controlled facts. File bindings,
real retired host identities, closed batch/public receipt schemas, lock-held
observations, retirement reopening and immediate successor lineage use the
production code. These fixtures grant no installed or scientific credit.
"""
from __future__ import annotations

import ast
import base64
import copy
import importlib.util
import json
import os
import subprocess
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from tools import rapid_rolling_capture as cli
from tests.test_rapid_ordinary_parallel import current as ordinary_current


ROOT = Path(__file__).resolve().parents[1]
KIND = "qcsd-rapid-v6-observed-prebirth-lane-retirement"

# Exact published V3 validator and changed control definitions. This immutable
# fixture is portable: no Git history, private checkout or archived runtime is
# needed. Its validator hash is independently checked by the compatibility test.
_HISTORICAL = json.loads(zlib.decompress(base64.b85decode(
    'c-qx{i+0<{k?5~rlzY~sLsE|!dnTN4&sAhiqK#i`X(l^I;=zGPP(n-*900VfIQsXkS3l7JLD|`RH+$AY0gdYJ>gsxRRrTk+56Lo{'
    'CskhTjibFQ`oFhDUar$wm3>H~a(0`}H_L2wGt5`Z`{=g~v|nViq{{MDRHU0SjTU(k75Ney;qSX-8O@S)wJFlk)#_?>ahsJ<vZ-$K'
    'BCGDBb&-~7@gXgv>Nbtw*-f^BFVYo)xJy^n0Gq6nBArJ!MY6tyk5}_(mE5KCtJUGr!4Lqf^A&XL3}zIaRna;v?y?HLfT4ZJ(vJWG'
    'I?Iyfu*!!3Gg&TE7+t=qptq~l>^525q*1b{(jv;2bNE*#uuN7k!t_&CRs?vS!=J0XiUeP2R29hr`W`?}>t!+nC@|M#ewURcqGq1X'
    'GW>zF$?tObV4fv6tGukTSvi1tE0p{r1qfAfkJw9KXm{&nTEVz+1S7;=8UX@ffnc7?C|i{kOoGvmcv&RbGMx{xHP0)V!TgK#F3DEW'
    'MrJt2h2Yg)EnqlN94|JwKye&pck8^U02a)Sz?QgZ>S<Z&-*-uMtN$ocfi#0vLt26FM#=R|fqRv#*Dxb#gb1s$yHvgX`Ql`tA4;1w'
    'fL~_Us>xgGjowuE2ui&;UftsW>CH$zglR4ou}hpu=@N+l4bWCLkA+fWp@|q50GeNCOC(l+p@}8*HKIKRN}H!Eq=1s?CfruGi0Tnr'
    '%cJ)8MVibrfLh`gs;`DmHY>zveG-O()Q6iYTdI%en<BYh!e`J`l_GXej^CdD{PHxu`1S2+G>NYEew&r^A$2nR@O-#7976A^p<xwB'
    'W+!i6U%Wd$xrl!`BmgoS{904x&{>}lq~V7{7ub;x40y%xIxDJMU<=DMDbp~RBO8nl1ICcf?q|z%xX6mK3Pbo7A^dU}|K;@M+tYXP'
    '`CpEYo;@c>^Y7Bd{P1~t{roWb{<~*C%)kFWO%Iaq=0}G=e0%imVs?}sKASx|IDDQQF1||-e)!>s`O(q!v)S`+XFohYct(Ja0)P*H'
    '_~9VE{`UFe`O(qr`Y25fzn?w(7QRZ-Kg|DdaP-}`hd=z`+aJE4Kl{TE=`8vFV3A&5fB*gS>+hcdpPc`IfM30NfeZQ5*-Ku?vY74T'
    'Vgl)2@4JL1vrR|qd;IeB^)F}d-n@Qw`kE2;pC{)p;&;by&tAkQZ(hDUJ-Il0^BR7>dV73v_NTL#XBWQ;iU`kdUdAs@e>!`8hRx0a'
    '!sn}11pf;T!P!UD|2P6V{YMIHzUs-B{Iv)N{v=yfATh4?2Jj+=Nu<e58n2W4WuDCCDL09MSE>g5BD=%3Fy+~M+%I>~fL|;VBv68X'
    'wfE2;v<%zZ((MEP0D@?79~(g@18jO;W)-j!>vxPh*KKFRkFT>8Fp3-Xjrue28N60}5BITrU_aW@myB6`0RnKvK-Qb<Wmeu=Pm1)n'
    'O$Kf5@_A}_nL_odz64G`B5mVa5S%fujEuHO^L4t44G7hp^Z<*KSJID}hkDw+uB-&aiVw7}Yn*K6nP62B=XFx)fifZC&yRWWJ}rPE'
    '*Bdo5d6cd`WJSITU>bCTOsJi|5Y&Sbv{@=BOv}*uVwv6CR$Iwd#6-HzXSZcwb_VYbhmJ|#bD&pwzAQWMhCS$6umWfT&8!jD_7&Je'
    '4M)CzAO_mNcAh>Bv!vY#APncSGlXgM&&VYmS$@<p(obsRJ7f}rJ_l={iJoL!ydWJwwk_=+|4oQxN*jk%=W&24b;E}?B&oTzF1X#L'
    'wPN)Z?*fh4fVL%UeqHO~LF9dqAdYq=h=$RH0bO<nQ6mYhi#Q7+)CBCIxYsWpc$TkE|3=~+=VoEc68s1O<VRKR<G*o>)VIjS`(FnL'
    'ahY$5*%ttEHcRWE*ZDG=-GfX4PR0!Ep-()(Muz!~IIaWJ3j%_qKodA-eb}Br+h=Oa@lIkRv~lES^~KOwz{UnDUfuBUVf5cRqjx5='
    'Wdb*wqyY1B#RSrI{64957`*NXEP%hW*{6p8;?2p=s4IG8c(wQT-JAaaWpQ*T`qez2mHVVe4#CX0`1#%G5H!fYxbIJYIeT&X`s8$Y'
    '_WH%?fAPB(lA>=Ew0Eb+FV0?{o}arQPhK9MpAXM3etz*Qy+DdloA=`Mygu+o>a#a6LV0=i>g<A5+`R>QGnDQ&j-DN0{{XOJ%?zH9'
    '5YM1R83Wx>(^wkd`{&;|6Ls2>vV;7Z_1kgu9W%X8+1=(&ltgSN>IZh_!s5{-vst>Xfc2xdfX8|G{NUi=!5DsjJ^fWCguDALK`j;C'
    '8H~@Qs4}GA7)*2F?aKGSe_i9gFsh{}92Ql&dWC7J{6T=@RlXvFmBDX{0@XL~v4DZ8Xl|*QI58tOg^R4rwK|&U-=eI-*NKdKnW6j0'
    ';khod0N%#Z(GWcuj0>lN<})dRfX37Rdi&<xMGU0>=Xb}i0Fgb_zRB0|qxvH+e~i$M649N2MLOyAp6qYRV!ylviA{24h;l{v?cZTS'
    'PX<r+(@zM%c?yD1gAy3a9I&?!#=-t7{Vg97u-OtPVZo@q>i6wYUG{Luy?I&nN2rDOo_xA~(jR>Up`7w7kbnIV>f-VBJy2z@-|v&3'
    '5S|a<vnX3dG_|P>HZMoBTd)&)&Epsx<j<Zx>*F_lbW~ie=IJ7eVG);0iz)Sr<l{J^uKUsO-=k`?UZ$7y_aK^Qv+A;}ia`YbOs8Y+'
    'ezQWyA&~q7|Ba(Xrz5rkdLKmTYL3Ge{yjPed;Mkn?)1+n@yBMHWs3+p9}%7O=+l1m%_KTRm!Ek7!1(dl<!VKem1*=#vfQMnMUfXh'
    '-hk|ch*;H03-~d6U*eE|+obFojY^(*bPe$5K=HV*`vy39HU{t^Ab&yw0rN2ZBqJPHPjG0?bm*HuP8h`F#;XRG7wBW1XNv`}6K8yc'
    '{!5(76vn4r0kE<OF6Je7jzgJRU%?xm&E=RHOrzgNi>tlgDbJea!5M!>;15^m2^|4!Fh_fRXpSEv*zuIX5<-v=de={A`n{g#DkQTh'
    '`sY8@W82y0+Ex*6o9Z@QL9b70^6RU>$99*OuzCK^XBUbv?1!tpXoBvW56|J(bZW*UXhgD}MAz^#`d#!QpMfp#q>O-JE)#S^^S+C&'
    'i)@ab6aEIc@SN;J#M32VjCVKvf=wbw4DAIN%%PwfX$zQ#f!1}Wbfh|S=m5NXRT6v6*p1IyXL--tC7o+pY}zMgke3J3hW*mASH57x'
    ';XT9q1w^s>VyM4BtD@T$DpDYomA8Mc8}?7AC)`ZV9vbk#EY`ffhtF(<v4_%c91#OHY<dtq9q0p$iSpETW!}(J2L0kG1n%4hA0(`g'
    '>H*2na#06W%XEoLcC;I)BmOM#jo_S*sBmjd>|u{?K<Pxx7+NwdfoNantF(=t77jtNgT2JFrwXu+;(@e+ar7Dcc+g~26=@0sfwdcv'
    'M+OOH0MrZn61e5W8W7M57}x21pe5xcthSPt*XULQbgUg<PvUoP-k|rGbb>fWxN(e%0kD@3z<;qFu$S@@Si;q+yayWuTEfOE)1vAf'
    '&?5I3$UYn9F!DaA8rS*!-s?GD0ZS(djsuu)?$$kgG5~%wTW;nlD0x+pU2lMlCO;*xNUV`y8)R7;j+Xzx7-D-~ms3kKkgpJbG#FO{'
    '0F@mN>R|iH7<xFSpJ12cV!uci1H#gAdB2)jPl27&StoolLj04Oq^Q7?ywHo&j#gz{C**d{Gl#u}T6l_QrmRSaf@2Y<Bd9H5t-7zX'
    'o31OM1+mpZx<sL<cNa|Uv$eejdapeYu8>|>z-@IV`MAN)JClk{Axvp~57{2UjFL5I#`Dgoa4=A&zMdt!PeDashEsT5yR_&NGRV@)'
    'FWVv0os_@=R248y^Wt8aIA$!s*fa&sN$#g4?ks^!vjEvUV`YP6E)9!*4fN>J)#eV}IB8Gs$$pTn14_PN)u*0HjSfEX8^Q2a>8Gmq'
    '1w#z64jk+mb?_6|j?5wG)d)<b%@SiM(1zOUk67#am;tZl6I&b{GEA2@2{MrmYEu|SM}sKv^ziGg`P~Loq;-+bQossyA}vDZz}4P7'
    'oh{KzJv0!9+<vGbhV&gk2r2r1&$Cs}+W|GMBWjSQ3jFbkaNEN*ni$cC{*E}iS>+(XCYPuOZf9+El}LNhOi0L=*{%||Ly{t*I30|w'
    '0eb<cZD|Fbki>#F6xV|5gs!q*BQz-T4J!FScDExHDbl1L2-fb<$;6w|5{wIxW-Y=I^>2&H)fY_Zwls_^cr53>na}}Al2v%X63=e4'
    'CHlc!(nQgbtv0E(Q!OrroqSA|?{&ZZx?t^vH{l|{P-;SCgbu?to-&!355g`@gYB!mRsJ#hcQ8cKWPTsd;a@z&7A>LT$LOxY)78n<'
    'Uitw&W2_!E_)D7wP(XQ*H4aN1wB4k^jux8Q0OH3$by9p8Iv&iUOm=GAYaYR*3bZE!0HaJS0YmJLCb}*%FeW9C1-TBJx{-E*>p_hp'
    'QhW3mK$V^YOL?EtXh2Hgcv2uKSOyjDg-d|S?F3cWvH}TKC@ocwEd8`*Roq&CGujr4scknR<sePtj_Wr{k<(A>qE5m)sX;)zY97<D'
    '-wZmJp}M=iMlBIdKyw|$6+W{51k@>e-7ND?a!3;zFQv^1ea+)8|KMpI)<{O{eBC<;$S2x>Lm|_lfgh4d3US-S4=&=P1dDQcv+>u<'
    'm-Dd-#ABI3LIkX~Rr;~v4I1I(@xc)vJ$ue}dXSTZjddfSj#u}te0q@<7*d*kLbcwtHPCU+ah^IjEHa*TFh!94z`QfyMYedd&2SPc'
    'j<Ik!h{BdbXGX;sjf`*xZh+&2VZH~>yo$`Rhb$(T9r?#}9s`Qe6Jd_<nw<~Y(V!bQ>8-6U2mAa`aY<rR0|{`QSYd!8IjoJd)d#>b'
    's8vWVKvJzuU{Z$t<0%<;01HolQ8#_HuY1;`q20QV4l)~0|BUqEVds@e=5wGCT8SdPfkC6upw^2F3EI%waFSPgon(^?thHq>HgHY='
    '$h<^{CTN`LT&CkPHlCI7-;jXEc9;0)bgOcLo*wDNoS|A>yJwWv3mb*Q$Ug9Y7zgZid#Wf!P`3bkC7o?h6&xyFH3TDPR%B~7{DCE)'
    '=gG6qmC<bn7iwc%_93Gspj-7qRLmMp`jK&l^1<*<<gq=^gOpsC`4X5S9xT;&3m~c2wArvDmoMvXNiO*zo;!g*+78|e^bD$9?WBL3'
    'F4x8*9C3^^Y4x&}CitD3*8Dd{FVcexJN>p1Q2No1k+lMI!gSMXBAf<nhCDV*S3)O~`g(=FX<U#=U_rd~_+3N^3@o*ni3~{{jdbb+'
    ';af%hqq)kt4bYDd%9VPARZ1_o0ac?yO(!Vz?nyq5IxUG4^c;we{<>?lb%9VI`zti4;rt;4$8dwmF5F<eGn&4w1%S6Bspgy$;3)5F'
    'C()6`E{*k3cSgFW4qIFVO}aoM(2%EeP6m(_1+;_*y5pe7)E(q9xx1bxe1_9-%tI$U*13-Q;WKT0P7#9^GQd=vSlJZ<5!DmfwN0M_'
    '!H{ZO`_ydsnly4cM*i%8>%y8t2QRo;z%m1qpailF?fTk5j6<(5c2PLU>!Cssa5rhxjNYgBWv>s)lb*6XYFss$vjKrR3j!v|WWeah'
    '{lJk!^~jS3v@ircq(lR+vvRcVfd2u@L(nypID7XqMy{$QVjBhHms}3-tZIMIhLEd0jShsP|G)?!jS+mK|FD>qD3OXy;ozA2StIk+'
    'LyDh5_0Vc#sf+kp_v!a%>8iR<^Nicw6!~WD2eQz^0TEG2o@j-x7pHGeUt^@*uWUGsvMRj;8nTubJ1Qj>%#LcMlV2js-@}-RUpSOX'
    'ojo{uE)9cu&>cvl4Jhdp@$U0e>~XYN<8gaW5B2=w_~Ps&esy|${`0$2RFfTB$IShb{zL1*N6n5z3TXAzU*8>Svbyg%-+d!my`|{e'
    'pcuwB=R}xUe5L_EIA*Ti1s-dRVOsTYCuEMcbeYyZCgvFa7};a!<6YQe``%X*HOJ99;=!T=c0%Zh%VK(@GPQ;}*6>2^7MBTlFezb>'
    'p-CXT0XCHV=Ymv0^z>2??(7F?z+v46g*$fnO>>{TPAz@zydJ2fx=EAe<{AbyqYRyXjejsJ0BY|6JV}5>*C*{Wy&aIwvK6O7jzBN@'
    '=_lB>%w0a<fPlR`v@&IMdncG&Sch#aOQl%3r(QZ>5ZDv+(yyO9@EkDz_J44PBcfGmuioz3ui{9&uffA$s&%xn6Q~2$5E1CE(Uhwe'
    'V+RUj_sr{rlgM4yOEUXygE7q_&|AcminWZD>om5$jrsT!s3{<{tacVEAG{+WTT%sN5XJ4%h6B-t<OA)(hpZ!*94p0i5-WmnB&p%h'
    'aKtgi`}|VGrDv4ahOEOO9ha;c3CmGGLKa3!<FM%^gm#Tu8>779J?qiH^&xuR;l7H#GIGoHGP+^jcDtTo$}k@X!Z%$(pgZzWJWo{+'
    '2-P%L7Z?Lh^zQoSKNAZ_7~&Wu6;1mQB?LaVMJqP2bT*IY;pw)r@CEhw0skU3(OMeu#hPaJBKdHeafV;oe?QofdIfB#8Kt99E@lsN'
    'CC3!I#d}hM_H+!sK10CM3Jkxu9tezaw1lO^1A!?W59q&~lYw_B;0~T{z?^l?rzP4oQbUW9;^xC3!rh0*aK__>?h*G~z-$pF*`Xva'
    'S_JdE=!8c}zONF1r_q0$zj+NmisZgT<F!H^rGhoqQkh%i*SM&q<&&wW)nk%IjA8he^T3<|>bHbu3U9LqIury_9KRb3v%v5V=LlVa'
    '9T0xW1CPgT>M@yj-@8O20?-2l=%vU4?Zk%%#47Q>Xg6qx@}3+q>M2IXj<PZ~?wDGiy6NGV1TILI;TiMB;h*ronz$|%J~-<X{+(r*'
    'Y(n}I7KhlIa{6Pg(w2t9>rJ+t4-udE1Y-yBcYoU7>CjL@p1HV*raW1XVDP$d2sOC?4J!8=jnE;&s<`)ERwW(QNQak-5IEWxr@5ib'
    'SrjCPQ=7IhQ6=h`X$_(?{Dyw_sd@zd+6fmT!DaXw3Fh3Mve<AiME}%*n+uVS7Mtag&To6r@bX~zhw1Of{2yE;oJ>Cu;kxtKXe4dR'
    'b4iI{?-6&Bl%(jUxKqDy#U!<eDqbi-q1KO#US@WeD#wUv62qksJsBA(<HMtAjV%NCw8Hc)?g5WqRKL8WjE%r|A7DT6z(BwJEDYlb'
    'rF{=2d06s(Ov=oYhp{{x7kMpxt`1dZ^@NYpiu)&10AMnPX21gSef4q&csCiQZNahy0p4WQ4zNJ?0_B_l@lS<6#OgegmEBkC5`deo'
    'K5(Ox<9C046JNl;rx)>yvv(5@qHg&5^grLkRQ%%4XBSxS;?>#3q?ry7|Ar8PBLMuZ^GsD@pj@ny5|}kW^w5H4k*#7{W8rnfSzt<p'
    '#)$YzG#sK2H^m?MVnLBYLq)pLa2*kCKzHzTktP@zTSiDK@HalK>ypy|E8~Rpp@`-oXKMW~VrfdJ;DP`D!OFZbeH~WT#B1;bg*4wU'
    'Vm|KrBeUUO<Km;)LLQ~(>x#1%!SMY+bkD~I-`42bRs)n5gsWW4Gf=lHwIh`7KyC;(>r&_lG;+$}OEH9>Ex7eE!%(mxesicoC2)&O'
    ')DFat$WDtXlT~d(y&H^+=Iqt+pHD5i!1nzv2^+!n=WR@5k-(?y?ru|IbtWsqBumiDTKF;wKO26=p+Ag2;~ygqg21{U*{9wUiRgLK'
    'f3VbKM$ANVc83Jq+00>z6O2%{cyfb3@bdu=Zt6nM$aW&|Y)qOQ;UQU-S9=e;bO_oi>RF1)C{I`Z`uurxHh*})KSCp+d9u{3D`Me('
    'r5$&*hGm{CFbZqyCPRw?f8%nDs;pXawjo&l9C#@2>$@$>=IUFez`}OxX^I^3__O(_!ipjNKKI9~;AJETg$PY(LgDHOLoHQVd_9?7'
    'J~2wn6V_oKf@5So8w3x}_T}-Pw#!9FKiUqHr0%Z5HX=t$aM8JLUW%-zFeTya^(VZdkkYKjZ~>3?{BIF;de#xoT4xUbKNfd^as6vW'
    '-WCa`bv;t^kerFFgIf6K({n|CNCJa~=9r;2*;gWw($u<Wer@v5>QIE-KAXV%QUOXMQR;RewJMp{N!W1N6AC9NRX`(QUU`J1#Fn)0'
    'ffz{(lzLw5D7te73Tp7((?JxMX}Yq?`H&OHskqU%vK=sr)J}Hb@KoPvgrmbKxTyM=E<cb32%2eqe&xWTI4YOKv8JrBIF2J7v=F&5'
    'Co*$`11k;^xHO*@fS}`P?ke`z1&HYtdSJ*e3wl4M<55(G-U<Yn&hPNQ|BOECe#NUzXDdhsdF2eAeN4&6KA+!6%B3W`bG)S89QsU@'
    'yRk<w={&^n-M*Q+`+k<Af2Pk#8e%0FzN<C|E#(kYo8c16N0!xQe(x57v>oHX6YM@TI4Ua<+q^v1rBiVXqCH&{cBG{TEKs^be@LO$'
    '&X<__<IK0UK1g3fg59n=zTEN^xx@|{2W)DsdIE`XE(pGCX}7}xjw2^Frt&O?)C$$kmN}lwY6=xzK6l6oTf&ET>z=}ZYDPs@tb<bh'
    '`M>MZup?key`L{m`aAC^85=Hw<UDb~TRm9ur`LD7iY_zgl%^oYvxT5>px2Xmh&~h0t#ovUnxS|Vw{<2yPml$a?qYXkh~GJcagf;a'
    '_Pv=V(TItUrfwDFzznhVc04$w>VT}xBLJ}0#sTNyNqfm%!_zKzBOAfY`7!Y7P7nghf9y_(2IE2iV&cnDQjH#&dwYmdML(=Y)~c&x'
    'WE4{pAw~Z2v28%8<s0he3T0HFN{1qOBw>JSVteqqbx4{bW37w<XK(|1mWE~xBq#X60MSzjIXqzoofm~weEHrDpw_4JtdRI;)^g&9'
    '=;f0zkDBb|+mAS=&OTz+lhN3t;*LS~qo>OzkrZch&Vl$@UCbM>L6+cxcd;4j3>U;2DP=VKR+!mw&TjJ>h6oA2+)i#`sO0tJh*bxk'
    '8v-P&c4<dAoZy!u{IZ4P_+FhB$E>!198f6v?Nl0;zy?mS!9teB>=tyO8Xp%Js1%zINcX3R=Tfm#*y$%))VqF#2+R0$Y>@x_CS6ey'
    'I-aPd+1jf67c?v$oH5~<p_kRxg}T6kl3hUqXKYv{w&VeAl<<UAj7Pu!810&l@CNF{2p6BIN%_{q?<Tv-XU({WJci7nCz=u4QU@Qk'
    'h#e0QxffM19D=f7m2Ont4p6OX$=jgzcg=<4<3EYsLz}Y{Mru;4)UoX>FXnX~)kH9I`b|qA49Ms{9D)?nOMz@{8*8DQ&V9?pRe?fH'
    'J<Y0b^QdP1%UPP>2zD|xx-sllMWx1!wy9ni*90~={D&%aNB<Tb<cEicH8?wrrUB#*Av;ogj5eobBU2m!Mt<<#MT4@oX%iJNZW~ZS'
    'MY?=tGIPq?VA!vGHi?X(GNjy}p$bYFHpY_(c;i>8N1wO>Xz$Z|il+2J9bl^YLh4?ILLi(%nSq_rTuRdqgb2AfnA~A#wm6Chk&L0y'
    'HR5Uh&QzS5eH2$w_fRPCju4b7uv<p|xqT3!$xj22>*KIH2@ORwbZ2PdQ)$srLx4m)ksJ?d_^iM?J(ITXNS|OM-}mT=nZP$Rb|V+4'
    'A5V;Q`O5FOW;2d80)iH$Me~X`IbZmEt9~5b<oj^JG<rxL>MO-@^PV%bmCy#YRTc;6g#HbYRoI*g3Cu>yYcTKz0gMOq?0#re%v_As'
    'BQo76Zt?&VlWH?jDqA>o){Qx~a%!Z~?+#smVUO0x!&X(-1qhi?Uf^DhY=Z2YOc^P`NZhTt&w$nxh`Q^fP=r7QGO^nfw*GFBcA5(('
    'R9jcO=q<pq%rzy`j;2HmNrsZf6C+erg&udrW@rU#EXJZ2S0SwRLrPZ*_v&{7u4Kp--~sns3wWOqbjMMnAIa~F<Eh$LqSe>Y1Ti#r'
    '$I;}ba<OV5Dxg=oTuv)Ugn4Qn?@UkI<I)laT)?!b?LMddHbcPwKq&^^35kpwk5O0^M%A~q=P$Kv0w9ALrVTeJ96N%Pt-|3KVW?r='
    '*$Q7isfoe#w+)ZpIyk~_eMyK0mLs5Qy;(c58Lf{*K6+owY(PclgCC{+Dw|?pJ+gwfiA`!hN=M-0k3n<5a=_7_-%NbbNza3cU9PoL'
    '^P&x+pi7Sr`U9S_!0>}q#AjE=B2$Nibj=}Cm9<{&t#>0_W1u!3N7@IA%`{3i4w_CC>9fnWPiUE_%C<wcb^Nt>LmX4i*@{71Z+FlJ'
    '&oz~!i_1tSOz`=y)<t$xMwtCO!T-()fpr$D^%ij`DlR33-j<#t0n4ON1oT`9mF9GSpbx=o?n<{1cGcB1k43E0VF0t8me?8uhCsQZ'
    'r<)U5jl)ZZd90dgFPF|`$cxCJspd!W%6)Y6ID19Hq+6wWSgtJH4W~Sk3fmB0J*bh!gL`)r2j?!+hoRhbu%~Y3O_h^LTfNQ|VD3E;'
    ')}d9;4GPskn|2hZ6HV!dbq-o0@00~*qI5iG-4@<$BGcUzCOhg!LXrCFG{wB*iWgqqXSc<b3k}Oa<dK2z93D_E?np91F(S9zEHEPX'
    'YHvses@Ygh!Y=ND(akcyhK5i5mJfOYj*GUXtJ*GZ>8#e)bhrEYiwet9_PTO(_`!ZQ=~?AZoF4VST8~b9x-3O2?-G=D1?8<kKQO9+'
    'f?0PWI3w>5{MXi4oJ!!yx<s&wSxrn|vQ4B(Tw)I8yd>A18mS5!lB+fCsc+yJIh*K`KIc5eucqRSJgDEn!mA0i1GDEzS9AKqAFD}w'
    'Mx5DOk`|2ym&`(GQ9f=sbQEjxc)C+veyJ}n-LE(z%W0uQ(LUr7dB(A`M$L0igKafWrq<WRDi_N<p=!a^gF0ckqZ<%PD!y-hfo>fB'
    '9sSXc5wp%_EG{T(ZY6|b154yRBKcFk?uU>^U;$O(B;tX%>?A~yjfFuoK#zVuDhsgZ1hjZ3%*N}N0wIad&k;|OqL0hd4<axWwkBh_'
    'G!)KpYgoiG)ZV5fvvbTh>Qt%4N!P3q8E%AChVxA|TIM&T5Rql-ktjDYde>Lz5=ebpm(awr(;k%urT03}$Ze6Ya_I72t_6zVckqn<'
    'i;nIZ*>)$>ql09KzLrr_D`@gHh*sH=vwWR>5ryxTXidGTV_wik`AR9Q`krHLQz!nEEiz3Rj@Hmg#~nL$wDLvQ6|qxqg1W4~73(P_'
    'Y%X_5C!zX_G&tMHrigV+c%cw~Dgldaf^pa3fa@W!*`YXY?V(E=V2v@@@Uc@BVx04J6ZY#sBr;FiA7%$nsonl7`77%~i0{%W0ZL0y'
    '2Wc}(t=QR)Cn_yjTBCW&Rl9*&ifr98h}s>tWrTUOSJTZJk8gZ%T=~eO<VPm;@cJ_y2g0l<z0qgjlI0^Bf-10Lij(*^eF7J{#cWe4'
    'PoiEI>Vdi?HMWbGXiq3zl`6GKFw11BYnRKEF~e{xgV3G!-KyC5u?o-&U7zY*ewxx{&RR#ruP^H#PJQ2BQ@h=+V(`j;;k13b3<ro6'
    'DY?JU;HOQ-IKK9ZlHj8quZviv>6}aIYEKSyakEsFHN82cri3IqyCbS*Wp0R&MZ#BVk!o{Nw~4ExG>VaiwVx$Ltjdd!YysPvZm*T6'
    'w2BD%GW2$88wlN_ppq3|^+C0yB7jL{%{iCTn>%W~&_XT~*5#Qnm5Xm&qZmx9Yuay^_l#pEyQ=M~7PUJq8-X6}#3#IROXPpREDb8B'
    '94xD1>fzy$r%5v)jo<pytv$oazTTte2$N^gS|yb(5&=sV{S*^Z`oJXteK7}93E+iamlQ3+__m1%Z;jNCgP^iGU#JPI0R*I3SVkcM'
    'bipRPagKC|k-6LN5cM|PX#kCMxM$YZqlbNUCV+o*rbD_^ns0C7qWTd~aa83%Zy!>1e~VmvE%R}fdL;F-)0lQ`T-$W|=(^X=c2zUy'
    'c-!Ik6X!3zF#Jxf5*CGacjyH7<scAWP#fw*_IQACOf4~EtzbEU|L*`BmAMJ}Agl^yl-<c*$5<WXWT<yzNlg0AxhY2VifNBdt8!rH'
    'G0;s1?rjHQ@^VfmC}1r}p#H7A-l{oE;@Xuu5ygia3XIpY)79}l2fi5B??2_ryKBDlh1@pMqE>%4l!MYd{GkQY6k{;J`*y665Z_kS'
    'LbH+(qWqvDRvY*WZ4|g#LA&=$zHQPb+->~s^!)9c*XO74o7XRYjnB_soSq!Ni+?$a&rkkx`sz6T<@DY8*_+q9DUU|Pn+sqt{USO%'
    'Iv6$xJ07cB8_lJ6O(JH3ZVQzI!PNu;R)mU~w`k3T;~1#kCRVvIR^f`~*5Lp|Q*<z0VZ_XxZRU*IJvXcx2cmzxVItq_2+~q@Yfzb;'
    '6Z0EKt&CB%ttClr={?BtLsOD$k#TSft35@GK(i5SZ8)Y6-Xj+?-Wq2O69IvjpLVT9#64>*frNRklt|@sPx$`Qb7($x2&4A8_w?!K'
    '_vt;GI-=bIbC945ZvOW8;xF-EPk%jU-H5bf9Wz3IWnzM<Fp&qV96&s$3!JFL&A2{*_7VWTf#&ld*6V|xipXoKEYN%pm0*lV8j~A^'
    '5l=;W1f4nx+r*`*dI$VpW80bZ33eZdQjh+Osvw{v{i6R^{oa^3m>G|$&<QyOG#7}h+bL9;Z<r#Ml;nx7lY1m)9uU4#TyCJq;N|h_'
    '_~O^Mr`8!Iw$nab=-3h+IKk)SOEGPj#l(_JW{0Gyo5P<SczOJI;=r*kIo7ep8&j$>UZ;gtlLAI=TU+e!yP6uWKeClCY287y#yO%W'
    'U_Ev^760N#>m4DH!YjYTf?WVp7}CTP<q>@6;8;2ox|2!pE=P)krNG<adR%%5Bewc>pp_!%cR#<rID3URxtzXyaqi~xNe?Z8VY)S1'
    'gXpXdVV6`ratYx_M!MHxZ#3o{G&L{J*bQo!C3ov2yIHXUht6Uew|)%v-k_ExWxezl+)tlDx$AU6KDLiG6fQ0~WnJ$6ZpkL0+s0RU'
    '@j?nKQ>5$K^F~)Ik1YQ|!{hr^j3wY@Hkh;rt8W#iqOMqJ{92f`76x9DdRDtIR);EDwO_f!yfYBMl!1+fpPka~2D-Ycv|YXCbyhu_'
    'in9GK`4rnc2aW%;i`um%VpwNdE0aQ>(e;;H(VGfSm;l2mM{1gOhYjtVq1)jfZYSz)nSb+u%JbceZYTade0Bog9iPvuKqv}w!j4$o'
    'c1nB=q~duDdcX?Z|Ne8>sMWpQ4xJVnx28OP4>2p3IOuv}Dymg3T5z9Ro68!bo3YIR+rxetcuOshossKQ*(W#ht-58?&#BO8mOJDo'
    '_GTv0Zr%E238LmZ`vlM<FYMcPQD0BMONxE{%$nbaFYfEq&(ZGv)Nb(GvSfHaW4(F~7ucz+yXDNv>YL?EPIV6Qp~y-K2(91qs+Q1U'
    '&R((p$u{Z?-P0w-F)6~{EAt;@;>5WP;}(wX^6E}WR-HKXmV~SNu$6RRIcf*9I|1s=IfZsPQ0sWP_Ple1yWdwZ+@0d!oq7mln5hd$'
    'YtzJwlYvqLFAk?Wvlstd52wmE>TzLoK%5g-8@$EH(63d_ranHtbSF3=`$k(VgH}5bWOa`060SxX&`ITm=N|TSew9Hkm*#HiNgK8`'
    '?a}FlOF4ymG8-60-qWX^T+&`7JC}7i?~=xfyjxJFZnsgfuyR32ql;szFYA$0GS^_|{&i%68+b7dIJv@|)T@i|iPSfqtIeRu@u_u0'
    'gQxUx7y2fl%SP9Yg@eakG@`2t-4x0Cwj5a2J+JpNxlWf9^3v?+3|vIwlcc$5ZeWtG&7Px+O7vfrA8Nh1US=gINIZP@?a)qntb@ne'
    'Y(Y;?&E*r<uM-J4f7)9$b+M@cIqLBLDITIEF#j<hU^<tT*RCXa%a~CNCqcmq+H!%MkWJ7Zk@`~HOhrZ}OO@gsu0?u>XJc0JAOB(!'
    '_e_<?<Q}T>GZiV)PI<tGsT?w?fWF58?dJ3o9#3SIeYLEL84~_Ocv5A@_%BQO!x8aA?|>CX3x@0nFGpIb7Hdqnu5D`cCgR5>SiRZm'
    'eUEKb<#CiQVTlY7#N{r#PUb+zlh;_KCQ<{9HY@BCbzs12C71rNI$=2x><V7WJ3wSS3e;v8bga<UVk<i7yRlR6JfP`#v98<T)^^R;'
    '0o!@Fwd9qrG+rOBcfXsV(jr~5kyhn)ZMGfrhAf(rZLO|!b*jXX385=bGBQgm`~tn^7yxQJ&_x~5<sm}4N*&z+eyHr`9M4>9g);#c'
    'ITuJ*m+^>qI0{B5jiW<4C3Tae$I;30+jBGv(P^x&x=LoGiYQykT4O0Vg0mpWq_-0D%IqI#_xJjP$ntHDi5qLDy92F`oLVAz!2j4('
    '1V?(Rzj8aRVOoD#UjtxWPi381S5HLhx}2OW1{N$5F+0YEbGlvP^<$;(>*d+2vx{^3vbA*VI65HFU(YWeb7HxuLi0_5$d8#93g@+~'
    'b2~95r6dTvTaZYm@2VkgwE!QEb#A2NKD3t6UP=0Co1zi@lP&Z~<OOTE|6{RDlHUEoKOBm8srIa*r2@s3jkrYRTEde+i&Z;^PTia`'
    '!d+tg8XHmoUA<87Wo_?H?Lpx7wcDC)Jk=Q~mJ4QJ`$^0n4>kxzuG9|`YeU)Ot;LVOYRTlw;9i*4YAu8!+%C-yo(7`b?AK~%KTb)T'
    'CF>IQgUT0`7&!3<nZ;3@TXBvp1(sb7V;2WD5CS!pagOS0)leQ23OTw!RRj5Ba2O1OBF}1l>~bo~s3GCI#sf@{x@c0>^l&L2Q`zoK'
    '%P5bxR0<2pmTB$G*G5Ui*T7lA%8pGphjly86->c=byH$YT_WdSl#8w)HYyZWIKibOd+qYkW?;6{qKScSsc)q@NL@(Ue#8KyaSu04'
    'u{o*>$}_8Z<mCCzwJNQ<H@RAZoIz;wxuJNVxHQQQ_yR=O<Bb_BWFj^S8#k^iw7F_Yr3|uPud5DQT<_GKwBC=vjOOWV30n7DGXyIS'
    'r=j}09l#%u{q8oSWFB%{qhrXvHq;7lv>vxA4BOA+K%<asax!@29@BOm!HUsl1O5Uene7d|&GYxDzD3F1H6<`<BQkWYZ2Bp^TT}d;'
    '?G8{of6}HTsgX{Ev)UPNdQOy#$IzU;-s&EEWR?KVJfd?8b^R(3J>8TljyY!=N$81kuIp8AtWjxBdUd<N?s8;_8=)9$WQL>tdU{Y^'
    'RIL+6yHz_>==Mrwnp5l+MX|YpdgEb;-QB<b#JcNQwO?tA5Zf(~^z7B!m#42zUtb(woV|G+zdJoSJ$rlMg^>n|?&vP;V^!zg*e`ZV'
    'xAkflKCfe`{bM?lrc1;14U26P*|9W~S$B1VJ%)GpRalpu>1I{n=60q6w?EbP65PAwg?Zt-`n=kT1@Lo^DDz(!Mi_r~Nv`Hr{xQ93'
    'YA|eH&SdSc0Qjxn)ZCxJ4(0lK{8Ghgbm_DCv*1~W3h-#%dT)Qd_zV085B<*{anfN{*jh>Gn}<q6D7}lNnC*6S2sEBYfLvFa3TQnn'
    ')*E=8$%F3T6p$kT=y9J73le!hMvElF%vuufpzi?Z<|Ib|eqVC(7039^slp=-IXZrO=E(fEXfF2q?H0+`QHPLjC)(pEN`-|$_bN;_'
    'DvVCym=%`01O0k@7)oc(=4@0YDUR%W?8(2b+W9Y>jpO*22u{Gq=c+wnTdp%blQk)ExN|q=&<ekWp@om<=q@ltWi^AbDOKObe^bW2'
    '0UI`}yI+99)T~qOagJnA+aZ;r$qQNox;*M6_o#~{csWbM);(U`<JJ{QjJLV`+Ef$_5UcC#;Y};I!a1R~>!if8DP>A|k+e_qO%>se'
    '%dT00%__9I5f$k2?5v~Lrx#Y%yKkv459Ov>`{K=00mQIiVEC5gr!!H%_Tx+ZZ0eMg+$Dk?xt&nFo2Sb-e^N$tGZ0c9F@KDJ@Ci;+'
    'zQ(gpViuJscJ?I^u>-=@1pl#w(;Ye%i5-=#a*4AvFoPV`bNBT41vxAtebaJO70Ifki=QZ-nJ*+;k{CgH#luM<GwUp=+}&1G7{$?}'
    'gxMBG^$;kc5vI>U(7be54|Y1*tZ`@(zm+TV$SVM9<xg0LK<?>jt<pV}i(->g$qOgktF3=!CAq_>l}rwlpC8oA=Lc%z_broG6Tgeh'
    '1_zR9u+4=e7eLZonN~jJZML*FTsXtL%hi?&gjYlYIEvCCy}K=UtLbBQfOW+s7j<zjy0oV|O6GIE<kGV^XsOjpS=@fZ72@0M@GZA-'
    '*tc#pUDMHClDHp0nn}$vku6~vXyzJrLMU^Q=p2K$gV?YxywIPtm2tND0?QH_hc!koEnk)9>JO~cc`SJAx(Lu5nh`On_MDv|n7_J`'
    '8W~qth5B*8KgK(klQJZyYc>|?%?8vh6C6Ub@+FZ}AEbBi2D)btcD^k4#?j}!vY64my}$sj_lsnm;jdMyGm1y+duj*Z(9FSi@b?~@'
    'KKfCQ?HV`2%Bohv${JypACbhtAC9bfb6utd)}V}*z>}hKvxYyj5>3ylLZ>6%9nIa&2N;O9B8_L2TV+pO1BGumi3L}&Ue2C%Zyy;u'
    'GafpHw6cos@@F^hx1!vQm{k`(n2BYMSRNLZEKP1wv4J?s#zKKbMtVS4xWcq>ZnjnCiD^r<wIm)-1q+X;GFZv6OkP{$@I%<+Gf<Ff'
    '?YGmRM*fo2Wj^C$7kZTzcdVE)biI{+RFxG#9Ys9=nPUPPLt5U#y3VjIhE3tYgqn$4)e-Fk!Ue{H)MrEQWiGWkALe5Wph2fkmuUhS'
    'Nk~Ctx?r>TN3@fe+)@s7U*F!B#F5D`mP;S-T$B_d&<&}WJ<!%_o`3uiu^`Ej*Qui5==xr4e%JUi(`N}MY4mzdelu*M^r(4E(wv_6'
    'G?0P7uxW4*ImuiToX5y{<d!d?5i3JKmIpB|c9m84+*eRR!U0Ly8NHv~TT41^K&-v9NJ+jjFOKMNr<@gFL)0#lm#eWSYNV8N4vZ7p'
    '^9dC}G@pAS=6BJ%lt4r>LCh22m}9<!Fv^KlNwr^AT&{DN1`fXj`dQ9LHRVHL@td8|DD57)sVv4?luZe9E;ssY5UHHh8I2ixHZ|qN'
    'iL%lKSjS9zm)4_cNUJsN{5LJ9U2d&E1H!2QNXiNe4Am}1FG9aPc&M#cvv&yEdQ-*uH6FVPz32_a@m{icf@MyS*V4)O?#DunUIe!e'
    'Rdu<WS(O@hqhlP2cH#l4Xw!G67iaIt3o3DKD$dE#1-LaU0kJ+~H61F!9(sq0=9tfzgQDGj?QoG$h%!1<#@fn{$uEFd)wOQPF`(}?'
    'ndo~>NI@BXcs5jF6GO~QNQ<Evs8a%kEYuOJH4=NH11_>V(x>!X8Im>STJ@&prafY^j-aO}A%3bNuafy)R+e<gw^^+d;Cl3lx0H?1'
    'SoUTNZM=cEi)!1YVVexReb7MZHi17pE@r8AA!9Ijsn+v!K$N5_p|>?vm<r3FhhT8G4j%)>2k^C071Dt4$XF75>!6n5wZ`{9ay&oB'
    '+G%!7c-sIwXJsH&6~zXl##rUBxHlhAhDwjM>jy4#Q^T|uAA@ch>3I^OZn2BlIJNFyq>9R>Ja|x3*omIEA<V+h*1Ip1oRnExQ?d4F'
    'Wx|r2eT3Cz{f0q-)qTL0I5rM$)GKA+?l`rsQ>(J-@(zBiwuIKEV!l9{?o$ROcb+9Hf1~T?B`QCaJT(yT@Gw)2=cFLTdi`n)g2!<g'
    '?v9IFOr3Utj;v;MBaCVq=$vWqXa{o1(^7I*$bwO7W2Mlq$Kz;$dObE7Doct4nDyY<=EkZmM)x*PLQ|CMyxpb4hic*2?MavhV{4`^'
    'uUJv)IsT-6#O0W(rCPl&Rqe-rr2dK^c=yZ}T^cXXemXt*_2lJg{PNAoU*osO??5Plj<OJ8%(x!vp$|Vp&ku4Rc|Tk*g?i$>Z$-#@'
    '9@WQB%S)7&c`@Q~TDUak`JGi4KYxC3V7(H^9Gq-D=Wh6u?i8gGr1b_~7a34ZYEcpqgfatc76jP-zhQK%?ZbG#+8c3@JKh<&id^1a'
    '-*S2<@4%LH&|v}t|ByxsSj4~_SDW5}15@Z4$MuhF-M(7~Q4gbxWm$(qP}bB>+=yI!l2XwtRKtW2O1}+V9Z`Uuz{a9`?}pqzq5E~L'
    'm_R`~yP<QXf*<GI*ihfSK-@|$3n1b;Xu5;oa{P?B+|}OxrY!cav(-K$OwHA3HJerTX}rI`{~;;%i;ZeGDm7;xVrJALyTQK{{O_jI'
    '#=f78x$mb|{d$D5$d>v#97_0{<i*Vh>2s8ST&2Y%c+0y0cWKhb6&Guk%e!k)=sU1%x{pZhGIUzqM>wvzGTW^pAP$de9U3TJ=2X)S'
    '4&8eITM9GeOL3mcQGYD%4DCMMthC#7v%>o+bh%PgGvLpWrb{Z%s$IWzdq%lyM{bYm1Wg$>enM=`ocZi^Q%|AggGNgHR_+-(_NDQ1'
    'Vv>KD!GR8(D=u|(sI@*9<8&r^7DyBegQK_!`XrR;6lfMmYjPnoFtMIF1!BVEq~HBc2}r?}<AdHIdg*~iYDGEQR!|>e*OrhE_iUIe'
    'D}7zZ8e65`>MP*i<E)mV<C@vzqbg+R!+o;g<u`d6883v2e!UEG^StaZAA60$CqS`#bdD+Xe!P9?tlT3q2Zmts5pZ;vn+jc=G}EPS'
    ')0cyLdMl^*jiiOw=s3hA#~T{){vii}P#*c%I`UA5s20H>a7t)|^~S1s{IMU_q?{ZbiKZW7I_rFy&F<AD?Ba~pxlx=F#n<Cf7AGiX'
    '2an&59PQ*_&6_y42;d4M?cLc=8gN1hTodVh;~ZF0sc9@<gMmAx)h#)b?qd^;<sS}*%BI$kcFjehxCqCXv<rHKf-7Be<zv`}bBQ6R'
    '@`0gLZq<n@l&pZsxW9lO0>fKX!vsb@54-0)W=QR|xY6JFEYSe;*R|F{mR2Kiu%nm?vY>`Ya~?HQxDbT%EV#Z6Q?4Zj>s5c;N^oSH'
    '%|5ie*}}+m!+u|bHXl;~*3S>MfTmVy<RIDrwVs+At{S(lT56nGcmw+@-%amm`k${gFajp}mkv#pS|&O|wHtV&jRi!9d1=sPU-_z#'
    ')v>Pznq!)6cxfLz@}(kbn04*&u?rD-TreJ}I6{wc>V1W4U(-;utYMmWnWoCR_mtUKt!zlMWhRN>Rw{3on54uXIxloWuO!gV?_&ub'
    'lp4w$lA$+Mu&bT-IJ>N6OAOsWFvgkn@WHJ%5nvWIIKDxq6t%6~gW^df$FA(xW3p;hWE5bzZl&9yr>Z<l&T-Y7ik88YWL-Q4fkyel'
    'y3EIPSv&poDg-EwGs}zhrVNt0J${Q})XCE)XaZ?&j%eIQx`eoMzt47Ctwl6&^q;3CsbgO+fS1nZy9Dq$E)@B?p)RxUN0HW-wU*?S'
    'cwWC6%YojlqH`AygQh7&j|siPGXy&iUWPX;vrlgPImZ(4=M*Rf6I8|Es^z^pQ7m;7Ei=1pWjhNg+}MW4S&|f8OCh)Tc_NW2D$P|0'
    'm14(k(@6TplblibHt25L_0bkb*vp{;f!g$QZ7izB5>};oi~Kapy=C7$RxC(5g>-N4fC<6)N_@O&LrPy}s~f6v0?jPE;Mq~iNR#k1'
    'mhbiFK`iMTB^XiiXR`*XY&eP&A7+aoQSPwHhic#1mQ369*|j&sS$H^T7#pL+k4SV-A`|@**Nz0LHI7TGLsXxi<en;<*)*PkF05xq'
    'm_7!c=EfSJN&%*Lk9AU%X`w?r_)i@c$A4l}LUBXCN5{p@1{dlrH&mfgctcMd&+}Ovn|hdtB2)ty3I_PXZoTHeO8m5%IH$Y9NayyH'
    'z1!Mt&*Y%Ntv1j;k%49D4?;%gK-)h9m+uU$%{Hj7v86o8gMfPN(d!`UtcE#JrF_AgLMLHSR>_OTlgojvK!qmk_*ksr#g8bX>UP+3'
    'BFm50t?L_rhUzFDMf!x}e?n_%53<djt=4_9Om5V=6BD*FDTd~WV=h?Fl{;`~MSWYT_WolDg9^v82j_pa7yX_F*=gp@a8#|G=5N!b'
    'gSRct<mR6E!;VYU3`S$tUyLt9!`B3+7FoMgzZjxAU!L9O8L){7-4*ic&5P6XN1;%tt<#{q<*zw>o4c``lDq8EuewOy=mW0TM~=T6'
    'A+XUcpJgOkWd#e2d+i+#qUV^>kuH+WvYH$=kG$q7YhjI+M)QRj53{#_%_4UCnx%!90<JXO4Um<cx$CE{1l#S~owi=f5CC~!w2j+b'
    ';E!~JpB%rv`1##w{PxYuvy)#3(cjKqzj*Vv*nRvzOut{1t$(GpQ^c#zoD5IsbwZ)VFT59_)qb=Ku6Y8eQVx|n3(FHbe5%$H`+-S{'
    'S-p2fVLR;3>e7yTrA)_Nx8Wlu!)s!z_?Gtn(0NWuwQuXPhQojrzr82RI3KE7fX$q*0fp^d*q$+4UT&M*SKO{&o8`9Pp-Co*1HoM~'
    '$JjHwDX<XXv8V_KGTbme=;7hN0cB@3vH'
)))
HISTORICAL_V3 = _HISTORICAL["validator"].encode()
HISTORICAL_CONTROLS = _HISTORICAL["controls"]
del _HISTORICAL


@pytest.fixture(scope="module")
def source_bytes():
    paths = {*ROOT.joinpath("src/qcsd_lab").glob("*.py"), *ROOT.joinpath("tools").glob("*.py"),
        *(ROOT / path for path in qualification.IMPLEMENTATION_STATIC_FILES),
        *(ROOT / path for path, _ in lanes.TRAFFIC_FILES.values()),
        *(ROOT / path for path in (".dockerignore", "Dockerfile", "pyproject.toml", "uv.lock",
            "neqo-qcsd/Cargo.toml", "neqo-qcsd/Cargo.lock", "neqo-qcsd/neqo-bin/src/qcsd/mod.rs"))}
    return {path.relative_to(ROOT).as_posix(): path.read_bytes() for path in paths}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else lanes._json(value))
    return path


def retained_launcher():
    """A failed historical batch keeps its reviewed launcher after new edits."""
    raw = (ROOT / "tests/fixtures/rapid_parallel_scheduling_v2.json.zlib.b85.txt").read_bytes()
    assert lanes._sha(raw) == "86fdebfa267f3b5a861992bae3d4776da18148b7ac04fb1592dd392a9fcb3aaf"
    value = json.loads(raw)
    assert value["source_commit"] == "65794a16dc59615cfa46b5fbb4e2d9a13f97640a"
    item = value["files"]["qcsd-lab"]
    source = zlib.decompress(base64.b85decode(item["encoded_source"]))
    assert len(source) == item["uncompressed_bytes"]
    assert lanes._sha(source) == item["sha256"] == "42489d4b66b004787c6a827084f311d6916c21f810ffd9373b2627df76a36d39"
    return source


@pytest.fixture
def closed_batch(tmp_path, monkeypatch, request):
    data = tmp_path / "data"
    root, execution, source = data / "evidence", data / "execution", data / "source"
    for path in (root, execution / "results", source):
        path.mkdir(parents=True)
    source_raw = retained_launcher()
    launcher = getattr(request, "param", "historical")
    if launcher in {"current", "unreviewed-current"}:
        source_raw = (ROOT / "qcsd-lab").read_bytes()
        assert lanes._sha(source_raw) == "35d443b9f092bf8c55137ca7730723c8f542a9b7899889c5e649d90a658885dd"
        if launcher == "unreviewed-current":
            source_raw += b"\n# Unreviewed whole-launcher change.\n"
    host = write(execution / "qcsd-lab", source_raw)
    base = write(source / "qcsd-lab", source_raw)
    operator_source = write(source / "tools/rapid_parallel_capture.py", (ROOT / "tools/rapid_parallel_capture.py").read_bytes())
    directories = {key: data / key for key in lanes.PATH_KEYS}
    directories.update(data_root=data, runtime_source_root=source, module_root=source, execution_root=execution,
        workload_root=execution / "config/workloads", campaign_dir=execution / "config/campaigns",
        host_launcher=host, base_launcher=base)
    for key in ("acquisition_root", "workload_root", "campaign_dir"):
        directories[key].mkdir(parents=True)
    for key in ("cohort", "qualification_spec", "source_manifest", "client_binary"):
        write(directories[key], b"controlled bound input\n")
    write(directories["plan_receipt"], lanes.admission._bind(lanes.PLAN_TYPE, {"study_version": 6}))
    write(execution / lanes.STUDY_PROFILE_FILE, (ROOT / lanes.STUDY_PROFILE_FILE).read_bytes())
    for relative, _ in lanes.TRAFFIC_FILES.values():
        write(execution / relative, (ROOT / relative).read_bytes())
    spec = lanes.CaptureSpec(**directories, collection_image_digest="sha256:" + "a" * 64,
                             execution_generation="engineering-prebirth-001")
    site = plan.Site("candidate", "workload", "b" * 64, "https://site.example", "named120", "c" * 64)
    identity = {"collection_image_digest": spec.collection_image_digest,
        "runtime_source": {"lab_commit": "d" * 40}, "client_sha256": lanes._sha(spec.client_binary.read_bytes()),
        "base_launcher_sha256": lanes._sha(base.read_bytes()), "host_launcher_sha256": lanes._sha(host.read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}}
    bindings = {"profile_sha256": "e" * 64, "cohort_sha256": lanes._sha(spec.cohort.read_bytes())}
    facts = []
    for block, mode in ((3, "tamaraw"), (2, "cs-buflo")):
        name = plan._campaign_name("formal", block, 1, mode, 1, 6)
        lane = plan.Lane("formal", block, 1, mode, name, (site.workload_id,), 4, site.qualification_set, 1, 6)
        campaign = write(spec.campaign_dir / (name + ".yml"), plan.render_lane_campaign(lane, (site,)))
        directory = root / "lanes" / name
        lineage = write(directory / "lineage.json", lanes.admission._bind(lanes.LINEAGE_TYPE, {"engineering_fixture": True}))
        intent = {"campaign_name": name, "campaign_sha256": lanes._sha(campaign.read_bytes()),
            "actuator": formal.ACTUATOR, "runtime_identity": identity, "bindings": bindings,
            "started_at": "2000-01-01T00:00:00Z", "generation": 1, "logical_lane": name}
        intent_path = write(directory / "intent.json", lanes.admission._bind(lanes.INTENT_TYPE, intent))
        facts.append((spec, root, intent_path, intent, {}, lane, (site,)))
    authority = write(data / "authority.json", {"schema_version": 1, "artifact_type": formal.AUTHORITY_TYPE,
        "runtime": {key: spec.serializable()[key] for key in parallel.RUNTIME_KEYS},
        "lane_intents": [{"path": str(fact[2]), "sha256": lanes._sha(fact[2].read_bytes())} for fact in facts]})
    value = parallel.load(authority)
    def audit(path, **_kwargs):
        assert path == authority
        assert parallel.load(path) == value
        for ref in value["lane_intents"]:
            formal._reference(ref)
        return value, facts
    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(lanes, "_intent_and_lineage", lambda actual_spec, actual_root, path:
        (facts[0][3], {}, facts[0][5], (site,)) if path == facts[0][2]
        else (facts[1][3], {}, facts[1][5], (site,)))
    monkeypatch.setattr(rolling, "require_mode_readiness", lambda *args, **kwargs: {})
    output = execution / "results/failed-batch"
    output.mkdir()
    command = [str(host), "parallel-formal-run", str(authority), str(output)]
    read_fd, write_fd = os.pipe()
    child = subprocess.Popen([sys.executable, "-c", lanes.HOST_GATE_SCRIPT, json.dumps(command), str(read_fd)],
        pass_fds=(read_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    operator = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        host_identity, operator_identity = lanes._process_identity(child.pid), lanes._process_identity(operator.pid)
        os.close(write_fd)
        write_fd = -1
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode == 125
        operator.terminate()
        operator.wait(timeout=5)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        for process in (child, operator):
            if process.poll() is None:
                process.kill()
                process.wait()
    started, completed = "2001-01-01T00:00:01Z", "2001-01-01T00:00:02Z"
    write(output / "host.stdout", stdout)
    write(output / "host.stderr", stderr)
    write(output / "operator-intent.json", {"schema_version": 1, "command": command,
        "created_at": "2001-01-01T00:00:00Z", "authority_sha256": lanes._sha(authority.read_bytes()),
        "operator_implementation_sha256": lanes._sha(operator_source.read_bytes()),
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    start_path = write(output / "host-start.json", {"schema_version": 1, "command": command,
        "started_at": started, "authority_sha256": lanes._sha(authority.read_bytes()),
        "gate_script_sha256": lanes._sha(lanes.HOST_GATE_SCRIPT.encode()),
        "host": host_identity, "operator": operator_identity})
    write(output / "host-process.json", {"schema_version": 1, "command": command,
        "started_at": started, "completed_at": completed, "returncode": 125,
        "host_start_sha256": lanes._sha(start_path.read_bytes()),
        "stdout_sha256": lanes._sha(stdout), "stderr_sha256": lanes._sha(stderr),
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    write(output / "blocked.json", {"schema_version": 1, "observed_at": completed,
        "exception_type": "ValueError", "message": "absent actual preflight",
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    public_started = write(data / "public/launch-started.json", {"command": [sys.executable, "-I", "-B",
        str(operator_source), "launch", "--authority", str(authority), "--output", str(output)],
        "started_at": "2001-01-01T00:00:00Z"})
    write(public_started.parent / "launch.stdout.log", b"")
    write(public_started.parent / "launch.stderr.log", b"controlled public failure\n")
    public_completed = write(public_started.parent / "launch-completed.json", {"returncode": 2,
        "completed_at": "2001-01-01T00:00:03Z", "stdout_sha256": lanes._sha(b""),
        "stderr_sha256": lanes._sha(b"controlled public failure\n")})
    lock_parent = tmp_path / "locks"
    lock_parent.mkdir(mode=0o700)
    monkeypatch.setattr(lanes, "CAPTURE_LOCK_PARENT", lock_parent)
    monkeypatch.setattr(lanes, "LIFECYCLE_LOCK_PARENT", lock_parent)
    def observations(actual_root, descriptor):
        assert actual_root == root
        metadata = os.fstat(descriptor)
        uid = os.getuid()
        executions = [{"command": ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", "/fixture-private",
            *operation, "--filter", "label=org.qcsd.owner=qcsd-lab"], "returncode": 0,
            "stdout": lanes._put_object(root, b""), "stderr": lanes._put_object(root, b"")}
            for operation in (("ps", "--all", "--quiet"), ("network", "ls", "--quiet"))]
        return {"lifecycle_lock": {"path": str(lock_parent / f"qcsd-docker-lifecycle-{uid}.lock"),
            "device": metadata.st_dev, "inode": metadata.st_ino, "uid": uid, "mode": 0o600, "links": 1, "size": 0},
            "guardian_processes": [], "guardian_sockets": lanes._put_object(root, b""),
            "lifecycle_entries": [], "docker_executions": executions}
    monkeypatch.setattr(lanes, "_retirement_quiescence", observations)
    return SimpleNamespace(spec=spec, root=root, authority=authority, output=output, facts=facts,
        public_started=public_started, public_completed=public_completed, observations=observations,
        proof={"runtime_source": identity["runtime_source"], "bindings": bindings,
               **{key: identity[key] for key in ("client_sha256", "base_launcher_sha256", "host_launcher_sha256", "traffic_hashes")}})


def retire(context, index=0):
    return lanes.retire_lane(context.spec, context.root, context.facts[index][2],
        batch_authority=context.authority, batch_output=context.output,
        public_started=context.public_started, public_completed=context.public_completed)


@pytest.mark.parametrize("closed_batch", ["historical", "current"], indirect=True)
def test_closed_prebirth_retirement_preserves_actual_failure_and_supports_exact_g02(closed_batch):
    c = closed_batch
    argv = parallel.load(c.public_started)["command"]
    assert len(argv) == 9 and argv[1:4] == ["-I", "-B", str(c.spec.module_root / "tools/rapid_parallel_capture.py")]
    before = {path.name: path.read_bytes() for path in c.output.iterdir()}
    intents = [fact[2].read_bytes() for fact in c.facts]
    paths = [retire(c, index) for index in range(2)]
    for index, path in enumerate(paths):
        value = lanes._verified_retirement(path.read_bytes(), c.root, intents[index], c.facts[index][5].campaign_name)
        assert value["scientific_credit"] is False
        assert value["retired_batch_processes"] == {"host": "absent", "operator": "absent"}
        assert not (path.parent / "host-start.json").exists()
        assert not (path.parent / "host-process.json").exists()
    with pytest.raises(FileExistsError):
        retire(c)
    original = c.facts[0][5]
    successor = plan.successor_lane(original, 2)
    write(c.spec.campaign_dir / (successor.campaign_name + ".yml"), plan.render_lane_campaign(successor, c.facts[0][6]))
    checked = {"proof": c.proof, "execution": {"started_at": lanes._now()}}
    lineage = lanes._lineage_payload(c.spec, successor, checked, c.root, c.facts[0][2])
    assert lineage["predecessor_campaign_name"] == original.campaign_name
    assert lineage["predecessor_attempt"]["host_process"] is None
    assert lineage["predecessor_attempt"]["retirement"]["sha256"] == lanes._sha(paths[0].read_bytes())
    assert original.block == successor.block and original.logical_name == successor.logical_name
    assert {path.name: path.read_bytes() for path in c.output.iterdir()} == before
    assert [fact[2].read_bytes() for fact in c.facts] == intents
    skipped = plan.successor_lane(original, 3)
    with pytest.raises((OSError, ValueError)):
        lanes._lineage_payload(c.spec, skipped, checked, c.root, c.facts[0][2])


@pytest.mark.parametrize("closed_batch", ["unreviewed-current"], indirect=True)
def test_prebirth_retirement_rejects_unreviewed_launcher_even_with_rebound_original_identities(closed_batch):
    c = closed_batch
    # Both original launcher refs and every intent already bind the changed
    # bytes. This rejects an unreviewed order, rather than a stale hash alone.
    assert c.spec.host_launcher.read_bytes() == c.spec.base_launcher.read_bytes()
    for fact in c.facts:
        assert fact[3]["runtime_identity"]["host_launcher_sha256"] == lanes._sha(c.spec.host_launcher.read_bytes())
    with pytest.raises(ValueError, match="reviewed original Source before worker birth"):
        retire(c)
    assert not any((fact[2].parent / "retirement.json").exists() for fact in c.facts)


@pytest.mark.parametrize("closed_batch", ["current"], indirect=True)
@pytest.mark.parametrize("mutation", ["bootstrap", "wrong-tool", "extra-argument", "missing-isolation"])
def test_current_launcher_retirement_requires_original_direct_nine_argv(closed_batch, mutation):
    c = closed_batch
    public = parallel.load(c.public_started)
    argv = public["command"]
    if mutation == "bootstrap":
        argv[1:4] = ["-c", "import runpy; runpy.run_path('rapid_parallel_capture.py')"]
    elif mutation == "wrong-tool":
        argv[3] = str(c.spec.module_root / "tools/another_launcher.py")
    elif mutation == "extra-argument":
        argv.append("--unreviewed")
    else:
        argv.remove("-B")
    write(c.public_started, public)
    with pytest.raises(ValueError, match="actual closed public batch invocation"):
        retire(c)
    assert not any((fact[2].parent / "retirement.json").exists() for fact in c.facts)


def test_changed_external_retirement_verifier_cannot_enter_original_ordinary_contract(ordinary_current, monkeypatch):
    from qcsd_lab import rapid_undefended_capture as ordinary
    c = ordinary_current
    lanes._check_spec(c.spec)
    original_controls = ordinary._sources()
    relative = "src/qcsd_lab/rapid_lane_evidence.py"
    original = Path(c.runtime["module_root"]) / relative
    original_raw = original.read_bytes()
    assert original_raw == Path(lanes.__file__).read_bytes()
    observer = write(c.root / "separate-observer" / relative,
                     original_raw + b"\n# Separately changed retirement verifier.\n")
    # Model a separately loaded observer's actual source path. The scientific
    # runtime, plan and original installed/frozen control bytes stay intact.
    monkeypatch.setattr(lanes, "__file__", str(observer))
    assert ordinary._sources() != original_controls
    with pytest.raises(ValueError, match="ordinary-only input layout differs from its exact current plan"):
        lanes._check_spec(c.spec)
    assert original.read_bytes() == original_raw
    assert c.spec.runtime_source_root == Path(c.runtime["runtime_source_root"])


@pytest.mark.parametrize("closed_batch", ["historical", "current"], indirect=True)
@pytest.mark.parametrize("mutation", ["preflight", "batch-intent", "release", "actual-launch", "worker-start",
    "result", "completion", "successful-host", "missing-terminal", "raw-log", "public-log", "public-success",
    "public-command", "unreviewed-source", "authority", "live-host", "partial-references", "boolean-count"])
def test_prebirth_retirement_rejects_unclosed_changed_born_or_unrelated_evidence(closed_batch, monkeypatch, mutation):
    c = closed_batch
    if mutation in {"preflight", "batch-intent", "release", "actual-launch"}:
        name = {"preflight": "image-preflight.json", "batch-intent": "batch-intent.json",
                "release": "release-prepared.json", "actual-launch": "actual-launch.json"}[mutation]
        write(c.output / name, {})
    elif mutation in {"worker-start", "completion"}:
        write(c.facts[0][2].parent / ("host-start.json" if mutation == "worker-start" else "complete.json"), {})
    elif mutation == "result":
        (c.spec.execution_root / "results" / c.facts[0][5].campaign_name).mkdir()
    elif mutation == "missing-terminal":
        (c.output / "host-process.json").unlink()
    elif mutation in {"raw-log", "public-log", "unreviewed-source", "authority"}:
        path = {"raw-log": c.output / "host.stderr", "public-log": c.public_started.parent / "launch.stderr.log",
                "unreviewed-source": c.spec.host_launcher, "authority": c.authority}[mutation]
        path.write_bytes(path.read_bytes() + b"changed\n")
    elif mutation == "live-host":
        monkeypatch.setattr(lanes, "_retired_identity", lambda _: (_ for _ in ()).throw(ValueError("original process is live")))
    elif mutation == "partial-references":
        with pytest.raises(ValueError, match="all exact batch"):
            lanes.retire_lane(c.spec, c.root, c.facts[0][2], batch_authority=c.authority)
        return
    else:
        path = c.output / "host-process.json" if mutation in {"successful-host", "boolean-count"} else c.public_completed
        if mutation == "public-command":
            path = c.public_started
        value = json.loads(path.read_bytes())
        if mutation == "public-command":
            value["command"][-1] += "-another-batch"
        elif mutation == "boolean-count":
            value["formal_accepted_trace_count"] = False
        else:
            value["returncode"] = 0
        write(path, value)
    with pytest.raises((OSError, ValueError, AssertionError, KeyError)):
        retire(c)
    assert not (c.facts[0][2].parent / "retirement.json").exists()


@pytest.mark.parametrize("mutation", ["container", "failed-query", "guardian", "socket", "ownership", "race"])
def test_fresh_locked_absence_is_required_before_publication(closed_batch, monkeypatch, mutation):
    c = closed_batch
    def observations(root, descriptor):
        checks = c.observations(root, descriptor)
        if mutation == "race":
            write(c.output / "image-preflight.json", {})
        elif mutation == "container":
            checks["docker_executions"][0]["stdout"] = lanes._put_object(root, b"live-container\n")
        elif mutation == "failed-query":
            checks["docker_executions"][0]["returncode"] = 125
        elif mutation == "guardian":
            checks["guardian_processes"] = [{}]
        elif mutation == "socket":
            checks["guardian_sockets"] = lanes._put_object(root, f"@qcsd-docker-lifecycle-guardian-{os.getuid()}".encode())
        else:
            checks["lifecycle_entries"] = ["run.live"]
        return checks
    monkeypatch.setattr(lanes, "_retirement_quiescence", observations)
    with pytest.raises(ValueError):
        retire(c)
    assert not (c.facts[0][2].parent / "retirement.json").exists()


def test_retirement_reopening_rejects_changed_original_bytes_and_early_observation(closed_batch):
    c = closed_batch
    receipt = retire(c)
    value = lanes._payload(receipt, KIND)
    changed = copy.deepcopy(value)
    changed["observed_at"] = "1999-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="exact original failed batch"):
        lanes._verified_retirement(lanes._json(lanes.admission._bind(KIND, changed)), c.root,
                                   c.facts[0][2].read_bytes(), c.facts[0][5].campaign_name)
    write(c.output / "host.stderr", b"changed old failure\n")
    with pytest.raises(ValueError):
        lanes._verified_retirement(receipt.read_bytes(), c.root, c.facts[0][2].read_bytes(), c.facts[0][5].campaign_name)


def test_public_cli_keeps_prebirth_evidence_explicit_and_optional():
    args = cli._parser().parse_args(["retire-lane", "--evidence-root", "/evidence", "--spec", "/spec",
        "--intent", "/intent", "--batch-authority", "/authority", "--batch-output", "/batch",
        "--public-started", "/started", "--public-completed", "/completed"])
    assert args.batch_authority == Path("/authority") and args.public_completed == Path("/completed")


@pytest.mark.parametrize("contract", [schedule.CONTRACT_V1, schedule.CONTRACT_V2, schedule.CONTRACT_V3])
def test_published_source_contracts_keep_exact_original_interpretation(source_bytes, tmp_path, contract):
    raw = HISTORICAL_V3
    assert lanes._sha(raw) == schedule.V3_HELPER_SHA256
    path = write(tmp_path / "historical_v3.py", raw)
    spec = importlib.util.spec_from_file_location("qcsd_lab._prebirth_retained_v3", path)
    historical = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(historical)
    old = {**source_bytes, schedule.MODULE_FILE: raw}
    new = dict(old)
    target = "src/qcsd_lab/rapid_lane_evidence.py"
    tree = ast.parse(new[target])
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_lineage_payload")
    node.body.insert(0, ast.parse("historical_control_only_probe = True").body[0])
    new[target] = ast.unparse(tree).encode()
    # Current inventories reach this whole module through their immutable
    # metadata dependencies. Named scheduling permission does not waive the
    # narrower qualification projection; the retained helper must still refuse.
    errors = []
    for validator in (historical, schedule):
        with pytest.raises(ValueError) as caught:
            validator.source_changes(old, new, client_sha256="a" * 64, contract=contract)
        errors.append(str(caught.value))
    assert errors == ["scheduling changed the response-only qualification primitive"] * 2
    # A genuine named HOST CLI control change preserves every package Source
    # byte and receives the same comparison from both original readers.
    cli_path = "tools/rapid_rolling_capture.py"
    cli_tree = ast.parse(old[cli_path])
    cli_parser = next(item for item in cli_tree.body if isinstance(item, ast.FunctionDef) and item.name == "_parser")
    cli_parser.body.insert(0, ast.parse("source_control_only_probe = True").body[0])
    qualified_same = {**old, cli_path: ast.unparse(cli_tree).encode()}
    expected = historical.source_changes(old, qualified_same, client_sha256="a" * 64, contract=contract)
    assert expected["changed_sources"][cli_path]["units"] == ["_parser"]
    assert schedule.source_changes(old, qualified_same, client_sha256="a" * 64, contract=contract) == expected
    protected = ast.parse(old[target])
    node = next(item for item in protected.body if isinstance(item, ast.FunctionDef) and item.name == "retire_lane")
    node.body.insert(0, ast.parse("new_prebirth_probe = True").body[0])
    new[target] = ast.unparse(protected).encode()
    for validator in (historical, schedule):
        with pytest.raises(ValueError, match="outside named control"):
            validator.source_changes(old, new, client_sha256="a" * 64, contract=contract)


def test_current_contract_refuses_retirement_primitive_changes_and_accepts_unchanged_science_controls(source_bytes):
    paths = {"src/qcsd_lab/rapid_lane_evidence.py", "tools/rapid_rolling_capture.py", schedule.MODULE_FILE}
    old = dict(source_bytes)
    old[schedule.MODULE_FILE] = HISTORICAL_V3
    for path in paths - {schedule.MODULE_FILE}:
        tree = ast.parse(old[path])
        controls = HISTORICAL_CONTROLS[path]
        added = schedule.CONTROL_DEFINITIONS[path] - schedule.V3_CONTROL_DEFINITIONS[path]
        tree.body = [node for node in tree.body if not (isinstance(node, ast.FunctionDef)
            and (node.name in controls or node.name in added))]
        tree.body.extend(ast.parse(raw).body[0] for raw in controls.values())
        old[path] = ast.unparse(tree).encode()
    new = {**old, **{path: (ROOT / path).read_bytes() for path in paths}}
    with pytest.raises(ValueError) as caught:
        schedule.source_changes(old, new, client_sha256="a" * 64)
    assert str(caught.value) == "scheduling changed the response-only qualification primitive"
    # Fresh-Source retirement is exercised separately by the production API
    # cases. Cross-Source reuse above remains blocked. This positive control
    # retains the identical package/metadata bodies, including retirement.
    protected_same = dict(source_bytes)
    cli_path = "tools/rapid_rolling_capture.py"
    cli_tree = ast.parse(protected_same[cli_path])
    cli_parser = next(item for item in cli_tree.body if isinstance(item, ast.FunctionDef) and item.name == "_parser")
    cli_parser.body.insert(0, ast.parse("source_control_only_probe = True").body[0])
    qualified_same = {**protected_same, cli_path: ast.unparse(cli_tree).encode()}
    actual = schedule.source_changes(protected_same, qualified_same, client_sha256="a" * 64)
    assert set(actual["changed_sources"]) == {cli_path}
    assert actual["changed_sources"][cli_path]["units"] == ["_parser"]
    unchanged = schedule.source_changes(protected_same, protected_same, client_sha256="a" * 64)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert actual[key] == unchanged[key]
    fixture = "tests/fixtures/rapid_parallel_scheduling_v2.json.zlib.b85.txt"
    fixture_bytes = (ROOT / fixture).read_bytes()
    with_fixture = schedule.source_changes(protected_same, {**qualified_same, fixture: fixture_bytes}, client_sha256="a" * 64)
    assert set(with_fixture["changed_sources"]) == {cli_path, fixture}
    assert with_fixture["changed_sources"][fixture]["units"] == ["nonexecuting-evidence-description"]
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert with_fixture[key] == unchanged[key]
    for contract in (schedule.CONTRACT_V1, schedule.CONTRACT_V2, schedule.CONTRACT_V3):
        with pytest.raises(ValueError, match="unregistered source"):
            schedule.source_changes(old, {**old, fixture: fixture_bytes}, client_sha256="a" * 64, contract=contract)
    for path in ("src/qcsd_lab/fidelity.py", "src/qcsd_lab/chaff_qualification.py", "neqo-qcsd/neqo-bin/src/qcsd/mod.rs"):
        with pytest.raises(ValueError):
            schedule.source_changes(protected_same, {**qualified_same, path: protected_same[path] + b"\nUNREVIEWED = True\n"},
                                    client_sha256="a" * 64)
