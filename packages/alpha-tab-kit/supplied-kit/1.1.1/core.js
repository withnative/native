/* Native core app kit — AGPL-3.0-only; Copyright Native contributors. */
/*
preact:
The MIT License (MIT)

Copyright (c) 2015-present Jason Miller

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

htm:

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2018 Google Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.*/

(function () {
var CoreFactoryExports=(function(ke){"use strict";class R extends Error{constructor(t,n,o){super(n??t),this.code=t,this.detail=o,this.name="PortError"}code;detail}const Mt=e=>!!e&&typeof e=="object"&&!Array.isArray(e);function It(e,t){if(!Mt(e)||!Array.isArray(e.rows))throw new R("malformed","the host's answer has no rows");const n=e.rows;return{label:typeof e.label=="string"?e.label:"",columns:Array.isArray(e.columns)?e.columns:[],rows:n,rowCount:typeof e.row_count=="number"?e.row_count:n.length,rowCountComplete:e.row_count_complete!==!1,truncated:e.truncated===!0}}function xt(){const e=window.native;return e&&typeof e=="object"?e:void 0}const Ke=e=>{const t=e?.input;return t&&typeof t=="object"&&!Array.isArray(t)?t:void 0},we=e=>e instanceof R?e:new R("unavailable",String(e));function Ut(e){let t=!1,n,o=!1,s=!1;const r=new Set,_=c=>{if(t)throw new R("closed");const l=n?.sql;if(!l||typeof l!="object"||Array.isArray(l)||!Object.hasOwn(l,c))throw new R("undeclared",`the snapshot "${c}" was not delivered: declare it as a param-less sql.snapshot.v1 need`);return It(l[c])},u=e.ready.then(c=>{!t&&!s&&(n=Ke(c)),o=!0},c=>{throw we(c)});u.catch(()=>{});const d=e.onInput(c=>{if(t)return;const l=Ke(c);if(l&&(s=!0,n=l,o))for(const a of[...r])a.update()});return{ready:u,async read(c){if(t)throw new R("closed");return await u,_(c)},subscribe(c,l){if(t)throw new R("closed");let a=!0,i;const f={update(){if(!a||t)return;let v;try{i=_(c),v={status:"ready",result:i}}catch(y){v={status:"error",error:we(y),...i?{last:i}:{}}}h(v)},close(){a=!1,r.delete(f)}},h=v=>{if(!(!a||t))try{l(v)}catch{f.close()}};r.add(f);try{l({status:"loading"})}catch(v){throw f.close(),v}return u.then(()=>f.update(),v=>{h({status:"error",error:we(v)})}).catch(()=>{f.close()}),f.close},dispose(){if(!t){t=!0;for(const c of[...r])c.close();d(),n=void 0}}}}const Wt={busy:"Native is busy right now.",timeout:"Native took too long to answer.",undeclared:"This app was not given access to that data.",refused:"Native refused that request.",unavailable:"That data is not available right now.",malformed:"Native's answer was not in the expected shape.",closed:"This app was closed."};function $e(e){return Wt[e.code]}function Ft(e){const t=e.rows.length;if(!e.truncated)return`${t}`;const n=e.rowCount.toLocaleString("en-US");return e.rowCountComplete?`${t} of ${n}`:`${t} of more than ${n}`}function Ve(e){return{"data-native-record-id":e}}function Xe(e){return{"data-native-external-url":e}}const Y={version:"1.1.1",major:1,layer:"core",factory:"native.app-kit.core.factory.v1",bridge:"native.html.bridge.v1"};function qt(e,t){if(Object.keys(t).sort().join(",")!=="bridge,factory,js_sha256,layer,major,types_sha256,version"||t.version!==Y.version||t.major!==Y.major||t.layer!==Y.layer||t.factory!==Y.factory||t.bridge!==Y.bridge||!/^[a-f0-9]{64}$/.test(t.js_sha256)||!/^[a-f0-9]{64}$/.test(t.types_sha256))throw new Error("incompatible core kit release metadata");const n=Ut(e),o=Object.freeze({release:Object.freeze({...t}),ready:n.ready,read:n.read,subscribe:n.subscribe,countLabel:Ft,errorText:$e,recordLink:Ve,externalLink:Xe});return Object.freeze({kit:o,dispose(){n.dispose()}})}var ne,b,Ze,U,Qe,Ye,Ge,Ee,re,G,Je,Ne,Se,Ce,et,oe={},ie=[],Bt=/acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i,se=Array.isArray;function L(e,t){for(var n in t)e[n]=t[n];return e}function Te(e){e&&e.parentNode&&e.parentNode.removeChild(e)}function m(e,t,n){var o,s,r,_={};for(r in t)r=="key"?o=t[r]:r=="ref"?s=t[r]:_[r]=t[r];if(arguments.length>2&&(_.children=arguments.length>3?ne.call(arguments,2):n),typeof e=="function"&&e.defaultProps!=null)for(r in e.defaultProps)_[r]===void 0&&(_[r]=e.defaultProps[r]);return ce(e,_,o,s,null)}function ce(e,t,n,o,s){var r={type:e,props:t,key:n,ref:o,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:s??++Ze,__i:-1,__u:0};return s==null&&b.vnode!=null&&b.vnode(r),r}function Z(e){return e.children}function le(e,t){this.props=e,this.context=t}function B(e,t){if(t==null)return e.__?B(e.__,e.__i+1):null;for(var n;t<e.__k.length;t++)if((n=e.__k[t])!=null&&n.__e!=null)return n.__e;return typeof e.type=="function"?B(e):null}function zt(e){if(e.__P&&e.__d){var t=e.__v,n=t.__e,o=[],s=[],r=L({},t);r.__v=t.__v+1,b.vnode&&b.vnode(r),Oe(e.__P,r,t,e.__n,e.__P.namespaceURI,32&t.__u?[n]:null,o,n??B(t),!!(32&t.__u),s),r.__v=t.__v,r.__.__k[r.__i]=r,ct(o,r,s),t.__e=t.__=null,r.__e!=n&&tt(r)}}function tt(e){if((e=e.__)!=null&&e.__c!=null)return e.__e=e.__c.base=null,e.__k.some(function(t){if(t!=null&&t.__e!=null)return e.__e=e.__c.base=t.__e}),tt(e)}function Ae(e){(!e.__d&&(e.__d=!0)&&U.push(e)&&!_e.__r++||Qe!=b.debounceRendering)&&((Qe=b.debounceRendering)||Ye)(_e)}function _e(){try{for(var e,t=1;U.length;)U.length>t&&U.sort(Ge),e=U.shift(),t=U.length,zt(e)}finally{U.length=_e.__r=0}}function nt(e,t,n,o,s,r,_,u,d,c,l){var a,i,f,h,v,y,g=o&&o.__k||ie,p=t.length;for(d=Kt(n,t,g,d,p),a=0;a<p;a++)(f=n.__k[a])!=null&&(i=f.__i!=-1&&g[f.__i]||oe,f.__i=a,y=Oe(e,f,i,s,r,_,u,d,c,l),h=f.__e,f.ref&&i.ref!=f.ref&&(i.ref&&Pe(i.ref,null,f),l.push(f.ref,f.__c||h,f)),v==null&&h!=null&&(v=h),4&f.__u?(d=rt(f,d,e),i.__e&&(i.__e=null)):typeof f.type=="function"&&y!==void 0?d=y:h&&(d=h.nextSibling),f.__u&=-7);return n.__e=v,d}function Kt(e,t,n,o,s){var r,_,u,d,c,l=n.length,a=l,i=0;for(e.__k=new Array(s),r=0;r<s;r++)(_=t[r])!=null&&typeof _!="boolean"&&typeof _!="function"?(typeof _=="string"||typeof _=="number"||typeof _=="bigint"||_.constructor==String?_=e.__k[r]=ce(null,_,null,null,null):se(_)?_=e.__k[r]=ce(Z,{children:_},null,null,null):_.constructor===void 0&&_.__b>0?_=e.__k[r]=ce(_.type,_.props,_.key,_.ref?_.ref:null,_.__v):e.__k[r]=_,d=r+i,_.__=e,_.__b=e.__b+1,u=null,(c=_.__i=Vt(_,n,d,a))!=-1&&(a--,(u=n[c])&&(u.__u|=2)),u==null||u.__v==null?(c==-1&&(s>l?i--:s<l&&i++),typeof _.type!="function"&&(_.__u|=4)):c!=d&&(c==d-1?i--:c==d+1?i++:(c>d?i--:i++,_.__u|=4))):e.__k[r]=null;if(a)for(r=0;r<l;r++)(u=n[r])!=null&&(2&u.__u)==0&&(u.__e==o&&(o=B(u)),_t(u,u));return o}function rt(e,t,n){var o,s;if(typeof e.type=="function"){for(o=e.__k,s=0;o&&s<o.length;s++)o[s]&&(o[s].__=e,t=rt(o[s],t,n));return t}e.__e!=t&&(t&&e.type&&!t.parentNode&&(t=B(e)),t=n.insertBefore(e.__e,t||null));do t=t&&t.nextSibling;while(t!=null&&t.nodeType==8);return t}function Vt(e,t,n,o){var s,r,_,u=e.key,d=e.type,c=t[n],l=c!=null&&(2&c.__u)==0;if(c===null&&u==null||l&&u==c.key&&d==c.type)return n;if(o>(l?1:0)){for(s=n-1,r=n+1;s>=0||r<t.length;)if((c=t[_=s>=0?s--:r++])!=null&&(2&c.__u)==0&&u==c.key&&d==c.type)return _}return-1}function ot(e,t,n){t[0]=="-"?e.setProperty(t,n??""):e[t]=n==null?"":typeof n!="number"||Bt.test(t)?n:n+"px"}function ue(e,t,n,o,s){var r,_;e:if(t=="style")if(typeof n=="string")e.style.cssText=n;else{if(typeof o=="string"&&(e.style.cssText=o=""),o)for(t in o)n&&t in n||ot(e.style,t,"");if(n)for(t in n)o&&n[t]==o[t]||ot(e.style,t,n[t])}else if(t[0]=="o"&&t[1]=="n")r=t!=(t=t.replace(Je,"$1")),_=t.toLowerCase(),t=_ in e||t=="onFocusOut"||t=="onFocusIn"?_.slice(2):t.slice(2),e.l||(e.l={}),e.l[t+r]=n,n?o?n[G]=o[G]:(n[G]=Ne,e.addEventListener(t,r?Ce:Se,r)):e.removeEventListener(t,r?Ce:Se,r);else{if(s=="http://www.w3.org/2000/svg")t=t.replace(/xlink(H|:h)/,"h").replace(/sName$/,"s");else if(t!="width"&&t!="height"&&t!="href"&&t!="list"&&t!="form"&&t!="tabIndex"&&t!="download"&&t!="rowSpan"&&t!="colSpan"&&t!="role"&&t!="popover"&&t in e)try{e[t]=n??"";break e}catch{}typeof n=="function"||(n==null||n===!1&&t[4]!="-"?e.removeAttribute(t):e.setAttribute(t,t=="popover"&&n==1?"":n))}}function it(e){return function(t){if(this.l){var n=this.l[t.type+e];if(t[re]==null)t[re]=Ne++;else if(t[re]<n[G])return;return n(b.event?b.event(t):t)}}}function Oe(e,t,n,o,s,r,_,u,d,c){var l,a,i,f,h,v,y,g,p,E,j,A,T,I,x,O,w=t.type;if(t.constructor!==void 0)return null;128&n.__u&&(d=!!(32&n.__u),r=[u=t.__e=n.__e]),(l=b.__b)&&l(t);e:if(typeof w=="function"){a=_.length;try{if(p=t.props,E=w.prototype&&w.prototype.render,j=(l=w.contextType)&&o[l.__c],A=l?j?j.props.value:l.__:o,n.__c?g=(i=t.__c=n.__c).__=i.__E:(E?t.__c=i=new w(p,A):(t.__c=i=new le(p,A),i.constructor=w,i.render=Zt),j&&j.sub(i),i.state||(i.state={}),i.__n=o,f=i.__d=!0,i.__h=[],i._sb=[]),E&&i.__s==null&&(i.__s=i.state),E&&w.getDerivedStateFromProps!=null&&(i.__s==i.state&&(i.__s=L({},i.__s)),L(i.__s,w.getDerivedStateFromProps(p,i.__s))),h=i.props,v=i.state,i.__v=t,f)E&&w.getDerivedStateFromProps==null&&i.componentWillMount!=null&&i.componentWillMount(),E&&i.componentDidMount!=null&&i.__h.push(i.componentDidMount);else{if(E&&w.getDerivedStateFromProps==null&&p!==h&&i.componentWillReceiveProps!=null&&i.componentWillReceiveProps(p,A),t.__v==n.__v||!i.__e&&i.shouldComponentUpdate!=null&&i.shouldComponentUpdate(p,i.__s,A)===!1){t.__v!=n.__v&&(i.props=p,i.state=i.__s,i.__d=!1),t.__e=n.__e,t.__k=n.__k,t.__k.some(function(W){W&&(W.__=t)}),ie.push.apply(i.__h,i._sb),i._sb=[],i.__h.length&&_.push(i),u=B(n);break e}i.componentWillUpdate!=null&&i.componentWillUpdate(p,i.__s,A),E&&i.componentDidUpdate!=null&&i.__h.push(function(){i.componentDidUpdate(h,v,y)})}if(i.context=A,i.props=p,i.__P=e,i.__e=!1,T=b.__r,I=0,E)i.state=i.__s,i.__d=!1,T&&T(t),l=i.render(i.props,i.state,i.context),ie.push.apply(i.__h,i._sb),i._sb=[];else do i.__d=!1,T&&T(t),l=i.render(i.props,i.state,i.context),i.state=i.__s;while(i.__d&&++I<25);i.state=i.__s,i.getChildContext!=null&&(o=L(L({},o),i.getChildContext())),E&&!f&&i.getSnapshotBeforeUpdate!=null&&(y=i.getSnapshotBeforeUpdate(h,v)),x=l!=null&&l.type===Z&&l.key==null?lt(l.props.children):l,u=nt(e,se(x)?x:[x],t,n,o,s,r,_,u,d,c),i.base=t.__e,t.__u&=-161,i.__h.length&&_.push(i),g&&(i.__E=i.__=null)}catch(W){if(_.length=a,t.__v=null,d||r!=null){if(W.then){for(t.__u|=d?160:128;u&&u.nodeType==8&&u.nextSibling;)u=u.nextSibling;r!=null&&(r[r.indexOf(u)]=null),t.__e=u}else if(r!=null)for(O=r.length;O--;)Te(r[O])}else t.__e=n.__e;t.__k==null&&(t.__k=n.__k||[]),W.then||st(t),b.__e(W,t,n)}}else r==null&&t.__v==n.__v?(t.__k=n.__k,t.__e=n.__e):u=t.__e=Xt(n.__e,t,n,o,s,r,_,d,c);return(l=b.diffed)&&l(t),128&t.__u?void 0:u}function st(e){e&&(e.__c&&(e.__c.__e=!0),e.__k&&e.__k.some(st))}function ct(e,t,n){for(var o=0;o<n.length;o++)Pe(n[o],n[++o],n[++o]);b.__c&&b.__c(t,e),e.some(function(s){try{e=s.__h,s.__h=[],e.some(function(r){r.call(s)})}catch(r){b.__e(r,s.__v)}})}function lt(e){return typeof e!="object"||e==null||e.__b>0?e:se(e)?e.map(lt):e.constructor!==void 0?null:L({},e)}function Xt(e,t,n,o,s,r,_,u,d){var c,l,a,i,f,h,v,y=n.props||oe,g=t.props,p=t.type;if(p=="svg"?s="http://www.w3.org/2000/svg":p=="math"?s="http://www.w3.org/1998/Math/MathML":s||(s="http://www.w3.org/1999/xhtml"),r!=null){for(c=0;c<r.length;c++)if((f=r[c])&&"setAttribute"in f==!!p&&(p?f.localName==p:f.nodeType==3)){e=f,r[c]=null;break}}if(e==null){if(p==null)return document.createTextNode(g);e=document.createElementNS(s,p,g.is&&g),u&&(b.__m&&b.__m(t,r),u=!1),r=null}if(p==null)y===g||u&&e.data==g||(e.data=g);else{if(r=p=="textarea"&&g.defaultValue!=null?null:r&&ne.call(e.childNodes),!u&&r!=null)for(y={},c=0;c<e.attributes.length;c++)y[(f=e.attributes[c]).name]=f.value;for(c in y)f=y[c],c=="dangerouslySetInnerHTML"?a=f:c=="children"||c in g||c=="value"&&"defaultValue"in g||c=="checked"&&"defaultChecked"in g||ue(e,c,null,f,s);for(c in g)f=g[c],c=="children"?i=f:c=="dangerouslySetInnerHTML"?l=f:c=="value"?h=f:c=="checked"?v=f:u&&typeof f!="function"||y[c]===f||ue(e,c,f,y[c],s);if(l)u||a&&(l.__html==a.__html||l.__html==e.innerHTML)||(e.innerHTML=l.__html),t.__k=[];else if(a&&(e.innerHTML=""),nt(t.type=="template"?e.content:e,se(i)?i:[i],t,n,o,p=="foreignObject"?"http://www.w3.org/1999/xhtml":s,r,_,r?r[0]:n.__k&&B(n,0),u,d),r!=null)for(c=r.length;c--;)Te(r[c]);u&&p!="textarea"||(c="value",p=="progress"&&h==null?e.removeAttribute("value"):h!=null&&(h!==e[c]||p=="progress"&&!h||p=="option"&&h!=y[c])&&ue(e,c,h,y[c],s),c="checked",v!=null&&v!=e[c]&&ue(e,c,v,y[c],s))}return e}function Pe(e,t,n){try{if(typeof e=="function"){var o=typeof e.__u=="function";o&&e.__u(),o&&t==null||(e.__u=e(t))}else e.current=t}catch(s){b.__e(s,n)}}function _t(e,t,n){var o,s;if(b.unmount&&b.unmount(e),(o=e.ref)&&(o.current&&o.current!=e.__e||Pe(o,null,t)),(o=e.__c)!=null){if(o.componentWillUnmount)try{o.componentWillUnmount()}catch(r){b.__e(r,t)}o.base=o.__P=o.__n=null}if(o=e.__k)for(s=0;s<o.length;s++)o[s]&&_t(o[s],t,n||typeof e.type!="function");n||Te(e.__e),e.__c=e.__=e.__e=void 0}function Zt(e,t,n){return this.constructor(e,n)}function Qt(e,t,n){var o,s,r,_;t==document&&(t=document.documentElement),b.__&&b.__(e,t),s=(o=typeof n=="function")?null:n&&n.__k||t.__k,r=[],_=[],Oe(t,e=(!o&&n||t).__k=m(Z,null,[e]),s||oe,oe,t.namespaceURI,!o&&n?[n]:s?null:t.firstChild?ne.call(t.childNodes):null,r,!o&&n?n:s?s.__e:t.firstChild,o,_),ct(r,e,_),e.props.children=null}function Yt(e){function t(n){var o,s;return this.getChildContext||(o=new Set,(s={})[t.__c]=this,this.getChildContext=function(){return s},this.componentWillUnmount=function(){o=null},this.shouldComponentUpdate=function(r){this.props.value!=r.value&&o.forEach(function(_){_.__e=!0,Ae(_)})},this.sub=function(r){o.add(r);var _=r.componentWillUnmount;r.componentWillUnmount=function(){o&&o.delete(r),_&&_.call(r)}}),n.children}return t.__c="__cC"+et++,t.__=e,t.Provider=t.__l=(t.Consumer=function(n,o){return n.children(o)}).contextType=t,t}ne=ie.slice,b={__e:function(e,t,n,o){for(var s,r,_;t=t.__;)if((s=t.__c)&&!s.__)try{if((r=s.constructor)&&r.getDerivedStateFromError!=null&&(s.setState(r.getDerivedStateFromError(e)),_=s.__d),s.componentDidCatch!=null&&(s.componentDidCatch(e,o||{}),_=s.__d),_)return s.__E=s}catch(u){e=u}throw e}},Ze=0,le.prototype.setState=function(e,t){var n;n=this.__s!=null&&this.__s!=this.state?this.__s:this.__s=L({},this.state),typeof e=="function"&&(e=e(L({},n),this.props)),e&&L(n,e),e!=null&&this.__v&&(t&&this._sb.push(t),Ae(this))},le.prototype.forceUpdate=function(e){this.__v&&(this.__e=!0,e&&this.__h.push(e),Ae(this))},le.prototype.render=Z,U=[],Ye=typeof Promise=="function"?Promise.prototype.then.bind(Promise.resolve()):setTimeout,Ge=function(e,t){return e.__v.__b-t.__v.__b},_e.__r=0,Ee=Math.random().toString(8),re="__d"+Ee,G="__a"+Ee,Je=/(PointerCapture)$|Capture$/i,Ne=0,Se=it(!1),Ce=it(!0),et=0;var H,k,Re,ut,Q=0,at=[],$=b,ft=$.__b,dt=$.__r,pt=$.diffed,ht=$.__c,mt=$.unmount,vt=$.__;function z(e,t){$.__h&&$.__h(k,e,Q||t),Q=0;var n=k.__H||(k.__H={__:[],__h:[]});return e>=n.__.length&&n.__.push({}),n.__[e]}function K(e){return Q=1,gt(wt,e)}function gt(e,t,n){var o=z(H++,2);if(o.t=e,!o.__c&&(o.__=[n?n(t):wt(void 0,t),function(u){var d=o.__N?o.__N[0]:o.__[0],c=o.t(d,u);d!==c&&(o.__N=[c,o.__[1]],o.__c.setState({}))}],o.__c=k,!k.__f)){var s=function(u,d,c){if(!o.__c.__H)return!0;var l=!1,a=o.__c.props!==u;if(o.__c.__H.__.some(function(f){if(f.__N){l=!0;var h=f.__[0];f.__=f.__N,f.__N=void 0,h!==f.__[0]&&(a=!0)}}),r){var i=r.call(this,u,d,c);return l?i||a:i}return!l||a};k.__f=!0;var r=k.shouldComponentUpdate,_=k.componentWillUpdate;k.componentWillUpdate=function(u,d,c){if(this.__e){var l=r;r=void 0,s(u,d,c),r=l}_&&_.call(this,u,d,c)},k.shouldComponentUpdate=s}return o.__N||o.__}function ae(e,t){var n=z(H++,3);!$.__s&&Le(n.__H,t)&&(n.__=e,n.u=t,k.__H.__h.push(n))}function yt(e,t){var n=z(H++,4);!$.__s&&Le(n.__H,t)&&(n.__=e,n.u=t,k.__h.push(n))}function fe(e){return Q=5,je(function(){return{current:e}},[])}function Gt(e,t,n){Q=6,yt(function(){if(typeof e=="function"){var o=e(t());return function(){e(null),o&&typeof o=="function"&&o()}}if(e)return e.current=t(),function(){return e.current=null}},n==null?n:n.concat(e))}function je(e,t){var n=z(H++,7);return Le(n.__H,t)&&(n.__=e(),n.__H=t,n.__h=e),n.__}function bt(e,t){return Q=8,je(function(){return e},t)}function Jt(e){var t=k.context[e.__c],n=z(H++,9);return n.c=e,t?(n.__==null&&(n.__=!0,t.sub(k)),t.props.value):e.__}function en(e,t){$.useDebugValue&&$.useDebugValue(t?t(e):e)}function tn(e){var t=z(H++,10),n=K();return t.__=e,k.componentDidCatch||(k.componentDidCatch=function(o,s){t.__&&t.__(o,s),n[1](o)}),[n[0],function(){n[1](void 0)}]}function nn(){var e=z(H++,11);if(!e.__){for(var t=k.__v;t!==null&&!t.__m&&t.__!==null;)t=t.__;var n=t.__m||(t.__m=[0,0]);e.__="P"+n[0]+"-"+n[1]++}return e.__}function rn(){for(var e;e=at.shift();){var t=e.__H;if(e.__P&&t)try{t.__h.some(de),t.__h.some(De),t.__h=[]}catch(n){t.__h=[],$.__e(n,e.__v)}}}$.__b=function(e){k=null,ft&&ft(e)},$.__=function(e,t){e&&t.__k&&t.__k.__m&&(e.__m=t.__k.__m),vt&&vt(e,t)},$.__r=function(e){dt&&dt(e),H=0;var t=(k=e.__c).__H;t&&(Re===k?(t.__h=[],k.__h=[],t.__.some(function(n){n.__N&&(n.__=n.__N),n.u=n.__N=void 0})):(t.__h.some(de),t.__h.some(De),t.__h=[],H=0)),Re=k},$.diffed=function(e){pt&&pt(e);var t=e.__c;t&&t.__H&&(t.__H.__h.length&&(at.push(t)!==1&&ut===$.requestAnimationFrame||((ut=$.requestAnimationFrame)||on)(rn)),t.__H.__.some(function(n){n.u&&(n.__H=n.u,n.u=void 0)})),Re=k=null},$.__c=function(e,t){t.some(function(n){try{n.__h.some(de),n.__h=n.__h.filter(function(o){return!o.__||De(o)})}catch(o){t.some(function(s){s.__h&&(s.__h=[])}),t=[],$.__e(o,n.__v)}}),ht&&ht(e,t)},$.unmount=function(e){mt&&mt(e);var t,n=e.__c;n&&n.__H&&(n.__H.__.some(function(o){try{de(o)}catch(s){t=s}}),n.__H=void 0,t&&$.__e(t,n.__v))};var kt=typeof requestAnimationFrame=="function";function on(e){var t,n=function(){clearTimeout(o),kt&&cancelAnimationFrame(t),setTimeout(e)},o=setTimeout(n,35);kt&&(t=requestAnimationFrame(n))}function de(e){var t=k,n=e.__c;typeof n=="function"&&(e.__c=void 0,n()),k=t}function De(e){var t=k;e.__c=e.__(),k=t}function Le(e,t){return!e||e.length!==t.length||t.some(function(n,o){return n!==e[o]})}function wt(e,t){return typeof t=="function"?t(e):t}const sn=Object.freeze(Object.defineProperty({__proto__:null,useCallback:bt,useContext:Jt,useDebugValue:en,useEffect:ae,useErrorBoundary:tn,useId:nn,useImperativeHandle:Gt,useLayoutEffect:yt,useMemo:je,useReducer:gt,useRef:fe,useState:K},Symbol.toStringTag,{value:"Module"}));var $t=function(e,t,n,o){var s;t[0]=0;for(var r=1;r<t.length;r++){var _=t[r++],u=t[r]?(t[0]|=_?1:2,n[t[r++]]):t[++r];_===3?o[0]=u:_===4?o[1]=Object.assign(o[1]||{},u):_===5?(o[1]=o[1]||{})[t[++r]]=u:_===6?o[1][t[++r]]+=u+"":_?(s=e.apply(u,$t(e,u,n,["",null])),o.push(s),u[0]?t[0]|=2:(t[r-2]=0,t[r]=s)):o.push(u)}return o},Et=new Map;function cn(e){var t=Et.get(this);return t||(t=new Map,Et.set(this,t)),(t=$t(this,t.get(e)||(t.set(e,t=(function(n){for(var o,s,r=1,_="",u="",d=[0],c=function(i){r===1&&(i||(_=_.replace(/^\s*\n\s*|\s*\n\s*$/g,"")))?d.push(0,i,_):r===3&&(i||_)?(d.push(3,i,_),r=2):r===2&&_==="..."&&i?d.push(4,i,0):r===2&&_&&!i?d.push(5,0,!0,_):r>=5&&((_||!i&&r===5)&&(d.push(r,0,_,s),r=6),i&&(d.push(r,i,0,s),r=6)),_=""},l=0;l<n.length;l++){l&&(r===1&&c(),c(l));for(var a=0;a<n[l].length;a++)o=n[l][a],r===1?o==="<"?(c(),d=[d],r=3):_+=o:r===4?_==="--"&&o===">"?(r=1,_=""):_=o+_[0]:u?o===u?u="":_+=o:o==='"'||o==="'"?u=o:o===">"?(c(),r=1):r&&(o==="="?(r=5,s=_,_=""):o==="/"&&(r<5||n[l][a+1]===">")?(c(),r===3&&(d=d[0]),r=d,(d=d[0]).push(2,0,r),r=0):o===" "||o==="	"||o===`
`||o==="\r"?(c(),r=2):_+=o),r===3&&_==="!--"&&(r=4,d=d[0])}return c(),d})(e)),t),arguments,[])).length>1?t:t[0]}let He=null;function ln(e){if(!/^[A-Za-z][A-Za-z0-9]{0,31}$/.test(e)||typeof document>"u")return;He??=document.createElement("textarea");const t=`&${e};`;He.innerHTML=t;const n=He.value;if(n!==t&&!(n.endsWith(";")&&n!==";"))return n}const _n=34,Nt="&(?:#([0-9]{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{0,31}));",un=new RegExp("^"+Nt);function St(e,t,n){if(n)return ln(n);const o=Number.parseInt(e??t,e===void 0?16:10);return String.fromCodePoint(!o||o>1114111||o>=55296&&o<=57343?65533:o)}function an(e,t){const n=un.exec(e.slice(t,t+_n));if(!n)return null;const o=St(n[1],n[2],n[3]);return o===void 0?null:{value:o,end:t+n[0].length}}const fn=new RegExp("\\\\[\\s\\S]|`+|"+Nt,"g");function Ct(e,t){let n=0;return e.replace(fn,(o,s,r,_,u)=>{if(u<n)return o;if(t&&o[0]==="`"){const d=e.indexOf(o,u+o.length);d>0&&e[d+o.length]!=="`"&&(n=d+o.length)}return o[0]==="&"?St(s,r,_)??o:o})}function dn(e){return Ct(e,!1)}function pn(e){return Ct(e,!0)}const Me=6,hn=2e4,mn=12,Tt=/^ {0,3}(`{3,}|~{3,})\s*([^`\s]*)[^`]*$/,At=/^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$/,Ot=/^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/,J=/^(\s*)([-*+]|\d{1,9}[.)])(?:[ \t]+(.*)|$)$/,pe=/^ {0,3}>[ \t]?(.*)$/,vn=/^\s*\|?\s*:?-{1,}:?\s*(?:\|\s*:?-{1,}:?\s*)*\|?\s*$/,ee=e=>{let t=0;for(const n of e)if(n===" ")t+=1;else if(n==="	")t+=4-t%4;else break;return t},gn=(e,t)=>{let n=0,o=0;for(;o<e.length&&n<t;){const s=e[o];if(s===" ")n+=1;else if(s==="	")n+=4-n%4;else break;o+=1}return e.slice(o)},V=e=>e.trim()==="",Ie=(e,t)=>Tt.test(e)||At.test(e)||Ot.test(e)||pe.test(e)||J.test(e)||Pt(e,t);function Pt(e,t){return t!==void 0&&e.includes("|")&&vn.test(t)&&t.includes("-")&&he(e).length>=1&&(t.includes("|")||e.trim().startsWith("|"))}function he(e){let t=e.trim();t.startsWith("|")&&(t=t.slice(1)),t.endsWith("|")&&!t.endsWith("\\|")&&(t=t.slice(0,-1));const n=[];let o="";for(let s=0;s<t.length;s+=1){const r=t[s];r==="\\"&&t[s+1]==="|"?(o+="|",s+=1):r==="|"?(n.push(o.trim()),o=""):o+=r}return n.push(o.trim()),n}function yn(e){return xe(e.replace(/\r\n?/g,`
`).split(`
`),0)}function xe(e,t,n,o){const s=[];if(t>mn){const u=e.join(`
`).trim();return u?[{type:"paragraph",children:[{type:"text",text:u}]}]:[]}let r=0;const _=u=>{s.push(u)};for(;r<e.length;){const u=e[r];if(V(u)){r+=1;continue}const d=Tt.exec(u);if(d){const i=d[1],f=[];for(r+=1;r<e.length&&!new RegExp(`^ {0,3}${i[0]==="`"?"`":"~"}{${i.length},}\\s*$`).test(e[r]);)f.push(e[r]),r+=1;r+=1,_({type:"code",lang:d[2]??"",text:f.join(`
`)});continue}const c=At.exec(u);if(c){r+=1,_({type:"heading",level:c[1].length,children:ve(c[2],o,!1)});continue}if(Ot.test(u)){r+=1,_({type:"rule"});continue}if(pe.test(u)){const i=[];for(;r<e.length&&(pe.test(e[r])||!V(e[r])&&i.length>0&&!Ie(e[r],void 0));){const v=pe.exec(e[r]);i.push(v?v[1]:e[r]),r+=1}let f=null;const h=/^\[!([A-Za-z]{2,12})\][ \t]*$/.exec(i[0]??"");h&&(f=h[1].toLowerCase(),i.shift()),_({type:"quote",callout:f,children:xe(i,t+1,void 0,o)});continue}if(J.exec(u)){const[i,f]=bn(e,r,t,o);r=f,_(i);continue}if(Pt(u,e[r+1])){const i=he(u),f=he(e[r+1]).map(y=>{const g=y.startsWith(":"),p=y.endsWith(":");return g&&p?"center":p?"right":g?"left":null}),h=[];for(r+=2;r<e.length&&!V(e[r])&&e[r].includes("|");)h.push(he(e[r])),r+=1;const v=i.length;_({type:"table",align:Array.from({length:v},(y,g)=>f[g]??null),head:i.map(y=>ve(y,o)),rows:h.map(y=>Array.from({length:v},(g,p)=>ve(y[p]??"",o)))});continue}const a=[u];for(r+=1;r<e.length&&!V(e[r])&&!Ie(e[r],e[r+1]);)a.push(e[r]),r+=1;_({type:"paragraph",children:ve(a.map((i,f)=>f<a.length-1?i.replace(/(?: {2,}|\\)$/,"\0"):i).join(`
`),o)})}return s}function bn(e,t,n,o){const s=J.exec(e[t]),r=ee(s[1]),_=/\d/.test(s[2]),u=[];let d=t;for(;d<e.length;){const l=J.exec(e[d]);if(!l||ee(l[1])!==r||/\d/.test(l[2])!==_)break;const a=ee(l[1])+l[2].length+1,i=[l[3]??""];for(d+=1;d<e.length;){const v=e[d];if(V(v)){let g=d;for(;g<e.length&&V(e[g]);)g+=1;if(g<e.length&&ee(e[g])>=a){for(;d<g;d+=1)i.push("");continue}break}const y=J.exec(v);if(ee(v)>=a){i.push(gn(v,a)),d+=1;continue}if(!y&&!Ie(v,void 0)&&i.length>0&&!V(i[i.length-1])){i.push(v.trim()),d+=1;continue}break}let f=null;const h=/^\[([ xX])\][ \t]+/.exec(i[0]);h&&(f=h[1]!==" ",i[0]=i[0].slice(h[0].length)),u.push({checked:f,children:xe(i,n+1,void 0,o)})}const c=_?Number.parseInt(s[2],10):1;return[{type:"list",ordered:_,start:c,items:u},d]}const me=e=>e===void 0||/\s/.test(e),Ue=e=>e!==void 0&&/[\p{L}\p{N}]/u.test(e);function ve(e,t,n=!0){return e.length>hn?[{type:"text",text:e.replace(/\u0000/g,"")}]:ge(e,0,t,n)}function M(e,t){if(!t)return;const n=e[e.length-1];n&&n.type==="text"?e[e.length-1]={type:"text",text:n.text+t}:e.push({type:"text",text:t})}function Rt(e,t){let n=0;for(let o=t;o<e.length;o+=1){const s=e[o];if(s==="\\")o+=1;else if(s==="[")n+=1;else if(s==="]"&&(n-=1,n===0))return o}return-1}function jt(e,t){if(e[t]!=="(")return null;let n=0;for(let o=t;o<e.length;o+=1){const s=e[o];if(s==="\\")o+=1;else if(s==="(")n+=1;else if(s===")"){if(n-=1,n===0){let r=e.slice(t+1,o).trim();const _=/^(<[^>]*>|\S+)(?:\s+(?:"[^"]*"|'[^']*'))?$/.exec(r);return _?(r=_[1],r.startsWith("<")&&r.endsWith(">")&&(r=r.slice(1,-1)),{url:dn(r),end:o+1}):null}}else if(s===`
`)return null}return null}function ge(e,t,n,o=!0){const s=[];let r=0;const _=u=>{M(s,e.slice(r,u)),r=u};for(;r<e.length;){const u=e[r];if(u==="\0"){s.push({type:"break"}),r+=1,e[r]===`
`&&(r+=1);continue}if(u===`
`){M(s," "),r+=1;continue}if(u==="\\"&&r+1<e.length&&/[!-/:-@[-`{-~]/.test(e[r+1])){M(s,e[r+1]),r+=2;continue}if(u==="&"){const l=an(e,r);if(l){M(s,l.value),r=l.end;continue}M(s,"&"),r+=1;continue}if(u==="`"){let l=1;for(;e[r+l]==="`";)l+=1;const a="`".repeat(l),i=e.indexOf(a,r+l);if(i>0&&e[i+l]!=="`"){s.push({type:"code",text:e.slice(r+l,i).replace(/\n/g," ").replace(/^ (.+) $/,"$1")}),r=i+l;continue}M(s,a),r+=l;continue}if(u==="!"&&e[r+1]==="["){const l=Rt(e,r+1),a=l>0?jt(e,l+1):null;if(a){M(s,pn(e.slice(r+2,l))||"image"),r=a.end;continue}}if(u==="["&&e[r+1]==="["){const l=e.indexOf("]]",r+2),a=l>0?e.slice(r+2,l).trim():"";if(a&&a.length<=128&&!/[\s[\]]/.test(a)){s.push({type:"ref",ref:a}),r=l+2;continue}}if(u==="["){const l=Rt(e,r),a=l>0?jt(e,l+1):null;if(a&&t<Me){s.push({type:"link",url:a.url,children:ge(e.slice(r+1,l),t+1)}),r=a.end;continue}}if(u==="<"){const l=/^<((?:https?):\/\/[^\s<>]+)>/i.exec(e.slice(r,r+2100));if(l){s.push({type:"link",url:l[1],children:[{type:"text",text:l[1]}]}),r+=l[0].length;continue}}const d=u==="h"&&/^https?:\/\//i.test(e.slice(r,r+8))&&!Ue(e[r-1])?/^https?:\/\/[^\s<>]+/i.exec(e.slice(r,r+2100)):null;if(d){let l=d[0];for(;/[.,;:!?'"*_~]$/.test(l)||l.endsWith(")")&&(l.match(/\(/g)?.length??0)<(l.match(/\)/g)?.length??0);)l=l.slice(0,-1);s.push({type:"link",url:l,children:[{type:"text",text:l}]}),r+=l.length;continue}if((e.startsWith("***",r)||e.startsWith("___",r))&&t<Me-1){const l=e.slice(r,r+3),a=e.indexOf(l,r+3);if(a>r+3&&!me(e[r+3])&&!me(e[a-1])){s.push({type:"strong",children:[{type:"em",children:ge(e.slice(r+3,a),t+2)}]}),r=a+3;continue}}if((u==="*"||u==="_"||u==="~")&&t<Me){const l=e[r+1]===u&&(u!=="~"||!0),a=l?2:1;if(u==="~"&&!l){M(s,u),r+=1;continue}const i=e[r-1],f=e[r+a];if(!me(f)&&!(u==="_"&&Ue(i))){const v=u.repeat(a);let y=r+a,g=-1;for(;y<e.length;){const p=e.indexOf(v,y);if(p<0)break;const E=e[p-1],j=e[p+a],A=(u==="_"?!Ue(j):!0)&&!(a===2&&u!=="~"&&j===u);if(p>r+a&&!me(E)&&A&&(a===2||e[p+1]!==u)&&E!=="\\"){g=p;break}y=p+1}if(g>0){const p=ge(e.slice(r+a,g),t+1);s.push({type:u==="~"?"del":a===2?"strong":"em",children:p}),r=g+a;continue}}M(s,e.slice(r,r+a)),r+=a;continue}let c=r+1;for(;c<e.length&&!"\0\n\\`![<*_~h&".includes(e[c]);)c+=1;_(c)}return s}var kn=0;function ye(e,t,n,o,s,r){t||(t={});var _,u,d=t;if("ref"in d)for(u in d={},t)u=="ref"?_=t[u]:d[u]=t[u];var c={type:e,props:d,key:n,ref:_,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:--kn,__i:-1,__u:0,__source:s,__self:r};if(typeof e=="function"&&(_=e.defaultProps))for(u in _)d[u]===void 0&&(d[u]=_[u]);return b.vnode&&b.vnode(c),c}function wn(e,t){return function n(o){return o.map((s,r)=>{switch(s.type){case"text":return s.text;case"code":return ye("code",{children:s.text},r);case"strong":case"em":case"del":{const _=s.type;return ye(_,{children:n(s.children)},r)}case"break":return ye("br",{},r);case"link":return ye(e,{url:s.url,children:n(s.children)},r);case"ref":return t(s.ref,r)}})}}const $n=e=>e.split(/[\s@._-]+/).filter(Boolean).slice(0,2).map(t=>t[0].toUpperCase()).join("")||"?",En=[1e3,2e3,4e3,8e3],Nn=4e3,Sn=1e4,Cn=new Set(["offline","busy","timeout","unavailable","query_timeout","network_lost","engine_error","subscription_limit","query_failed","database_pool_timeout"]);function We(e,t){const n=e.trim().toLowerCase();return Cn.has(n)||/^http_(?:408|429|5\d\d)$/.test(n)||/^authority_changed(?::|$)/.test(n)?t?"retry":"wait":"stop"}function Dt(e){const t=e?.retryDelaysMs??En;return{delays:t,noticeDelay:e?.noticeDelayMs??Nn,deadline:e?.resubscribeDeadlineMs??Sn,budget:t.reduce((n,o)=>n+o,0)}}function Lt({id:e,children:t,className:n}){return m("button",{type:"button",className:n??"kit-record-link",...Ve(e)},t??e)}function Tn({url:e,children:t}){return m("button",{type:"button",className:"kit-link",...Xe(e)},t)}const be=wn(Tn,(e,t)=>m(Lt,{id:e,key:t}));function Fe(e){return e.map((t,n)=>{switch(t.type){case"heading":return m(`h${t.level}`,{key:n},be(t.children));case"paragraph":return m("p",{key:n},be(t.children));case"quote":return m("blockquote",{key:n,className:t.callout?"kit-callout":void 0},t.callout&&m("strong",{},t.callout),Fe(t.children));case"code":return m("pre",{key:n},m("code",{},t.text));case"rule":return m("hr",{key:n});case"list":return m(t.ordered?"ol":"ul",{key:n,start:t.ordered?t.start:void 0},t.items.map((o,s)=>m("li",{key:s},o.checked!==null&&m("input",{type:"checkbox",checked:o.checked,disabled:!0}),Fe(o.children))));case"table":return m("table",{key:n},m("thead",{},m("tr",{},t.head.map((o,s)=>m("th",{key:s,style:{textAlign:t.align[s]??void 0}},be(o))))),m("tbody",{},t.rows.map((o,s)=>m("tr",{key:s},o.map((r,_)=>m("td",{key:_,style:{textAlign:t.align[_]??void 0}},be(r)))))))}})}function An(e,t){let n=!1;const o=new Set,s=c=>{let l=!0;const a=()=>{l&&(l=!1,o.delete(a),c())};return n?a():o.add(a),a};function r(c){const[l,a]=K({key:c,feed:{status:"loading"}});return ae(()=>{let i=!0;a({key:c,feed:{status:"loading"}});let f=()=>{};try{if(n)throw new R("closed","The kit has been disposed.");f=s(e.subscribe(c,h=>{i&&!n&&a({key:c,feed:h})}))}catch(h){a({key:c,feed:{status:"error",error:h instanceof R?h:new R("unavailable",String(h))}})}return()=>{i=!1,f()}},[c]),n?{status:"error",error:new R("closed","The kit has been disposed.")}:l.key===c?l.feed:{status:"loading"}}const _=(c,l)=>c?{status:"loading",last:c,deliveredAt:l}:{status:"loading"};function u(c,l){const a=JSON.stringify(c),i=fe(Dt(l));i.current=Dt(l);const[f,h]=K(0),[v,y]=K(0),g=bt(()=>{n||h(P=>P+1)},[]),[p,E]=K({key:a,nonce:f,feed:{status:"loading"}}),[j,A]=K({key:a,kind:"none"}),T=fe({key:a}),I=fe({attempts:0,troubled:!1,timers:new Set}),x=()=>{clearTimeout(I.current.deadline),I.current.deadline=void 0},O=()=>{for(const P of I.current.timers)clearTimeout(P);I.current.timers.clear(),I.current.failTimer=void 0,x()};ae(()=>s(O),[]),ae(()=>{if(n)return;let P=!0,te=()=>{};const N=I.current,Be=N.key!==a||N.nonce!==f,Pn=N.key===a&&(!Be||N.troubled);Be&&(O(),Object.assign(N,{key:a,nonce:f,attempts:0,troubled:!1})),T.current.key!==a&&(T.current={key:a});let{last:D,deliveredAt:F}=T.current;Be&&(E({key:a,nonce:f,feed:_(D,F)}),A(C=>({key:a,kind:C.key===a&&C.kind==="failed"?"reconnecting":"none"})));const X=C=>A(S=>S.key===a&&S.kind==="failed"&&C==="reconnecting"?S:{key:a,kind:C}),ze=(C,S)=>{const q=setTimeout(()=>{N.timers.delete(q),n||S()},C);return N.timers.add(q),q},Rn=C=>{if(C==="stop"){O(),N.troubled=!0,X("failed");return}if(N.troubled||(N.troubled=!0,ze(i.current.noticeDelay,()=>X("reconnecting"))),C==="wait"){N.failTimer||(N.failTimer=ze(i.current.budget,()=>{N.failTimer=void 0,O(),X("failed")}));return}const S=i.current.delays[N.attempts];if(S===void 0){O(),X("failed");return}N.attempts++,ze(S,()=>y(q=>q+1))},jn=()=>{N.deadline=void 0,!(!P||n)&&(P=!1,te(),O(),N.troubled=!0,X("failed"),E({key:a,nonce:f,feed:{status:"error",error:{code:"timeout",message:"The read did not answer in time.",terminal:!0},...D?{last:D,deliveredAt:F}:{}}}))};Pn&&(x(),N.deadline=setTimeout(jn,i.current.deadline));const Dn=C=>{!P||n||(O(),N.troubled=!0,X("failed"),E({key:a,nonce:f,feed:{status:"error",error:{code:"unavailable",message:String(C),terminal:!0},...D?{last:D,deliveredAt:F}:{}}}))};return e.ready.then(()=>{if(!P||n)return;const C=t();if(typeof C?.subscribe!="function"){x(),E({key:a,nonce:f,feed:{status:"unsupported",message:"This host does not offer app-v2 query subscriptions."}});return}te=s(C.subscribe(JSON.parse(a),S=>{if(!(!P||n))if(x(),S.status==="ready")D={rows:S.rows,columns:S.columns,truncated:S.truncated,...S.cached?{cached:!0}:{}},F=Date.now(),T.current={key:a,last:D,deliveredAt:F},O(),Object.assign(N,{attempts:0,troubled:!1}),X("none"),E({key:a,nonce:f,feed:{status:"ready",result:D,deliveredAt:F}});else{const q=We(S.code,S.terminal);q==="stop"&&(D=F=void 0,T.current={key:a}),E({key:a,nonce:f,feed:{status:"error",error:{code:S.code,message:S.message,terminal:S.terminal},...D?{last:D,deliveredAt:F}:{}}}),S.terminal&&(P=!1,te()),Rn(q)}})),P||te()}).catch(Dn),()=>{P=!1,te()}},[a,f,v]);const w=n?{status:"error",error:{code:"closed",message:"The kit has been disposed.",terminal:!0}}:p.key===a&&p.nonce===f?p.feed:T.current.key===a?_(T.current.last,T.current.deliveredAt):{status:"loading"},W=w.status==="ready"?w.result:w.status==="loading"||w.status==="error"?w.last:void 0,qe=n||w.status==="unsupported"||j.key!==a?"none":j.kind,Ht=w.status==="error"&&!n&&qe!=="failed"&&We(w.error.code,w.error.terminal)!=="stop"?qe==="reconnecting"?"reconnecting":"quiet":void 0;return{...w.status==="error"&&Ht?{...w,error:{...w.error,retrying:Ht}}:w,retry:g,truncated:W?.truncated??!1,notice:qe}}return{api:Object.freeze({h:m,render:Qt,Fragment:Z,createContext:Yt,...sn,html:cn.bind(m),useFeed:r,useQueryFeed:u,Loading:({what:c="data"})=>m("p",{className:"kit-state",role:"status"},`Loading ${c}\u2026`),Empty:({children:c})=>m("p",{className:"kit-state kit-empty"},c),ErrorState:({error:c,onRetry:l})=>c.retrying==="quiet"?null:c.retrying==="reconnecting"?m("p",{className:"kit-state kit-notice",role:"status"},"Reconnecting\u2026"):m("div",{className:"kit-state kit-error",role:"alert"},m("p",{},$e(c)),c.message&&m("p",{},c.message),l&&m("button",{type:"button",onClick:l},"Try again")),FeedNotice:({feed:c})=>{const l=c.notice==="failed"&&c.error&&We(c.error.code,c.error.terminal??!0)==="stop"?$e(c.error):void 0;return m(Z,{},c.notice==="reconnecting"&&m("p",{className:"kit-state kit-notice",role:"status"},"Reconnecting\u2026"),c.notice==="failed"&&m("div",{className:"kit-state kit-notice kit-error",role:"alert"},m("p",{},"Couldn\u2019t refresh"),l&&m("p",{},l),m("button",{type:"button",onClick:c.retry},"Try again")),c.truncated&&m("p",{className:"kit-state kit-partial",role:"status"},"Showing part of the results."))},PreviewBanner:()=>m("p",{className:"kit-preview",role:"status"},"Preview \u2014 sample data, not persisted."),Markdown:({source:c,className:l})=>m("div",{className:l??"kit-markdown"},Fe(yn(c))),Avatar:({name:c="",initials:l=$n(c),title:a,className:i})=>m("span",{className:i??"kit-avatar",title:a,"aria-hidden":"true"},l),IconSvg:({children:c,title:l,viewBox:a="0 0 24 24",className:i})=>m("svg",{className:i??"kit-icon",viewBox:a,role:l?"img":void 0,"aria-label":l,"aria-hidden":l?void 0:"true"},l&&m("title",{},l),c),RecordLink:Lt}),dispose(){if(!n){n=!0;for(const c of[...o])c()}}}}function On(e,t){const n=qt(e,t),o=An(n.kit,()=>xt()),s=Object.freeze({...n.kit,preact:o.api});return Object.freeze({kit:s,dispose(){o.dispose(),n.dispose()}})}return ke.createCoreKit=On,Object.defineProperty(ke,Symbol.toStringTag,{value:"Module"}),ke})({});

return CoreFactoryExports.createCoreKit;
})()
