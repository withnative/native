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
var CoreFactoryExports=(function(le){"use strict";class N extends Error{constructor(t,n,o){super(n??t),this.code=t,this.detail=o,this.name="PortError"}code;detail}const kt=e=>!!e&&typeof e=="object"&&!Array.isArray(e);function $t(e,t){if(!kt(e)||!Array.isArray(e.rows))throw new N("malformed","the host's answer has no rows");const n=e.rows;return{label:typeof e.label=="string"?e.label:"",columns:Array.isArray(e.columns)?e.columns:[],rows:n,rowCount:typeof e.row_count=="number"?e.row_count:n.length,rowCountComplete:e.row_count_complete!==!1,truncated:e.truncated===!0}}function Et(){const e=window.native;return e&&typeof e=="object"?e:void 0}const Oe=e=>{const t=e?.input;return t&&typeof t=="object"&&!Array.isArray(t)?t:void 0},ue=e=>e instanceof N?e:new N("unavailable",String(e));function Ct(e){let t=!1,n,o=!1,s=!1;const r=new Set,c=_=>{if(t)throw new N("closed");const l=n?.sql;if(!l||typeof l!="object"||Array.isArray(l)||!Object.hasOwn(l,_))throw new N("undeclared",`the snapshot "${_}" was not delivered: declare it as a param-less sql.snapshot.v1 need`);return $t(l[_])},u=e.ready.then(_=>{!t&&!s&&(n=Oe(_)),o=!0},_=>{throw ue(_)});u.catch(()=>{});const a=e.onInput(_=>{if(t)return;const l=Oe(_);if(l&&(s=!0,n=l,o))for(const f of[...r])f.update()});return{ready:u,async read(_){if(t)throw new N("closed");return await u,c(_)},subscribe(_,l){if(t)throw new N("closed");let f=!0,i;const d={update(){if(!f||t)return;let m;try{i=c(_),m={status:"ready",result:i}}catch(y){m={status:"error",error:ue(y),...i?{last:i}:{}}}v(m)},close(){f=!1,r.delete(d)}},v=m=>{if(!(!f||t))try{l(m)}catch{d.close()}};r.add(d);try{l({status:"loading"})}catch(m){throw d.close(),m}return u.then(()=>d.update(),m=>{v({status:"error",error:ue(m)})}).catch(()=>{d.close()}),d.close},dispose(){if(!t){t=!0;for(const _ of[...r])_.close();a(),n=void 0}}}}const Nt={busy:"Native is busy right now.",timeout:"Native took too long to answer.",undeclared:"This app was not given access to that data.",refused:"Native refused that request.",unavailable:"That data is not available right now.",malformed:"Native's answer was not in the expected shape.",closed:"This app was closed."};function je(e){return Nt[e.code]}function St(e){const t=e.rows.length;if(!e.truncated)return`${t}`;const n=e.rowCount.toLocaleString("en-US");return e.rowCountComplete?`${t} of ${n}`:`${t} of more than ${n}`}function He(e){return{"data-native-record-id":e}}function Le(e){return{"data-native-external-url":e}}const U={version:"1.1.0",major:1,layer:"core",factory:"native.app-kit.core.factory.v1",bridge:"native.html.bridge.v1"};function At(e,t){if(Object.keys(t).sort().join(",")!=="bridge,factory,js_sha256,layer,major,types_sha256,version"||t.version!==U.version||t.major!==U.major||t.layer!==U.layer||t.factory!==U.factory||t.bridge!==U.bridge||!/^[a-f0-9]{64}$/.test(t.js_sha256)||!/^[a-f0-9]{64}$/.test(t.types_sha256))throw new Error("incompatible core kit release metadata");const n=Ct(e),o=Object.freeze({release:Object.freeze({...t}),ready:n.ready,read:n.read,subscribe:n.subscribe,countLabel:St,errorText:je,recordLink:He,externalLink:Le});return Object.freeze({kit:o,dispose(){n.dispose()}})}var B,b,xe,H,Ie,Re,Me,ae,K,W,Ue,fe,de,pe,We,V={},X=[],Tt=/acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i,Z=Array.isArray;function P(e,t){for(var n in t)e[n]=t[n];return e}function he(e){e&&e.parentNode&&e.parentNode.removeChild(e)}function g(e,t,n){var o,s,r,c={};for(r in t)r=="key"?o=t[r]:r=="ref"?s=t[r]:c[r]=t[r];if(arguments.length>2&&(c.children=arguments.length>3?B.call(arguments,2):n),typeof e=="function"&&e.defaultProps!=null)for(r in e.defaultProps)c[r]===void 0&&(c[r]=e.defaultProps[r]);return Q(e,c,o,s,null)}function Q(e,t,n,o,s){var r={type:e,props:t,key:n,ref:o,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:s??++xe,__i:-1,__u:0};return s==null&&b.vnode!=null&&b.vnode(r),r}function D(e){return e.children}function G(e,t){this.props=e,this.context=t}function L(e,t){if(t==null)return e.__?L(e.__,e.__i+1):null;for(var n;t<e.__k.length;t++)if((n=e.__k[t])!=null&&n.__e!=null)return n.__e;return typeof e.type=="function"?L(e):null}function Pt(e){if(e.__P&&e.__d){var t=e.__v,n=t.__e,o=[],s=[],r=P({},t);r.__v=t.__v+1,b.vnode&&b.vnode(r),ve(e.__P,r,t,e.__n,e.__P.namespaceURI,32&t.__u?[n]:null,o,n??L(t),!!(32&t.__u),s),r.__v=t.__v,r.__.__k[r.__i]=r,Ve(o,r,s),t.__e=t.__=null,r.__e!=n&&De(r)}}function De(e){if((e=e.__)!=null&&e.__c!=null)return e.__e=e.__c.base=null,e.__k.some(function(t){if(t!=null&&t.__e!=null)return e.__e=e.__c.base=t.__e}),De(e)}function me(e){(!e.__d&&(e.__d=!0)&&H.push(e)&&!J.__r++||Ie!=b.debounceRendering)&&((Ie=b.debounceRendering)||Re)(J)}function J(){try{for(var e,t=1;H.length;)H.length>t&&H.sort(Me),e=H.shift(),t=H.length,Pt(e)}finally{H.length=J.__r=0}}function Fe(e,t,n,o,s,r,c,u,a,_,l){var f,i,d,v,m,y,h=o&&o.__k||X,p=t.length;for(a=Ot(n,t,h,a,p),f=0;f<p;f++)(d=n.__k[f])!=null&&(i=d.__i!=-1&&h[d.__i]||V,d.__i=f,y=ve(e,d,i,s,r,c,u,a,_,l),v=d.__e,d.ref&&i.ref!=d.ref&&(i.ref&&ge(i.ref,null,d),l.push(d.ref,d.__c||v,d)),m==null&&v!=null&&(m=v),4&d.__u?(a=ze(d,a,e),i.__e&&(i.__e=null)):typeof d.type=="function"&&y!==void 0?a=y:v&&(a=v.nextSibling),d.__u&=-7);return n.__e=m,a}function Ot(e,t,n,o,s){var r,c,u,a,_,l=n.length,f=l,i=0;for(e.__k=new Array(s),r=0;r<s;r++)(c=t[r])!=null&&typeof c!="boolean"&&typeof c!="function"?(typeof c=="string"||typeof c=="number"||typeof c=="bigint"||c.constructor==String?c=e.__k[r]=Q(null,c,null,null,null):Z(c)?c=e.__k[r]=Q(D,{children:c},null,null,null):c.constructor===void 0&&c.__b>0?c=e.__k[r]=Q(c.type,c.props,c.key,c.ref?c.ref:null,c.__v):e.__k[r]=c,a=r+i,c.__=e,c.__b=e.__b+1,u=null,(_=c.__i=jt(c,n,a,f))!=-1&&(f--,(u=n[_])&&(u.__u|=2)),u==null||u.__v==null?(_==-1&&(s>l?i--:s<l&&i++),typeof c.type!="function"&&(c.__u|=4)):_!=a&&(_==a-1?i--:_==a+1?i++:(_>a?i--:i++,c.__u|=4))):e.__k[r]=null;if(f)for(r=0;r<l;r++)(u=n[r])!=null&&(2&u.__u)==0&&(u.__e==o&&(o=L(u)),Ze(u,u));return o}function ze(e,t,n){var o,s;if(typeof e.type=="function"){for(o=e.__k,s=0;o&&s<o.length;s++)o[s]&&(o[s].__=e,t=ze(o[s],t,n));return t}e.__e!=t&&(t&&e.type&&!t.parentNode&&(t=L(e)),t=n.insertBefore(e.__e,t||null));do t=t&&t.nextSibling;while(t!=null&&t.nodeType==8);return t}function jt(e,t,n,o){var s,r,c,u=e.key,a=e.type,_=t[n],l=_!=null&&(2&_.__u)==0;if(_===null&&u==null||l&&u==_.key&&a==_.type)return n;if(o>(l?1:0)){for(s=n-1,r=n+1;s>=0||r<t.length;)if((_=t[c=s>=0?s--:r++])!=null&&(2&_.__u)==0&&u==_.key&&a==_.type)return c}return-1}function qe(e,t,n){t[0]=="-"?e.setProperty(t,n??""):e[t]=n==null?"":typeof n!="number"||Tt.test(t)?n:n+"px"}function Y(e,t,n,o,s){var r,c;e:if(t=="style")if(typeof n=="string")e.style.cssText=n;else{if(typeof o=="string"&&(e.style.cssText=o=""),o)for(t in o)n&&t in n||qe(e.style,t,"");if(n)for(t in n)o&&n[t]==o[t]||qe(e.style,t,n[t])}else if(t[0]=="o"&&t[1]=="n")r=t!=(t=t.replace(Ue,"$1")),c=t.toLowerCase(),t=c in e||t=="onFocusOut"||t=="onFocusIn"?c.slice(2):t.slice(2),e.l||(e.l={}),e.l[t+r]=n,n?o?n[W]=o[W]:(n[W]=fe,e.addEventListener(t,r?pe:de,r)):e.removeEventListener(t,r?pe:de,r);else{if(s=="http://www.w3.org/2000/svg")t=t.replace(/xlink(H|:h)/,"h").replace(/sName$/,"s");else if(t!="width"&&t!="height"&&t!="href"&&t!="list"&&t!="form"&&t!="tabIndex"&&t!="download"&&t!="rowSpan"&&t!="colSpan"&&t!="role"&&t!="popover"&&t in e)try{e[t]=n??"";break e}catch{}typeof n=="function"||(n==null||n===!1&&t[4]!="-"?e.removeAttribute(t):e.setAttribute(t,t=="popover"&&n==1?"":n))}}function Be(e){return function(t){if(this.l){var n=this.l[t.type+e];if(t[K]==null)t[K]=fe++;else if(t[K]<n[W])return;return n(b.event?b.event(t):t)}}}function ve(e,t,n,o,s,r,c,u,a,_){var l,f,i,d,v,m,y,h,p,$,E,S,A,C,ce,Pe,T=t.type;if(t.constructor!==void 0)return null;128&n.__u&&(a=!!(32&n.__u),r=[u=t.__e=n.__e]),(l=b.__b)&&l(t);e:if(typeof T=="function"){f=c.length;try{if(p=t.props,$=T.prototype&&T.prototype.render,E=(l=T.contextType)&&o[l.__c],S=l?E?E.props.value:l.__:o,n.__c?h=(i=t.__c=n.__c).__=i.__E:($?t.__c=i=new T(p,S):(t.__c=i=new G(p,S),i.constructor=T,i.render=Lt),E&&E.sub(i),i.state||(i.state={}),i.__n=o,d=i.__d=!0,i.__h=[],i._sb=[]),$&&i.__s==null&&(i.__s=i.state),$&&T.getDerivedStateFromProps!=null&&(i.__s==i.state&&(i.__s=P({},i.__s)),P(i.__s,T.getDerivedStateFromProps(p,i.__s))),v=i.props,m=i.state,i.__v=t,d)$&&T.getDerivedStateFromProps==null&&i.componentWillMount!=null&&i.componentWillMount(),$&&i.componentDidMount!=null&&i.__h.push(i.componentDidMount);else{if($&&T.getDerivedStateFromProps==null&&p!==v&&i.componentWillReceiveProps!=null&&i.componentWillReceiveProps(p,S),t.__v==n.__v||!i.__e&&i.shouldComponentUpdate!=null&&i.shouldComponentUpdate(p,i.__s,S)===!1){t.__v!=n.__v&&(i.props=p,i.state=i.__s,i.__d=!1),t.__e=n.__e,t.__k=n.__k,t.__k.some(function(M){M&&(M.__=t)}),X.push.apply(i.__h,i._sb),i._sb=[],i.__h.length&&c.push(i),u=L(n);break e}i.componentWillUpdate!=null&&i.componentWillUpdate(p,i.__s,S),$&&i.componentDidUpdate!=null&&i.__h.push(function(){i.componentDidUpdate(v,m,y)})}if(i.context=S,i.props=p,i.__P=e,i.__e=!1,A=b.__r,C=0,$)i.state=i.__s,i.__d=!1,A&&A(t),l=i.render(i.props,i.state,i.context),X.push.apply(i.__h,i._sb),i._sb=[];else do i.__d=!1,A&&A(t),l=i.render(i.props,i.state,i.context),i.state=i.__s;while(i.__d&&++C<25);i.state=i.__s,i.getChildContext!=null&&(o=P(P({},o),i.getChildContext())),$&&!d&&i.getSnapshotBeforeUpdate!=null&&(y=i.getSnapshotBeforeUpdate(v,m)),ce=l!=null&&l.type===D&&l.key==null?Xe(l.props.children):l,u=Fe(e,Z(ce)?ce:[ce],t,n,o,s,r,c,u,a,_),i.base=t.__e,t.__u&=-161,i.__h.length&&c.push(i),h&&(i.__E=i.__=null)}catch(M){if(c.length=f,t.__v=null,a||r!=null){if(M.then){for(t.__u|=a?160:128;u&&u.nodeType==8&&u.nextSibling;)u=u.nextSibling;r!=null&&(r[r.indexOf(u)]=null),t.__e=u}else if(r!=null)for(Pe=r.length;Pe--;)he(r[Pe])}else t.__e=n.__e;t.__k==null&&(t.__k=n.__k||[]),M.then||Ke(t),b.__e(M,t,n)}}else r==null&&t.__v==n.__v?(t.__k=n.__k,t.__e=n.__e):u=t.__e=Ht(n.__e,t,n,o,s,r,c,a,_);return(l=b.diffed)&&l(t),128&t.__u?void 0:u}function Ke(e){e&&(e.__c&&(e.__c.__e=!0),e.__k&&e.__k.some(Ke))}function Ve(e,t,n){for(var o=0;o<n.length;o++)ge(n[o],n[++o],n[++o]);b.__c&&b.__c(t,e),e.some(function(s){try{e=s.__h,s.__h=[],e.some(function(r){r.call(s)})}catch(r){b.__e(r,s.__v)}})}function Xe(e){return typeof e!="object"||e==null||e.__b>0?e:Z(e)?e.map(Xe):e.constructor!==void 0?null:P({},e)}function Ht(e,t,n,o,s,r,c,u,a){var _,l,f,i,d,v,m,y=n.props||V,h=t.props,p=t.type;if(p=="svg"?s="http://www.w3.org/2000/svg":p=="math"?s="http://www.w3.org/1998/Math/MathML":s||(s="http://www.w3.org/1999/xhtml"),r!=null){for(_=0;_<r.length;_++)if((d=r[_])&&"setAttribute"in d==!!p&&(p?d.localName==p:d.nodeType==3)){e=d,r[_]=null;break}}if(e==null){if(p==null)return document.createTextNode(h);e=document.createElementNS(s,p,h.is&&h),u&&(b.__m&&b.__m(t,r),u=!1),r=null}if(p==null)y===h||u&&e.data==h||(e.data=h);else{if(r=p=="textarea"&&h.defaultValue!=null?null:r&&B.call(e.childNodes),!u&&r!=null)for(y={},_=0;_<e.attributes.length;_++)y[(d=e.attributes[_]).name]=d.value;for(_ in y)d=y[_],_=="dangerouslySetInnerHTML"?f=d:_=="children"||_ in h||_=="value"&&"defaultValue"in h||_=="checked"&&"defaultChecked"in h||Y(e,_,null,d,s);for(_ in h)d=h[_],_=="children"?i=d:_=="dangerouslySetInnerHTML"?l=d:_=="value"?v=d:_=="checked"?m=d:u&&typeof d!="function"||y[_]===d||Y(e,_,d,y[_],s);if(l)u||f&&(l.__html==f.__html||l.__html==e.innerHTML)||(e.innerHTML=l.__html),t.__k=[];else if(f&&(e.innerHTML=""),Fe(t.type=="template"?e.content:e,Z(i)?i:[i],t,n,o,p=="foreignObject"?"http://www.w3.org/1999/xhtml":s,r,c,r?r[0]:n.__k&&L(n,0),u,a),r!=null)for(_=r.length;_--;)he(r[_]);u&&p!="textarea"||(_="value",p=="progress"&&v==null?e.removeAttribute("value"):v!=null&&(v!==e[_]||p=="progress"&&!v||p=="option"&&v!=y[_])&&Y(e,_,v,y[_],s),_="checked",m!=null&&m!=e[_]&&Y(e,_,m,y[_],s))}return e}function ge(e,t,n){try{if(typeof e=="function"){var o=typeof e.__u=="function";o&&e.__u(),o&&t==null||(e.__u=e(t))}else e.current=t}catch(s){b.__e(s,n)}}function Ze(e,t,n){var o,s;if(b.unmount&&b.unmount(e),(o=e.ref)&&(o.current&&o.current!=e.__e||ge(o,null,t)),(o=e.__c)!=null){if(o.componentWillUnmount)try{o.componentWillUnmount()}catch(r){b.__e(r,t)}o.base=o.__P=o.__n=null}if(o=e.__k)for(s=0;s<o.length;s++)o[s]&&Ze(o[s],t,n||typeof e.type!="function");n||he(e.__e),e.__c=e.__=e.__e=void 0}function Lt(e,t,n){return this.constructor(e,n)}function xt(e,t,n){var o,s,r,c;t==document&&(t=document.documentElement),b.__&&b.__(e,t),s=(o=typeof n=="function")?null:n&&n.__k||t.__k,r=[],c=[],ve(t,e=(!o&&n||t).__k=g(D,null,[e]),s||V,V,t.namespaceURI,!o&&n?[n]:s?null:t.firstChild?B.call(t.childNodes):null,r,!o&&n?n:s?s.__e:t.firstChild,o,c),Ve(r,e,c),e.props.children=null}function It(e){function t(n){var o,s;return this.getChildContext||(o=new Set,(s={})[t.__c]=this,this.getChildContext=function(){return s},this.componentWillUnmount=function(){o=null},this.shouldComponentUpdate=function(r){this.props.value!=r.value&&o.forEach(function(c){c.__e=!0,me(c)})},this.sub=function(r){o.add(r);var c=r.componentWillUnmount;r.componentWillUnmount=function(){o&&o.delete(r),c&&c.call(r)}}),n.children}return t.__c="__cC"+We++,t.__=e,t.Provider=t.__l=(t.Consumer=function(n,o){return n.children(o)}).contextType=t,t}B=X.slice,b={__e:function(e,t,n,o){for(var s,r,c;t=t.__;)if((s=t.__c)&&!s.__)try{if((r=s.constructor)&&r.getDerivedStateFromError!=null&&(s.setState(r.getDerivedStateFromError(e)),c=s.__d),s.componentDidCatch!=null&&(s.componentDidCatch(e,o||{}),c=s.__d),c)return s.__E=s}catch(u){e=u}throw e}},xe=0,G.prototype.setState=function(e,t){var n;n=this.__s!=null&&this.__s!=this.state?this.__s:this.__s=P({},this.state),typeof e=="function"&&(e=e(P({},n),this.props)),e&&P(n,e),e!=null&&this.__v&&(t&&this._sb.push(t),me(this))},G.prototype.forceUpdate=function(e){this.__v&&(this.__e=!0,e&&this.__h.push(e),me(this))},G.prototype.render=D,H=[],Re=typeof Promise=="function"?Promise.prototype.then.bind(Promise.resolve()):setTimeout,Me=function(e,t){return e.__v.__b-t.__v.__b},J.__r=0,ae=Math.random().toString(8),K="__d"+ae,W="__a"+ae,Ue=/(PointerCapture)$|Capture$/i,fe=0,de=Be(!1),pe=Be(!0),We=0;var O,w,ye,Qe,R=0,Ge=[],k=b,Je=k.__b,Ye=k.__r,et=k.diffed,tt=k.__c,nt=k.unmount,rt=k.__;function x(e,t){k.__h&&k.__h(w,e,R||t),R=0;var n=w.__H||(w.__H={__:[],__h:[]});return e>=n.__.length&&n.__.push({}),n.__[e]}function F(e){return R=1,ot(lt,e)}function ot(e,t,n){var o=x(O++,2);if(o.t=e,!o.__c&&(o.__=[n?n(t):lt(void 0,t),function(u){var a=o.__N?o.__N[0]:o.__[0],_=o.t(a,u);a!==_&&(o.__N=[_,o.__[1]],o.__c.setState({}))}],o.__c=w,!w.__f)){var s=function(u,a,_){if(!o.__c.__H)return!0;var l=!1,f=o.__c.props!==u;if(o.__c.__H.__.some(function(d){if(d.__N){l=!0;var v=d.__[0];d.__=d.__N,d.__N=void 0,v!==d.__[0]&&(f=!0)}}),r){var i=r.call(this,u,a,_);return l?i||f:i}return!l||f};w.__f=!0;var r=w.shouldComponentUpdate,c=w.componentWillUpdate;w.componentWillUpdate=function(u,a,_){if(this.__e){var l=r;r=void 0,s(u,a,_),r=l}c&&c.call(this,u,a,_)},w.shouldComponentUpdate=s}return o.__N||o.__}function be(e,t){var n=x(O++,3);!k.__s&&$e(n.__H,t)&&(n.__=e,n.u=t,w.__H.__h.push(n))}function st(e,t){var n=x(O++,4);!k.__s&&$e(n.__H,t)&&(n.__=e,n.u=t,w.__h.push(n))}function it(e){return R=5,we(function(){return{current:e}},[])}function Rt(e,t,n){R=6,st(function(){if(typeof e=="function"){var o=e(t());return function(){e(null),o&&typeof o=="function"&&o()}}if(e)return e.current=t(),function(){return e.current=null}},n==null?n:n.concat(e))}function we(e,t){var n=x(O++,7);return $e(n.__H,t)&&(n.__=e(),n.__H=t,n.__h=e),n.__}function _t(e,t){return R=8,we(function(){return e},t)}function Mt(e){var t=w.context[e.__c],n=x(O++,9);return n.c=e,t?(n.__==null&&(n.__=!0,t.sub(w)),t.props.value):e.__}function Ut(e,t){k.useDebugValue&&k.useDebugValue(t?t(e):e)}function Wt(e){var t=x(O++,10),n=F();return t.__=e,w.componentDidCatch||(w.componentDidCatch=function(o,s){t.__&&t.__(o,s),n[1](o)}),[n[0],function(){n[1](void 0)}]}function Dt(){var e=x(O++,11);if(!e.__){for(var t=w.__v;t!==null&&!t.__m&&t.__!==null;)t=t.__;var n=t.__m||(t.__m=[0,0]);e.__="P"+n[0]+"-"+n[1]++}return e.__}function Ft(){for(var e;e=Ge.shift();){var t=e.__H;if(e.__P&&t)try{t.__h.some(ee),t.__h.some(ke),t.__h=[]}catch(n){t.__h=[],k.__e(n,e.__v)}}}k.__b=function(e){w=null,Je&&Je(e)},k.__=function(e,t){e&&t.__k&&t.__k.__m&&(e.__m=t.__k.__m),rt&&rt(e,t)},k.__r=function(e){Ye&&Ye(e),O=0;var t=(w=e.__c).__H;t&&(ye===w?(t.__h=[],w.__h=[],t.__.some(function(n){n.__N&&(n.__=n.__N),n.u=n.__N=void 0})):(t.__h.some(ee),t.__h.some(ke),t.__h=[],O=0)),ye=w},k.diffed=function(e){et&&et(e);var t=e.__c;t&&t.__H&&(t.__H.__h.length&&(Ge.push(t)!==1&&Qe===k.requestAnimationFrame||((Qe=k.requestAnimationFrame)||zt)(Ft)),t.__H.__.some(function(n){n.u&&(n.__H=n.u,n.u=void 0)})),ye=w=null},k.__c=function(e,t){t.some(function(n){try{n.__h.some(ee),n.__h=n.__h.filter(function(o){return!o.__||ke(o)})}catch(o){t.some(function(s){s.__h&&(s.__h=[])}),t=[],k.__e(o,n.__v)}}),tt&&tt(e,t)},k.unmount=function(e){nt&&nt(e);var t,n=e.__c;n&&n.__H&&(n.__H.__.some(function(o){try{ee(o)}catch(s){t=s}}),n.__H=void 0,t&&k.__e(t,n.__v))};var ct=typeof requestAnimationFrame=="function";function zt(e){var t,n=function(){clearTimeout(o),ct&&cancelAnimationFrame(t),setTimeout(e)},o=setTimeout(n,35);ct&&(t=requestAnimationFrame(n))}function ee(e){var t=w,n=e.__c;typeof n=="function"&&(e.__c=void 0,n()),w=t}function ke(e){var t=w;e.__c=e.__(),w=t}function $e(e,t){return!e||e.length!==t.length||t.some(function(n,o){return n!==e[o]})}function lt(e,t){return typeof t=="function"?t(e):t}const qt=Object.freeze(Object.defineProperty({__proto__:null,useCallback:_t,useContext:Mt,useDebugValue:Ut,useEffect:be,useErrorBoundary:Wt,useId:Dt,useImperativeHandle:Rt,useLayoutEffect:st,useMemo:we,useReducer:ot,useRef:it,useState:F},Symbol.toStringTag,{value:"Module"}));var ut=function(e,t,n,o){var s;t[0]=0;for(var r=1;r<t.length;r++){var c=t[r++],u=t[r]?(t[0]|=c?1:2,n[t[r++]]):t[++r];c===3?o[0]=u:c===4?o[1]=Object.assign(o[1]||{},u):c===5?(o[1]=o[1]||{})[t[++r]]=u:c===6?o[1][t[++r]]+=u+"":c?(s=e.apply(u,ut(e,u,n,["",null])),o.push(s),u[0]?t[0]|=2:(t[r-2]=0,t[r]=s)):o.push(u)}return o},at=new Map;function Bt(e){var t=at.get(this);return t||(t=new Map,at.set(this,t)),(t=ut(this,t.get(e)||(t.set(e,t=(function(n){for(var o,s,r=1,c="",u="",a=[0],_=function(i){r===1&&(i||(c=c.replace(/^\s*\n\s*|\s*\n\s*$/g,"")))?a.push(0,i,c):r===3&&(i||c)?(a.push(3,i,c),r=2):r===2&&c==="..."&&i?a.push(4,i,0):r===2&&c&&!i?a.push(5,0,!0,c):r>=5&&((c||!i&&r===5)&&(a.push(r,0,c,s),r=6),i&&(a.push(r,i,0,s),r=6)),c=""},l=0;l<n.length;l++){l&&(r===1&&_(),_(l));for(var f=0;f<n[l].length;f++)o=n[l][f],r===1?o==="<"?(_(),a=[a],r=3):c+=o:r===4?c==="--"&&o===">"?(r=1,c=""):c=o+c[0]:u?o===u?u="":c+=o:o==='"'||o==="'"?u=o:o===">"?(_(),r=1):r&&(o==="="?(r=5,s=c,c=""):o==="/"&&(r<5||n[l][f+1]===">")?(_(),r===3&&(a=a[0]),r=a,(a=a[0]).push(2,0,r),r=0):o===" "||o==="	"||o===`
`||o==="\r"?(_(),r=2):c+=o),r===3&&c==="!--"&&(r=4,a=a[0])}return _(),a})(e)),t),arguments,[])).length>1?t:t[0]}let Ee=null;function Kt(e){if(!/^[A-Za-z][A-Za-z0-9]{0,31}$/.test(e)||typeof document>"u")return;Ee??=document.createElement("textarea");const t=`&${e};`;Ee.innerHTML=t;const n=Ee.value;if(n!==t&&!(n.endsWith(";")&&n!==";"))return n}const Vt=34,ft="&(?:#([0-9]{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{0,31}));",Xt=new RegExp("^"+ft);function dt(e,t,n){if(n)return Kt(n);const o=Number.parseInt(e??t,e===void 0?16:10);return String.fromCodePoint(!o||o>1114111||o>=55296&&o<=57343?65533:o)}function Zt(e,t){const n=Xt.exec(e.slice(t,t+Vt));if(!n)return null;const o=dt(n[1],n[2],n[3]);return o===void 0?null:{value:o,end:t+n[0].length}}const Qt=new RegExp("\\\\[\\s\\S]|`+|"+ft,"g");function pt(e,t){let n=0;return e.replace(Qt,(o,s,r,c,u)=>{if(u<n)return o;if(t&&o[0]==="`"){const a=e.indexOf(o,u+o.length);a>0&&e[a+o.length]!=="`"&&(n=a+o.length)}return o[0]==="&"?dt(s,r,c)??o:o})}function Gt(e){return pt(e,!1)}function Jt(e){return pt(e,!0)}const Ce=6,Yt=2e4,en=12,ht=/^ {0,3}(`{3,}|~{3,})\s*([^`\s]*)[^`]*$/,mt=/^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$/,vt=/^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/,z=/^(\s*)([-*+]|\d{1,9}[.)])(?:[ \t]+(.*)|$)$/,te=/^ {0,3}>[ \t]?(.*)$/,tn=/^\s*\|?\s*:?-{1,}:?\s*(?:\|\s*:?-{1,}:?\s*)*\|?\s*$/,q=e=>{let t=0;for(const n of e)if(n===" ")t+=1;else if(n==="	")t+=4-t%4;else break;return t},nn=(e,t)=>{let n=0,o=0;for(;o<e.length&&n<t;){const s=e[o];if(s===" ")n+=1;else if(s==="	")n+=4-n%4;else break;o+=1}return e.slice(o)},I=e=>e.trim()==="",Ne=(e,t)=>ht.test(e)||mt.test(e)||vt.test(e)||te.test(e)||z.test(e)||gt(e,t);function gt(e,t){return t!==void 0&&e.includes("|")&&tn.test(t)&&t.includes("-")&&ne(e).length>=1&&(t.includes("|")||e.trim().startsWith("|"))}function ne(e){let t=e.trim();t.startsWith("|")&&(t=t.slice(1)),t.endsWith("|")&&!t.endsWith("\\|")&&(t=t.slice(0,-1));const n=[];let o="";for(let s=0;s<t.length;s+=1){const r=t[s];r==="\\"&&t[s+1]==="|"?(o+="|",s+=1):r==="|"?(n.push(o.trim()),o=""):o+=r}return n.push(o.trim()),n}function rn(e){return Se(e.replace(/\r\n?/g,`
`).split(`
`),0)}function Se(e,t,n,o){const s=[];if(t>en){const u=e.join(`
`).trim();return u?[{type:"paragraph",children:[{type:"text",text:u}]}]:[]}let r=0;const c=u=>{s.push(u)};for(;r<e.length;){const u=e[r];if(I(u)){r+=1;continue}const a=ht.exec(u);if(a){const i=a[1],d=[];for(r+=1;r<e.length&&!new RegExp(`^ {0,3}${i[0]==="`"?"`":"~"}{${i.length},}\\s*$`).test(e[r]);)d.push(e[r]),r+=1;r+=1,c({type:"code",lang:a[2]??"",text:d.join(`
`)});continue}const _=mt.exec(u);if(_){r+=1,c({type:"heading",level:_[1].length,children:oe(_[2],o,!1)});continue}if(vt.test(u)){r+=1,c({type:"rule"});continue}if(te.test(u)){const i=[];for(;r<e.length&&(te.test(e[r])||!I(e[r])&&i.length>0&&!Ne(e[r],void 0));){const m=te.exec(e[r]);i.push(m?m[1]:e[r]),r+=1}let d=null;const v=/^\[!([A-Za-z]{2,12})\][ \t]*$/.exec(i[0]??"");v&&(d=v[1].toLowerCase(),i.shift()),c({type:"quote",callout:d,children:Se(i,t+1,void 0,o)});continue}if(z.exec(u)){const[i,d]=on(e,r,t,o);r=d,c(i);continue}if(gt(u,e[r+1])){const i=ne(u),d=ne(e[r+1]).map(y=>{const h=y.startsWith(":"),p=y.endsWith(":");return h&&p?"center":p?"right":h?"left":null}),v=[];for(r+=2;r<e.length&&!I(e[r])&&e[r].includes("|");)v.push(ne(e[r])),r+=1;const m=i.length;c({type:"table",align:Array.from({length:m},(y,h)=>d[h]??null),head:i.map(y=>oe(y,o)),rows:v.map(y=>Array.from({length:m},(h,p)=>oe(y[p]??"",o)))});continue}const f=[u];for(r+=1;r<e.length&&!I(e[r])&&!Ne(e[r],e[r+1]);)f.push(e[r]),r+=1;c({type:"paragraph",children:oe(f.map((i,d)=>d<f.length-1?i.replace(/(?: {2,}|\\)$/,"\0"):i).join(`
`),o)})}return s}function on(e,t,n,o){const s=z.exec(e[t]),r=q(s[1]),c=/\d/.test(s[2]),u=[];let a=t;for(;a<e.length;){const l=z.exec(e[a]);if(!l||q(l[1])!==r||/\d/.test(l[2])!==c)break;const f=q(l[1])+l[2].length+1,i=[l[3]??""];for(a+=1;a<e.length;){const m=e[a];if(I(m)){let h=a;for(;h<e.length&&I(e[h]);)h+=1;if(h<e.length&&q(e[h])>=f){for(;a<h;a+=1)i.push("");continue}break}const y=z.exec(m);if(q(m)>=f){i.push(nn(m,f)),a+=1;continue}if(!y&&!Ne(m,void 0)&&i.length>0&&!I(i[i.length-1])){i.push(m.trim()),a+=1;continue}break}let d=null;const v=/^\[([ xX])\][ \t]+/.exec(i[0]);v&&(d=v[1]!==" ",i[0]=i[0].slice(v[0].length)),u.push({checked:d,children:Se(i,n+1,void 0,o)})}const _=c?Number.parseInt(s[2],10):1;return[{type:"list",ordered:c,start:_,items:u},a]}const re=e=>e===void 0||/\s/.test(e),Ae=e=>e!==void 0&&/[\p{L}\p{N}]/u.test(e);function oe(e,t,n=!0){return e.length>Yt?[{type:"text",text:e.replace(/\u0000/g,"")}]:se(e,0,t,n)}function j(e,t){if(!t)return;const n=e[e.length-1];n&&n.type==="text"?e[e.length-1]={type:"text",text:n.text+t}:e.push({type:"text",text:t})}function yt(e,t){let n=0;for(let o=t;o<e.length;o+=1){const s=e[o];if(s==="\\")o+=1;else if(s==="[")n+=1;else if(s==="]"&&(n-=1,n===0))return o}return-1}function bt(e,t){if(e[t]!=="(")return null;let n=0;for(let o=t;o<e.length;o+=1){const s=e[o];if(s==="\\")o+=1;else if(s==="(")n+=1;else if(s===")"){if(n-=1,n===0){let r=e.slice(t+1,o).trim();const c=/^(<[^>]*>|\S+)(?:\s+(?:"[^"]*"|'[^']*'))?$/.exec(r);return c?(r=c[1],r.startsWith("<")&&r.endsWith(">")&&(r=r.slice(1,-1)),{url:Gt(r),end:o+1}):null}}else if(s===`
`)return null}return null}function se(e,t,n,o=!0){const s=[];let r=0;const c=u=>{j(s,e.slice(r,u)),r=u};for(;r<e.length;){const u=e[r];if(u==="\0"){s.push({type:"break"}),r+=1,e[r]===`
`&&(r+=1);continue}if(u===`
`){j(s," "),r+=1;continue}if(u==="\\"&&r+1<e.length&&/[!-/:-@[-`{-~]/.test(e[r+1])){j(s,e[r+1]),r+=2;continue}if(u==="&"){const l=Zt(e,r);if(l){j(s,l.value),r=l.end;continue}j(s,"&"),r+=1;continue}if(u==="`"){let l=1;for(;e[r+l]==="`";)l+=1;const f="`".repeat(l),i=e.indexOf(f,r+l);if(i>0&&e[i+l]!=="`"){s.push({type:"code",text:e.slice(r+l,i).replace(/\n/g," ").replace(/^ (.+) $/,"$1")}),r=i+l;continue}j(s,f),r+=l;continue}if(u==="!"&&e[r+1]==="["){const l=yt(e,r+1),f=l>0?bt(e,l+1):null;if(f){j(s,Jt(e.slice(r+2,l))||"image"),r=f.end;continue}}if(u==="["&&e[r+1]==="["){const l=e.indexOf("]]",r+2),f=l>0?e.slice(r+2,l).trim():"";if(f&&f.length<=128&&!/[\s[\]]/.test(f)){s.push({type:"ref",ref:f}),r=l+2;continue}}if(u==="["){const l=yt(e,r),f=l>0?bt(e,l+1):null;if(f&&t<Ce){s.push({type:"link",url:f.url,children:se(e.slice(r+1,l),t+1)}),r=f.end;continue}}if(u==="<"){const l=/^<((?:https?):\/\/[^\s<>]+)>/i.exec(e.slice(r,r+2100));if(l){s.push({type:"link",url:l[1],children:[{type:"text",text:l[1]}]}),r+=l[0].length;continue}}const a=u==="h"&&/^https?:\/\//i.test(e.slice(r,r+8))&&!Ae(e[r-1])?/^https?:\/\/[^\s<>]+/i.exec(e.slice(r,r+2100)):null;if(a){let l=a[0];for(;/[.,;:!?'"*_~]$/.test(l)||l.endsWith(")")&&(l.match(/\(/g)?.length??0)<(l.match(/\)/g)?.length??0);)l=l.slice(0,-1);s.push({type:"link",url:l,children:[{type:"text",text:l}]}),r+=l.length;continue}if((e.startsWith("***",r)||e.startsWith("___",r))&&t<Ce-1){const l=e.slice(r,r+3),f=e.indexOf(l,r+3);if(f>r+3&&!re(e[r+3])&&!re(e[f-1])){s.push({type:"strong",children:[{type:"em",children:se(e.slice(r+3,f),t+2)}]}),r=f+3;continue}}if((u==="*"||u==="_"||u==="~")&&t<Ce){const l=e[r+1]===u&&(u!=="~"||!0),f=l?2:1;if(u==="~"&&!l){j(s,u),r+=1;continue}const i=e[r-1],d=e[r+f];if(!re(d)&&!(u==="_"&&Ae(i))){const m=u.repeat(f);let y=r+f,h=-1;for(;y<e.length;){const p=e.indexOf(m,y);if(p<0)break;const $=e[p-1],E=e[p+f],S=(u==="_"?!Ae(E):!0)&&!(f===2&&u!=="~"&&E===u);if(p>r+f&&!re($)&&S&&(f===2||e[p+1]!==u)&&$!=="\\"){h=p;break}y=p+1}if(h>0){const p=se(e.slice(r+f,h),t+1);s.push({type:u==="~"?"del":f===2?"strong":"em",children:p}),r=h+f;continue}}j(s,e.slice(r,r+f)),r+=f;continue}let _=r+1;for(;_<e.length&&!"\0\n\\`![<*_~h&".includes(e[_]);)_+=1;c(_)}return s}var sn=0;function ie(e,t,n,o,s,r){t||(t={});var c,u,a=t;if("ref"in a)for(u in a={},t)u=="ref"?c=t[u]:a[u]=t[u];var _={type:e,props:a,key:n,ref:c,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:--sn,__i:-1,__u:0,__source:s,__self:r};if(typeof e=="function"&&(c=e.defaultProps))for(u in c)a[u]===void 0&&(a[u]=c[u]);return b.vnode&&b.vnode(_),_}function _n(e,t){return function n(o){return o.map((s,r)=>{switch(s.type){case"text":return s.text;case"code":return ie("code",{children:s.text},r);case"strong":case"em":case"del":{const c=s.type;return ie(c,{children:n(s.children)},r)}case"break":return ie("br",{},r);case"link":return ie(e,{url:s.url,children:n(s.children)},r);case"ref":return t(s.ref,r)}})}}const cn=e=>e.split(/[\s@._-]+/).filter(Boolean).slice(0,2).map(t=>t[0].toUpperCase()).join("")||"?";function wt({id:e,children:t,className:n}){return g("button",{type:"button",className:n??"kit-record-link",...He(e)},t??e)}function ln({url:e,children:t}){return g("button",{type:"button",className:"kit-link",...Le(e)},t)}const _e=_n(ln,(e,t)=>g(wt,{id:e,key:t}));function Te(e){return e.map((t,n)=>{switch(t.type){case"heading":return g(`h${t.level}`,{key:n},_e(t.children));case"paragraph":return g("p",{key:n},_e(t.children));case"quote":return g("blockquote",{key:n,className:t.callout?"kit-callout":void 0},t.callout&&g("strong",{},t.callout),Te(t.children));case"code":return g("pre",{key:n},g("code",{},t.text));case"rule":return g("hr",{key:n});case"list":return g(t.ordered?"ol":"ul",{key:n,start:t.ordered?t.start:void 0},t.items.map((o,s)=>g("li",{key:s},o.checked!==null&&g("input",{type:"checkbox",checked:o.checked,disabled:!0}),Te(o.children))));case"table":return g("table",{key:n},g("thead",{},g("tr",{},t.head.map((o,s)=>g("th",{key:s,style:{textAlign:t.align[s]??void 0}},_e(o))))),g("tbody",{},t.rows.map((o,s)=>g("tr",{key:s},o.map((r,c)=>g("td",{key:c,style:{textAlign:t.align[c]??void 0}},_e(r)))))))}})}function un(e,t){let n=!1;const o=new Set,s=a=>{let _=!0;const l=()=>{_&&(_=!1,o.delete(l),a())};return n?l():o.add(l),l};function r(a){const[_,l]=F({key:a,feed:{status:"loading"}});return be(()=>{let f=!0;l({key:a,feed:{status:"loading"}});let i=()=>{};try{if(n)throw new N("closed","The kit has been disposed.");i=s(e.subscribe(a,d=>{f&&!n&&l({key:a,feed:d})}))}catch(d){l({key:a,feed:{status:"error",error:d instanceof N?d:new N("unavailable",String(d))}})}return()=>{f=!1,i()}},[a]),n?{status:"error",error:new N("closed","The kit has been disposed.")}:_.key===a?_.feed:{status:"loading"}}function c(a){const _=JSON.stringify(a),[l,f]=F(0),i=_t(()=>f(h=>h+1),[]),[d,v]=F({key:_,nonce:l,feed:{status:"loading"}}),m=it({key:_});return be(()=>{let h=!0,p=()=>{};m.current.key!==_&&(m.current={key:_});let{last:$,deliveredAt:E}=m.current;v({key:_,nonce:l,feed:{status:"loading"}});const S=A=>{h&&!n&&v({key:_,nonce:l,feed:{status:"error",error:{code:"unavailable",message:String(A),terminal:!0},last:$,deliveredAt:E}})};return e.ready.then(()=>{if(!h||n)return;const A=t();if(typeof A?.subscribe!="function"){v({key:_,nonce:l,feed:{status:"unsupported",message:"This host does not offer app-v2 query subscriptions."}});return}p=s(A.subscribe(JSON.parse(_),C=>{!h||n||(C.status==="ready"?($={rows:C.rows,columns:C.columns,truncated:C.truncated,...C.cached?{cached:!0}:{}},E=Date.now(),m.current={key:_,last:$,deliveredAt:E},v({key:_,nonce:l,feed:{status:"ready",result:$,deliveredAt:E}})):(v({key:_,nonce:l,feed:{status:"error",error:{code:C.code,message:C.message,terminal:C.terminal},last:$,deliveredAt:E}}),C.terminal&&(h=!1,p())))})),h||p()}).catch(S),()=>{h=!1,p()}},[_,l]),{...n?{status:"error",error:{code:"closed",message:"The kit has been disposed.",terminal:!0}}:d.key===_&&d.nonce===l?d.feed:{status:"loading"},retry:i}}return{api:Object.freeze({h:g,render:xt,Fragment:D,createContext:It,...qt,html:Bt.bind(g),useFeed:r,useQueryFeed:c,Loading:({what:a="data"})=>g("p",{className:"kit-state",role:"status"},`Loading ${a}\u2026`),Empty:({children:a})=>g("p",{className:"kit-state kit-empty"},a),ErrorState:({error:a,onRetry:_})=>g("div",{className:"kit-state kit-error",role:"alert"},g("p",{},je(a)),a.message&&g("p",{},a.message),_&&g("button",{type:"button",onClick:_},"Try again")),PreviewBanner:()=>g("p",{className:"kit-preview",role:"status"},"Preview \u2014 sample data, not persisted."),Markdown:({source:a,className:_})=>g("div",{className:_??"kit-markdown"},Te(rn(a))),Avatar:({name:a="",initials:_=cn(a),title:l,className:f})=>g("span",{className:f??"kit-avatar",title:l,"aria-hidden":"true"},_),IconSvg:({children:a,title:_,viewBox:l="0 0 24 24",className:f})=>g("svg",{className:f??"kit-icon",viewBox:l,role:_?"img":void 0,"aria-label":_,"aria-hidden":_?void 0:"true"},_&&g("title",{},_),a),RecordLink:wt}),dispose(){if(!n){n=!0;for(const a of[...o])a()}}}}function an(e,t){const n=At(e,t),o=un(n.kit,()=>Et()),s=Object.freeze({...n.kit,preact:o.api});return Object.freeze({kit:s,dispose(){o.dispose(),n.dispose()}})}return le.createCoreKit=an,Object.defineProperty(le,Symbol.toStringTag,{value:"Module"}),le})({});

return CoreFactoryExports.createCoreKit;
})()
