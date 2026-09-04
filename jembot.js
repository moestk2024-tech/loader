(function () {
'use strict';

var FETCH_TIMEOUT_MS = 8000;
var WATCHDOG_MS = 8000;

function meta(name) {
  var el = document.querySelector('meta[name="' + name + '"]');
  return el ? el.content : '';
}

function showError(msg) {
  var el = document.getElementById('err');
  var s = document.getElementById('spin');
  if (s) s.style.display = 'none';
  if (!el) return;
  el.textContent = String(msg) + ' ';
  var a = document.createElement('a');
  a.href = '';
  a.textContent = 'Coba lagi';
  a.style.color = '#53d6b2';
  a.style.textDecoration = 'underline';
  a.onclick = function (ev) { ev.preventDefault(); location.replace(location.href); };
  el.appendChild(a);
  el.style.display = 'block';
}

var watchdog = setTimeout(function () {
  var el = document.getElementById('err');
  if (el && el.style.display !== 'block') {
    el.textContent = 'Proses sedikit lebih lama dari biasanya.';
    el.style.display = 'block';
  }
}, WATCHDOG_MS);

function clearWatchdog() {
  if (watchdog) { clearTimeout(watchdog); watchdog = null; }
}

function fetchTimeout(url, init) {
  init = init || {};
  var ctrl = null;
  try { ctrl = new AbortController(); } catch (_) {}
  if (ctrl) init.signal = ctrl.signal;
  var to = ctrl ? setTimeout(function(){ ctrl.abort(); }, FETCH_TIMEOUT_MS) : 0;
  return fetch(url, init).then(function(r){
    if (to) clearTimeout(to);
    return r;
  }, function(e){
    if (to) clearTimeout(to);
    throw e;
  });
}

var K = new Uint32Array([
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
var W = new Uint32Array(64);
var H = new Uint32Array(8);

function sha256(bytes) {
  var l = bytes.length;
  var padLen = ((56 - (l + 1) % 64) + 64) % 64;
  var totalLen = l + 1 + padLen + 8;
  var msg = new Uint8Array(totalLen);
  msg.set(bytes); msg[l] = 0x80;
  var bitLen = l * 8;
  msg[totalLen - 4] = (bitLen >>> 24) & 255;
  msg[totalLen - 3] = (bitLen >>> 16) & 255;
  msg[totalLen - 2] = (bitLen >>> 8) & 255;
  msg[totalLen - 1] = bitLen & 255;

  H[0]=0x6a09e667;H[1]=0xbb67ae85;H[2]=0x3c6ef372;H[3]=0xa54ff53a;
  H[4]=0x510e527f;H[5]=0x9b05688c;H[6]=0x1f83d9ab;H[7]=0x5be0cd19;

  for (var off=0; off<totalLen; off+=64) {
    var i;
    for (i=0;i<16;i++) {
      W[i]=((msg[off+i*4]<<24)|(msg[off+i*4+1]<<16)|(msg[off+i*4+2]<<8)|msg[off+i*4+3])>>>0;
    }
    for (i=16;i<64;i++) {
      var w15=W[i-15],w2=W[i-2];
      var s0=((w15>>>7)|(w15<<25))^((w15>>>18)|(w15<<14))^(w15>>>3);
      var s1=((w2>>>17)|(w2<<15))^((w2>>>19)|(w2<<13))^(w2>>>10);
      W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(i=0;i<64;i++){
      var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
      var ch=(e&f)^((~e)&g);
      var t1=(h+S1+ch+K[i]+W[i])>>>0;
      var S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
      var mj=(a&b)^(a&c)^(b&c);
      var t2=(S0+mj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
  }
  var out=new Uint8Array(32);
  for(var j=0;j<8;j++){out[j*4]=(H[j]>>>24)&255;out[j*4+1]=(H[j]>>>16)&255;out[j*4+2]=(H[j]>>>8)&255;out[j*4+3]=H[j]&255;}
  return out;
}

function leadingZeroBits(bytes){
  var bits=0;
  for(var i=0;i<bytes.length;i++){
    var b=bytes[i];
    if(b===0){bits+=8;continue;}
    bits+=Math.clz32(b)-24;break;
  }
  return bits;
}

var enc=new TextEncoder();

function findNonce(challenge,difficulty){
  var BATCH=4000;
  var prefix=enc.encode(challenge+':');
  return new Promise(function(resolve,reject){
    var nonce=0;
    function step(){
      try{
        var end=nonce+BATCH;
        for(;nonce<end;nonce++){
          var ns=''+nonce;
          var buf=new Uint8Array(prefix.length+ns.length);
          buf.set(prefix);
          for(var j=0;j<ns.length;j++) buf[prefix.length+j]=ns.charCodeAt(j);
          if(leadingZeroBits(sha256(buf))>=difficulty){resolve(nonce);return;}
        }
        setTimeout(step,0);
      }catch(e){reject(e);}
    }
    step();
  });
}

var refresh=document.getElementById('amrk-refresh');
if(refresh) refresh.onclick=function(){location.replace(location.href);};

if(typeof crypto==='undefined' || !crypto.getRandomValues){
  clearWatchdog(); showError('Browser tidak mendukung Web Crypto.'); return;
}

var code=meta('amk-code');
if(!code || code==='__CODE__'){
  clearWatchdog(); showError('Konfigurasi gate belum lengkap.'); return;
}

fetchTimeout('/amarok/gate/challenge?code='+encodeURIComponent(code),{
  credentials:'same-origin',cache:'no-store'
})
.then(function(r){
  if(!r.ok) throw new Error('challenge HTTP '+r.status);
  return r.json();
})
.then(function(data){
  if(!data || !data.challenge || !Number.isFinite(Number(data.difficulty))) throw new Error('bad challenge');
  return findNonce(data.challenge,data.difficulty|0).then(function(nonce){
    return fetchTimeout('/amarok/gate/issue',{
      method:'POST',
      credentials:'same-origin',
      cache:'no-store',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({code:code,challenge:data.challenge,nonce:nonce,ua:navigator.userAgent})
    });
  });
})
.then(function(r){
  clearWatchdog();
  if(r.status===204){
    setTimeout(function(){ location.replace(location.href); },100);
    return;
  }
  var reason=r.headers.get('x-amrk-reason')||('HTTP '+r.status);
  throw new Error(reason);
})
.catch(function(e){
  clearWatchdog();
  showError('Verifikasi gagal: '+(e&&e.message?e.message:String(e)));
});
})();