(function(){
'use strict';
const form=document.getElementById('regForm');
if(!form)return;
const photo=document.getElementById('photo');
const preview=document.getElementById('preview');
const notice=document.getElementById('notice');
const btn=document.getElementById('submitBtn');
const dob=document.getElementById('dob');
const state=document.getElementById('state');
const searchBtn=document.getElementById('searchBtn');
const searchId=document.getElementById('searchId');
const result=document.getElementById('result');
const states=['Abia','Adamawa','Akwa Ibom','Anambra','Bauchi','Bayelsa','Benue','Borno','Cross River','Delta','Ebonyi','Edo','Ekiti','Enugu','Federal Capital Territory (FCT)','Gombe','Imo','Jigawa','Kaduna','Kano','Katsina','Kebbi','Kogi','Kwara','Lagos','Nasarawa','Niger','Ogun','Ondo','Osun','Oyo','Plateau','Rivers','Sokoto','Taraba','Yobe','Zamfara'];
if(state&&state.options.length<=1)states.forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;state.appendChild(o)});
if(dob)dob.max=new Date().toISOString().slice(0,10);
function msg(text,kind){if(!notice)return;notice.className='notice '+(kind||'');notice.innerHTML=text||'';}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function phone(v){const x=String(v||'').replace(/[\s()-]/g,'');if(/^0\d{10}$/.test(x))return '+234'+x.slice(1);if(/^234\d{10}$/.test(x))return '+'+x;if(/^\+234\d{10}$/.test(x))return x;return null;}
function compress(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>{const img=new Image();img.onload=()=>{const max=520,scale=Math.min(1,max/Math.max(img.width,img.height)),canvas=document.createElement('canvas');canvas.width=Math.max(1,Math.round(img.width*scale));canvas.height=Math.max(1,Math.round(img.height*scale));const ctx=canvas.getContext('2d');if(!ctx)return reject(Error('Unable to process passport image.'));ctx.drawImage(img,0,0,canvas.width,canvas.height);resolve(canvas.toDataURL('image/jpeg',.65));};img.onerror=()=>reject(Error('The passport image could not be read.'));img.src=reader.result;};reader.onerror=()=>reject(Error('Unable to read the passport image.'));reader.readAsDataURL(file);});}
if(photo)photo.addEventListener('change',()=>{const f=photo.files&&photo.files[0];if(!f){if(preview)preview.hidden=true;return;}if(f.size>3*1024*1024){photo.value='';if(preview)preview.hidden=true;msg('Passport photo must be 3 MB or smaller.','error');return;}if(preview){preview.src=URL.createObjectURL(f);preview.hidden=false;}msg('Passport photo selected.','success');});
form.addEventListener('submit',async function(e){e.preventDefault();e.stopImmediatePropagation();msg('');
try{
 if(!form.checkValidity()){form.reportValidity();msg('Please complete all required fields.','error');return;}
 const f=photo&&photo.files&&photo.files[0];if(!f){msg('Please upload the passport photograph.','error');return;}
 const d=Object.fromEntries(new FormData(form).entries());d.phone=phone(d.phone);d.emergency_phone=phone(d.emergency_phone);
 if(!d.phone)return msg('Enter a valid Nigerian phone number.','error');
 if(!d.emergency_phone)return msg('Enter a valid emergency phone number.','error');
 if(!d.date_of_birth||new Date(d.date_of_birth)>new Date())return msg('Enter a valid date of birth.','error');
 btn.disabled=true;form.classList.add('loading');btn.textContent='Submitting...';msg('Submitting your registration securely...','success');
 d.photo_url=await compress(f);
 if(d.photo_url.length>1400000)throw Error('The passport image is still too large. Please choose a clearer photo with a smaller file size.');
 const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),30000);
 let response;
 try{response=await fetch('/api/register?source=public',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(d),signal:ctl.signal});}finally{clearTimeout(timer);}
 let data={};try{data=await response.json();}catch(_){ }
 if(!response.ok)throw Error(data.error||('Registration failed (HTTP '+response.status+').'));
 msg('<b>Registration successful.</b><br>Your Member ID is <b>'+esc(data.member_id)+'</b>.<br><span class="small">Status: <b>PENDING</b> — your application is waiting for administrator approval.</span>','success');
 form.reset();if(preview)preview.hidden=true;
}catch(err){msg(err.name==='AbortError'?'The server took too long to respond. Please try again.':(err.message||'Unable to submit registration. Please try again.'),'error');}
finally{btn.disabled=false;form.classList.remove('loading');btn.textContent='Submit registration';}
},true);
if(searchBtn)searchBtn.addEventListener('click',async()=>{const id=(searchId&&searchId.value||'').trim();if(!id){result.textContent='Enter a Member ID first.';return;}result.textContent='Searching...';try{const r=await fetch('/api/member/'+encodeURIComponent(id)+'?t='+Date.now(),{cache:'no-store'});let j={};try{j=await r.json();}catch(_){}if(!r.ok)throw Error(j.error||'Member not found');result.innerHTML='<div class="member">'+(j.photo_url?'<img src="'+esc(j.photo_url)+'" class="passport" alt="Member passport">':'')+'<b>'+esc(j.full_name)+'</b><span>Member ID: '+esc(j.member_id)+'</span><span>Status: APPROVED</span><span>Rank: '+esc(j.rank||'Not yet assigned')+'</span><span>Office / Unit: '+esc(j.unit||'—')+'</span></div>';}catch(err){result.textContent=err.message;}});
})();
