import numpy as np, json, sys, wave
SR=48000; rng=np.random.default_rng(7)
def env(n,a=.005,r=.2):
    t=np.arange(n)/SR; e=np.minimum(1,t/a)*np.exp(-t/r); return e
def tone(f,d,a=.005,r=.1,shape='sine'):
    n=int(d*SR); t=np.arange(n)/SR
    w=np.sin(2*np.pi*f*t) if shape=='sine' else np.sign(np.sin(2*np.pi*f*t))*.6
    return w*env(n,a,r)
def noise(d): return rng.standard_normal(int(d*SR))
def lp(x,k):  # simple one-pole lowpass, k in (0,1)
    y=np.empty_like(x); s=0.
    for i,v in enumerate(x): s+=k*(v-s); y[i]=s
    return y
def bp_sweep(d,f0,f1,q=.15):
    n=int(d*SR); x=noise(d); t=np.arange(n)/SR; f=f0*(f1/f0)**(t/d)
    # state variable filter
    lowv=bandv=0.; y=np.empty(n)
    for i in range(n):
        F=2*np.sin(np.pi*f[i]/SR); high=x[i]-lowv-q*bandv; bandv+=F*high; lowv+=F*bandv; y[i]=bandv
    return y
def mix(*xs):
    n=max(len(x) for x in xs); o=np.zeros(n)
    for x in xs: o[:len(x)]+=x
    return o
def norm(x,p=.9): return x/ (np.max(np.abs(x))+1e-9)*p
S={}
w=bp_sweep(.55,300,3500,.35); w*=np.sin(np.linspace(0,np.pi,len(w)))**1.5; S['whoosh']=norm(w,.55)
S['swipe']=norm(bp_sweep(.3,1200,5000,.4)*np.sin(np.linspace(0,np.pi,int(.3*SR)))**2,.45)
S['pop']=norm(mix(tone(520,.12,.002,.04),.5*tone(1040,.08,.002,.025)),.5)
S['tick']=norm(tone(1900,.05,.001,.012)+noise(.05)*env(int(.05*SR),.001,.004)*.3,.42)
S['beep']=norm(tone(2700,.16,.003,.5,'square')*np.r_[np.ones(int(.13*SR)),np.linspace(1,0,int(.03*SR))],.5)
S['ding']=norm(mix(tone(1318.5,1.1,.002,.35),.6*tone(1975.5,1.1,.002,.25),.3*tone(2637,.9,.002,.15)),.55)
im=mix(lp(noise(1.2),.02)*env(int(1.2*SR),.002,.35)*2,tone(55,1.2,.003,.5)*1.2,tone(82,1.0,.003,.35))
S['impact']=norm(im,.85)
sh=np.zeros(int(1.6*SR))
for k,f in enumerate([1568,2093,2637,3136,3951]):
    o=int(k*.07*SR); tt=tone(f,1.2,.003,.35)*.5; sh[o:o+len(tt)]+=tt
S['shimmer']=norm(sh,.4)
sc=bp_sweep(.22,2500,1200,.5)*env(int(.22*SR),.003,.12); S['scratch']=norm(sc,.5)
n1=noise(.06)*env(int(.06*SR),.001,.01); n2=noise(.09)*env(int(.09*SR),.001,.02)
sh2=np.zeros(int(.2*SR)); sh2[:len(n1)]+=n1; sh2[int(.07*SR):int(.07*SR)+len(n2)]+=n2*.8; S['shutter']=norm(lp(sh2,.5),.55)
bz=tone(110,.45,.005,1,'square')*np.r_[np.ones(int(.4*SR)),np.linspace(1,0,int(.05*SR))]; bz2=tone(116,.45,.005,1,'square')*np.r_[np.ones(int(.4*SR)),np.linspace(1,0,int(.05*SR))]
S['buzz']=norm(lp(bz+bz2,.15),.6)
mm=np.zeros(int(.35*SR)); a=tone(880,.12,.002,.06); b=tone(1320,.2,.002,.08); mm[:len(a)]+=a; mm[int(.1*SR):int(.1*SR)+len(b)]+=b; S['msg']=norm(mm,.5)
r=bp_sweep(1.6,200,2400,.25)*np.linspace(0,1,int(1.6*SR))**2; S['rise']=norm(r,.35)
cn=np.zeros(int(.9*SR))
for k,(o,f) in enumerate([(0,3520),(.09,4186),(.2,3729),(.33,4435),(.5,3951)]):
    tt=mix(tone(f,.35,.001,.06),.5*tone(f*1.5,.25,.001,.04)); i=int(o*SR); cn[i:i+len(tt)]+=tt
S['coin']=norm(cn,.45)
w3=bp_sweep(1.2,250,1800,.3)*np.sin(np.linspace(0,np.pi,int(1.2*SR)))**1.2; S['swoosh360']=norm(w3,.5)
cues=json.load(open(sys.argv[1])); dur=float(sys.argv[2])
out=np.zeros(int(dur*SR)+SR)
for name,t in cues:
    x=S[name]; o=int(t*SR); out[o:o+len(x)]+=x[:len(out)-o]
out=np.tanh(out*1.1)*.92
st=(np.stack([out,out],1)*32767).astype(np.int16)
with wave.open(sys.argv[3],'wb') as f: f.setnchannels(2); f.setsampwidth(2); f.setframerate(SR); f.writeframes(st.tobytes())
print('ok',len(cues))
