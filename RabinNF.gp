\\ Tonelli-Shanks algorithm --------------------------------------------------------------

sqroot(c,p,bp) = {local(phi, s, t, b, cm, ct, j, e1, e2);
phi=p^poldegree(pol)-1;
s=0;
t=phi;
while(t%2==0,t=t/2;s++);
cm = Mod(c*Mod(1, p),pol*Mod(1,p));
ct = cm^(-t);
j=1;
b=Mod(bp*Mod(1,p),pol*Mod(1,p));
while(ct!=b^(2*j*t),j++);
cm^((t+1)/2)*b^(t*j)
}

\\ The Rabin cryptosystem in number fields -----------------------------------------------

\\ Key generation with list of congruences and precomputations
\\ Example of valid parameters for the Gaussian integers, primes congruent to 3 modulo 8
\\ pol=x^2+1;
\\ C=[3];
\\ D=8;

key_deg2(max=2^2048) = {local(p, q, l);
l=random(max)*D+1;
while(!ispseudoprime(l), l=l+D); 
p=(C[random(length(C))+1]-1+D)*l+1;
while(!ispseudoprime(p), p=p+D*l); 
l=2*random(max)*D+1;
while(!ispseudoprime(l), l=l+D); 
q=(C[random(length(C))+1]-1+D)*l+1;
while(!ispseudoprime(q), q=q+D*l); 
bp=Mod((1+x)*Mod(1,p),pol*Mod(1,p));
while(liftall(bp^((p^poldegree(pol)-1)/2))!=p-1,bp=bp+x);
bq=Mod((1+x)*Mod(1,p),pol*Mod(1,p));
while(liftall(bq^((p^poldegree(pol)-1)/2))!=p-1,bq=bq+x);
[p*q, [p,q,liftall(bp),liftall(bq)]]
}

\\ Key generation with precomputations but without list of congruences 
\\ Example of a valid parameter
\\ pol=x^4+x+1;

key_general(max=2^2048) = {local(p, q, l); 
l=4*random(max)+1;
while(!ispseudoprime(l), l=l+4); 
p=2*l+1;
while(!ispseudoprime(p) || !polisirreducible(pol*Mod(1,p)), p=p+4*l); 
l=4*random(max)+1;
while(!ispseudoprime(l), l=l+4); 
q=2*l+1;
while(!ispseudoprime(q) || !polisirreducible(pol*Mod(1,q)), q=q+4*l); 
bp=Mod((1+x)*Mod(1,p),pol*Mod(1,p));
while(liftall(bp^((p^poldegree(pol)-1)/2))!=p-1,bp=bp+x);
bq=Mod((1+x)*Mod(1,q),pol*Mod(1,q));
while(liftall(bq^((q^poldegree(pol)-1)/2))!=q-1,bq=bq+x);
[p*q, [p,q,liftall(bp),liftall(bq)]]
}

\\ Key generation with list of congruences but without precomputations
\\ Example of valid parameters for a degree 3 subextension of a cyclotomic field, primes congruent to 3, 11, 19 or 23 modulo 28
\\ pol=x^3+x^2-2*x-1;
\\ C=[3,11,19,23];
\\ D=28;

key_deg3(max=2^2048) = {local(p, q, l);
l=random(max)*D+1;
while(!ispseudoprime(l), l=l+D); 
p=(C[random(length(C))+1]-1+D)*l+1;
while(!ispseudoprime(p), p=p+D*l); 
l=2*random(max)*D+1;
while(!ispseudoprime(l), l=l+D); 
q=(C[random(length(C))+1]-1+D)*l+1;
while(!ispseudoprime(q), q=q+D*l); 
[p*q, [p,q]]
}


\\ Encryption function

encrypt(m,pk) ={
if(polcoef(m,0)==0,error("0 constant term in message not allowed"));
[liftall(Mod(m*Mod(1,pk),pol*Mod(1,pk))^2),polcoef(m,0)%2,(1-kronecker(polcoef(m,0),pk))/2]
}

\\ Decryption algorithm whenever the Tonelli-Shanks algorithm is required (e.g. Gaussian integers or pol=x^4+x+1)

decrypt_general(c, sk) = {local(m1, m2, m, n, bz, k1, k2, k);
k=1-c[3]*2;
bz=bezout(sk[1],sk[2]);
n=sk[1]*sk[2];
m1 = liftall(sqroot(c[1],sk[1],sk[3]));
m2 = liftall(sqroot(c[1],sk[2],sk[4]));
k1=kronecker(polcoef(m1,0),sk[1]);
k2=kronecker(polcoef(m2,0),sk[2]);
if(k1*k2==0,error("invalid cipher"));
if(k1*k2==k,m=m1*sk[2]*bz[2]+m2*sk[1]*bz[1],m=m1*sk[2]*bz[2]-m2*sk[1]*bz[1]);
if((polcoef(m,0)%n)%2==c[2],lift(m*Mod(1,n)),lift(-m*Mod(1,n)))
}

\\ Decryption algorithm when Tonelli-Shanks is not needed (e.g. pol=x^3+x^2-2*x-1) 

decrypt_deg3(c, sk) = {local(m1, m2, m, n, bz, k1, k2, k);
k=1-c[3]*2;
bz=bezout(sk[1],sk[2]);
n=sk[1]*sk[2];
m1 = liftall(Mod(c[1]*Mod(1,sk[1]),pol*Mod(1,sk[1]))^((sk[1]^3+1) / 4));
m2 = liftall(Mod(c[1]*Mod(1,sk[2]),pol*Mod(1,sk[2]))^((sk[2]^3+1) / 4));
k1=kronecker(polcoef(m1,0),sk[1]);
k2=kronecker(polcoef(m2,0),sk[2]);
if(k1*k2==0,error("invalid cipher"));
if(k1*k2==k,m=m1*sk[2]*bz[2]+m2*sk[1]*bz[1],m=m1*sk[2]*bz[2]-m2*sk[1]*bz[1]);
if((polcoef(m,0)%n)%2==c[2],lift(m*Mod(1,n)),lift(-m*Mod(1,n)))
}



\\ The classical Rabin cryptosystem -------------------------------------------------

\\ Key generation

key_classic(max=2^2048) = {local(p, q, l);
l=random(max)*4+1;
while(!ispseudoprime(l), l=l+4); 
p=2*l+1;
while(!ispseudoprime(p), p=p+4*l); 
l=random(max)*4+1;
while(!ispseudoprime(l), l=l+4); 
q=2*l+1;
while(!ispseudoprime(q), q=q+4*l); 
[p*q, [p,q]]
}

\\ Encryption

encrypt_classic(m, pk) = {
if(polcoef(m,0)==0,error("0 message not allowed"));
[lift(Mod(m,pk)^2), m%2, (1-kronecker(m, pk))/2]
}

\\ Decryption

decrypt_classic(c, sk) = {local(m1, m2, m, bz, k1, k2, n, k);
k=1-c[3]*2;
bz=bezout(sk[1],sk[2]);
n=sk[1]*sk[2];
m1 = lift(Mod(c[1],sk[1])^((sk[1]+1) / 4));
m2 = lift(Mod(c[1],sk[2])^((sk[2]+1) / 4)); 
k1 = kronecker(m1,sk[1]);
k2 = kronecker(m2,sk[2]);
if(k1*k2==0,error("invalid cipher"));
if(k1*k2==k,m=(m1*sk[2]*bz[2]+m2*sk[1]*bz[1])%n,m=(m1*sk[2]*bz[2]-m2*sk[1]*bz[1])%n);
if(m%2==c[2],m,n-m)
}
