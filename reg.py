import os
def x():
 b=[f for f in os.listdir()if f.endswith('.txt')and f!='marchiori_lul.txt']
 if not b:return
 with open('marchiori_lul.txt','a',encoding='utf-8')as j:
  for k in b:
   try:
    with open(k,'r',encoding='utf-8')as g:
     for l in g:j.write(l)
    j.write('\n')
   except:
    try:
     with open(k,'r',encoding='latin-1')as g:
      for l in g:j.write(l)
     j.write('\n')
    except:pass
   try:os.remove(k)
   except:pass
x()