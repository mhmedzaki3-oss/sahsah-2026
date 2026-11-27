# الاستخدام:
#   python make_code.py رقم_الجهاز [عدد_الأيام=30] ["ملاحظة/اسم العميل"]
#   python make_code.py --batch devices.txt     (كل سطر: رقم_الجهاز,الأيام,ملاحظة)
#   python make_code.py --list                  (عرض سجل الأكواد وحالتها)
# كل كود يُسجَّل تلقائيا في codes_log.csv (لا ترفعه على GitHub).
import sys,csv,os,base64,datetime
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
H=os.path.dirname(os.path.abspath(__file__));LOG=os.path.join(H,"codes_log.csv")
COLS=["issued","device","days","expires","code","note"]
def make(dev,days,note=""):
    dev=dev.strip().upper();today=datetime.date.today()
    exp=(today+datetime.timedelta(days=days)).strftime("%Y%m%d")
    k=serialization.load_pem_private_key(open(os.path.join(H,"private.pem"),"rb").read(),None)
    r,s=decode_dss_signature(k.sign(f"{dev}.{exp}".encode(),ec.ECDSA(hashes.SHA256())))
    code=f"{dev}.{exp}."+base64.urlsafe_b64encode(r.to_bytes(32,"big")+s.to_bytes(32,"big")).rstrip(b"=").decode()
    new=not os.path.exists(LOG)
    with open(LOG,"a",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f)
        if new:w.writerow(COLS)
        w.writerow([today.isoformat(),dev,days,exp,code,note])
    return code
a=sys.argv[1:]
if not a:sys.exit(__doc__)
if a[0]=="--list":
    if not os.path.exists(LOG):sys.exit("لا توجد أكواد بعد")
    t=datetime.date.today().strftime("%Y%m%d")
    for r in csv.DictReader(open(LOG,encoding="utf-8-sig")):
        print(r["issued"],r["device"],r["expires"],"نشط" if r["expires"]>=t else "منتهي",r["note"],"\n   ",r["code"])
elif a[0]=="--batch":
    for ln in open(a[1],encoding="utf-8"):
        p=[x.strip() for x in ln.split(",")]
        if p and p[0]:print(p[0].upper(),"->",make(p[0],int(p[1]) if len(p)>1 and p[1] else 30,p[2] if len(p)>2 else ""))
else:
    print(make(a[0],int(a[1]) if len(a)>1 else 30,a[2] if len(a)>2 else ""))
