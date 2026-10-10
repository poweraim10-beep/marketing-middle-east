# MARKETING MIDDLE EAST

الموقع الرسمي لشركة MARKETING MIDDLE EAST (MME): منصة النمو والتسويق في العالم العربي.

## الملفات
| الملف | الوصف |
|---|---|
| `index.html` | الموقع الأساسي. ملف واحد يحتوي على كل التصميم والصور والشعارات. |
| `academy/index.html` | صفحة أكاديمية التدريب والتطوير، تُنشر على `academy.marketingmiddleeast.com`. |

## التقنيات
HTML5 و CSS3 و JavaScript بدون مكتبات، مع Canvas 2D لخرائط الشبكة و Google Fonts (Unbounded، Readex Pro، IBM Plex Mono).

## النشر
الموقع ثابت (static) ولا يحتاج أي بناء. اربط المستودع مع Cloudflare Pages أو Netlify:
- Build command: اتركه فارغًا
- Output directory: `/`

أي تعديل يُرفع على الفرع `main` ينزل على الموقع تلقائيًا.

### الدومين الفرعي للأكاديمية
مشروع Pages ثانٍ من نفس المستودع:
- Project name: `mme-academy`
- Root directory: `academy` (إلزامي: فيه wrangler.toml وربط قاعدة البيانات D1 والـ API)
- Build command: فارغ، Output directory: `/`
- Custom domain: `academy.marketingmiddleeast.com`

## الأكاديمية (المرحلة الثانية)
- حسابات الطلاب وقاعدة البيانات: Supabase
- حماية الفيديو: Bunny Stream
- الدفع: Stripe أو PayTabs

## نظام الأكاديمية (academy/)
- `academy/public/index.html`: واجهة الأكاديمية (الصفحة التعريفية، الحسابات، الدورة، لوحة التحكم).
- `academy/functions/api/[[path]].js`: الـ API (تسجيل/دخول، طلبات التسجيل، الدروس، الإدارة).
- `academy/wrangler.toml`: ربط قاعدة بيانات D1 `mme-academy`.
- التدفق: إنشاء حساب ← تقديم طلب ← الدفع عبر واتساب ← قبول الطلب من لوحة التحكم ← تفتح الدورة للطالب.
- لوحة التحكم: `https://academy.marketingmiddleeast.com/#/admin` (لحسابات role = admin فقط).
- هدية التسجيل: «شنطة أدوات الطالب» في `academy/public/gift/student-kit.pdf`. بتظهر رسالة «مبروك» بعد إنشاء الحساب، وزر تحميل دائم بصفحة «حسابي». التحميل محمي بـ `academy/functions/gift/[[path]].js` (لازم الطالب يكون مسجّل دخول). لتحديث الشنطة، استبدل ملف الـ PDF بنفس الاسم.
