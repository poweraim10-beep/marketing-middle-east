# MARKETING MIDDLE EAST

الموقع الرسمي لشركة MARKETING MIDDLE EAST (MME): منصة النمو والتسويق في العالم العربي.

## الملفات
| الملف | الوصف |
|---|---|
| `index.html` | الموقع الأساسي. ملف واحد يحتوي على كل التصميم والصور والشعارات. |
| `academy/index.html` | أكاديمية التدريب والتطوير. نسخة مرجعية للمرحلة الثانية، لم تُربط بقاعدة بيانات بعد. |

## التقنيات
HTML5 و CSS3 و JavaScript بدون مكتبات، مع Canvas 2D لخرائط الشبكة و Google Fonts (Unbounded، Readex Pro، IBM Plex Mono).

## النشر
الموقع ثابت (static) ولا يحتاج أي بناء. اربط المستودع مع Cloudflare Pages أو Netlify:
- Build command: اتركه فارغًا
- Output directory: `/`

أي تعديل يُرفع على الفرع `main` ينزل على الموقع تلقائيًا.

## الأكاديمية (المرحلة الثانية)
- حسابات الطلاب وقاعدة البيانات: Supabase
- حماية الفيديو: Bunny Stream
- الدفع: Stripe أو PayTabs
