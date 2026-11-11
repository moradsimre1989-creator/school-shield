"""درع المدرسة - School Shield.

طبقات الحماية:
  1. عميل Cloudflare One (WARP) مُدار + سياسات Gateway  -> الحجب الفعلي
  2. خدمة Windows تعمل كـ SYSTEM                        -> المراقبة وإعادة الفرض
  3. سياسات التسجيل (Registry) للمتصفحات                -> منع التجاوز
  4. تشديد ACL وجدار الحماية                            -> منع الإيقاف والإزالة
"""

__version__ = "1.0.0"
APP_NAME_AR = "درع المدرسة"
APP_NAME_EN = "School Shield"
SERVICE_NAME = "SchoolShield"
SERVICE_DISPLAY = "School Shield Protection Service"
