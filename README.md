# xr Deployer

سایت نصب‌کننده‌ی xr PANEL روی Cloudflare Workers (Node بدون وابستگی، آماده‌ی Railway).

## Deploy روی Railway
1. این پوشه را روی یک ریپوی GitHub بگذار.
2. railway.com → New Project → Deploy from GitHub repo. (Railway خودش `Dockerfile` را تشخیص می‌دهد.)
3. Settings → Networking → Generate Domain.

اجرای محلی: `node server.js` یا `docker build -t xr-deployer . && docker run -p 3000:3000 xr-deployer`

## جریان کار
توکن → تأیید → انتخاب اسم و پلن → ساخت D1 → آپلود assets → نصب Worker → فعال‌سازی workers.dev → نمایش دامنه.

- لینک «ساخت توکن» دسترسی‌های Workers Scripts:Edit، D1:Edit، Account Analytics:Read و Account Settings:Read را از قبل پر می‌کند.
- همین توکن به‌صورت secret (`CF_API_TOKEN`) داخل Worker گذاشته می‌شود تا Home تعداد درخواست‌های امروز را از GraphQL Analytics بخواند.
- توکن در سرور deployer ذخیره یا لاگ نمی‌شود و فقط در حافظه‌ی همان نصب می‌ماند.
- دوباره نصب کردن با همان اسم = آپدیت (دیتابیس حفظ می‌شود).

ورود اولیه پنل: `admin` / `admin` (فوراً عوض کن).

## تغییرات در worker
- `src/index.js`: مسیر `/api/cf` (کش ۶۰ ثانیه‌ای؛ Workers و Pages Functions هر دو شمرده می‌شن).
- `src/ui.js`: کارت «Requests today» در Home.

## Workers یا Pages
در مرحله‌ی تنظیمات می‌توانی انتخاب کنی. Workers با workers.dev و Pages با pages.dev. برای Pages، worker موقع build داکر با esbuild به یک فایل `_worker.js` تبدیل می‌شود و مسیر `/static/*` از Worker معاف است. بایندینگ D1 و secretها روی خود پروژه‌ی Pages تنظیم می‌شوند.
