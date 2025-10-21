import streamlit as st
import os
import bcrypt
import pandas as pd
import time
from datetime import datetime
from dotenv import load_dotenv
from PIL import Image
from google import genai 
from supabase import create_client, Client
# تم تصحيح الاستيراد للمرة الأخيرة ليناسب آخر تحديثات Streamlit Extras
from streamlit_extras.cookie_manager import get_cookies

# -------------------- 1. الثوابت والإعداد الأولي --------------------

load_dotenv() 

# مفاتيح الكوكيز لتذكّر المستخدم
COOKIE_KEY_USER = "math_user_email"

MAX_QUESTIONS_DAILY = 5
DEFAULT_GRADE = "الثانية بكالوريا (علوم رياضية)"

# تهيئة الاتصال بـ Gemini و Supabase
try:
    # 1. جلب المفاتيح (سيستخدم st.secrets في Streamlit Cloud)
    API_KEY = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))
    SUPABASE_URL = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL"))
    SUPABASE_KEY = st.secrets.get("SUPABASE_KEY", os.getenv("SUPABASE_KEY"))

    if not API_KEY or not SUPABASE_URL or not SUPABASE_KEY:
        st.error("الرجاء التأكد من إعداد جميع المفاتيح (GEMINI_API_KEY, SUPABASE_URL, SUPABASE_KEY) في ملف الأسرار.")
        st.stop()
        
    client = genai.Client(api_key=API_KEY) 

    @st.cache_resource
    def init_supabase_client(url, key):
        return create_client(url, key)
    
    supabase: Client = init_supabase_client(SUPABASE_URL, SUPABASE_KEY)

except Exception as e:
    st.error(f"حدث خطأ في تهيئة الاتصال: {e}")
    st.stop()


# 2. قراءة تعليمات النظام
try:
    # لتشغيل التطبيق على Cloud، يجب أن يكون الملف في المستودع
    with open("system_prompt.txt", "r", encoding="utf-8") as f:
        SYSTEM_PROMPT = f.read()
except FileNotFoundError:
    SYSTEM_PROMPT = "أنت مساعد رياضي خبير متخصص في المنهاج المغربي. قم بحل المسألة الرياضية المقدمة في الصورة بتفصيل." 
    
st.set_page_config(page_title="Math AI with zaoujal", layout="centered")

# تهيئة مدير الكوكيز الجديد والمستقر
cookie_manager = get_cookies()

# -------------------- دوال مساعدة (إدارة IP فقط) --------------------

def get_client_ip():
    """محاولة استخراج عنوان IP الخاص بالعميل. هذه الميزة تبقى معتمدة على بيئة التشغيل وقد لا تعمل دائماً في Cloud."""
    try:
        # هذه الخاصية قد لا تعمل في جميع بيئات Streamlit، لكننا نحافظ عليها لأفضل محاولة
        request_details = st.script_request_queue.get_request_details()
        if request_details and 'remoteIp' in request_details:
            return request_details['remoteIp']
        
        if request_details and 'headers' in request_details:
            headers = request_details['headers']
            ip_list = headers.get('X-Forwarded-For', '').split(',')
            if ip_list and ip_list[0]:
                return ip_list[0].strip()
    except:
        pass # تجاهل الأخطاء التشغيلية لـ get_request_details

    return "غير متاح/غير معروف"

# -------------------- 2. دوال Supabase وإدارة المستخدمين (مع التخزين المؤقت) --------------------

@st.cache_data(ttl=60)
def get_user_data(email):
    """جلب بيانات المستخدم من Supabase."""
    if not email or not email.strip(): return None
    try:
        response = supabase.table("users").select("*").eq("email", email).single().execute()
        return response.data
    except Exception:
        return None

def add_user(email, password, grade):
    """إضافة مستخدم جديد إلى Supabase."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    client_ip = get_client_ip()
    
    try:
        data = {
            "email": email,
            "password_hash": hashed_password,
            "school_grade": grade,
            "last_use_date": datetime.now().strftime("%Y-%m-%d"),
            "questions_used": 0,
            "is_admin": False, 
            "is_premium": False,
            "registration_ip": client_ip
        }
        supabase.table("users").insert(data).execute()
        get_user_data.clear() 
        return True
    except Exception:
        return False

def update_user_usage(email, increment=False):
    """تحديث عدد استخدامات المستخدم وإعادة تعيينها يومياً."""
    user_data = get_user_data(email)
    today_str = datetime.now().strftime("%Y-%m-%d")

    if user_data is None: return False, 0
    
    current_used = user_data.get('questions_used', 0)
    last_date_str = user_data.get('last_use_date', today_str)
    is_premium = user_data.get('is_premium', False)

    if is_premium:
        return True, 0 

    if last_date_str != today_str:
        current_used = 0
    
    new_used = current_used
    can_use = True
    
    if increment and current_used < MAX_QUESTIONS_DAILY:
        new_used = current_used + 1
        
        supabase.table("users").update({
            "questions_used": new_used, 
            "last_use_date": today_str
        }).eq("email", email).execute()
        
        get_user_data.clear() 
    
    elif increment and current_used >= MAX_QUESTIONS_DAILY:
        can_use = False

    return can_use, new_used

# -------------------- 3. دوال المصادقة وإدارة الكوكيز (باستخدام streamlit-extras) --------------------

def initialize_session_state():
    """تهيئة حالة الجلسة بناءً على ملف تعريف الارتباط."""
    if 'initialized' in st.session_state: return

    # استخدام المدير الجديد لقراءة الكوكي (المستقر)
    user_from_cookie = cookie_manager.get(COOKIE_KEY_USER)
    
    st.session_state['initialized'] = True
    st.session_state['logged_in'] = False
    st.session_state['user_email'] = None
    st.session_state['is_admin'] = False
    st.session_state['is_premium'] = False

    if user_from_cookie:
        user_data = get_user_data(user_from_cookie)
        if user_data:
            st.session_state['logged_in'] = True
            st.session_state['user_email'] = user_from_cookie
            st.session_state['is_admin'] = user_data.get('is_admin', False) 
            st.session_state['is_premium'] = user_data.get('is_premium', False) 
        else:
            # إذا كان الكوكي موجوداً لكن المستخدم حُذف
            cookie_manager[COOKIE_KEY_USER] = None 
            cookie_manager.save()
            st.rerun()

def login_successful(email, is_admin, is_premium):
    """تخزين حالة الجلسة والكوكيز."""
    st.session_state['logged_in'] = True
    st.session_state['user_email'] = email
    st.session_state['is_admin'] = is_admin
    st.session_state['is_premium'] = is_premium
    
    # حفظ في الكوكي لتذكّر المستخدم (يبقى مدى الحياة)
    cookie_manager[COOKIE_KEY_USER] = email
    cookie_manager.save() # حفظ الكوكيز الجديدة
    st.rerun()

def logout_user():
    """تسجيل الخروج وحذف الكوكيز."""
    # حذف الكوكي باستخدام المدير الجديد
    cookie_manager[COOKIE_KEY_USER] = None
    cookie_manager.save() # حفظ التغيير
    
    # مسح حالة الجلسة
    st.session_state['logged_in'] = False
    st.session_state['user_email'] = None
    st.session_state['is_admin'] = False
    st.session_state['is_premium'] = False
    st.rerun()

# -------------------- 4. دوال عرض نماذج التسجيل والدخول --------------------

def login_form():
    """عرض نموذج تسجيل الدخول."""
    with st.form("login_form"):
        st.subheader("تسجيل الدخول")
        email = st.text_input("البريد الإلكتروني").strip()
        password = st.text_input("كلمة المرور", type="password")
        submitted = st.form_submit_button("تسجيل الدخول")

        if submitted:
            user_data = get_user_data(email) 
            
            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data.get('password_hash', '').encode('utf-8')): 
                login_successful(
                    email,
                    user_data.get('is_admin', False),
                    user_data.get('is_premium', False)
                )
                st.success("تم تسجيل الدخول بنجاح! 🥳")
            else:
                st.error("خطأ في البريد الإلكتروني أو كلمة المرور.")

def register_form():
    """عرض نموذج تسجيل حساب جديد."""
    with st.form("register_form"):
        st.subheader("إنشاء حساب جديد")
        email = st.text_input("البريد الإلكتروني").strip()
        password = st.text_input("كلمة المرور", type="password")
        
        grades = [
            "السنة الأولى إعدادي", "السنة الثانية إعدادي", "السنة الثالثة إعدادي",
            "الجذع المشترك العلمي", "الأولى بكالوريا (علوم تجريبية)", 
            "الأولى بكالوريا (علوم رياضية)", "الثانية بكالوريا (علوم فيزيائية)",
            "الثانية بكالوريا (علوم الحياة والأرض)", "الثانية بكالوريا (علوم رياضية)",
            "غير ذلك (جامعة/آداب/تكوين مهني)"
        ]
        initial_grade_index = grades.index(DEFAULT_GRADE) if DEFAULT_GRADE in grades else 0
        grade = st.selectbox("المستوى الدراسي (النظام المغربي)", grades, index=initial_grade_index)
        
        submitted = st.form_submit_button("تسجيل الحساب")

        if submitted:
            if not email or not password or len(password) < 6:
                st.error("الرجاء إدخال بيانات صالحة وكلمة مرور لا تقل عن 6 أحرف.")
                return

            if get_user_data(email):
                 st.error("البريد الإلكتروني مُسجل بالفعل. حاول تسجيل الدخول.")
                 return
                 
            if add_user(email, password, grade):
                st.success("تم التسجيل بنجاح! يمكنك الآن تسجيل الدخول.")
            else:
                st.error("حدث خطأ غير متوقع أثناء التسجيل.")

# -------------------- 5. دالة لوحة التحكم الإدارية (Admin Dashboard) 👑 --------------------

def admin_dashboard_ui():
    """عرض لوحة التحكم للمسؤولين فقط لإدارة صلاحيات المستخدمين المميزين."""
    st.title("لوحة التحكم الإدارية 👑")
    st.caption("هذه الصفحة متاحة لك بصفتك مسؤول المشروع.")

    try:
        response = supabase.table("users").select("*").order("email").execute()
        users = response.data

        st.subheader("إدارة الوصول المميز")
        
        users_df = pd.DataFrame(users)
        
        # التأكد من وجود الأعمدة المطلوبة قبل العرض
        required_cols = ['email', 'school_grade', 'is_premium', 'registration_ip']
        for col in required_cols:
            if col not in users_df.columns:
                users_df[col] = None # إضافة عمود فارغ إذا كان مفقودًا لتجنب الخطأ
        
        edited_df = st.data_editor(
            users_df[required_cols],
            column_config={
                "is_premium": st.column_config.CheckboxColumn(
                    "وصول مميز (Premium)",
                    help="تفعيل الوصول غير المحدود لهذا المستخدم.",
                    default=False
                ),
                "registration_ip": st.column_config.TextColumn(
                    "IP التسجيل",
                    disabled=True,
                )
            },
            hide_index=True,
            num_rows="fixed"
        )
        
        if st.button("🚀 تحديث صلاحيات الوصول"):
            for index, row in edited_df.iterrows():
                original_row = users_df[users_df['email'] == row['email']].iloc[0]
                
                # تحديث فقط إذا كان هناك تغيير في is_premium
                if original_row.get('is_premium') != row['is_premium']:
                    supabase.table("users").update({
                        "is_premium": row['is_premium']
                    }).eq("email", row['email']).execute()
            
            st.success("تم تحديث صلاحيات الوصول بنجاح!")
            get_user_data.clear() 
            st.rerun()

    except Exception as e:
        st.error(f"خطأ في جلب بيانات لوحة التحكم. تأكد من إعداد سياسات الأمان (RLS) للسماح للمسؤولين بالقراءة والتحديث: {e}")


# -------------------- 6. دالة واجهة التطبيق الرئيسية (Main UI) --------------------

def main_app_ui():
    """عرض واجهة التطبيق الرئيسية (حل المسائل) والتحكم بالتقييد والتخصيص."""
    
    st.title("🇲🇦 حلول المسائل بالذكاء الاصطناعي")
    st.caption("يرجى التأكد من تحميل صورة عالية الجودة مع نص واضح وتمرين واحد")
    
    user_email = st.session_state['user_email']
    is_premium = st.session_state.get('is_premium', False)

    # 1. تحديث العداد وعرض حالة الاستخدام
    if not is_premium:
        can_use, current_used = update_user_usage(user_email)
        
        st.info(f"الأسئلة المجانية اليومية المتبقية: {MAX_QUESTIONS_DAILY - current_used} من {MAX_QUESTIONS_DAILY}.")
        
        if current_used >= MAX_QUESTIONS_DAILY:
            st.error(f"لقد استنفدت الحد الأقصى ({MAX_QUESTIONS_DAILY}) من الأسئلة لهذا اليوم. يرجى العودة غداً. (هنا يمكنك إضافة رابط الاشتراك المدفوع).")
            st.markdown("---")
            return
    else:
        st.info("✅ لديك وصول مميز (Premium Access) وغير محدود!")


    # 2. منطق رفع الصورة والحل
    uploaded_file = st.file_uploader("قم بتحميل صورة المسألة", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption='صورة المسألة.', use_column_width=True)
        
        if st.button("🚀 ابدأ الحل والتحليل"):
            
            with st.status('يتم تحليل الصورة وتقديم الحل...') as status:
                try:
                    
                    # 🌟 التخصيص حسب المستوى 🌟
                    full_user_data = get_user_data(user_email)
                    # ضمان قيمة افتراضية إذا كان full_user_data فارغاً أو Grade غير موجودة
                    user_grade = full_user_data.get('school_grade', DEFAULT_GRADE) if full_user_data else DEFAULT_GRADE

                    custom_prompt = (
                        f"{SYSTEM_PROMPT}\n"
                        f"مستوى الطالب هو: {user_grade}. يجب أن يكون الحل المفصل المقدم مناسبًا تمامًا لهذا المستوى التعليمي المحدد في النظام المغربي، مع التركيز على المنهجيات التي تدرس في هذا المستوى."
                    )
                    
                    contents = [custom_prompt, image]
                    
                    st.subheader("📝 الحل المفصل (يتم عرضه مباشرة)")
                    
                    stream = client.models.generate_content_stream(
                        model='gemini-2.5-flash', 
                        contents=contents
                    )
                    
                    st.write_stream(token.text for token in stream)

                    # 3. تحديث الاستخدام بعد نجاح الحل (فقط للمستخدمين العاديين)
                    if not is_premium:
                        update_user_usage(user_email, increment=True) 
                    
                    status.update(label="تم تحليل وحل المسألة بنجاح! 🎉", state="complete", expanded=False)
                    
                except Exception as e:
                    status.update(label="حدث خطأ!", state="error")
                    st.error(f"حدث خطأ أثناء الاتصال بالنموذج: {e}")
                    
# -------------------- 7. الشريط الجانبي (Sidebar) والإعدادات --------------------

def sidebar_ui():
    """عرض معلومات المستخدم وأزرار تسجيل الخروج والروابط."""
    st.sidebar.image("https://placehold.co/100x100/1e40af/ffffff?text=Zaoujal", use_column_width=False)
    st.sidebar.title("منصة زواجل للرياضيات")
    
    if st.session_state.get('logged_in'):
        st.sidebar.markdown("---")
        st.sidebar.subheader("حالة المستخدم")
        
        email_display = st.session_state['user_email']
        st.sidebar.write(f"**البريد:** `{email_display}`")
        
        if st.session_state.get('is_premium'):
            st.sidebar.markdown("🔥 **وصول مميز (Premium)**")
        elif st.session_state.get('is_admin'):
            st.sidebar.markdown("👑 **مسؤول النظام (Admin)**")
        else:
             st.sidebar.markdown("👤 **وصول مجاني (Free)**")

        st.sidebar.caption(f"IP الحالي (للمراقبة): `{get_client_ip()}`")
             
        if st.sidebar.button("تسجيل الخروج", use_container_width=True):
            logout_user()
            
        st.sidebar.markdown("---")

    YOUTUBE_LINK = "https://www.youtube.com/@AhmadElTantawy"
    PROJECT_LINK = "#" 

    st.sidebar.header("تابعني!")
    st.sidebar.markdown(f"**🔗 مشروعي الإلكتروني:** [مشاهدة التطبيق]({PROJECT_LINK})")
    st.sidebar.markdown(f"**🎬 قناتي على يوتيوب:** [اشترك الآن]({YOUTUBE_LINK})")
    st.sidebar.caption("By Ahmad El-Tantawy")

# -------------------- 8. المنطق الرئيسي للتطبيق (Main) --------------------

if __name__ == "__main__":
    initialize_session_state()
    sidebar_ui()

    if st.session_state['logged_in']:
        is_admin = st.session_state.get('is_admin', False)

        if is_admin:
            admin_tab, app_tab = st.tabs(["لوحة التحكم (Admin)", "حل المسائل"])
            with admin_tab:
                admin_dashboard_ui() 
            with app_tab:
                main_app_ui()
        else:
            main_app_ui()
    else:
        st.header("أهلاً بك في منصة Math AI zaoujal")
        st.subheader(f"الرجاء تسجيل الدخول أو إنشاء حساب لاستخدام خدمة حل المسائل ({MAX_QUESTIONS_DAILY} أسئلة مجانية يومياً)")
        login_tab, register_tab = st.tabs(["تسجيل الدخول", "إنشاء حساب"])
        
        with login_tab:
            login_form()
        
        with register_tab:
            register_form()
