-- 1. สร้างตารางและเปิด RLS
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;

CREATE TABLE students (
    id VARCHAR(11) PRIMARY KEY,
    title VARCHAR(20),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(10),
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT
);
ALTER TABLE students ENABLE ROW LEVEL SECURITY;

CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(10) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;

CREATE TABLE progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER CHECK (unit BETWEEN 1 AND 5),
    done BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, unit)
);
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- 2. ฟังก์ชันตรวจสอบสิทธิ์ผู้สอน (Security Definer)
CREATE OR REPLACE FUNCTION is_teacher()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
$$;

-- 3. Trigger ตรวจสอบและผูกบัญชีนักศึกษา (ก่อน Insert เข้า auth.users)
CREATE OR REPLACE FUNCTION check_and_bind_student_account()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    extracted_id VARCHAR(11);
BEGIN
    -- ข้ามการตรวจสอบถ้าเป็นผู้สอน (ดูจากโดเมนอีเมล หรือถ้าไม่ได้ขึ้นต้นด้วยตัวเลข 11 หลัก)
    IF NEW.email NOT SIMILAR TO '[0-9]{11}@%' THEN
        RETURN NEW;
    END IF;

    extracted_id := split_part(NEW.email, '@', 1);

    -- ตรวจสอบว่ามีรายชื่อไหม และ user_id ยังว่างอยู่
    IF NOT EXISTS (SELECT 1 FROM students WHERE id = extracted_id AND user_id IS NULL) THEN
        RAISE EXCEPTION 'รหัสนักศึกษานี้ไม่มีในระบบ หรือลงทะเบียนไปแล้ว';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created_check
BEFORE INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION check_and_bind_student_account();

-- ผูก user_id กลับไปยังตาราง students หลังสร้าง auth.users สำเร็จ
CREATE OR REPLACE FUNCTION update_student_user_id()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    extracted_id VARCHAR(11);
BEGIN
    IF NEW.email SIMILAR TO '[0-9]{11}@%' THEN
        extracted_id := split_part(NEW.email, '@', 1);
        UPDATE students SET user_id = NEW.id WHERE id = extracted_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created_update
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION update_student_user_id();

-- 4. Trigger ป้องกันนักศึกษาแก้คะแนนตัวเอง
CREATE OR REPLACE FUNCTION prevent_student_grading()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF NOT is_teacher() THEN
        NEW.score = OLD.score;
        NEW.teacher_comment = OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER before_update_submissions
BEFORE UPDATE ON submissions
FOR EACH ROW EXECUTE FUNCTION prevent_student_grading();

-- 5. สร้าง View สำหรับสรุปผล (Security Invoker)
CREATE VIEW results WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
    pre.score AS pre_score, post.score AS post_score,
    (SELECT COUNT(*) FROM progress WHERE user_id = s.user_id AND done = true) AS units_done,
    sub.score AS submission_score
FROM students s
LEFT JOIN attempts pre ON s.user_id = pre.user_id AND pre.kind = 'pre'
LEFT JOIN attempts post ON s.user_id = post.user_id AND post.kind = 'post'
LEFT JOIN submissions sub ON s.user_id = sub.user_id;

-- 6. RLS Policies
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- Teachers Table
CREATE POLICY "Teachers can read all" ON teachers FOR SELECT TO authenticated USING (true);

-- Students Table
CREATE POLICY "Students read own, Teachers read all" ON students FOR SELECT TO authenticated
USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students update own photo" ON students FOR UPDATE TO authenticated
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid()); -- ป้องกันแก้คอลัมน์อื่นผ่าน UI, Trigger ป้องกันเพิ่มเติมระดับ API หากจำเป็น

-- Attempts Table
CREATE POLICY "Students read/insert own, Teachers read all" ON attempts FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students insert own attempts" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Progress Table
CREATE POLICY "Students read/insert/update own, Teachers read all" ON progress FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students insert own progress" ON progress FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Students update own progress" ON progress FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Submissions Table
CREATE POLICY "Students read own, Teachers read all" ON submissions FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students insert own submissions" ON submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Students update own submissions" ON submissions FOR UPDATE TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Teachers update any submissions" ON submissions FOR UPDATE TO authenticated USING (is_teacher());

-- Materials Table
CREATE POLICY "Anyone read materials" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teachers manage materials" ON materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- 7. Storage Setup และ Policies
INSERT INTO storage.buckets (id, name, public) VALUES 
('photos', 'photos', false),
('submissions', 'submissions', false),
('materials', 'materials', false)
ON CONFLICT (id) DO NOTHING;

-- Policies for Storage (ต้องใช้คำสั่งของ Supabase Storage)
-- เนื่องจากเป็นการรันใน SQL Editor ข้อจำกัด MIME type และ Size จะใช้เงื่อนไขตรวจสอบ

-- Photos: นศ.ใส่ได้เฉพาะโฟลเดอร์ตัวเอง ขนาดไม่เกิน 2MB รูปภาพเท่านั้น
CREATE POLICY "Photo read access" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND ((storage.foldername(name))[1] = auth.uid()::text OR is_teacher()));
CREATE POLICY "Photo insert access" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text AND (LOWER(storage.extension(name)) IN ('png', 'jpg', 'jpeg')) AND (COALESCE(metadata->>'size', '0')::bigint <= 2097152));
CREATE POLICY "Photo delete access" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);

-- Submissions: นศ.ใส่โฟลเดอร์ตัวเอง ไม่เกิน 20MB png, jpg, pdf, mp4
CREATE POLICY "Submission read access" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND ((storage.foldername(name))[1] = auth.uid()::text OR is_teacher()));
CREATE POLICY "Submission insert access" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text AND (LOWER(storage.extension(name)) IN ('png', 'jpg', 'jpeg', 'pdf', 'mp4')) AND (COALESCE(metadata->>'size', '0')::bigint <= 20971520));

-- Materials: ผู้สอนจัดการได้ทั้งหมด สื่อ <= 50MB (pptx, docx, pdf) นักศึกษาอ่านได้
CREATE POLICY "Materials read access" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Materials insert access" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'materials' AND is_teacher() AND (LOWER(storage.extension(name)) IN ('pptx', 'docx', 'pdf')) AND (COALESCE(metadata->>'size', '0')::bigint <= 52428800));
CREATE POLICY "Materials update/delete" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND is_teacher());

-- 8. เพิ่มข้อมูลจำลองนักศึกษา 6 คน
-- (สำหรับการนำเข้ารายชื่อจริง ให้ใช้ Table Editor ใน Supabase อัปโหลดไฟล์ CSV ที่มีคอลัมน์ id, title, first_name, last_name, section)
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('66000000001', 'นาย', 'สมชาย', 'เรียนดี', '01'),
('66000000002', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', '01'),
('66000000003', 'นาย', 'มานะ', 'อดทน', '02'),
('66000000004', 'นางสาว', 'มานี', 'มีใจ', '02'),
('66000000005', 'นาย', 'ปิติ', 'ยินดี', '01'),
('66000000006', 'นางสาว', 'ชูใจ', 'ร่าเริง', '02');

-- 9. ตั้งค่าผู้สอน (เมื่อเข้าสู่ระบบด้วยอีเมลสำเร็จ ให้ Copy UUID จากเมนู Authentication มาใส่แทน 'uuid_ของผู้สอน' แล้วรันคำสั่งนี้)
-- INSERT INTO teachers (user_id) VALUES ('uuid_ของผู้สอน');