import json
import os
import asyncio
import glob
import html
import shutil
import hashlib
from telegram.error import TelegramError
from telegram.ext import ApplicationHandlerStop
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

BOT_TOKEN = 'YOUR_BOT_TOKEN'

REGISTER_FILE = 'registered_users.json'

os.makedirs("./users", exist_ok=True)

logged_in = {}  # Trạng thái đăng nhập
user_states = {} # {chat_id: state}
session_by_chat = {} # {chat_id: username}

def load_registered_users():
    if os.path.exists(REGISTER_FILE):
        try:
            with open(REGISTER_FILE) as f:
                content = f.read().strip()
                if not content:
                    return {}  
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[ERROR] Không thể đọc {REGISTER_FILE}: {e}")
            return {}
    return {}

def hash_password(password: str, method: str = "sha256") -> str:
    if method == "sha1":
        return hashlib.sha1(password.encode("utf-8")).hexdigest()
    elif method == "sha256":
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    else:
        raise ValueError("Unsupported hash method")

def verify_password(password: str, hashed: str, method: str = "sha256") -> bool:
    return hash_password(password, method) == hashed

async def require_login(update: Update) -> str:
    chat_id = str(update.effective_chat.id)
    for u, chats in logged_in.items():
        if chat_id in chats:
            return u, chat_id
    await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
    raise ApplicationHandlerStop

async def switch_login(username: str, chat_id: str):
    username = str(username)
    chat_id = str(chat_id)

    old_user = session_by_chat.get(chat_id)
    if old_user == username:
        return False, old_user
    
    # gỡ chat_id khỏi user cũ
    if old_user and old_user in logged_in:
        logged_in[old_user].discard(chat_id)
        if not logged_in[old_user]:
            del logged_in[old_user]

    # gán user mới
    session_by_chat[chat_id] = username
    logged_in.setdefault(username, set()).add(chat_id)
    return True, old_user


def save_registered_users(users):
    with open(REGISTER_FILE, 'w') as f:
        json.dump(users, f, indent=2)

async def register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    user_states[chat_id] = {"step": "ask_username_register"}
    await update.message.reply_text("📝 Vui lòng nhập tên đăng ký:")

async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    user_states[chat_id] = {"step": "ask_username_login"}
    await update.message.reply_text("🔑 Vui lòng nhập username để đăng nhập:")

async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    username, chat_id = await require_login(update) 
    if username:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]
        await update.message.reply_text("🚪 Bạn đã đăng xuất thành công. Hẹn gặp lại!")
    else:
        await update.message.reply_text("❌ Bạn chưa đăng nhập hoặc đã đăng xuất rồi.")

async def forgot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username, chat_id = await require_login(update) 
    users = load_registered_users()
    # Xoá tài khoản trong registered_users
    if username in users:
        del users[username]
        save_registered_users(users)

    # Xoá thư mục cá nhân nếu có
    user_folder = f"./users/{username}"
    if os.path.exists(user_folder):
        try:
            shutil.rmtree(user_folder)
        except Exception as e:
            await update.message.reply_text(f"❗ Lỗi khi xoá thư mục user: {e}")
            return

    # Xoá trạng thái đăng nhập của username này
    if username in logged_in:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]

    await update.message.reply_text("🗑 Tài khoản và thư mục đã được xoá. Muốn sử dụng lại, hãy đăng ký mới bằng /register.")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username, chat_id = await require_login(update) 
    idx = None
    filename_query = None

    if context.args:
        if context.args[0].isdigit():
            idx = int(context.args[0])
            if idx <= 0 or len(context.args) < 2:
                await update.message.reply_text("❗ Ví dụ đúng: /info 1 tenfile.php.")
                return
            filename_query = " ".join(context.args[1:]).lower().strip()
        else:
            filename_query = " ".join(context.args).lower().strip()
    else:
        await update.message.reply_text("❗ Sử dụng đúng cú pháp: /info [số thứ tự log] <tên file>")
        return

    # 🔁 Đọc file log của người dùng
    folder_path = f"./users/{username}/logs"
    log_filename = f"scan_log_{idx}.json" if idx else "scan_log_1.json"
    log_path = os.path.join(folder_path, log_filename)

    if not os.path.exists(log_path):
        await update.message.reply_text(f"❗ Không tìm thấy file log {log_filename}.")
        return

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        all_files = log.get("WebshellPaths", []) + log.get("NotWebshellPaths", [])
        found = False

        for item in all_files:
            base_name = os.path.basename(item.get("path", "")).lower()
            if filename_query == base_name:
                found = True
                safe_base_name = html.escape(base_name)
                safe_logged_path = html.escape(item.get("path", "Không rõ"))
                safe_sha1 = html.escape(item.get("Hash_SHA-1", "Không có"))
                safe_ext = html.escape(item.get("Extension", "Không có"))

                await update.message.reply_text(
                    f"<b>📄 Thông tin chi tiết:</b>\n"
                    f"• 📝 <b>Tên file:</b> {safe_base_name}\n"
                    f"• 📂 <b>Đường dẫn:</b> {safe_logged_path}\n"
                    f"• 🔑 <b>SHA1:</b> <code>{safe_sha1}</code>\n"
                    f"• 📎 <b>Đuôi file:</b> {safe_ext}",
                    parse_mode="HTML"
                )
                break

        if not found:
            await update.message.reply_text(f"❌ Không tìm thấy file {filename_query} trong {log_filename}.")
    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")

async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username, chat_id = await require_login(update) 

    args = context.args
    if not args:
        await update.message.reply_text(
            "❗ Sử dụng đúng cú pháp:\n"
            "/delete log - Xoá tất cả file log trong thư mục logs\n"
            "/delete zip - Xoá tất cả file zip trong thư mục output\n"
            "/delete all - Xoá tất cả file log và zip"
        )
        return

    action = args[0].lower()
    folder_path = f"./users/{username}"

    try:
        deleted_any = False

        if action in ("log", "all"):
            logs_path = os.path.join(folder_path, "logs")
            if os.path.exists(logs_path):
                for f in os.listdir(logs_path):
                    file_path = os.path.join(logs_path, f)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        deleted_any = True
            if action == "log":
                await update.message.reply_text(
                    "🗑 Đã xoá tất cả file trong thư mục logs." if deleted_any else "ℹ️ Không có file nào trong thư mục logs để xoá."
                )

        if action in ("zip", "all"):
            output_path = os.path.join(folder_path, "output")
            if os.path.exists(output_path):
                for f in os.listdir(output_path):
                    if f.endswith(".zip"):
                        file_path = os.path.join(output_path, f)
                        os.remove(file_path)
                        deleted_any = True
            if action == "zip":
                await update.message.reply_text(
                    "🗑 Đã xoá tất cả file zip trong thư mục output." if deleted_any else "ℹ️ Không có file zip nào trong thư mục output để xoá."
                )

        if action == "all":
            await update.message.reply_text(
                "🗑 Đã xoá tất cả file log và zip." if deleted_any else "ℹ️ Không có file log hoặc zip nào để xoá."
            )

        if action not in ("scanlog", "log", "zip", "all"):
            await update.message.reply_text(
                "❗ Loại cần xoá không hợp lệ. Dùng:\n"
                "/delete log - Xoá tất cả file trong logs\n"
                "/delete zip - Xoá file zip trong output\n"
                "/delete all - Xoá tất cả file log và zip"
            )

    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi xoá: {e}")

async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username, chat_id = await require_login(update) 

    log_dir = f"./users/{username}/logs"
    if not os.path.exists(log_dir):
        await update.message.reply_text("❗ Thư mục log chưa tồn tại.")
        return

    log_files = sorted(
        [f for f in os.listdir(log_dir) if f.startswith("scan_log_") and f.endswith(".json")]
    )

    if not log_files:
        await update.message.reply_text("ℹ️ Không có log nào trong thư mục.")
        return

    # Nếu có tham số → đọc log cụ thể
    if context.args:
        try:
            idx = int(context.args[0])
            if idx <= 0 or idx > len(log_files):
                raise ValueError
        except ValueError:
            await update.message.reply_text("❗ Tham số không hợp lệ. Ví dụ: /check 1")
            return

        log_filename = log_files[idx-1]
        log_path = os.path.join(log_dir, log_filename)

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                log = json.load(f)

            # Trích xuất dữ liệu
            total_files = log.get("TotalFilesFound", 0)
            potential_webshells = log.get("PotentialWebshells", 0)
            not_webshell = log.get("NotWebshell", 0)
            total_ignored = log.get("TotalFilesIgnored", 0)
            scan_time = log.get("ScanTime", "N/A")

            webshells = log.get("WebshellPaths", [])
            ignored_paths = log.get("FilesIgnoredPath", [])

            details = "".join(f"📁 File: {item.get('path','Không rõ')}\n" for item in webshells)
            ignored_details = "".join(f"{i+1}. {path}\n" for i, path in enumerate(ignored_paths))

            await update.message.reply_text(
                f"<b>📝 Kết quả quét từ {html.escape(log_filename)}:</b>\n"
                f"- 🧾 Tổng số file đã quét: {total_files}\n"
                f"- ❗ Webshell nghi ngờ: {potential_webshells}\n"
                f"- ✅ File sạch: {not_webshell}\n"
                f"- 🚫 File không đọc được: {total_ignored}\n"
                f"- 🕒 Thời gian quét: {html.escape(scan_time)}\n\n"
                f"<b>📂 Danh sách Webshell:</b>\n<pre>{html.escape(details) or 'Không có'}</pre>",
                parse_mode="HTML"
            )

            if ignored_details:
                await update.message.reply_text(
                    f"<b>🧾 Danh sách file bị bỏ qua:</b>\n<pre>{html.escape(ignored_details)}</pre>",
                    parse_mode="HTML"
                )
        except Exception as e:
            await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")

    else:
        # Nếu không có tham số → chỉ liệt kê danh sách log
        list_text = "\n".join(f"{i+1}. {fname}" for i, fname in enumerate(log_files))
        await update.message.reply_text(
            f"<b>📂 Danh sách log hiện có ({len(log_files)} file):</b>\n<pre>{html.escape(list_text)}</pre>\n\n"
            f"ℹ️ Dùng /check [số] để xem chi tiết log. Ví dụ: /check 2",
            parse_mode="HTML"
        )

async def get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    username, chat_id = await require_login(update) 

    folder_path = f"./users/{username}/output"
    zip_files = glob.glob(os.path.join(folder_path, "*.zip"))

    if not zip_files:
        await update.message.reply_text("❗ Không tìm thấy file zip kết quả quét.")
        return

    for zip_file in zip_files:
        try:
            await update.message.reply_document(
                document=open(zip_file, "rb"),
                caption=f"📦 Kết quả quét: {os.path.basename(zip_file)}"
            )
        except Exception as e:
            await update.message.reply_text(f"❗ Lỗi khi gửi file {os.path.basename(zip_file)}: {e}")

async def alert(app):
    print("[INFO] Bắt đầu kiểm tra định kỳ thư mục output...")
    sent_files = set()  # ✅ giữ danh sách file đã gửi

    while True:
        try:
            await asyncio.sleep(5)

            for username, chat_ids in logged_in.items():
                output_path = os.path.join(f"./users/{username}", "output")
                os.makedirs(output_path, exist_ok=True)

                zip_files = glob.glob(os.path.join(output_path, "*.zip"))
                for zip_file in zip_files:
                    if zip_file in sent_files:
                        continue  

                    for chat_id in chat_ids:
                        try:
                            with open(zip_file, "rb") as f:
                                await app.bot.send_document(
                                    chat_id=chat_id,
                                    document=f,
                                    caption="🚨 Phát hiện webshell mới!",
                                    read_timeout=120,  
                                    write_timeout=120 
                                )

                            print(f"[INFO] Đã gửi file: {zip_file}")
                            sent_files.add(zip_file) 
                            break 
                        except asyncio.TimeoutError:
                            print(f"[ERROR] Gửi file {zip_file} thất bại: Timeout")
                        except Exception as e:
                            print(f"[ERROR] Gửi file {zip_file} thất bại: {e}")
        except Exception as e:
            print(f"[FATAL] Lỗi trong alert: {e}")


async def setup_background_tasks(app):
    app.create_task(alert(app))

async def error_handler(update, context):
    try:
        raise context.error
    except TelegramError as e:
        print(f"[ERROR] Telegram error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error: {e}")
    raise ApplicationHandlerStop

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    text = update.message.text.strip()
    users = load_registered_users()

    if chat_id in user_states:
        state = user_states[chat_id]

        # Xử lý đăng ký
        if state["step"] == "ask_username_register":
            state["username"] = text
            state["step"] = "ask_password_register"
            await update.message.reply_text("🔒 Nhập mật khẩu:")

        elif state["step"] == "ask_password_register":
            state["password"] = text

            # Kiểm tra username trùng
            if state["username"] in users:
                await update.message.reply_text("❌ Username đã được sử dụng. Vui lòng thử username khác bằng lệnh /register.")
                del user_states[chat_id]
                return

            # Tạo thư mục theo username 
            folder_path = f"./users/{state['username']}"
            os.makedirs(folder_path, exist_ok=True)
            os.makedirs(os.path.join(folder_path, "logs"), exist_ok=True)
            os.makedirs(os.path.join(folder_path, "output"), exist_ok=True)

            # Ghi thông tin đăng ký
            users[state["username"]] = {
                "password": hash_password(state["password"])
            }
            save_registered_users(users)

            await update.message.reply_text(f"✅ Đăng ký thành công! Xin chào {state['username']}.\nThư mục riêng: {state['username']}")
            del user_states[chat_id]

        # Xử lý đăng nhập
        elif state["step"] == "ask_username_login":
            state["username"] = text
            state["step"] = "ask_password_login"
            await update.message.reply_text("🔒 Nhập mật khẩu:")

        elif state["step"] == "ask_password_login":
            state["password"] = text

            user = users.get(state["username"])
            if user and verify_password(state["password"], user["password"]):
                username = state["username"]
                await switch_login(username, chat_id)
                logged_in.setdefault(username, set()).add(chat_id)

                # Tạo thư mục người dùng nếu chưa có
                user_log_dir = f"./users/{username}/logs"
                user_out_dir = f"./users/{username}/output"
                os.makedirs(user_log_dir, exist_ok=True)
                os.makedirs(user_out_dir, exist_ok=True)

                # Copy tất cả file từ ./logs vào ./users/{username}/logs
                if os.path.exists("./logs"):
                    for file in os.listdir("./logs"):
                        src = os.path.join("./logs", file)
                        dst = os.path.join(user_log_dir, file)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)

                # Copy tất cả file từ ./output vào ./users/{username}/output
                if os.path.exists("./output"):
                    for file in os.listdir("./output"):
                        src = os.path.join("./output", file)
                        dst = os.path.join(user_out_dir, file)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
                            os.utime(dst, None)

                await update.message.reply_text(f"✅ Đăng nhập thành công! Xin chào {username}.")
                await update.message.reply_text("✅ Bạn đã đăng nhập rồi! Gửi /menu để xem các lệnh hỗ trợ.")
            else:
                await update.message.reply_text("❌ Sai username hoặc mật khẩu. Vui lòng thử lại.")

            del user_states[chat_id]
    else:
        # Kiểm tra chat_id đã đăng nhập qua bất kỳ username nào
        found = False
        for chats in logged_in.values():
            if chat_id in chats:
                found = True
                break

        if found:
            await update.message.reply_text("✅ Bạn đã đăng nhập rồi! Gửi /menu để xem các lệnh hỗ trợ.")
        else:
            await update.message.reply_text("🤖 Gửi /register hoặc /login để bắt đầu.")

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await require_login(update) 
    message = (
        "<b>📋 Danh sách lệnh hỗ trợ:</b>\n\n"
        "/menu - Hiển thị menu\n"
        "/check - Hiển thị thông tin quét cơ bản\n"
        "/get - Gửi file zip chứa kết quả quét\n"
        "/info &lt;tên file&gt; - Hiển thị thông tin chi tiết webshell theo file log\n"
        "/delete - Xóa file log hoặc zip\n"
        "/logout - Đăng xuất khỏi tài khoản hiện tại\n"
        "/forgot - Xóa thông tin của tài khoản hiện tại"
    )
    await update.message.reply_text(message, parse_mode="HTML")

def run_bot():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.post_init = setup_background_tasks 
    app.add_error_handler(error_handler)
    app.add_handler(CommandHandler("register", register))
    app.add_handler(CommandHandler("login", login))
    app.add_handler(CommandHandler("forgot", forgot))
    app.add_handler(CommandHandler("check", check))
    app.add_handler(CommandHandler("logout", logout))
    app.add_handler(CommandHandler("menu", menu))
    app.add_handler(CommandHandler("get", get))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(CommandHandler("delete", delete))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))

    print("🤖 Bot đang chạy polling (v20+)...")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    run_bot()
