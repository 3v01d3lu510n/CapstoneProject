import json
import os
import asyncio
import glob
import html
import shutil
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

logged_in = {}  # Login status
user_states = {} # Temporary state per chat id


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

async def require_login(update: Update) -> str:
    chat_id = str(update.effective_chat.id)
    for u, chats in logged_in.items():
        if chat_id in chats:
            return u, chat_id
    await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
    raise ApplicationHandlerStop

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
    # Delete account in registered_users
    if username in users:
        del users[username]
        save_registered_users(users)

    # Delete personal folder if exists
    user_folder = f"./users/{username}"
    if os.path.exists(user_folder):
        try:
            shutil.rmtree(user_folder)
        except Exception as e:
            await update.message.reply_text(f"❗ Lỗi khi xoá thư mục user: {e}")
            return

    # Delete login state of this username
    if username in logged_in:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]

    await update.message.reply_text("🗑 Tài khoản và thư mục đã được xoá. Muốn sử dụng lại, hãy đăng ký mới bằng /register.")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 
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

    # 🔁 Read user log file
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
                safe_created_time = html.escape(item.get("date", "Không rõ"))
                safe_sha1 = html.escape(item.get("Hash_SHA-1", "Không có"))
                safe_ext = html.escape(item.get("Extension", "Không có"))

                await update.message.reply_text(
                    f"<b>📄 Thông tin chi tiết:</b>\n"
                    f"- Tên file: {safe_base_name}\n"
                    f"- Đường dẫn lưu trong log: {safe_logged_path}\n"
                    f"- Ngày phát hiện: {safe_created_time}\n"
                    f"- SHA1: <code>{safe_sha1}</code>\n"
                    f"- Phần đuôi file: {safe_ext}",
                    parse_mode="HTML"
                )
                break

        if not found:
            await update.message.reply_text(f"❌ Không tìm thấy file {filename_query} trong {log_filename}.")
    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")

async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 

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
    username = await require_login(update) 

    # Read log index from command /check [index]
    idx = None
    if context.args:
        try:
            idx = int(context.args[0])
            if idx <= 0:
                raise ValueError
        except ValueError:
            await update.message.reply_text("❗ Tham số không hợp lệ. Ví dụ đúng: /check 1 hoặc chỉ /check.")
            return
        
    # Build path to user's log file
    folder_path = f"./users/{username}/logs"
    log_filename = f"scan_log_{idx}.json" if idx else "scan_log_1.json"
    log_path = os.path.join(folder_path, log_filename)

    if not os.path.exists(log_path):
        await update.message.reply_text(f"❗ Không tìm thấy file log: {log_filename}")
        return

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        # Extract scan results
        total_files = log.get("TotalFilesFound", 0)
        potential_webshells = log.get("PotentialWebshells", 0)
        not_webshell = log.get("NotWebshell", 0)
        total_ignored = log.get("TotalFilesIgnored", 0)
        scan_time = log.get("ScanTime", "N/A")

        webshells = log.get("WebshellPaths", [])
        ignored_paths = log.get("FilesIgnoredPath", [])

        # Build webshell details list
        details = ""
        for item in webshells:
            details += (
                f"📁 File: {item.get('path', 'Không rõ')}\n"
            )

        # Build ignored file list
        ignored_details = ""
        for i, path in enumerate(ignored_paths):
            ignored_details += f"{i+1}. {path}\n"

        # Send main report
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

        # Send ignored file list if exists
        if ignored_details:
            await update.message.reply_text(
                f"<b>🧾 Danh sách file bị bỏ qua:</b>\n<pre>{html.escape(ignored_details)}</pre>",
                parse_mode="HTML"
            )

        await update.message.reply_text("ℹ️ Dùng /check [số] để xem các bản log khác. Ví dụ: /check 2")

    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")

async def get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    username = await require_login(update) 

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
    sent_files = set()  # ✅ keep list of sent files

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

        # Handle registration flow
        if state["step"] == "ask_username_register":
            state["username"] = text
            state["step"] = "ask_password_register"
            await update.message.reply_text("🔒 Nhập mật khẩu:")

        elif state["step"] == "ask_password_register":
            state["password"] = text

            # Check duplicate username
            if state["username"] in users:
                await update.message.reply_text("❌ Username đã được sử dụng. Vui lòng thử username khác bằng lệnh /register.")
                del user_states[chat_id]
                return

            # Create folder structure for user
            folder_path = f"./users/{state['username']}"
            os.makedirs(folder_path, exist_ok=True)
            os.makedirs(os.path.join(folder_path, "logs"), exist_ok=True)
            os.makedirs(os.path.join(folder_path, "output"), exist_ok=True)

            # Save registration info
            users[state["username"]] = {
                "password": state["password"],
            }
            save_registered_users(users)

            await update.message.reply_text(f"✅ Đăng ký thành công! Xin chào {state['username']}.\nThư mục riêng: {state['username']}")
            del user_states[chat_id]

        # Handle login flow
        elif state["step"] == "ask_username_login":
            state["username"] = text
            state["step"] = "ask_password_login"
            await update.message.reply_text("🔒 Nhập mật khẩu:")

        elif state["step"] == "ask_password_login":
            state["password"] = text

            user = users.get(state["username"])
            if user and user["password"] == state["password"]:
                username = state["username"]
                logged_in.setdefault(username, set()).add(chat_id)

                # Ensure user folders exist
                user_log_dir = f"./users/{username}/logs"
                user_out_dir = f"./users/{username}/output"
                os.makedirs(user_log_dir, exist_ok=True)
                os.makedirs(user_out_dir, exist_ok=True)

                # Copy files from ./logs to ./users/{username}/logs
                if os.path.exists("./logs"):
                    for file in os.listdir("./logs"):
                        src = os.path.join("./logs", file)
                        dst = os.path.join(user_log_dir, file)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)

                # Copy files from ./output to ./users/{username}/output
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
        # Check if chat_id is already logged in
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
    await update.message.reply_text

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
