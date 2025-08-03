import json
import os
import datetime
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

# Create users directory if not exists
os.makedirs("./users", exist_ok=True)

logged_in = {}  # Login status: username ➔ set(chat_id)
user_states = {}  # Temporary state per chat_id

def load_registered_users():
    # Load registered users from JSON file
    if os.path.exists(REGISTER_FILE):
        try:
            with open(REGISTER_FILE) as f:
                content = f.read().strip()
                if not content:
                    return {}  # Empty file ➔ return empty dict
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[ERROR] Không thể đọc {REGISTER_FILE}: {e}")
            return {}
    return {}

def save_registered_users(users):
    # Save registered users to JSON file
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
    chat_id = str(update.effective_chat.id)
    username = None

    # Find the username that chat_id is logged into
    for u, chats in logged_in.items():
        if chat_id in chats:
            username = u
            break

    if username:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]
        await update.message.reply_text("🚪 Bạn đã đăng xuất thành công. Hẹn gặp lại!")
    else:
        await update.message.reply_text("❌ Bạn chưa đăng nhập hoặc đã đăng xuất rồi.")

async def forgot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    users = load_registered_users()

    # Find username from logged_in state
    username = None
    for u, chats in logged_in.items():
        if chat_id in chats:
            username = u
            break

    if username is None:
        await update.message.reply_text("❌ Bạn chưa đăng nhập hoặc chưa đăng ký, không có tài khoản để xóa.")
        return

    # Delete account from registered_users
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

    # Clear login state
    if username in logged_in:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:  # No one logged into this account
            del logged_in[username]

    await update.message.reply_text("🗑 Tài khoản và thư mục đã được xoá. Muốn sử dụng lại, hãy đăng ký mới bằng /register.")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)

    # Check if user is logged in
    if not any(chat_id in chats for chats in logged_in.values()):
        await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
        return

    idx = None
    filename_query = None

    # Parse arguments: index and filename
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

    log_filename = f"scan_log_{idx}.json" if idx else "scan_log.json"
    log_path = os.path.join("log", log_filename)

    if not os.path.exists(log_path):
        await update.message.reply_text(f"❗ Không tìm thấy file log {log_filename}.")
        return

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        webshells = log.get("WebshellPaths", [])
        found = False

        for item in webshells:
            base_name = os.path.basename(item.get("path", "")).lower()
            if filename_query == base_name:
                found = True
                safe_base_name = html.escape(base_name)
                safe_logged_path = html.escape(item.get("path", "Không rõ"))
                safe_created_time = html.escape(item.get("date", "Không rõ"))

                await update.message.reply_text(
                    f"<b>📄 Thông tin chi tiết:</b>\n"
                    f"- Tên file: {safe_base_name}\n"
                    f"- Đường dẫn lưu trong log: {safe_logged_path}\n"
                    f"- Ngày phát hiện: {safe_created_time}",
                    parse_mode="HTML"
                )
                break

        if not found:
            await update.message.reply_text(f"❌ Không tìm thấy file {filename_query} trong {log_filename}.")
    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")
async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)

    # Find the username corresponding to this chat_id
    username = None
    for u, chats in logged_in.items():
        if chat_id in chats:
            username = u
            break

    if username is None:
        await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
        return

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

        # Delete all log files in logs/ folder
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

        # Delete all .zip files in output/ folder
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

        # Final message if action is 'all'
        if action == "all":
            await update.message.reply_text(
                "🗑 Đã xoá tất cả file log và zip." if deleted_any else "ℹ️ Không có file log hoặc zip nào để xoá."
            )

        # Invalid action keyword
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
    chat_id = str(update.effective_chat.id)

    # Check login
    if not any(chat_id in chats for chats in logged_in.values()):
        await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
        return

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

    # Get username from chat_id
    username = None
    for user, chats in logged_in.items():
        if chat_id in chats:
            username = user
            break

    if not username:
        await update.message.reply_text("❌ Không xác định được username.")
        return

    # Build path to user’s log file
    folder_path = f"./users/{username}/logs"
    log_filename = f"scan_log_{idx}.json" if idx else "scan_log_1.json"
    log_path = os.path.join(folder_path, log_filename)

    if not os.path.exists(log_path):
        await update.message.reply_text(f"❗ Không tìm thấy file log: {log_filename}")
        return

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        # Extract data
        total_files = log.get("TotalFilesFound", 0)
        potential_webshells = log.get("PotentialWebshells", 0)
        not_webshell = log.get("NotWebshell", 0)
        total_ignored = log.get("TotalFilesIgnored", 0)
        scan_time = log.get("ScanTime", "N/A")

        webshells = log.get("WebshellPaths", [])
        ignored_paths = log.get("FilesIgnoredPath", [])

        # Webshell file details
        details = ""
        for item in webshells:
            details += (
                f"📁 File: {item.get('path', 'Không rõ')}\n"
                f"📅 Ngày phát hiện: {item.get('CreationDate', 'Không rõ')}\n"
                f"🧬 MD5: <code>{item.get('Hash_MD5', '')}</code>\n"
                f"🔑 SHA-1: <code>{item.get('Hash_SHA-1', '')}</code>\n"
                f"🧩 Phần đuôi file: {item.get('Extension', 'Không rõ')}\n\n"
            )

        # Ignored files
        ignored_details = ""
        for i, path in enumerate(ignored_paths):
            ignored_details += f"{i+1}. {path}\n"

        # Send report
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

        # Send ignored file list if available
        if ignored_details:
            await update.message.reply_text(
                f"<b>🧾 Danh sách file bị bỏ qua:</b>\n<pre>{html.escape(ignored_details)}</pre>",
                parse_mode="HTML"
            )

        await update.message.reply_text("ℹ️ Dùng /check [số] để xem các bản log khác. Ví dụ: /check 2")

    except Exception as e:
        await update.message.reply_text(f"❗ Đã xảy ra lỗi khi đọc file log: {e}")
async def get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    # Find username associated with chat_id
    username = None
    for u, chats in logged_in.items():
        if chat_id in chats:
            username = u
            break

    if username is None:
        await update.message.reply_text("❌ Bạn chưa đăng nhập. Gửi /login để đăng nhập trước.")
        return

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

async def poll_output_folders():
    print("[INFO] Bắt đầu kiểm tra định kỳ thư mục output...")
    checked_files = {}

    while True:
        try:
            await asyncio.sleep(5)
            for username, chat_ids in logged_in.items():
                folder_path = f"./users/{username}"
                output_path = os.path.join(folder_path, "output")
                os.makedirs(output_path, exist_ok=True)

                # Read scan time from log file, if exists
                log_path = os.path.join(folder_path, "scan_log.json")
                scan_time = ""
                if os.path.exists(log_path):
                    with open(log_path, "r") as f:
                        try:
                            log = json.load(f)
                            scan_time = log.get("ScanTime", "N/A")
                        except Exception as e:
                            print(f"[ERROR] Lỗi đọc log {log_path}: {e}")

                zip_files = glob.glob(os.path.join(output_path, "*.zip"))
                for zip_file in zip_files:
                    mtime = os.path.getmtime(zip_file)
                    if checked_files.get(zip_file) != mtime:
                        print(f"[ALERT] Phát hiện file mới cho username {username}: {zip_file}")
                        for chat_id in chat_ids:
                            try:
                                await app.bot.send_document(
                                    chat_id=chat_id,
                                    document=open(zip_file, "rb"),
                                    caption=f"🚨 Phát hiện webshell mới!\n🕒 Thời gian quét: {scan_time}"
                                )
                                checked_files[zip_file] = mtime
                            except Exception as e:
                                print(f"[ERROR] Gửi file cho chat {chat_id} thất bại: {e}")
        except Exception as e:
            print(f"[FATAL] Lỗi trong poll_output_folders: {e}")

async def setup_background_tasks(app):
    # Start background task after bot starts
    app.create_task(poll_output_folders())

async def error_handler(update, context):
    # Catch all errors and print to console
    try:
        raise context.error
    except TelegramError as e:
        print(f"[ERROR] Telegram error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error: {e}")
    raise ApplicationHandlerStop  # Stop processing faulty update

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    text = update.message.text.strip()
    users = load_registered_users()

    if chat_id in user_states:
        state = user_states[chat_id]

        # Handle registration steps
        if state["step"] == "ask_username_register":
            state["username"] = text
            state["step"] = "ask_password_register"
            await update.message.reply_text("🔒 Nhập mật khẩu:")

        elif state["step"] == "ask_password_register":
            state["password"] = text

            # Check if username already exists
            if state["username"] in users:
                await update.message.reply_text("❌ Username đã được sử dụng. Vui lòng thử username khác bằng lệnh /register.")
                del user_states[chat_id]
                return

            # Create user folder (no longer tied to chat_id)
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

        # Handle login steps
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

                # Create user directories if not already exist
                user_log_dir = f"./users/{username}/logs"
                user_out_dir = f"./users/{username}/output"
                os.makedirs(user_log_dir, exist_ok=True)
                os.makedirs(user_out_dir, exist_ok=True)

                import shutil

                # Copy all files from ./logs to ./users/{username}/logs
                if os.path.exists("./logs"):
                    for file in os.listdir("./logs"):
                        src = os.path.join("./logs", file)
                        dst = os.path.join(user_log_dir, file)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)

                # Copy all files from ./output to ./users/{username}/output
                if os.path.exists("./output"):
                    for file in os.listdir("./output"):
                        src = os.path.join("./output", file)
                        dst = os.path.join(user_out_dir, file)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)

                await update.message.reply_text(f"✅ Đăng nhập thành công! Xin chào {username}.")
                await update.message.reply_text("✅ Bạn đã đăng nhập rồi! Gửi /menu để xem các lệnh hỗ trợ.")
            else:
                await update.message.reply_text("❌ Sai username hoặc mật khẩu. Vui lòng thử lại.")

            del user_states[chat_id]
    else:
        # If chat_id is already logged in with any account
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
    # Display help menu
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
    # Main entry to start the bot
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.post_init = setup_background_tasks  # Run after bot startup
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
    app.run_polling()

if __name__ == '__main__':
    run_bot()
