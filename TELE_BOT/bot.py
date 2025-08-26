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

logged_in = {}  # Login status
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
            print(f"[ERROR] Cannot read {REGISTER_FILE}: {e}")
            return {}
    return {}

def hash_password(password: str, method: str = "sha256") -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, hashed: str, method: str = "sha256") -> bool:
    return hash_password(password, method) == hashed

async def require_login(update: Update) -> str:
    chat_id = str(update.effective_chat.id)
    for u, chats in logged_in.items():
        if chat_id in chats:
            return u
    await update.message.reply_text("❌ You are not logged in. Send /login to log in first.")
    raise ApplicationHandlerStop

async def switch_login(username: str, chat_id: str):
    username = str(username)
    chat_id = str(chat_id)

    old_user = session_by_chat.get(chat_id)
    if old_user == username:
        return False, old_user
    
    # remove chat_id from old user
    if old_user and old_user in logged_in:
        logged_in[old_user].discard(chat_id)
        if not logged_in[old_user]:
            del logged_in[old_user]

    # assign new user
    session_by_chat[chat_id] = username
    logged_in.setdefault(username, set()).add(chat_id)
    return True, old_user


def save_registered_users(users):
    with open(REGISTER_FILE, 'w') as f:
        json.dump(users, f, indent=2)

async def register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    user_states[chat_id] = {"step": "ask_username_register"}
    await update.message.reply_text("📝 Please enter a username to register:")

async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    user_states[chat_id] = {"step": "ask_username_login"}
    await update.message.reply_text("🔑 Please enter username to log in:")

async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    username = await require_login(update) 
    chat_id = str(update.effective_chat.id)

    if username:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]
        await update.message.reply_text("🚪 You have successfully logged out. See you again!")
    else:
        await update.message.reply_text("❌ You are not logged in or already logged out.")

async def forgot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 
    chat_id = str(update.effective_chat.id)
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
            await update.message.reply_text(f"❗ Error when deleting user folder: {e}")
            return

    # Remove login state of this username
    if username in logged_in:
        logged_in[username].discard(chat_id)
        if not logged_in[username]:
            del logged_in[username]

    await update.message.reply_text("🗑 Account and folder deleted. To use again, register new with /register.")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 
    idx = None
    filename_query = None

    if context.args:
        if context.args[0].isdigit():
            idx = int(context.args[0])
            if idx <= 0 or len(context.args) < 2:
                await update.message.reply_text("❗ Correct example: /info 1 filename.php.")
                return
            filename_query = " ".join(context.args[1:]).lower().strip()
        else:
            filename_query = " ".join(context.args).lower().strip()
    else:
        await update.message.reply_text("❗ Correct usage: /info [log number] <filename>")
        return

    # 🔁 Read user's log file
    folder_path = f"./users/{username}/logs"
    log_filename = f"scan_log_{idx}.json" if idx else "scan_log_1.json"
    log_path = os.path.join(folder_path, log_filename)

    if not os.path.exists(log_path):
        await update.message.reply_text(f"❗ Log file {log_filename} not found.")
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
                safe_logged_path = html.escape(item.get("path", "Unknown"))
                safe_sha1 = html.escape(item.get("Hash_SHA-1", "Not available"))
                safe_ext = html.escape(item.get("Extension", "Not available"))

                await update.message.reply_text(
                    f"<b>📄 Detailed information:</b>\n"
                    f"• 📝 <b>Filename:</b> {safe_base_name}\n"
                    f"• 📂 <b>Path:</b> {safe_logged_path}\n"
                    f"• 🔑 <b>SHA1:</b> <code>{safe_sha1}</code>\n"
                    f"• 📎 <b>Extension:</b> {safe_ext}",
                    parse_mode="HTML"
                )
                break

        if not found:
            await update.message.reply_text(f"❌ File {filename_query} not found in {log_filename}.")
    except Exception as e:
        await update.message.reply_text(f"❗ Error reading log file: {e}")

async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 

    args = context.args
    if not args:
        await update.message.reply_text(
            "❗ Correct usage:\n"
            "/delete log - Delete all log files in logs folder\n"
            "/delete zip - Delete all zip files in output folder\n"
            "/delete all - Delete all log and zip files"
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
                    "🗑 Deleted all files in logs folder." if deleted_any else "ℹ️ No files to delete in logs folder."
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
                    "🗑 Deleted all zip files in output folder." if deleted_any else "ℹ️ No zip files to delete in output folder."
                )

        if action == "all":
            await update.message.reply_text(
                "🗑 Deleted all log and zip files." if deleted_any else "ℹ️ No log or zip files to delete."
            )

        if action not in ("scanlog", "log", "zip", "all"):
            await update.message.reply_text(
                "❗ Invalid delete type. Use:\n"
                "/delete log - Delete all in logs\n"
                "/delete zip - Delete zip in output\n"
                "/delete all - Delete all log and zip files"
            )

    except Exception as e:
        await update.message.reply_text(f"❗ Error deleting: {e}")

async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = await require_login(update) 

    log_dir = f"./users/{username}/logs"
    if not os.path.exists(log_dir):
        await update.message.reply_text("❗ Log folder does not exist.")
        return

    log_files = sorted(
        [f for f in os.listdir(log_dir) if f.startswith("scan_log_") and f.endswith(".json")]
    )

    if not log_files:
        await update.message.reply_text("ℹ️ No logs in folder.")
        return

    # If parameter provided → read specific log
    if context.args:
        try:
            idx = int(context.args[0])
            if idx <= 0 or idx > len(log_files):
                raise ValueError
        except ValueError:
            await update.message.reply_text("❗ Invalid parameter. Example: /check 1")
            return

        log_filename = log_files[idx-1]
        log_path = os.path.join(log_dir, log_filename)

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

            details = "".join(f"📁 File: {item.get('path','Unknown')}\n" for item in webshells)
            ignored_details = "".join(f"{i+1}. {path}\n" for i, path in enumerate(ignored_paths))

            await update.message.reply_text(
                f"<b>📝 Scan results from {html.escape(log_filename)}:</b>\n"
                f"- 🧾 Total files scanned: {total_files}\n"
                f"- ❗ Suspicious webshells: {potential_webshells}\n"
                f"- ✅ Clean files: {not_webshell}\n"
                f"- 🚫 Unreadable files: {total_ignored}\n"
                f"- 🕒 Scan time: {html.escape(scan_time)}\n\n"
                f"<b>📂 Webshell list:</b>\n<pre>{html.escape(details) or 'None'}</pre>",
                parse_mode="HTML"
            )

            if ignored_details:
                await update.message.reply_text(
                    f"<b>🧾 Ignored files list:</b>\n<pre>{html.escape(ignored_details)}</pre>",
                    parse_mode="HTML"
                )
        except Exception as e:
            await update.message.reply_text(f"❗ Error reading log file: {e}")

    else:
        # If no parameter → only list available logs
        list_text = "\n".join(f"{i+1}. {fname}" for i, fname in enumerate(log_files))
        await update.message.reply_text(
            f"<b>📂 Existing logs ({len(log_files)} files):</b>\n<pre>{html.escape(list_text)}</pre>\n\n"
            f"ℹ️ Use /check [number] to view detailed log. Example: /check 2",
            parse_mode="HTML"
        )

async def get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    username = await require_login(update) 

    folder_path = f"./users/{username}/output"
    zip_files = glob.glob(os.path.join(folder_path, "*.zip"))

    if not zip_files:
        await update.message.reply_text("❗ No scan result zip files found.")
        return

    for zip_file in zip_files:
        try:
            await update.message.reply_document(
                document=open(zip_file, "rb"),
                caption=f"📦 Scan result: {os.path.basename(zip_file)}"
            )
        except Exception as e:
            await update.message.reply_text(f"❗ Error sending file {os.path.basename(zip_file)}: {e}")

async def alert(app):
    print("[INFO] Start periodic check of output folder...")
    sent_files = set()

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
                                    caption="🚨 New webshell detected!",
                                    read_timeout=120,  
                                    write_timeout=120 
                                )

                            print(f"[INFO] Sent file: {zip_file}")
                            sent_files.add(zip_file) 
                            break 
                        except asyncio.TimeoutError:
                            print(f"[ERROR] Sending file {zip_file} failed: Timeout")
                        except Exception as e:
                            print(f"[ERROR] Sending file {zip_file} failed: {e}")
        except Exception as e:
            print(f"[FATAL] Error in alert: {e}")


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

        # Handle registration
        if state["step"] == "ask_username_register":
            state["username"] = text
            state["step"] = "ask_password_register"
            await update.message.reply_text("🔒 Enter password:")

        elif state["step"] == "ask_password_register":
            state["password"] = text

            # Check duplicate username
            if state["username"] in users:
                await update.message.reply_text("❌ Username already taken. Please try another username with /register.")
                del user_states[chat_id]
                return

            # Create folder by username 
            folder_path = f"./users/{state['username']}"
            os.makedirs(folder_path, exist_ok=True)
            os.makedirs(os.path.join(folder_path, "logs"), exist_ok=True)
            os.makedirs(os.path.join(folder_path, "output"), exist_ok=True)

            # Save registration info
            users[state["username"]] = {
                "password": hash_password(state["password"])
            }
            save_registered_users(users)

            await update.message.reply_text(f"✅ Registration successful! Welcome {state['username']}.\nYour private folder: {state['username']}")
            del user_states[chat_id]

        # Handle login
        elif state["step"] == "ask_username_login":
            state["username"] = text
            state["step"] = "ask_password_login"
            await update.message.reply_text("🔒 Enter password:")

        elif state["step"] == "ask_password_login":
            state["password"] = text

            user = users.get(state["username"])
            if user and verify_password(state["password"], user["password"]):
                username = state["username"]
                await switch_login(username, chat_id)
                logged_in.setdefault(username, set()).add(chat_id)

                # Create user folder if not exist
                user_log_dir = f"./users/{username}/logs"
                user_out_dir = f"./users/{username}/output"
                os.makedirs(user_log_dir, exist_ok=True)
                os.makedirs(user_out_dir, exist_ok=True)

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
                            os.utime(dst, None)

                await update.message.reply_text(f"✅ Login successful! Welcome {username}.")
                await update.message.reply_text("✅ You are already logged in! Send /menu to view supported commands.")
            else:
                await update.message.reply_text("❌ Wrong username or password. Please try again.")

            del user_states[chat_id]
    else:
        # Check if chat_id already logged in via any username
        found = False
        for chats in logged_in.values():
            if chat_id in chats:
                found = True
                break

        if found:
            await update.message.reply_text("✅ You are already logged in! Send /menu to view supported commands.")
        else:
            await update.message.reply_text("🤖 Send /register or /login to get started.")


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await require_login(update) 
    message = (
        "<b>📋 Supported commands list:</b>\n\n"
        "• 🗂 <b>/menu</b> – Show menu\n"
        "• 📊 <b>/check</b> – Show basic scan information\n"
        "• 📦 <b>/get</b> – Send zip file containing scan results\n"
        "• ℹ️ <b>/info</b> <code>&lt;filename&gt;</code> – Show detailed webshell info from log file\n"
        "• 🗑 <b>/delete</b> – Delete log or zip file\n"
        "• 🚪 <b>/logout</b> – Log out from current account\n"
        "• ❌ <b>/forgot</b> – Delete current account information"
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

    print("🤖 Bot is running with polling (v20+)...")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':    run_bot()

