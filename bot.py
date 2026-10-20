import os
import re
import io
import tempfile
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)
from androguard.misc import AnalyzeDEX

# Aapka Telegram Bot Token
BOT_TOKEN = "8984636537:AAFbsVoQu5eXaner1CKxnUqnEBc1ZOJQu84"

# Available Category Tags ki list
VALID_CATEGORIES = [
    "NETWORK_URL",
    "API_ENDPOINT",
    "SHARED_PREF",
    "PERMISSION",
    "DATABASE_SQL",
    "CRYPTO_SECURITY",
    "INTENT_ACTION",
    "FILE_PATH",
    "FILE_ASSET",
    "JSON_KEY",
    "BUNDLE_KEY",
    "NETWORK_HEADER",
    "LOG_DEBUG",
    "CONFIG_KEY",
    "CLASS_DESCRIPTOR",
    "UI_OR_CONST",
]

def classify_string(val: str, xrefs: list) -> str:
    """String ki value aur uske usage location (XREF) ke basis par 1-word tag return karta hai."""
    v = val.strip()
    v_lower = v.lower()

    xref_context = " ".join(
        [f"{m.class_name} {m.name}".lower() for _, m in xrefs[:5]]
    )

    # 1. Value-based classification
    if v_lower.startswith(("http://", "https://", "ws://", "wss://")):
        return "NETWORK_URL"
    if re.match(r"^/[a-zA-Z0-9_\-\/]+$", v) and len(v) > 3:
        if any(ext in v_lower for ext in (".so", ".dex", ".xml", ".json", "/sdcard", "/data/")):
            return "FILE_PATH"
        return "API_ENDPOINT"
    if v.startswith("android.permission.") or "PERMISSION" in v:
        return "PERMISSION"
    if v.startswith(("android.intent.", "com.google.android.c2dm")):
        return "INTENT_ACTION"
    if any(sql in v.upper() for sql in ("SELECT ", "INSERT INTO ", "CREATE TABLE ", "UPDATE ", "DELETE FROM ")):
        return "DATABASE_SQL"
    if any(alg in v.upper() for alg in ("AES/", "RSA/", "HMAC", "SHA-256", "SHA1", "PBKDF2")):
        return "CRYPTO_SECURITY"
    if v_lower.endswith((".json", ".xml", ".db", ".sqlite", ".so", ".png", ".properties")):
        return "FILE_ASSET"
    if v.startswith("L") and v.endswith(";") and "/" in v:
        return "CLASS_DESCRIPTOR"

    # 2. XREF Context-based classification
    if "sharedpreferences" in xref_context or "getboolean" in xref_context or "getstring" in xref_context:
        return "SHARED_PREF"
    if "android/util/log" in xref_context or "println" in xref_context:
        return "LOG_DEBUG"
    if "jsonobject" in xref_context or "gson" in xref_context:
        return "JSON_KEY"
    if "intent" in xref_context or "bundle" in xref_context:
        return "BUNDLE_KEY"
    if "http" in xref_context or "retrofit" in xref_context or "okhttp" in xref_context:
        return "NETWORK_HEADER"

    # 3. Fallback pattern check
    if re.match(r"^[a-z0-9_.\-]+$", v) and ("_" in v or "." in v):
        return "CONFIG_KEY"

    return "UI_OR_CONST"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 **DEX Static Analyzer & Smart String Tagger Bot**\n\n"
        "1️⃣ Sabse pehle koi bhi `classes.dex` file upload karein.\n"
        "2️⃣ Keyword dhoondhne ke liye: `/search <keyword>`\n"
        "3️⃣ Specific category filter karne ke liye: `/category <TAG_NAME>`\n"
        "   (Saare tags dekhne ke liye sirf `/category` likhein)",
        parse_mode="Markdown",
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document

    if not document.file_name.endswith(".dex"):
        await update.message.reply_text("Kripya sirf `.dex` extension wali file upload karein.")
        return

    if document.file_size > 20 * 1024 * 1024:
        await update.message.reply_text("File size 20 MB se zyada hai. Chhoti DEX file bhejein.")
        return

    status_msg = await update.message.reply_text(
        "⏳ File download aur cross-reference (XREF) index taiyar ho raha hai, kripya wait karein..."
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".dex") as tmp_file:
        temp_path = tmp_file.name

    try:
        tg_file = await context.bot.get_file(document.file_id)
        await tg_file.download_to_drive(temp_path)

        sha256, d, dx = AnalyzeDEX(temp_path)

        context.user_data["dx"] = dx
        context.user_data["file_name"] = document.file_name

        report = (
            f"✅ **DEX File Indexed Successfully!**\n\n"
            f"• **File:** `{document.file_name}`\n"
            f"• **Classes:** `{len(list(dx.get_classes()))}`\n"
            f"• **Methods:** `{len(list(dx.get_methods()))}`\n"
            f"• **Strings:** `{len(list(dx.get_strings()))}`\n\n"
            f"🔍 **Commands:**\n"
            f"• `/search <keyword>` - Keyword dhoondhein\n"
            f"• `/category` - Category tags ki list dekhein\n"
            f"• `/category NETWORK_URL` - Sirf URLs nikaalein"
        )
        await status_msg.edit_text(report, parse_mode="Markdown")

    except Exception as e:
        await status_msg.edit_text(f"❌ Analysis error: {str(e)}")

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def search_in_dex(dx, keyword: str) -> str:
    escaped_kw = re.escape(keyword)
    pattern = f"(?i).*{escaped_kw}.*"

    results = []
    results.append(f"🔎 SMART SEARCH REPORT FOR: '{keyword}'\n" + "=" * 48 + "\n")

    matched_strings = list(dx.find_strings(pattern))
    results.append(f"\n📌 [1] MATCHING STRINGS ({len(matched_strings)} found):")
    if matched_strings:
        for s_obj in matched_strings[:35]:
            val = s_obj.get_value().replace("\n", "\\n")
            xrefs = list(s_obj.get_xref_from())
            role_tag = classify_string(val, xrefs)
            results.append(f'\n  🏷️ [{role_tag}] -> "{val}"')
            if xrefs:
                for _, meth_obj in xrefs[:8]:
                    results.append(
                        f"    ↳ Location: {meth_obj.class_name} -> {meth_obj.name}{meth_obj.descriptor}"
                    )
            else:
                results.append("    ↳ Location: Unused / Constant Pool only")
    else:
        results.append("  No matching strings found.")

    matched_classes = list(dx.find_classes(pattern))
    results.append(f"\n\n📂 [2] MATCHING CLASSES ({len(matched_classes)} found):")
    if matched_classes:
        for c_obj in matched_classes[:25]:
            results.append(f"  • [CLASS_DEF] {c_obj.name}")
    else:
        results.append("  No matching classes found.")

    matched_methods = list(dx.find_methods(methodname=pattern))
    results.append(f"\n\n⚙️ [3] MATCHING METHODS ({len(matched_methods)} found):")
    if matched_methods:
        for m_obj in matched_methods[:25]:
            results.append(
                f"\n  • [METHOD] {m_obj.name}{m_obj.descriptor}\n"
                f"    ↳ Class: {m_obj.class_name}"
            )
            caller_xrefs = list(m_obj.get_xref_from())
            for _, caller_meth, offset in caller_xrefs[:5]:
                results.append(
                    f"    ↳ Called by: {caller_meth.class_name}->{caller_meth.name} (offset: {offset})"
                )
    else:
        results.append("  No matching methods found.")

    return "\n".join(results)

async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "dx" not in context.user_data:
        await update.message.reply_text("⚠️ Pehle koi `classes.dex` file upload karein.")
        return

    if not context.args:
        await update.message.reply_text("Example: `/search token`", parse_mode="Markdown")
        return

    keyword = " ".join(context.args)
    dx = context.user_data["dx"]
    status_msg = await update.message.reply_text(f"🔍 `{keyword}` search ho raha hai...", parse_mode="Markdown")

    try:
        report_text = search_in_dex(dx, keyword)
        if len(report_text) <= 3900:
            await status_msg.edit_text(f"```text\n{report_text}\n```", parse_mode="Markdown")
        else:
            await status_msg.delete()
            report_file = io.BytesIO(report_text.encode("utf-8"))
            report_file.name = f"search_{keyword}.txt"
            await update.message.reply_document(document=report_file)
    except Exception as e:
        await status_msg.edit_text(f"❌ Error: {str(e)}")

def filter_by_category(dx, target_tag: str) -> str:
    target_tag = target_tag.upper().strip()
    matched_items = []

    for s_obj in dx.get_strings():
        val = s_obj.get_value()
        if not val or len(val.strip()) == 0:
            continue

        xrefs = list(s_obj.get_xref_from())
        tag = classify_string(val, xrefs)

        if tag == target_tag:
            matched_items.append((val.replace("\n", "\\n"), xrefs))

    results = [
        f"📂 CATEGORY FILTER REPORT: [{target_tag}]",
        f"Total Found: {len(matched_items)}",
        "=" * 48 + "\n",
    ]

    if not matched_items:
        results.append(f"Is DEX file mein [{target_tag}] category ki koi string nahi mili.")
        return "\n".join(results)

    for idx, (val, xrefs) in enumerate(matched_items[:100], start=1):
        results.append(f'\n{idx}. 🏷️ [{target_tag}] -> "{val}"')
        if xrefs:
            for _, meth_obj in xrefs[:5]:
                results.append(
                    f"   ↳ Location: {meth_obj.class_name} -> {meth_obj.name}{meth_obj.descriptor}"
                )
        else:
            results.append("   ↳ Location: Unused / Constant Pool only")

    return "\n".join(results)

async def category_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "dx" not in context.user_data:
        await update.message.reply_text("⚠️ Pehle `classes.dex` file upload karein.")
        return

    if not context.args:
        tags_list = "\n".join([f"• `{tag}`" for tag in VALID_CATEGORIES])
        await update.message.reply_text(
            f"📋 **Available Category Tags:**\n\n{tags_list}\n\n"
            f"👉 Use: `/category NETWORK_URL`",
            parse_mode="Markdown",
        )
        return

    target_tag = context.args[0].upper().strip()
    if target_tag not in VALID_CATEGORIES:
        await update.message.reply_text(f"❌ Invalid category tag: `{target_tag}`", parse_mode="Markdown")
        return

    dx = context.user_data["dx"]
    status_msg = await update.message.reply_text(f"⏳ `{target_tag}` filter ho raha hai...", parse_mode="Markdown")

    try:
        report_text = filter_by_category(dx, target_tag)
        if len(report_text) <= 3900:
            await status_msg.edit_text(f"```text\n{report_text}\n```", parse_mode="Markdown")
        else:
            await status_msg.delete()
            report_file = io.BytesIO(report_text.encode("utf-8"))
            report_file.name = f"category_{target_tag}.txt"
            await update.message.reply_document(document=report_file)
    except Exception as e:
        await status_msg.edit_text(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("search", search_command))
    app.add_handler(CommandHandler("category", category_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    print("Bot chalu ho gaya hai...")
    app.run_polling()
      
