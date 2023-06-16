import logging
import re

try:
    import ipaddress
except ImportError:
    ipaddress = None

try:
    import requests
except ImportError:
    requests = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    import telegram
    from telegram import __version__ as TG_VER
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
except ImportError:
    telegram = None

# Установка уровня логирования для модуля httpx
logging.getLogger("httpx").setLevel(logging.WARNING)

# Включение логирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


def is_valid_ipv4(ip: str) -> bool:
    """Проверка, является ли переданная строка действительным IPv4-адресом."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, ip))


def is_valid_ipv6(ip: str) -> bool:
    """Проверка, является ли переданная строка действительным IPv6-адресом."""
    pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return bool(re.match(pattern, ip))


def is_private_ipv4(ip: str) -> bool:
    """Проверка, является ли переданный IPv4-адрес частным адресом."""
    if ipaddress is None:
        return False

    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private
    except ipaddress.AddressValueError:
        return False


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Отправка сообщения при получении команды /start."""
    user = update.effective_user
    await update.message.reply_html(
        rf"Привет, {user.mention_html()}!",
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Отправка сообщения при получении команды /help."""
    await update.message.reply_text("Помощь!")


def get_ip_info_whois(ip: str) -> dict:
    """Получение информации об IP-адресе с использованием ipwhois."""
    if IPWhois is None:
        return {}

    ip_info = IPWhois(ip)
    result = ip_info.lookup_rdap()

    asn = result.get("asn")
    asn_cidr = result.get("asn_cidr")
    asn_country_code = result.get("asn_country_code")
    asn_description = result.get("asn_description")
    cidr = result.get("network").get("cidr")
    country = result.get("network").get("country")
    description = result.get("network").get("description")

    ip_info_dict = {
        "ASN": asn,
        "ASN CIDR": asn_cidr,
        "ASN Country Code": f"{asn_country_code} {get_country_flag(asn_country_code)}",
        "ASN Description": asn_description,
        "CIDR": cidr,
        "Country": country,
        "Description": description,
    }

    return ip_info_dict

def get_ip_info_ipapi(ip: str) -> dict:
    """Получение информации об IP-адресе с использованием ipapi."""
    response = requests.get(f"https://ipapi.co/{ip}/json")
    data = response.json()
    print (data)
    if 'error' in data and data['error']:
        return {'reason': data.get('reason')}

    ip_info_dict = {
        "IP": data.get("ip"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "country": f"{data.get('country')} {get_country_flag(data.get('country'))}",
        "region": data.get("region"),
        "Org": data.get("org"),
    }

    return ip_info_dict if ip_info_dict["IP"] else {}


def get_ip_info_ipinfo(ip: str) -> dict:
    """Получение информации об IP-адресе с использованием ipapi."""
    if requests is None:
        return {}

    token = read_ipinfo_token_from_file("tokens.txt")
    url = f"https://ipinfo.io/{ip}/json?token={token}"
    response = requests.get(url)
    data = response.json()
    ip_info_dict = {
        "IP": data.get("ip"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "country": f"{data.get('country')} {get_country_flag(data.get('country'))}",
        "region": data.get("region"),
        "Org": data.get("org"),
    }

    return ip_info_dict    


def get_country_flag(country_code: str) -> str:
    """Получение emoji флага для указанного кода страны."""
    if country_code:
        code_points = [ord(char) + 127397 for char in country_code.upper()]
        return chr(code_points[0]) + chr(code_points[1])
    return ""

async def check_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Проверка валидности IP-адреса и получение информации о нем."""
    ip = update.message.text.replace(",", ".")  # Замена запятой на точку

    # Отправка сообщения о начале проверки IP
    message = await update.message.reply_text(f"Ожидайте, идет проверка IP: {ip}")

    if is_valid_ipv4(ip) or is_valid_ipv6(ip):
        if is_private_ipv4(ip):
            await update.message.reply_text("Это частный IP-адрес")
            logger.info(f"Пользователь {update.effective_user.username} указал частный IP-адрес: {ip}")
        else:
            if IPWhois is None or requests is None:
                await update.message.reply_text("Необходимо установить дополнительные библиотеки для получения информации об IP-адресе.")
            else:
                ip_info_whois = get_ip_info_whois(ip)
                ip_info_ipapi = get_ip_info_ipapi(ip)
                ip_info_ipinfo = get_ip_info_ipinfo(ip)

                ip_info_whois_text = ""
                for key, value in ip_info_whois.items():
                    ip_info_whois_text += f"{key}: {value}\n"

                ip_info_ipapi_text = ""
                for key, value in ip_info_ipapi.items():
                    ip_info_ipapi_text += f"{key}: {value}\n"

                ip_info_ipinfo_text = ""
                for key, value in ip_info_ipinfo.items():
                    ip_info_ipinfo_text += f"{key}: {value}\n"                    

                response_text = f"Информация об IP-адресе (сервис ipwhois):\n\n{ip_info_whois_text}\n\n" \
                                f"Информация об IP-адресе (сервис ipapi):\n\n{ip_info_ipapi_text}\n\n"\
                                f"Информация об IP-адресе (сервис ipinfo):\n\n{ip_info_ipinfo_text}"

                await update.message.reply_text(response_text)

                logger.info(f"Пользователь {update.effective_user.username} указал публичный IP-адрес: {ip}")
                
                # Удаление сообщения о начале проверки IP
                await message.delete()                
    else:
        await update.message.reply_text("Недопустимый IP-адрес")
        await message.delete()
        logger.info(f"Пользователь {update.effective_user.username} указал недопустимый IP-адрес: {ip}")


def read_telegram_token_from_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
        match = re.search(r'telegram_bot_token\s*=\s*"([^"]+)"', content)
        if match:
            token = match.group(1)
            return token
        else:
            return None

def read_ipinfo_token_from_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
        match = re.search(r'ipinfo_token\s*=\s*"([^"]+)"', content)
        if match:
            token = match.group(1)
            return token
        else:
            return None

def main() -> None:
    """Запуск бота."""
    # Проверка наличия необходимых библиотек
    if ipaddress is None or requests is None or IPWhois is None or telegram is None:
        missing_libs = []
        if ipaddress is None:
            missing_libs.append("ipaddress")
        if requests is None:
            missing_libs.append("requests")
        if IPWhois is None:
            missing_libs.append("ipwhois")
        if telegram is None:
            missing_libs.append("python-telegram-bot")

        missing_libs_str = ", ".join(missing_libs)
        print(f"Необходимо установить следующие библиотеки: {missing_libs_str}")
        return

    # Чтение токена из файла
    token = read_telegram_token_from_file("tokens.txt")
    if token:
        print("Token:", token)
    else:
        print("Token not found in the file.")

    # Создание приложения и передача токена бота
    application = Application.builder().token(token).build()

    # Обработчики команд - ответы в Telegram
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))

    # Обработчик для обычных сообщений - проверка IP-адреса
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_ip))

    # Запуск бота
    application.run_polling()


if __name__ == "__main__":
    main()
