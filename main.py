import os
import sys
import subprocess
import logging
from utils.network_scan import scan_network, analyze_traffic, check_bluetooth, check_wifi

banner = """
 _   _  _____ _____    _____ _
| \ | ||  ___/|_   _|  /  ___/ 
|  \| || |__   | |    \ `--. 
| . ` ||  __|  | |     `--. \ 
| |\  || |___  | |    /\__/ / 
\_| \_/\____/  \_/    \____/ 
"""

def check_admin():
    """Проверка прав администратора"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def setup_logging():
    """Настройка логирования"""
    logging.basicConfig(
        filename='network_scan.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def main():
    print(banner)
    if not check_admin():
        print("Для работы программы требуются права администратора!")
        sys.exit(1)

    setup_logging()
    print("Это приложение для обнаружения каналов утечки информации в локальной сети.")
    
    while True:
        confirmation = input("Вы уверены, что хотите продолжить? (да/нет): ").strip().lower()
        if confirmation in ['да', 'нет']:
            break
        print("Пожалуйста, введите 'да' или 'нет'")

    if confirmation == 'да':
        try:
            print("Начинаем сканирование сети...")
            results = {
                'network': scan_network(),
                'traffic': analyze_traffic(),
                'bluetooth': check_bluetooth(),
                'wifi': check_wifi()
            }

            print("\nРезультаты анализа сети:")
            for key, value in results.items():
                print(f"\n{key.upper()}:")
                print(value)
                logging.info(f"{key}: {value}")

        except Exception as e:
            print(f"Произошла ошибка при сканировании: {str(e)}")
            logging.error(f"Ошибка сканирования: {str(e)}")
        finally:
            print("\nЗавершение работы программы...")
    else:
        print("Сканирование отменено.")
        logging.info("Сканирование отменено пользователем")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем")
        logging.info("Программа прервана пользователем")
        sys.exit(0)
